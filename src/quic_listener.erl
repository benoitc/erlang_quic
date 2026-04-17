%%% -*- erlang -*-
%%%
%%% QUIC Listener
%%% RFC 9000 Section 5 - Connections
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC server listener for accepting connections.
%%%
%%% This module handles:
%%% - UDP socket management
%%% - Initial packet routing to connections
%%% - Connection ID management
%%% - Stateless retry (optional)
%%%
%%% == Connection Handler Callback ==
%%%
%%% The `connection_handler' option allows custom handling of new connections:
%%% ```
%%% Opts = #{
%%%     cert => Cert,
%%%     key => Key,
%%%     connection_handler => fun(Conn) ->
%%%         %% Conn is the connection pid
%%%         %% Spawn your handler and return its pid
%%%         HandlerPid = spawn(fun() -> my_handler(Conn) end),
%%%         %% Ownership will be transferred to HandlerPid
%%%         {ok, HandlerPid}
%%%     end
%%% }
%%% '''

-module(quic_listener).
-behaviour(gen_server).

%% Suppress pattern warnings for defensive callback handling (user-provided callbacks)
-dialyzer({no_match, create_connection/5}).

-export([
    start_link/2,
    start/2,
    stop/1,
    get_port/1,
    get_connections/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_continue/2,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include("quic.hrl").
-include_lib("kernel/include/logger.hrl").
-define(QUIC_LOG_META, #{
    domain => [erlang_quic, listener], report_cb => fun quic_log:format_report/2
}).

-record(listener_state, {
    socket :: gen_udp:socket() | socket:socket(),
    %% Socket state for quic_socket abstraction (for GRO support on Linux)
    socket_state :: quic_socket:socket_state() | undefined,
    %% Which socket backend: gen_udp or socket (OTP 27+ with GRO)
    socket_backend = gen_udp :: gen_udp | socket,
    %% GRO receiver process (when using socket backend)
    gro_receiver :: pid() | undefined,
    port :: inet:port_number(),
    cert :: binary(),
    cert_chain :: [binary()],
    private_key :: term(),
    alpn_list :: [binary()],
    %% Connection ID -> Pid mapping
    connections :: ets:tid(),
    tickets_table :: ets:tid(),
    %% Whether this listener owns the ETS tables (false in pool mode)
    owns_tables = true :: boolean(),
    %% Stateless reset secret (RFC 9000 Section 10.3). Also serves as
    %% the HMAC key for RFC 9000 §8.1 retry / NEW_TOKEN envelopes so
    %% operators only have to manage one rotating secret.
    reset_secret :: binary(),
    %% Address validation policy (RFC 9000 §8.1.2). `never' preserves
    %% the legacy no-retry behaviour; `always' makes the listener emit
    %% a Retry packet whenever a client's Initial arrives without a
    %% valid token. Token freshness bound is `token_max_age_ms'.
    address_validation = never :: never | always,
    token_max_age_ms = 600000 :: non_neg_integer(),
    %% Connection handler callback: fun(Conn) -> {ok, HandlerPid} where Conn is pid()
    connection_handler ::
        fun((pid()) -> {ok, pid()} | {error, term()})
        | fun((pid(), binary()) -> {ok, pid()} | {error, term()})
        | undefined,
    %% QUIC-LB CID configuration (RFC 9312)
    cid_config :: #cid_config{} | undefined,
    %% Expected DCID length for short header packets
    dcid_len = 8 :: pos_integer(),
    %% Options
    opts :: map()
}).
-type state() :: #listener_state{}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a QUIC listener on the given port.
%% Options:
%%   - cert: Server certificate (DER binary)
%%   - cert_chain: Certificate chain [binary()]
%%   - key: Private key
%%   - alpn: List of supported ALPN protocols
%%   - active_n: Number of packets before socket goes passive (default 100)
%%   - reuseport: Enable SO_REUSEPORT for multiple listeners (default false)
%%   - connections_table: Shared ETS table for connection tracking (pool mode)
%%   - preferred_ipv4: {IP, Port} for preferred IPv4 address (RFC 9000 Section 9.6)
%%   - preferred_ipv6: {IP, Port} for preferred IPv6 address (RFC 9000 Section 9.6)
-spec start_link(inet:port_number(), map()) -> {ok, pid()} | {error, term()}.
start_link(Port, Opts) ->
    gen_server:start_link(?MODULE, {Port, Opts}, []).

%% @doc Start a QUIC listener (without linking to caller).
-spec start(inet:port_number(), map()) -> {ok, pid()} | {error, term()}.
start(Port, Opts) ->
    gen_server:start(?MODULE, {Port, Opts}, []).

%% @doc Stop the listener.
-spec stop(pid()) -> ok.
stop(Listener) ->
    gen_server:stop(Listener).

%% @doc Get the port the listener is bound to.
-spec get_port(pid()) -> inet:port_number().
get_port(Listener) ->
    gen_server:call(Listener, get_port).

%% @doc Get list of active connections.
-spec get_connections(pid()) -> [pid()].
get_connections(Listener) ->
    gen_server:call(Listener, get_connections).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @doc false
-spec init({inet:port_number(), map()}) -> term().
init({Port, Opts}) ->
    process_flag(trap_exit, true),

    %% Check which socket backend to use
    %% socket_backend => socket enables GRO on Linux (OTP 27+)
    %% Default: gen_udp for backwards compatibility
    Backend = maps:get(socket_backend, Opts, gen_udp),

    case Backend of
        socket ->
            init_socket_backend(Port, Opts);
        gen_udp ->
            init_genudp_backend(Port, Opts)
    end.

%% Initialize with OTP socket backend (GRO support on Linux)
init_socket_backend(Port, Opts) ->
    case quic_socket:open(Port, Opts) of
        {ok, SocketState} ->
            Socket = quic_socket:get_socket(SocketState),
            {ok, {Socket, SocketState, socket, Opts}, {continue, discover_manager}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% Initialize with gen_udp backend (default, backwards compatible)
init_genudp_backend(Port, Opts) ->
    ActiveN = maps:get(active_n, Opts, 100),
    ReusePort = maps:get(reuseport, Opts, false),
    ExtraFlags = maps:get(extra_socket_opts, Opts, []),

    %% UDP buffer sizing - larger buffers improve throughput significantly
    %% OS may cap to lower values (check sysctl net.core.rmem_max on Linux)
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),

    SocketOpts =
        [
            binary,
            inet,
            {active, ActiveN},
            {reuseaddr, true},
            {recbuf, RecBuf},
            {sndbuf, SndBuf}
        ] ++
            case ReusePort of
                true -> [{reuseport, true}, {reuseport_lb, true}];
                false -> []
            end ++ ExtraFlags,
    case gen_udp:open(Port, SocketOpts) of
        {ok, Socket} ->
            {ok, {Socket, undefined, gen_udp, Opts}, {continue, discover_manager}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @doc false
handle_continue(discover_manager, {Socket, SocketState, Backend, Opts}) ->
    %% Extract required options
    #{cert := Cert, key := PrivateKey} = Opts,
    CertChain = maps:get(cert_chain, Opts, []),
    ALPNList = maps:get(alpn, Opts, [<<"h3">>]),
    ConnHandler = maps:get(connection_handler, Opts, undefined),

    {ConnTab, TicketTab, OwnsTables} = get_tables(Opts),

    %% Get actual port and bound address
    ActualPort = get_socket_port(Socket, SocketState, Backend),

    %% Generate or use provided stateless reset secret
    ResetSecret = maps:get(reset_secret, Opts, crypto:strong_rand_bytes(32)),

    %% Initialize QUIC-LB CID configuration (RFC 9312)
    {CIDConfig, DCIDLen} = init_cid_config(Opts, ResetSecret),

    %% Start GRO receiver if using socket backend
    GROReceiver = maybe_start_gro_receiver(Backend, SocketState),

    State = #listener_state{
        socket = Socket,
        socket_state = SocketState,
        socket_backend = Backend,
        gro_receiver = GROReceiver,
        port = ActualPort,
        cert = Cert,
        cert_chain = CertChain,
        private_key = PrivateKey,
        alpn_list = ALPNList,
        connections = ConnTab,
        tickets_table = TicketTab,
        owns_tables = OwnsTables,
        reset_secret = ResetSecret,
        address_validation = maps:get(address_validation, Opts, never),
        token_max_age_ms = maps:get(address_token_max_age_ms, Opts, 600000),
        connection_handler = ConnHandler,
        cid_config = CIDConfig,
        dcid_len = DCIDLen,
        opts = Opts
    },
    {noreply, State}.

%% Get socket port depending on backend
get_socket_port(_Socket, SocketState, socket) when SocketState =/= undefined ->
    case quic_socket:sockname(SocketState) of
        {ok, {_IP, Port}} -> Port;
        {error, _} -> 0
    end;
get_socket_port(Socket, _SocketState, gen_udp) ->
    case inet:sockname(Socket) of
        {ok, {_IP, Port}} -> Port;
        {error, _} -> 0
    end.

%% Start GRO receiver process for socket backend
maybe_start_gro_receiver(socket, SocketState) when SocketState =/= undefined ->
    Listener = self(),
    spawn_link(fun() -> gro_receive_loop(SocketState, Listener) end);
maybe_start_gro_receiver(_, _) ->
    undefined.

%% GRO receiver loop - runs in separate process
%% Does blocking recvmsg calls and forwards packets to listener
gro_receive_loop(SocketState, Listener) ->
    case quic_socket:recv(SocketState, infinity) of
        {ok, {IP, Port}, Packets} ->
            %% Send packets to listener (may be multiple with GRO)
            Listener ! {gro_packets, IP, Port, Packets},
            gro_receive_loop(SocketState, Listener);
        {error, closed} ->
            ok;
        {error, _Reason} ->
            %% Retry on transient errors
            gro_receive_loop(SocketState, Listener)
    end.

%% @doc false
-spec handle_call(term(), gen_server:from(), state()) -> {reply, term(), state()}.
handle_call(get_port, _From, #listener_state{port = Port} = State) ->
    {reply, Port, State};
%% @doc false
handle_call(get_socket_info, _From, #listener_state{socket = Socket, port = Port} = State) ->
    SockInfo = inet:info(Socket),
    {reply, #{port => Port, socket => Socket, info => SockInfo}, State};
handle_call(get_connections, _From, #listener_state{connections = Conns} = State) ->
    Pids = ets:foldl(fun({_CID, Pid}, Acc) -> [Pid | Acc] end, [], Conns),
    {reply, lists:usort(Pids), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

%% @doc false
-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @doc false
%% Handle incoming UDP packets (gen_udp backend)
handle_info(
    {udp, Socket, SrcIP, SrcPort, Packet},
    #listener_state{socket = Socket, socket_backend = gen_udp} = State
) ->
    ?LOG_DEBUG(
        #{what => udp_received, src_ip => SrcIP, src_port => SrcPort, size => byte_size(Packet)},
        ?QUIC_LOG_META
    ),
    handle_packet(Packet, {SrcIP, SrcPort}, State),
    {noreply, State};
%% Handle GRO packets (socket backend with GRO)
%% May receive multiple packets in single recv call
handle_info(
    {gro_packets, SrcIP, SrcPort, Packets},
    #listener_state{socket_backend = socket} = State
) ->
    ?LOG_DEBUG(
        #{
            what => gro_packets_received,
            src_ip => SrcIP,
            src_port => SrcPort,
            count => length(Packets)
        },
        ?QUIC_LOG_META
    ),
    RemoteAddr = {SrcIP, SrcPort},
    handle_gro_packets(Packets, RemoteAddr, State),
    {noreply, State};
%% Handle socket going passive (backpressure with {active, N}) - gen_udp only
handle_info(
    {udp_passive, Socket},
    #listener_state{socket = Socket, opts = Opts, socket_backend = gen_udp} = State
) ->
    N = maps:get(active_n, Opts, 100),
    inet:setopts(Socket, [{active, N}]),
    {noreply, State};
%% Handle connection process exit
handle_info(
    {'EXIT', Pid, _Reason}, #listener_state{connections = Conns, gro_receiver = GROReceiver} = State
) ->
    case Pid of
        GROReceiver ->
            %% GRO receiver died - restart it
            NewReceiver = maybe_start_gro_receiver(
                State#listener_state.socket_backend,
                State#listener_state.socket_state
            ),
            {noreply, State#listener_state{gro_receiver = NewReceiver}};
        _ ->
            cleanup_connection(Conns, Pid),
            {noreply, State}
    end;
%% Handle UDP from different socket (shouldn't happen)
handle_info({udp, _OtherSocket, _SrcIP, _SrcPort, _Packet}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%% Handle multiple packets received via GRO
%% Groups packets by connection and sends batched messages
handle_gro_packets([], _RemoteAddr, _State) ->
    ok;
handle_gro_packets([Packet], RemoteAddr, State) ->
    %% Single packet - no need to batch
    handle_packet(Packet, RemoteAddr, State);
handle_gro_packets(Packets, RemoteAddr, State) ->
    %% Multiple packets - group by connection ID and batch
    dispatch_batched_packets(Packets, RemoteAddr, State).

%% Group packets by connection ID and dispatch in batches
dispatch_batched_packets(
    Packets, RemoteAddr, #listener_state{dcid_len = DCIDLen, connections = Conns} = State
) ->
    %% Build map of ConnPid -> [Packets] (preserving order)
    Groups = group_packets_by_conn(Packets, DCIDLen, Conns, #{}),
    %% Dispatch each batch
    maps:foreach(
        fun
            ({conn, ConnPid}, PacketList) ->
                %% Reverse to restore original order (we prepended)
                send_packets_to_connection(ConnPid, lists:reverse(PacketList), RemoteAddr);
            ({new, DCID, Version}, PacketList) ->
                %% Initial packets that need new connections
                [FirstPacket | _] = lists:reverse(PacketList),
                create_connection(FirstPacket, DCID, Version, RemoteAddr, State)
        end,
        Groups
    ).

%% Group packets by their destination connection
group_packets_by_conn([], _DCIDLen, _Conns, Acc) ->
    Acc;
group_packets_by_conn([Packet | Rest], DCIDLen, Conns, Acc) ->
    case parse_packet_header(Packet, DCIDLen) of
        {initial, DCID, _SCID, Version, _Rest} ->
            case ets:lookup(Conns, DCID) of
                [{DCID, ConnPid}] ->
                    %% Existing connection
                    Key = {conn, ConnPid},
                    Acc1 = maps:update_with(Key, fun(L) -> [Packet | L] end, [Packet], Acc),
                    group_packets_by_conn(Rest, DCIDLen, Conns, Acc1);
                [] ->
                    %% New connection - group by DCID
                    Key = {new, DCID, Version},
                    Acc1 = maps:update_with(Key, fun(L) -> [Packet | L] end, [Packet], Acc),
                    group_packets_by_conn(Rest, DCIDLen, Conns, Acc1)
            end;
        {short, DCID, _Rest} ->
            case ets:lookup(Conns, DCID) of
                [{DCID, ConnPid}] ->
                    Key = {conn, ConnPid},
                    Acc1 = maps:update_with(Key, fun(L) -> [Packet | L] end, [Packet], Acc),
                    group_packets_by_conn(Rest, DCIDLen, Conns, Acc1);
                [] ->
                    %% Unknown - skip (will be handled as stateless reset if needed)
                    group_packets_by_conn(Rest, DCIDLen, Conns, Acc)
            end;
        {long, DCID, _SCID, _PacketType, _Rest} ->
            case ets:lookup(Conns, DCID) of
                [{DCID, ConnPid}] ->
                    Key = {conn, ConnPid},
                    Acc1 = maps:update_with(Key, fun(L) -> [Packet | L] end, [Packet], Acc),
                    group_packets_by_conn(Rest, DCIDLen, Conns, Acc1);
                [] ->
                    %% Unknown long header - skip
                    group_packets_by_conn(Rest, DCIDLen, Conns, Acc)
            end;
        {error, _Reason} ->
            %% Skip invalid packets
            group_packets_by_conn(Rest, DCIDLen, Conns, Acc)
    end.

%% Send batched packets to a connection
send_packets_to_connection(ConnPid, [Packet], RemoteAddr) ->
    %% Single packet - use existing message format
    ConnPid ! {quic_packet, Packet, RemoteAddr};
send_packets_to_connection(ConnPid, Packets, RemoteAddr) ->
    %% Multiple packets - use batched message
    ConnPid ! {quic_packets, Packets, RemoteAddr}.

%% @doc false
terminate(_Reason, #listener_state{
    connections = ConnTab,
    tickets_table = TicketTab,
    owns_tables = OwnsTables,
    socket_state = SocketState,
    socket_backend = Backend,
    socket = Socket
}) ->
    %% Close socket based on backend
    case Backend of
        socket when SocketState =/= undefined ->
            quic_socket:close(SocketState);
        _ ->
            safe_close_socket(Socket)
    end,
    %% Only delete ETS tables if we own them (standalone mode, not pool mode)
    case OwnsTables of
        true ->
            safe_delete_table(ConnTab),
            safe_delete_table(TicketTab);
        false ->
            ok
    end,
    ok;
terminate(_Reason, _) ->
    %% Handle case where state is not fully initialized (e.g., init failed early)
    ok.

%% @doc false
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal Functions
%%====================================================================

safe_close_socket(Socket) ->
    try
        gen_udp:close(Socket)
    catch
        _:_ -> ok
    end.

safe_delete_table(Tab) ->
    try
        ets:delete(Tab)
    catch
        _:_ -> ok
    end.

%% Initialize QUIC-LB CID configuration from options
%% Returns {CIDConfig | undefined, DCIDLen}
init_cid_config(Opts, ResetSecret) ->
    case maps:get(lb_config, Opts, undefined) of
        undefined ->
            %% No LB config - use default random CIDs
            DCIDLen = maps:get(cid_len, Opts, 8),
            {undefined, DCIDLen};
        LBConfig when is_map(LBConfig) ->
            %% LB config provided as map - create config
            case quic_lb:new_config(LBConfig) of
                {ok, LBCfg} ->
                    CIDLen = quic_lb:expected_cid_len(LBCfg),
                    case
                        quic_lb:new_cid_config(#{
                            lb_config => LBCfg,
                            cid_len => CIDLen,
                            reset_secret => ResetSecret
                        })
                    of
                        {ok, CIDConfig} ->
                            {CIDConfig, CIDLen};
                        {error, Reason} ->
                            ?LOG_WARNING(
                                #{what => invalid_cid_config, reason => Reason},
                                ?QUIC_LOG_META
                            ),
                            {undefined, 8}
                    end;
                {error, Reason} ->
                    ?LOG_WARNING(
                        #{what => invalid_lb_config, reason => Reason},
                        ?QUIC_LOG_META
                    ),
                    {undefined, 8}
            end;
        #lb_config{} = LBCfg ->
            %% LB config provided as record
            CIDLen = quic_lb:expected_cid_len(LBCfg),
            case
                quic_lb:new_cid_config(#{
                    lb_config => LBCfg,
                    cid_len => CIDLen,
                    reset_secret => ResetSecret
                })
            of
                {ok, CIDConfig} ->
                    {CIDConfig, CIDLen};
                {error, Reason} ->
                    ?LOG_WARNING(
                        #{what => invalid_cid_config, reason => Reason},
                        ?QUIC_LOG_META
                    ),
                    {undefined, 8}
            end
    end.

%% Remove all CIDs associated with this connection
cleanup_connection(Conns, Pid) ->
    %% Use '$1' match spec variable, not literal atom '_'
    Pattern = {{'$1', Pid}, [], [true]},
    _ = ets:select_delete(Conns, [Pattern]).

%% Use provided ETS table or create new one for connection tracking
%% When using pool mode, the supervisor is in the options, query it for the
%% table manager and get the table from it.
%% Returns {ConnTab, TicketTab, OwnsTable} where OwnsTable indicates if
%% this listener should delete the tables on terminate.
get_tables(#{supervisor := SupPid}) ->
    Children = supervisor:which_children(SupPid),
    {quic_listener_manager, ManagerPid, _, _} = lists:keyfind(quic_listener_manager, 1, Children),
    {ok, {ConnTab, TicketTab}} = quic_listener_manager:get_tables(ManagerPid),
    % Pool mode - don't own tables
    {ConnTab, TicketTab, false};
get_tables(_) ->
    ConnTab = ets:new(quic_connections, [set, protected]),
    TicketTab = ets:new(quic_tickets, [set, protected]),
    % Standalone mode - own tables
    {ConnTab, TicketTab, true}.

handle_packet(Packet, RemoteAddr, #listener_state{dcid_len = DCIDLen} = State) ->
    case parse_packet_header(Packet, DCIDLen) of
        {initial, DCID, _SCID, Version, _Rest} ->
            ?LOG_INFO(
                #{
                    what => initial_packet,
                    remote_addr => RemoteAddr,
                    dcid => DCID,
                    version => Version
                },
                ?QUIC_LOG_META
            ),
            handle_initial_packet(Packet, DCID, Version, RemoteAddr, State);
        {short, DCID, _Rest} ->
            ?LOG_INFO(#{what => short_header_packet, dcid => DCID}, ?QUIC_LOG_META),
            route_to_connection(DCID, Packet, RemoteAddr, State);
        {long, DCID, _SCID, PacketType, _Rest} ->
            ?LOG_INFO(
                #{what => long_header_packet, packet_type => PacketType, dcid => DCID},
                ?QUIC_LOG_META
            ),
            route_to_connection(DCID, Packet, RemoteAddr, State);
        {error, Reason} ->
            ?LOG_WARNING(#{what => packet_parse_failed, reason => Reason}, ?QUIC_LOG_META),
            ok
    end.

%% Parse packet header to extract DCID for routing
%% DCIDLen parameter specifies expected DCID length for short header packets
parse_packet_header(
    <<FirstByte, Version:32, DCIDLenField, DCID:DCIDLenField/binary, SCIDLen, SCID:SCIDLen/binary,
        Rest/binary>>,
    _DCIDLen
) when
    FirstByte band 16#80 =:= 16#80
->
    %% Long header - extract packet type from bits 4-5 of first byte
    %% Type: 00=Initial, 01=0-RTT, 10=Handshake, 11=Retry
    PacketType = (FirstByte bsr 4) band 2#11,
    case PacketType of
        0 -> {initial, DCID, SCID, Version, Rest};
        _ -> {long, DCID, SCID, PacketType, Rest}
    end;
parse_packet_header(<<0:1, _:7, Rest/binary>>, DCIDLen) ->
    %% Short header - use configured DCID length
    case Rest of
        <<DCID:DCIDLen/binary, Remaining/binary>> ->
            {short, DCID, Remaining};
        _ ->
            {error, short_header_too_small}
    end;
parse_packet_header(_, _DCIDLen) ->
    {error, invalid_header}.

%% Handle Initial packet - may create new connection
handle_initial_packet(
    Packet,
    DCID,
    Version,
    RemoteAddr,
    #listener_state{connections = Conns} = State
) ->
    case ets:lookup(Conns, DCID) of
        [{DCID, ConnPid}] ->
            %% Existing connection
            send_to_connection(ConnPid, Packet, RemoteAddr);
        [] ->
            %% New connection
            create_connection(Packet, DCID, Version, RemoteAddr, State)
    end.

%% Route packet to existing connection
route_to_connection(
    DCID,
    Packet,
    RemoteAddr,
    #listener_state{connections = Conns} = State
) ->
    case ets:lookup(Conns, DCID) of
        [{DCID, ConnPid}] ->
            send_to_connection(ConnPid, Packet, RemoteAddr);
        [] ->
            %% Unknown connection - potentially send stateless reset
            handle_unknown_packet(DCID, Packet, RemoteAddr, State)
    end.

%% Create a new server-side connection
create_connection(
    Packet,
    DCID,
    Version,
    RemoteAddr,
    #listener_state{
        socket = Socket,
        socket_state = SocketState,
        socket_backend = Backend,
        cid_config = CIDConfig,
        reset_secret = ResetSecret,
        address_validation = Policy,
        token_max_age_ms = MaxAge
    } = State
) ->
    {IP, Port} = RemoteAddr,
    case decide_address_validation(Packet, Version, RemoteAddr, ResetSecret, Policy, MaxAge) of
        {send_retry, ClientSCID, RetryToken} ->
            %% Fresh server-chosen CID the client must use as DCID on
            %% its next Initial.
            RetrySCID =
                case CIDConfig of
                    undefined -> crypto:strong_rand_bytes(8);
                    #cid_config{} -> quic_lb:generate_cid(CIDConfig)
                end,
            RetryPacket = quic_packet:encode_retry(
                DCID, ClientSCID, RetrySCID, RetryToken, Version
            ),
            send_packet(Socket, SocketState, Backend, IP, Port, RetryPacket),
            ok;
        Verdict when Verdict =:= spawn_validated orelse Verdict =:= spawn_unvalidated ->
            create_connection_unconditional(
                Verdict, Packet, DCID, Version, RemoteAddr, State
            )
    end.

create_connection_unconditional(
    Verdict,
    Packet,
    DCID,
    Version,
    RemoteAddr,
    #listener_state{
        socket = Socket,
        socket_state = SocketState,
        socket_backend = Backend,
        cert = Cert,
        cert_chain = CertChain,
        private_key = PrivateKey,
        alpn_list = ALPNList,
        connections = Conns,
        connection_handler = ConnHandler,
        cid_config = CIDConfig,
        reset_secret = ResetSecret,
        opts = Opts
    }
) ->
    %% Generate server connection ID (LB-aware if configured)
    ServerCID =
        case CIDConfig of
            undefined -> crypto:strong_rand_bytes(8);
            #cid_config{} -> quic_lb:generate_cid(CIDConfig)
        end,

    %% Start connection process with client's QUIC version.
    %% `reset_secret' is propagated so this connection's
    %% NEW_CONNECTION_ID tokens match the ones the listener will emit
    %% for orphan packets after the connection goes away (RFC 9000
    %% §10.3.2).
    %% Capabilities of the listener's underlying UDP socket. The server
    %% connection uses these to build a per-connection sender socket_state
    %% that reuses the shared socket but owns its own batch buffer (so
    %% each connection's outgoing packets can be coalesced via GSO on
    %% Linux + socket backend, or just in-memory batched otherwise).
    ListenerGSO =
        case SocketState of
            undefined -> false;
            _ -> quic_socket:gso_supported(SocketState)
        end,
    ConnOpts = #{
        role => server,
        socket => Socket,
        listener_socket_backend => Backend,
        listener_gso_supported => ListenerGSO,
        remote_addr => RemoteAddr,
        initial_dcid => DCID,
        scid => ServerCID,
        cert => Cert,
        cert_chain => CertChain,
        private_key => PrivateKey,
        alpn => ALPNList,
        listener => self(),
        cid_config => CIDConfig,
        reset_secret => ResetSecret,
        %% For Verdict = spawn_validated the listener already checked
        %% the client's retry token; skip the per-connection
        %% re-validation to avoid redundant work.
        address_validated => (Verdict =:= spawn_validated),
        %% When spawn_validated is reached, the DCID on the accepted
        %% Initial is the SCID the listener issued in its Retry
        %% (RFC 9000 §7.3 client behaviour). Echo it back to the
        %% client as retry_source_connection_id in our transport
        %% parameters.
        retry_scid =>
            case Verdict of
                spawn_validated -> DCID;
                _ -> undefined
            end,
        version => Version
    },

    ?LOG_INFO(#{what => creating_connection, dcid => DCID}, ?QUIC_LOG_META),
    case quic_connection:start_server(maps:merge(Opts, ConnOpts)) of
        {ok, ConnPid} ->
            ?LOG_INFO(#{what => connection_created, conn_pid => ConnPid}, ?QUIC_LOG_META),

            %% Register connection ID
            ets:insert(Conns, {DCID, ConnPid}),
            ets:insert(Conns, {ServerCID, ConnPid}),

            %% Invoke connection handler callback BEFORE sending packet
            %% This ensures ownership is transferred before handshake can complete
            case ConnHandler of
                undefined ->
                    ok;
                Fun when is_function(Fun, 2) ->
                    %% Handler takes (ConnPid, DCID)
                    case Fun(ConnPid, DCID) of
                        {ok, HandlerPid} when is_pid(HandlerPid) ->
                            ok = quic:set_owner_sync(ConnPid, HandlerPid);
                        {error, HandlerError} ->
                            ?LOG_WARNING(
                                #{
                                    what => connection_handler_failed,
                                    error => HandlerError
                                },
                                ?QUIC_LOG_META
                            )
                    end;
                Fun when is_function(Fun, 1) ->
                    case Fun(ConnPid) of
                        {ok, HandlerPid} when is_pid(HandlerPid) ->
                            %% Transfer ownership to handler (sync to ensure it completes
                            %% before any packets trigger handshake completion)
                            ok = quic:set_owner_sync(ConnPid, HandlerPid);
                        {error, HandlerError} ->
                            ?LOG_WARNING(
                                #{
                                    what => connection_handler_failed,
                                    error => HandlerError
                                },
                                ?QUIC_LOG_META
                            )
                    end
            end,

            %% Send initial packet to new connection (after ownership transfer)
            send_to_connection(ConnPid, Packet, RemoteAddr),

            {ok, ConnPid};
        {error, Reason} ->
            ?LOG_WARNING(#{what => start_connection_failed, reason => Reason}, ?QUIC_LOG_META),
            {error, Reason}
    end.

send_to_connection(ConnPid, Packet, RemoteAddr) ->
    ConnPid ! {quic_packet, Packet, RemoteAddr}.

%%====================================================================
%% Stateless Reset (RFC 9000 Section 10.3)
%%====================================================================

%% Handle packet to unknown connection - potentially send stateless reset
handle_unknown_packet(
    DCID,
    Packet,
    {IP, Port},
    #listener_state{
        socket = Socket,
        socket_state = SocketState,
        socket_backend = Backend,
        reset_secret = Secret
    }
) ->
    %% RFC 9000 Section 10.3.3: Don't send reset if packet might be a reset
    case is_potential_stateless_reset(Packet) of
        true ->
            %% Don't respond to avoid reset loops
            ok;
        false ->
            %% RFC 9000 Section 10.3.3: Reset must be smaller than triggering packet
            %% and at least 21 bytes (minimum QUIC packet size)
            TriggerSize = byte_size(Packet),
            case TriggerSize > 21 of
                true ->
                    %% Generate and send stateless reset
                    Token = compute_stateless_reset_token(Secret, DCID),
                    ResetPacket = build_stateless_reset(Token, TriggerSize),
                    send_packet(Socket, SocketState, Backend, IP, Port, ResetPacket);
                false ->
                    %% Packet too small to respond with reset
                    ok
            end
    end.

%% Decide whether a freshly arrived Initial gets a Retry, spawns a
%% validated connection, or spawns an unvalidated one per the
%% listener's `address_validation' policy.
%%
%% The caller passes the *whole* Initial packet; this helper peels the
%% Long Header off and inspects the Token field.
%%
%% Returns:
%%   spawn_unvalidated — policy is `never' or token was missing on a
%%     `never' server; pass through.
%%   spawn_validated   — token present + signature + addr + freshness
%%     all validated; connection is exempt from re-validation.
%%   {send_retry, ClientSCID, Token} — emit a Retry addressed back to
%%     ClientSCID (which we took from the Initial's SCID) carrying
%%     Token for the client to echo back.
decide_address_validation(_Packet, _Version, _Addr, _Secret, never, _MaxAge) ->
    spawn_unvalidated;
decide_address_validation(Packet, _Version, Addr, Secret, always, MaxAge) ->
    case parse_initial_token(Packet) of
        {ok, <<>>, ClientSCID, ODCID} ->
            %% No token → mint one and require the client to echo it.
            Token = quic_address_token:encode_retry(
                Secret, Addr, ODCID, erlang:system_time(millisecond)
            ),
            {send_retry, ClientSCID, Token};
        {ok, Token, ClientSCID, ExpectedODCID} ->
            case validate_initial_token(Secret, Token, Addr, ExpectedODCID, MaxAge) of
                ok ->
                    spawn_validated;
                {error, _} ->
                    Fresh = quic_address_token:encode_retry(
                        Secret, Addr, ExpectedODCID, erlang:system_time(millisecond)
                    ),
                    {send_retry, ClientSCID, Fresh}
            end;
        {error, _} ->
            %% Malformed Initial — fall back to unvalidated spawn so
            %% the connection's own decoder reports the real error.
            spawn_unvalidated
    end.

%% Extract the Token field from a Long Header Initial packet. Also
%% returns the client's SCID and the DCID (which the client chose as
%% the original destination CID before any retry).
parse_initial_token(
    <<FirstByte, _Version:32, DCIDLen:8, DCID:DCIDLen/binary, SCIDLen:8, SCID:SCIDLen/binary,
        Rest/binary>>
) when
    FirstByte band 16#F0 =:= 16#C0
->
    try
        {TokenLen, Rest1} = quic_varint:decode(Rest),
        <<Token:TokenLen/binary, _/binary>> = Rest1,
        {ok, Token, SCID, DCID}
    catch
        _:_ -> {error, malformed_initial}
    end;
parse_initial_token(_) ->
    {error, not_initial}.

validate_initial_token(Secret, Token, Addr, ExpectedODCID, MaxAge) ->
    case quic_address_token:decode(Secret, Token) of
        {ok, #{addr := TokAddr} = Decoded} when TokAddr =:= Addr ->
            quic_address_token:validate(Decoded, ExpectedODCID, #{max_age_ms => MaxAge});
        {ok, _} ->
            {error, address_mismatch};
        {error, _} = Err ->
            Err
    end.

%% Send a packet using the appropriate backend.
%% Listener self-sends are one-shot control-plane packets (version
%% negotiation, retry, stateless reset) that never benefit from
%% batching. Use send_immediate/4 so the returned state (which has
%% the listener's batch buffer updated) does not need to be
%% persisted back on #listener_state{}; before, send/4's returned
%% state was dropped on the floor and the packet was lost when
%% batching_enabled was true on the socket backend.
send_packet(_Socket, SocketState, socket, IP, Port, Packet) when SocketState =/= undefined ->
    _ = quic_socket:send_immediate(SocketState, IP, Port, Packet),
    ok;
send_packet(Socket, _SocketState, gen_udp, IP, Port, Packet) ->
    gen_udp:send(Socket, IP, Port, Packet).

%% Check if a packet might be a stateless reset
%% RFC 9000 Section 10.3: A reset looks like a short header packet
%% ending with a 16-byte token
is_potential_stateless_reset(<<0:1, _:7, _Rest/binary>> = Packet) ->
    %% Short header - could be a stateless reset
    %% A stateless reset is at least 21 bytes (1 header + 4 random + 16 token)
    byte_size(Packet) >= 21;
is_potential_stateless_reset(_) ->
    %% Long header packets are not stateless resets
    false.

%% Compute stateless reset token from secret and CID
%% RFC 9000 Section 10.3.2: Token = HMAC(secret, CID)[0:16]
compute_stateless_reset_token(Secret, CID) ->
    <<Token:16/binary, _/binary>> = crypto:mac(hmac, sha256, Secret, CID),
    Token.

%% Build a stateless reset packet
%% RFC 9000 Section 10.3: Looks like a short header packet with random bytes
%% followed by the 16-byte stateless reset token
build_stateless_reset(Token, TriggerSize) ->
    %% Reset should be smaller than trigger (RFC 9000 Section 10.3.3)
    %% but at least 21 bytes. Use a size between 21 and TriggerSize-1.
    ResetSize = min(TriggerSize - 1, max(21, rand:uniform(20) + 21)),
    %% Unpredictable bits with fixed bit = 1 (first bit = 0 for short header)

    % 1 byte header + 16 byte token
    RandomLen = ResetSize - 17,
    RandomBytes = crypto:strong_rand_bytes(RandomLen),
    %% First byte: 0|1|XXXX = short header with fixed bit set
    %% Use random bits for rest to be unpredictable
    <<FirstRandom:6, _:2>> = crypto:strong_rand_bytes(1),
    FirstByte = (0 bsl 7) bor (1 bsl 6) bor FirstRandom,
    <<FirstByte, RandomBytes/binary, Token/binary>>.
