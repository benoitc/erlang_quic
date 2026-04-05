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
    socket :: gen_udp:socket(),
    %% Socket state for quic_socket abstraction (optional, for future GRO support)
    socket_state :: quic_socket:socket_state() | undefined,
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
    %% Stateless reset secret (RFC 9000 Section 10.3)
    reset_secret :: binary(),
    %% Connection handler callback: fun(Conn) -> {ok, HandlerPid} where Conn is pid()
    connection_handler :: fun((pid()) -> {ok, pid()}) | undefined,
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

    %% Open UDP socket
    %% Default to IPv4 for maximum compatibility
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
            {ok, {Socket, Opts}, {continue, discover_manager}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @doc false
handle_continue(discover_manager, {Socket, Opts}) ->
    %% Extract required options
    #{cert := Cert, key := PrivateKey} = Opts,
    CertChain = maps:get(cert_chain, Opts, []),
    ALPNList = maps:get(alpn, Opts, [<<"h3">>]),
    ConnHandler = maps:get(connection_handler, Opts, undefined),

    {ConnTab, TicketTab, OwnsTables} = get_tables(Opts),

    %% Get actual port and bound address
    {ok, {_BoundAddr, ActualPort}} = inet:sockname(Socket),

    %% Generate or use provided stateless reset secret
    ResetSecret = maps:get(reset_secret, Opts, crypto:strong_rand_bytes(32)),

    %% Initialize QUIC-LB CID configuration (RFC 9312)
    {CIDConfig, DCIDLen} = init_cid_config(Opts, ResetSecret),

    State = #listener_state{
        socket = Socket,
        port = ActualPort,
        cert = Cert,
        cert_chain = CertChain,
        private_key = PrivateKey,
        alpn_list = ALPNList,
        connections = ConnTab,
        tickets_table = TicketTab,
        owns_tables = OwnsTables,
        reset_secret = ResetSecret,
        connection_handler = ConnHandler,
        cid_config = CIDConfig,
        dcid_len = DCIDLen,
        opts = Opts
    },
    {noreply, State}.

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
%% Handle incoming UDP packets
handle_info(
    {udp, Socket, SrcIP, SrcPort, Packet},
    #listener_state{socket = Socket} = State
) ->
    ?LOG_DEBUG(
        #{what => udp_received, src_ip => SrcIP, src_port => SrcPort, size => byte_size(Packet)},
        ?QUIC_LOG_META
    ),
    handle_packet(Packet, {SrcIP, SrcPort}, State),
    {noreply, State};
%% TODO: this might still be accepting more packets
%% than connection workers might be willing to accept
%% Handle socket going passive (backpressure with {active, N})
handle_info({udp_passive, Socket}, #listener_state{socket = Socket, opts = Opts} = State) ->
    N = maps:get(active_n, Opts, 100),
    inet:setopts(Socket, [{active, N}]),
    {noreply, State};
%% Handle connection process exit
handle_info({'EXIT', Pid, _Reason}, #listener_state{connections = Conns} = State) ->
    cleanup_connection(Conns, Pid),
    {noreply, State};
%% Handle UDP from different socket (shouldn't happen)
handle_info({udp, _OtherSocket, _SrcIP, _SrcPort, _Packet}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%% @doc false
terminate(_Reason, #listener_state{
    connections = ConnTab,
    tickets_table = TicketTab,
    owns_tables = OwnsTables,
    socket = Socket
}) ->
    safe_close_socket(Socket),
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
        cert = Cert,
        cert_chain = CertChain,
        private_key = PrivateKey,
        alpn_list = ALPNList,
        connections = Conns,
        connection_handler = ConnHandler,
        cid_config = CIDConfig,
        opts = Opts
    }
) ->
    %% Generate server connection ID (LB-aware if configured)
    ServerCID =
        case CIDConfig of
            undefined -> crypto:strong_rand_bytes(8);
            #cid_config{} -> quic_lb:generate_cid(CIDConfig)
        end,

    %% Start connection process with client's QUIC version
    ConnOpts = #{
        role => server,
        socket => Socket,
        remote_addr => RemoteAddr,
        initial_dcid => DCID,
        scid => ServerCID,
        cert => Cert,
        cert_chain => CertChain,
        private_key => PrivateKey,
        alpn => ALPNList,
        listener => self(),
        cid_config => CIDConfig,
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
                Fun when is_function(Fun, 1) ->
                    case Fun(ConnPid) of
                        {ok, HandlerPid} when is_pid(HandlerPid) ->
                            %% Transfer ownership to handler (sync to ensure it completes
                            %% before any packets trigger handshake completion)
                            case quic:set_owner_sync(ConnPid, HandlerPid) of
                                ok ->
                                    ok;
                                {error, Reason} ->
                                    ?LOG_WARNING(
                                        #{
                                            what => set_owner_failed,
                                            conn => ConnPid,
                                            reason => Reason
                                        },
                                        ?QUIC_LOG_META
                                    )
                            end;
                        {error, HandlerError} ->
                            ?LOG_WARNING(
                                #{
                                    what => connection_handler_failed,
                                    error => HandlerError
                                },
                                ?QUIC_LOG_META
                            );
                        Other ->
                            ?LOG_WARNING(
                                #{
                                    what => connection_handler_unexpected,
                                    result => Other
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
    #listener_state{socket = Socket, reset_secret = Secret}
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
                    gen_udp:send(Socket, IP, Port, ResetPacket);
                false ->
                    %% Packet too small to respond with reset
                    ok
            end
    end.

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
