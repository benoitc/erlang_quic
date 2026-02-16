%%% -*- erlang -*-
%%%
%%% QUIC Connection State Machine
%%% RFC 9000 - QUIC Transport
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC connection state machine implemented as gen_statem.
%%%
%%% This module manages the lifecycle of a QUIC connection, handling:
%%% - TLS 1.3 handshake via CRYPTO frames
%%% - Packet encryption/decryption at each level
%%% - Stream management
%%% - Flow control
%%% - Timer management
%%%
%%% == Connection States ==
%%%
%%% idle -> handshaking -> connected -> draining -> closed
%%%
%%% == Messages to Owner ==
%%%
%%% {quic, ConnRef, {connected, Info}}
%%% {quic, ConnRef, {stream_headers, StreamId, Headers, Fin}}
%%% {quic, ConnRef, {stream_data, StreamId, Data, Fin}}
%%% {quic, ConnRef, {stream_opened, StreamId}}
%%% {quic, ConnRef, {closed, Reason}}
%%%

-module(quic_connection).

-behaviour(gen_statem).

-include("quic.hrl").

%% Registry API
-export([
    register_conn/2,
    unregister_conn/1,
    lookup/1
]).

%% API
-export([
    start_link/4,
    start_link/5,
    connect/4,
    send_data/4,
    send_headers/4,
    open_stream/1,
    close/2,
    close_stream/3,
    reset_stream/3,
    handle_timeout/1,
    process/1,
    get_state/1,
    peername/1,
    sockname/1,
    setopts/2
]).

%% gen_statem callbacks
-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4
]).

%% State functions
-export([
    idle/3,
    handshaking/3,
    connected/3,
    draining/3,
    closed/3
]).

%% Registry table name
-define(REGISTRY, quic_connection_registry).

%% TLS handshake states
-define(TLS_AWAITING_SERVER_HELLO, awaiting_server_hello).
-define(TLS_AWAITING_ENCRYPTED_EXT, awaiting_encrypted_extensions).
-define(TLS_AWAITING_CERT, awaiting_certificate).
-define(TLS_AWAITING_CERT_VERIFY, awaiting_certificate_verify).
-define(TLS_AWAITING_FINISHED, awaiting_finished).
-define(TLS_HANDSHAKE_COMPLETE, handshake_complete).

%% Connection state record
-record(state, {
    %% Connection identity
    scid :: binary(),
    dcid :: binary(),
    original_dcid :: binary(),
    role :: client | server,
    version = ?QUIC_VERSION_1 :: non_neg_integer(),

    %% Socket
    socket :: gen_udp:socket() | undefined,
    remote_addr :: {inet:ip_address(), inet:port_number()},
    local_addr :: {inet:ip_address(), inet:port_number()} | undefined,

    %% Owner process (receives {quic, Ref, Event} messages)
    owner :: pid(),
    conn_ref :: reference(),

    %% Options
    server_name :: binary() | undefined,
    verify :: boolean(),

    %% Encryption keys per level
    initial_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    handshake_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    app_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,

    %% TLS state
    tls_state :: atom(),
    tls_private_key :: binary() | undefined,
    tls_transcript = <<>> :: binary(),
    handshake_secret :: binary() | undefined,
    master_secret :: binary() | undefined,
    server_hs_secret :: binary() | undefined,
    client_hs_secret :: binary() | undefined,

    %% CRYPTO frame buffer (per level: initial, handshake, app)
    crypto_buffer = #{initial => #{}, handshake => #{}, app => #{}} :: map(),
    crypto_offset = #{initial => 0, handshake => 0, app => 0} :: map(),
    %% Incomplete TLS message buffer (data that couldn't be parsed yet)
    tls_buffer = #{initial => <<>>, handshake => <<>>, app => <<>>} :: map(),

    %% Negotiated ALPN
    alpn :: binary() | undefined,
    alpn_list :: [binary()],

    %% Packet number spaces
    pn_initial :: #pn_space{},
    pn_handshake :: #pn_space{},
    pn_app :: #pn_space{},

    %% Flow control
    max_data_local :: non_neg_integer(),
    max_data_remote :: non_neg_integer(),
    data_sent = 0 :: non_neg_integer(),
    data_received = 0 :: non_neg_integer(),

    %% Stream management
    streams = #{} :: #{non_neg_integer() => #stream_state{}},
    next_stream_id_bidi :: non_neg_integer(),
    next_stream_id_uni :: non_neg_integer(),
    max_streams_bidi_local :: non_neg_integer(),
    max_streams_bidi_remote :: non_neg_integer(),
    max_streams_uni_local :: non_neg_integer(),
    max_streams_uni_remote :: non_neg_integer(),

    %% Transport parameters (received from peer)
    transport_params = #{} :: map(),

    %% Timers
    idle_timeout :: non_neg_integer(),
    last_activity :: non_neg_integer(),
    timer_ref :: reference() | undefined,

    %% Pending data
    send_queue = [] :: [term()],

    %% Close reason
    close_reason :: term()
}).

%%====================================================================
%% Registry API
%%====================================================================

%% @doc Register a connection reference to a pid.
-spec register_conn(reference(), pid()) -> ok.
register_conn(ConnRef, Pid) ->
    ensure_registry(),
    ets:insert(?REGISTRY, {ConnRef, Pid}),
    ok.

%% @doc Unregister a connection reference.
-spec unregister_conn(reference()) -> ok.
unregister_conn(ConnRef) ->
    catch ets:delete(?REGISTRY, ConnRef),
    ok.

%% @doc Lookup a connection pid by reference.
-spec lookup(reference()) -> {ok, pid()} | error.
lookup(ConnRef) ->
    ensure_registry(),
    case ets:lookup(?REGISTRY, ConnRef) of
        [{_, Pid}] -> {ok, Pid};
        [] -> error
    end.

ensure_registry() ->
    case ets:whereis(?REGISTRY) of
        undefined ->
            try
                ets:new(?REGISTRY, [named_table, public, set, {read_concurrency, true}])
            catch
                error:badarg -> ok  % Already exists (race condition)
            end;
        _ ->
            ok
    end.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a QUIC connection process.
-spec start_link(inet:hostname() | inet:ip_address(),
                 inet:port_number(),
                 map(),
                 pid()) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner) ->
    start_link(Host, Port, Opts, Owner, undefined).

%% @doc Start a QUIC connection with optional pre-opened socket.
-spec start_link(inet:hostname() | inet:ip_address(),
                 inet:port_number(),
                 map(),
                 pid(),
                 gen_udp:socket() | undefined) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner, Socket) ->
    gen_statem:start_link(?MODULE, [Host, Port, Opts, Owner, Socket], []).

%% @doc Initiate a connection to a QUIC server.
%% This is a convenience wrapper that starts the process and initiates handshake.
-spec connect(inet:hostname() | inet:ip_address(),
              inet:port_number(),
              map(),
              pid()) -> {ok, reference(), pid()} | {error, term()}.
connect(Host, Port, Opts, Owner) ->
    case start_link(Host, Port, Opts, Owner) of
        {ok, Pid} ->
            ConnRef = gen_statem:call(Pid, get_ref),
            {ok, ConnRef, Pid};
        Error ->
            Error
    end.

%% @doc Send data on a stream.
-spec send_data(pid(), non_neg_integer(), iodata(), boolean()) ->
    ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    gen_statem:call(Conn, {send_data, StreamId, Data, Fin}).

%% @doc Send headers on a stream (HTTP/3).
-spec send_headers(pid(), non_neg_integer(), [{binary(), binary()}], boolean()) ->
    ok | {error, term()}.
send_headers(Conn, StreamId, Headers, Fin) ->
    gen_statem:call(Conn, {send_headers, StreamId, Headers, Fin}).

%% @doc Open a new bidirectional stream.
-spec open_stream(pid()) -> {ok, non_neg_integer()} | {error, term()}.
open_stream(Conn) ->
    gen_statem:call(Conn, open_stream).

%% @doc Close the connection.
-spec close(pid(), term()) -> ok.
close(Conn, Reason) ->
    gen_statem:cast(Conn, {close, Reason}).

%% @doc Close a specific stream.
-spec close_stream(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
close_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:call(Conn, {close_stream, StreamId, ErrorCode}).

%% @doc Reset a stream.
-spec reset_stream(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
reset_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:call(Conn, {close_stream, StreamId, ErrorCode}).

%% @doc Handle a timeout event.
-spec handle_timeout(pid()) -> ok.
handle_timeout(Conn) ->
    gen_statem:cast(Conn, handle_timeout).

%% @doc Process pending events (called when socket is ready).
-spec process(pid()) -> ok.
process(Conn) ->
    gen_statem:cast(Conn, process).

%% @doc Get current connection state (for debugging).
-spec get_state(pid()) -> {atom(), map()}.
get_state(Conn) ->
    gen_statem:call(Conn, get_state).

%% @doc Get remote address.
-spec peername(pid()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
peername(Conn) ->
    gen_statem:call(Conn, peername).

%% @doc Get local address.
-spec sockname(pid()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
sockname(Conn) ->
    gen_statem:call(Conn, sockname).

%% @doc Set connection options.
-spec setopts(pid(), [{atom(), term()}]) -> ok | {error, term()}.
setopts(Conn, Opts) ->
    gen_statem:call(Conn, {setopts, Opts}).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() ->
    [state_functions, state_enter].

init([Host, Port, Opts, Owner, Socket]) ->
    process_flag(trap_exit, true),

    %% Generate connection IDs
    SCID = generate_connection_id(),
    DCID = generate_connection_id(),

    %% Determine remote address
    RemoteAddr = resolve_address(Host, Port),

    %% Create or use provided socket
    {ok, Sock, LocalAddr} = case Socket of
        undefined ->
            {ok, S} = gen_udp:open(0, [binary, {active, false}]),
            {ok, LA} = inet:sockname(S),
            {ok, S, LA};
        S ->
            {ok, LA} = inet:sockname(S),
            {ok, S, LA}
    end,

    %% Generate initial keys
    InitialKeys = derive_initial_keys(DCID),

    %% Initialize packet number spaces
    PNSpace = #pn_space{
        next_pn = 0,
        largest_acked = undefined,
        largest_recv = undefined,
        recv_time = undefined,
        ack_ranges = [],
        ack_eliciting_in_flight = 0,
        loss_time = undefined,
        sent_packets = #{}
    },

    %% Create connection reference and register
    ConnRef = make_ref(),
    register_conn(ConnRef, self()),

    %% Get server name for SNI
    ServerName = case maps:get(server_name, Opts, undefined) of
        undefined when is_binary(Host) -> Host;
        undefined when is_list(Host) -> list_to_binary(Host);
        SN -> SN
    end,

    %% Get ALPN list
    AlpnOpt = maps:get(alpn, Opts, [<<"h3">>]),
    AlpnList = normalize_alpn_list(AlpnOpt),

    %% Initialize state
    State = #state{
        scid = SCID,
        dcid = DCID,
        original_dcid = DCID,
        role = client,
        socket = Sock,
        remote_addr = RemoteAddr,
        local_addr = LocalAddr,
        owner = Owner,
        conn_ref = ConnRef,
        server_name = ServerName,
        verify = maps:get(verify, Opts, false),
        initial_keys = InitialKeys,
        tls_state = ?TLS_AWAITING_SERVER_HELLO,
        alpn_list = AlpnList,
        pn_initial = PNSpace,
        pn_handshake = PNSpace,
        pn_app = PNSpace,
        max_data_local = maps:get(max_data, Opts, ?DEFAULT_INITIAL_MAX_DATA),
        max_data_remote = ?DEFAULT_INITIAL_MAX_DATA,
        next_stream_id_bidi = 0,  % Client-initiated bidi: 0, 4, 8, ...
        next_stream_id_uni = 2,   % Client-initiated uni: 2, 6, 10, ...
        max_streams_bidi_local = maps:get(max_streams_bidi, Opts, ?DEFAULT_MAX_STREAMS_BIDI),
        max_streams_bidi_remote = ?DEFAULT_MAX_STREAMS_BIDI,
        max_streams_uni_local = maps:get(max_streams_uni, Opts, ?DEFAULT_MAX_STREAMS_UNI),
        max_streams_uni_remote = ?DEFAULT_MAX_STREAMS_UNI,
        idle_timeout = maps:get(idle_timeout, Opts, ?DEFAULT_MAX_IDLE_TIMEOUT),
        last_activity = erlang:monotonic_time(millisecond)
    },

    {ok, idle, State}.

terminate(_Reason, _StateName, #state{socket = Socket, conn_ref = ConnRef}) ->
    unregister_conn(ConnRef),
    case Socket of
        undefined -> ok;
        _ -> gen_udp:close(Socket)
    end,
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%====================================================================
%% State Functions
%%====================================================================

%% ----- IDLE STATE -----

idle(enter, _OldState, State) ->
    %% Start the handshake by sending Initial packet with ClientHello
    NewState = send_client_hello(State),
    {keep_state, NewState};

idle({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

idle({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {idle, state_to_map(State)}}]};

idle({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

idle({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

idle(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(idle, NewState);

idle(cast, process, State) ->
    %% Re-enable socket for receiving
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

idle(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, idle, State).

%% ----- HANDSHAKING STATE -----

handshaking(enter, idle, State) ->
    %% Continue handshake
    {keep_state, State};

handshaking({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

handshaking({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {handshaking, state_to_map(State)}}]};

handshaking({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

handshaking({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

handshaking(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(handshaking, NewState);

handshaking(cast, process, State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

handshaking(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, handshaking, State).

%% ----- CONNECTED STATE -----

connected(enter, handshaking, #state{owner = Owner, conn_ref = Ref, alpn = Alpn} = State) ->
    %% Notify owner that connection is established
    Info = #{
        alpn => Alpn,
        alpn_protocol => Alpn
    },
    Owner ! {quic, Ref, {connected, Info}},
    {keep_state, State};

connected({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

connected({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {connected, state_to_map(State)}}]};

connected({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

connected({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

connected({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {send_headers, StreamId, Headers, Fin}, State) ->
    %% HTTP/3 headers - encode and send on stream
    case do_send_headers(StreamId, Headers, Fin, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, open_stream, State) ->
    case do_open_stream(State) of
        {ok, StreamId, NewState} ->
            {keep_state, NewState, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {close_stream, StreamId, ErrorCode}, State) ->
    case do_close_stream(StreamId, ErrorCode, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {setopts, _Opts}, State) ->
    {keep_state, State, [{reply, From, ok}]};

connected(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(connected, NewState);

connected(cast, {close, Reason}, State) ->
    NewState = initiate_close(Reason, State),
    {next_state, draining, NewState};

connected(cast, process, State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

connected(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, connected, State).

%% ----- DRAINING STATE -----

draining(enter, _OldState, #state{owner = Owner, conn_ref = Ref, close_reason = Reason} = State) ->
    Owner ! {quic, Ref, {closed, Reason}},
    %% Start drain timer (3 * PTO)
    TimerRef = erlang:send_after(3000, self(), drain_timeout),
    {keep_state, State#state{timer_ref = TimerRef}};

draining({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {draining, state_to_map(State)}}]};

draining(info, drain_timeout, State) ->
    {next_state, closed, State};

draining(info, {udp, _Socket, _IP, _Port, _Data}, State) ->
    %% Ignore packets in draining state
    {keep_state, State};

draining(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, draining, State).

%% ----- CLOSED STATE -----

closed(enter, _OldState, State) ->
    {stop, normal, State};

closed({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {closed, state_to_map(State)}}]};

closed(_EventType, _EventContent, State) ->
    {keep_state, State}.

%%====================================================================
%% Common Event Handling
%%====================================================================

handle_common_event({call, From}, get_ref, _StateName, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

handle_common_event(cast, handle_timeout, _StateName, State) ->
    %% Handle loss detection / idle timeout
    NewState = check_timeouts(State),
    {keep_state, NewState};

handle_common_event(info, {'EXIT', _Pid, _Reason}, _StateName, State) ->
    {keep_state, State};

handle_common_event(_EventType, _EventContent, _StateName, State) ->
    {keep_state, State}.

%%====================================================================
%% Internal Functions - TLS Handshake
%%====================================================================

%% Send ClientHello in an Initial packet
send_client_hello(State) ->
    #state{
        scid = SCID,
        server_name = ServerName,
        alpn_list = AlpnList,
        max_data_local = MaxData,
        max_streams_bidi_local = MaxStreamsBidi,
        max_streams_uni_local = MaxStreamsUni
    } = State,

    %% Build transport parameters
    TransportParams = #{
        initial_scid => SCID,
        initial_max_data => MaxData,
        initial_max_stream_data_bidi_local => ?DEFAULT_INITIAL_MAX_STREAM_DATA,
        initial_max_stream_data_bidi_remote => ?DEFAULT_INITIAL_MAX_STREAM_DATA,
        initial_max_stream_data_uni => ?DEFAULT_INITIAL_MAX_STREAM_DATA,
        initial_max_streams_bidi => MaxStreamsBidi,
        initial_max_streams_uni => MaxStreamsUni,
        max_idle_timeout => State#state.idle_timeout,
        active_connection_id_limit => 2
    },

    %% Build ClientHello
    {ClientHello, PrivKey, _Random} = quic_tls:build_client_hello(#{
        server_name => ServerName,
        alpn => AlpnList,
        transport_params => TransportParams
    }),

    %% Update transcript
    Transcript = ClientHello,

    %% Create CRYPTO frame
    CryptoFrame = quic_frame:encode({crypto, 0, ClientHello}),

    %% Encrypt and send Initial packet
    NewState = send_initial_packet(CryptoFrame, State#state{
        tls_private_key = PrivKey,
        tls_transcript = Transcript
    }),

    %% Enable socket for receiving
    inet:setopts(NewState#state.socket, [{active, once}]),

    NewState.

%% Send an Initial packet
send_initial_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        socket = Socket,
        remote_addr = {IP, Port},
        initial_keys = {ClientKeys, _ServerKeys},
        pn_initial = PNSpace
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Build header (without packet number, for AAD)
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary,
        0,  % Token length (varint = 0)
        (quic_varint:encode(byte_size(Payload) + PNLen + 16))/binary  % +16 for AEAD tag
    >>,

    %% First byte: 1100 0000 | (PNLen - 1)
    FirstByte = 16#C0 bor (PNLen - 1),
    Header = <<FirstByte, HeaderBody/binary>>,

    %% AAD is the header with encoded PN appended
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt payload
    #crypto_keys{key = Key, iv = IV, hp = HP} = ClientKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, Payload),

    %% Apply header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build final packet
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,

    %% Pad Initial packets to at least 1200 bytes
    PaddedPacket = pad_initial_packet(Packet),

    %% Send
    gen_udp:send(Socket, IP, Port, PaddedPacket),

    %% Update packet number space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_initial = NewPNSpace}.

%% Send an Initial ACK packet
send_initial_ack(State) ->
    #state{pn_initial = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;  % Nothing to ACK
        Ranges ->
            %% Build ACK frame
            AckFrame = build_ack_frame(Ranges),
            send_initial_packet(AckFrame, State)
    end.

%% Send a Handshake ACK packet
send_handshake_ack(State) ->
    #state{pn_handshake = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;
        Ranges ->
            AckFrame = build_ack_frame(Ranges),
            send_handshake_packet(AckFrame, State)
    end.

%% Send an app-level ACK packet (1-RTT)
send_app_ack(State) ->
    #state{pn_app = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;
        Ranges ->
            AckFrame = build_ack_frame(Ranges),
            send_app_packet(AckFrame, State)
    end.

%% Build an ACK frame from ranges
build_ack_frame(Ranges) ->
    %% Get the largest acknowledged PN
    [{LargestAcked, _} | _] = Ranges,
    %% ACK delay in microseconds (convert to ack_delay_exponent units, default 3)
    AckDelay = 0,  % For simplicity
    %% For a simple implementation, just acknowledge the largest
    %% A complete implementation would encode all ranges
    quic_frame:encode({ack, Ranges, AckDelay, undefined}).

%% Send a Handshake packet
send_handshake_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        socket = Socket,
        remote_addr = {IP, Port},
        handshake_keys = {ClientKeys, _ServerKeys},
        pn_handshake = PNSpace
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% First byte for Handshake: 1110 0000 | (PNLen - 1)
    FirstByte = 16#E0 bor (PNLen - 1),

    %% Build header
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary,
        (quic_varint:encode(byte_size(Payload) + PNLen + 16))/binary
    >>,
    Header = <<FirstByte, HeaderBody/binary>>,

    %% AAD
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt
    #crypto_keys{key = Key, iv = IV, hp = HP} = ClientKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, Payload),

    %% Header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    gen_udp:send(Socket, IP, Port, Packet),

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_handshake = NewPNSpace}.

%% Send a 1-RTT (application) packet
send_app_packet(Payload, State) ->
    #state{
        dcid = DCID,
        socket = Socket,
        remote_addr = {IP, Port},
        app_keys = {ClientKeys, _ServerKeys},
        pn_app = PNSpace
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% First byte for short header: 01XX XXXX
    %% Bit 5 = spin bit (0), bits 3-4 reserved (0), bit 2 = key phase (0), bits 0-1 = PN length
    FirstByte = 16#40 bor (PNLen - 1),

    %% Header is just first byte + DCID
    Header = <<FirstByte, DCID/binary>>,

    %% AAD
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt
    #crypto_keys{key = Key, iv = IV, hp = HP} = ClientKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, Payload),

    %% Header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    gen_udp:send(Socket, IP, Port, Packet),

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_app = NewPNSpace}.

%% Pad Initial packet to minimum 1200 bytes
pad_initial_packet(Packet) when byte_size(Packet) >= 1200 ->
    Packet;
pad_initial_packet(Packet) ->
    PadLen = 1200 - byte_size(Packet),
    <<Packet/binary, 0:PadLen/unit:8>>.

%%====================================================================
%% Internal Functions - Packet Processing
%%====================================================================

%% Handle incoming packet (may be coalesced with multiple QUIC packets)
handle_packet(Data, State) ->
    handle_packet_loop(Data, State).

handle_packet_loop(<<>>, State) ->
    %% No more data to process
    inet:setopts(State#state.socket, [{active, once}]),
    State;
handle_packet_loop(Data, State) ->
    case decode_and_decrypt_packet(Data, State) of
        {ok, _Type, Frames, RemainingData, NewState} ->
            %% Process frames from this packet
            State1 = process_frames_noreenbl(_Type, Frames, NewState),
            %% Continue with remaining coalesced packets
            handle_packet_loop(RemainingData, State1);
        {error, _Reason} ->
            %% Re-enable socket
            inet:setopts(State#state.socket, [{active, once}]),
            State
    end.

%% Decode and decrypt a packet
decode_and_decrypt_packet(Data, State) ->
    %% Check header form (first bit)
    case Data of
        <<1:1, _:7, _/binary>> ->
            decode_long_header_packet(Data, State);
        <<0:1, _:7, _/binary>> ->
            decode_short_header_packet(Data, State);
        _ ->
            {error, invalid_packet}
    end.

%% Decode long header packet (Initial, Handshake, etc.)
decode_long_header_packet(Data, State) ->
    %% Parse unprotected header to get DCID length
    <<FirstByte, _Version:32, DCIDLen, Rest/binary>> = Data,
    <<DCID:DCIDLen/binary, SCIDLen, Rest2/binary>> = Rest,
    <<SCID:SCIDLen/binary, Rest3/binary>> = Rest2,

    Type = (FirstByte bsr 4) band 2#11,

    case Type of
        0 -> %% Initial
            decode_initial_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        2 -> %% Handshake
            decode_handshake_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        _ ->
            {error, unsupported_packet_type}
    end.

decode_initial_packet(FullPacket, FirstByte, _DCID, ServerSCID, Rest, State) ->
    #state{initial_keys = {_ClientKeys, ServerKeys}} = State,

    %% Parse token and length
    {TokenLen, Rest2} = quic_varint:decode(Rest),
    <<_Token:TokenLen/binary, Rest3/binary>> = Rest2,
    {PayloadLen, Rest4} = quic_varint:decode(Rest3),

    %% Header ends here, payload starts
    HeaderLen = byte_size(FullPacket) - byte_size(Rest4),
    <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

    %% Update DCID to server's SCID (this becomes our destination for future packets)
    State1 = case State#state.dcid =:= State#state.original_dcid of
        true -> State#state{dcid = ServerSCID};  % First packet from server, update DCID
        false -> State  % Already updated
    end,

    %% Ensure we have enough data
    case byte_size(Payload) >= PayloadLen of
        true ->
            <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
            decrypt_packet(initial, Header, FirstByte, EncryptedPayload, RemainingData, ServerKeys, State1);
        false ->
            {error, incomplete_packet}
    end.

decode_handshake_packet(FullPacket, FirstByte, _DCID, _SCID, Rest, State) ->
    case State#state.handshake_keys of
        undefined ->
            {error, no_handshake_keys};
        {_ClientKeys, ServerKeys} ->
            %% Parse length
            {PayloadLen, Rest2} = quic_varint:decode(Rest),
            HeaderLen = byte_size(FullPacket) - byte_size(Rest2),
            <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

            case byte_size(Payload) >= PayloadLen of
                true ->
                    <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
                    decrypt_packet(handshake, Header, FirstByte, EncryptedPayload, RemainingData, ServerKeys, State);
                false ->
                    {error, incomplete_packet}
            end
    end.

decode_short_header_packet(Data, State) ->
    case State#state.app_keys of
        undefined ->
            {error, no_app_keys};
        {_ClientKeys, ServerKeys} ->
            %% Short header: first byte + DCID (assume 8 bytes based on our SCID)
            %% Short header packets don't have length field, so they consume all remaining data
            DCIDLen = byte_size(State#state.scid),
            <<FirstByte, DCID:DCIDLen/binary, EncryptedPayload/binary>> = Data,
            Header = <<FirstByte, DCID/binary>>,
            %% No remaining data after short header packet
            decrypt_packet(app, Header, FirstByte, EncryptedPayload, <<>>, ServerKeys, State)
    end.

%% Decrypt a packet
%% RemainingData is the data after this packet (for coalesced packets)
decrypt_packet(Level, Header, _FirstByte, EncryptedPayload, RemainingData, Keys, State) ->
    #crypto_keys{key = Key, iv = IV, hp = HP} = Keys,

    %% Remove header protection
    %% unprotect_header returns UnprotectedHeader which includes the unprotected PN at the end
    PNOffset = byte_size(Header),
    {UnprotectedHeader, PNLen} = quic_aead:unprotect_header(HP, Header, EncryptedPayload, PNOffset),

    %% Extract unprotected PN from the end of UnprotectedHeader
    UnprotHeaderLen = byte_size(UnprotectedHeader),
    <<_:((UnprotHeaderLen - PNLen) * 8), PN:PNLen/unit:8>> = UnprotectedHeader,

    %% AAD is the full unprotected header (already includes PN)
    AAD = UnprotectedHeader,

    %% Actual ciphertext starts after PN bytes in EncryptedPayload
    Ciphertext = binary:part(EncryptedPayload, PNLen, byte_size(EncryptedPayload) - PNLen),

    %% Decrypt
    case quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext) of
        {ok, Plaintext} ->
            %% Decode frames
            case quic_frame:decode_all(Plaintext) of
                {ok, Frames} ->
                    %% Track received packet number for ACK generation
                    State1 = record_received_pn(Level, PN, State),
                    NewState = update_last_activity(State1),
                    {ok, Level, Frames, RemainingData, NewState};
                {error, Reason} ->
                    {error, {frame_decode_error, Reason}}
            end;
        {error, bad_tag} ->
            {error, decryption_failed}
    end.

%% Process decoded frames (re-enables socket when done)
process_frames(_Level, [], State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    State;
process_frames(Level, [Frame | Rest], State) ->
    NewState = process_frame(Level, Frame, State),
    process_frames(Level, Rest, NewState).

%% Process decoded frames without re-enabling socket (for coalesced packets)
process_frames_noreenbl(_Level, [], State) ->
    State;
process_frames_noreenbl(Level, [Frame | Rest], State) ->
    NewState = process_frame(Level, Frame, State),
    process_frames_noreenbl(Level, Rest, NewState).

%% Process individual frames
process_frame(_Level, padding, State) ->
    State;

process_frame(_Level, ping, State) ->
    %% Should trigger ACK
    State;

process_frame(Level, {crypto, Offset, Data}, State) ->
    buffer_crypto_data(Level, Offset, Data, State);

process_frame(_Level, {ack, _Ranges, _Delay, _ECN}, State) ->
    %% Process ACK - update loss detection, congestion control
    State;

process_frame(_Level, handshake_done, State) ->
    %% Server confirmed handshake complete
    State;

process_frame(app, {stream, StreamId, Offset, Data, Fin}, State) ->
    process_stream_data(StreamId, Offset, Data, Fin, State);

process_frame(_Level, {max_data, MaxData}, State) ->
    State#state{max_data_remote = MaxData};

process_frame(_Level, {max_stream_data, StreamId, MaxData}, State) ->
    case maps:find(StreamId, State#state.streams) of
        {ok, Stream} ->
            NewStream = Stream#stream_state{send_max_data = MaxData},
            State#state{streams = maps:put(StreamId, NewStream, State#state.streams)};
        error ->
            State
    end;

process_frame(_Level, {max_streams, bidi, Max}, State) ->
    State#state{max_streams_bidi_remote = Max};

process_frame(_Level, {max_streams, uni, Max}, State) ->
    State#state{max_streams_uni_remote = Max};

process_frame(_Level, {connection_close, _Type, _Code, _FrameType, _Reason}, State) ->
    State#state{close_reason = connection_closed};

process_frame(_Level, _Frame, State) ->
    %% Ignore unknown frames
    State.

%% Buffer CRYPTO data and process when complete messages are available
buffer_crypto_data(Level, Offset, Data, State) ->
    LevelAtom = case Level of
        initial -> initial;
        handshake -> handshake;
        app -> app;
        _ -> initial
    end,

    %% Get current buffer
    Buffer = maps:get(LevelAtom, State#state.crypto_buffer, #{}),

    %% Add data to buffer
    NewBuffer = maps:put(Offset, Data, Buffer),
    NewCryptoBuffer = maps:put(LevelAtom, NewBuffer, State#state.crypto_buffer),

    State1 = State#state{crypto_buffer = NewCryptoBuffer},

    %% Try to process contiguous data
    process_crypto_buffer(LevelAtom, State1).

%% Process contiguous CRYPTO data
process_crypto_buffer(Level, State) ->
    Buffer = maps:get(Level, State#state.crypto_buffer, #{}),
    ExpectedOffset = maps:get(Level, State#state.crypto_offset, 0),

    case maps:find(ExpectedOffset, Buffer) of
        {ok, Data} ->
            %% Process this data
            State1 = process_tls_data(Level, Data, State),

            %% Update offset and remove from buffer
            NewOffset = ExpectedOffset + byte_size(Data),
            NewBuffer = maps:remove(ExpectedOffset, Buffer),
            NewCryptoBuffer = maps:put(Level, NewBuffer, State1#state.crypto_buffer),
            NewCryptoOffset = maps:put(Level, NewOffset, State1#state.crypto_offset),

            State2 = State1#state{
                crypto_buffer = NewCryptoBuffer,
                crypto_offset = NewCryptoOffset
            },

            %% Try to process more
            process_crypto_buffer(Level, State2);
        error ->
            State
    end.

%% Process TLS handshake data from CRYPTO frames
process_tls_data(Level, Data, State) ->
    %% Prepend any buffered incomplete TLS data
    BufferedData = maps:get(Level, State#state.tls_buffer, <<>>),
    FullData = <<BufferedData/binary, Data/binary>>,
    %% Clear the buffer before processing
    State1 = State#state{tls_buffer = maps:put(Level, <<>>, State#state.tls_buffer)},
    process_tls_messages(Level, FullData, State1).

%% Process TLS messages
process_tls_messages(_Level, <<>>, State) ->
    State;
process_tls_messages(Level, Data, State) ->
    case quic_tls:decode_handshake_message(Data) of
        {ok, {Type, Body}, Rest} ->
            %% Capture the ORIGINAL bytes from the wire (including TLS header)
            OriginalMsg = binary:part(Data, 0, 4 + byte_size(Body)),
            %% Pass the original bytes to process_tls_message for transcript
            State1 = process_tls_message(Level, Type, Body, OriginalMsg, State),
            process_tls_messages(Level, Rest, State1);
        {error, incomplete} ->
            %% Buffer the incomplete data for next CRYPTO frame
            State#state{tls_buffer = maps:put(Level, Data, State#state.tls_buffer)};
        {error, _Err} ->
            State
    end.

%% Process individual TLS messages
%% OriginalMsg contains the exact bytes from the wire for transcript computation
process_tls_message(_Level, ?TLS_SERVER_HELLO, Body, OriginalMsg, State) ->
    case quic_tls:parse_server_hello(Body) of
        {ok, #{public_key := ServerPubKey, cipher := Cipher}} ->
            %% Compute shared secret
            SharedSecret = quic_crypto:compute_shared_secret(
                x25519, State#state.tls_private_key, ServerPubKey),

            %% Update transcript - USE ORIGINAL BYTES FROM WIRE
            Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
            %% Use cipher-appropriate hash for transcript
            TranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),

            %% Derive handshake secrets (cipher-aware for SHA-384 with AES-256-GCM)
            HashLen = case Cipher of
                aes_256_gcm -> 48;  % SHA-384
                _ -> 32  % SHA-256
            end,
            EarlySecret = quic_crypto:derive_early_secret(Cipher, <<0:HashLen/unit:8>>),
            HandshakeSecret = quic_crypto:derive_handshake_secret(Cipher, EarlySecret, SharedSecret),

            ClientHsSecret = quic_crypto:derive_client_handshake_secret(Cipher, HandshakeSecret, TranscriptHash),
            ServerHsSecret = quic_crypto:derive_server_handshake_secret(Cipher, HandshakeSecret, TranscriptHash),

            %% Derive handshake keys
            {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientHsSecret, Cipher),
            {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerHsSecret, Cipher),

            ClientHsKeys = #crypto_keys{key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher},
            ServerHsKeys = #crypto_keys{key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher},

            State1 = State#state{
                tls_state = ?TLS_AWAITING_ENCRYPTED_EXT,
                tls_transcript = Transcript,
                handshake_secret = HandshakeSecret,
                client_hs_secret = ClientHsSecret,
                server_hs_secret = ServerHsSecret,
                handshake_keys = {ClientHsKeys, ServerHsKeys}
            },
            %% Send ACK for the Initial packet that contained ServerHello
            send_initial_ack(State1);
        {error, _} ->
            State
    end;

process_tls_message(_Level, ?TLS_ENCRYPTED_EXTENSIONS, Body, OriginalMsg, State) ->
    %% Update transcript - USE ORIGINAL BYTES
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,

    case quic_tls:parse_encrypted_extensions(Body) of
        {ok, #{alpn := Alpn, transport_params := TP}} ->
            State#state{
                tls_state = ?TLS_AWAITING_CERT,
                tls_transcript = Transcript,
                alpn = Alpn,
                transport_params = TP
            };
        _ ->
            State#state{
                tls_state = ?TLS_AWAITING_CERT,
                tls_transcript = Transcript
            }
    end;

process_tls_message(_Level, ?TLS_CERTIFICATE, _Body, OriginalMsg, State) ->
    %% Update transcript (we don't verify certs if verify = false)
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_state = ?TLS_AWAITING_CERT_VERIFY,
        tls_transcript = Transcript
    };

process_tls_message(_Level, ?TLS_CERTIFICATE_VERIFY, _Body, OriginalMsg, State) ->
    %% Update transcript
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_state = ?TLS_AWAITING_FINISHED,
        tls_transcript = Transcript
    };

process_tls_message(_Level, ?TLS_FINISHED, Body, OriginalMsg, State) ->
    %% Get cipher from handshake keys for cipher-aware operations
    {ClientHsKeys, _} = State#state.handshake_keys,
    Cipher = ClientHsKeys#crypto_keys.cipher,

    %% Verify server Finished
    case quic_tls:parse_finished(Body) of
        {ok, VerifyData} ->
            TranscriptHash = quic_crypto:transcript_hash(Cipher, State#state.tls_transcript),
            case quic_tls:verify_finished(VerifyData, State#state.server_hs_secret, TranscriptHash, Cipher) of
                true ->
                    %% Update transcript with server Finished - USE ORIGINAL BYTES
                    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
                    TranscriptHashFinal = quic_crypto:transcript_hash(Cipher, Transcript),

                    %% Derive master secret and application keys (cipher-aware)
                    MasterSecret = quic_crypto:derive_master_secret(Cipher, State#state.handshake_secret),
                    ClientAppSecret = quic_crypto:derive_client_app_secret(Cipher, MasterSecret, TranscriptHashFinal),
                    ServerAppSecret = quic_crypto:derive_server_app_secret(Cipher, MasterSecret, TranscriptHashFinal),

                    %% Derive app keys
                    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientAppSecret, Cipher),
                    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerAppSecret, Cipher),

                    ClientAppKeys = #crypto_keys{key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher},
                    ServerAppKeys = #crypto_keys{key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher},

                    %% Send client Finished (cipher-aware)
                    %% Client Finished uses transcript INCLUDING server Finished (RFC 8446 Section 4.4.4)
                    ClientFinishedKey = quic_crypto:derive_finished_key(Cipher, State#state.client_hs_secret),
                    ClientVerifyData = quic_crypto:compute_finished_verify(Cipher, ClientFinishedKey, TranscriptHashFinal),
                    ClientFinishedMsg = quic_tls:build_finished(ClientVerifyData),
                    CryptoFrame = quic_frame:encode({crypto, 0, ClientFinishedMsg}),

                    State1 = State#state{
                        tls_state = ?TLS_HANDSHAKE_COMPLETE,
                        tls_transcript = <<Transcript/binary, ClientFinishedMsg/binary>>,
                        master_secret = MasterSecret,
                        app_keys = {ClientAppKeys, ServerAppKeys}
                    },

                    %% Send client Finished in Handshake packet
                    send_handshake_packet(CryptoFrame, State1);
                false ->
                    %% Verification failed
                    error_logger:info_msg("[QUIC] Server Finished verification failed~n", []),
                    State
            end;
        {error, _} ->
            State
    end;

process_tls_message(_Level, _Type, _Body, _OriginalMsg, State) ->
    State.

%%====================================================================
%% Internal Functions - Stream Processing
%%====================================================================

process_stream_data(StreamId, Offset, Data, Fin, State) ->
    #state{owner = Owner, conn_ref = Ref, streams = Streams} = State,

    %% Get or create stream state
    Stream = case maps:find(StreamId, Streams) of
        {ok, S} -> S;
        error ->
            %% New stream from server
            #stream_state{
                id = StreamId,
                state = open,
                send_offset = 0,
                send_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                recv_fin = false,
                recv_buffer = <<>>,
                final_size = undefined
            }
    end,

    %% For now, deliver data immediately (ignoring out-of-order for simplicity)
    Owner ! {quic, Ref, {stream_data, StreamId, Data, Fin}},

    NewStream = Stream#stream_state{
        recv_offset = Offset + byte_size(Data),
        recv_fin = Fin
    },

    %% Send ACK for received data
    State1 = State#state{streams = maps:put(StreamId, NewStream, Streams)},
    send_app_ack(State1).

%%====================================================================
%% Internal Functions - Helpers
%%====================================================================

%% Generate a random connection ID (8-20 bytes, using 8)
generate_connection_id() ->
    crypto:strong_rand_bytes(8).

%% Resolve hostname to IP address
resolve_address(Host, Port) when is_tuple(Host) ->
    {Host, Port};
resolve_address(Host, Port) when is_list(Host) ->
    case inet:getaddr(Host, inet) of
        {ok, IP} -> {IP, Port};
        _ ->
            case inet:getaddr(Host, inet6) of
                {ok, IP} -> {IP, Port};
                _ -> {{127,0,0,1}, Port}
            end
    end;
resolve_address(Host, Port) when is_binary(Host) ->
    resolve_address(binary_to_list(Host), Port).

%% Derive initial encryption keys
derive_initial_keys(DCID) ->
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID),
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID),
    ClientKeys = #crypto_keys{
        key = ClientKey,
        iv = ClientIV,
        hp = ClientHP,
        cipher = aes_128_gcm
    },
    ServerKeys = #crypto_keys{
        key = ServerKey,
        iv = ServerIV,
        hp = ServerHP,
        cipher = aes_128_gcm
    },
    {ClientKeys, ServerKeys}.

%% Check if we should transition to a new state
check_state_transition(CurrentState, State) ->
    case {CurrentState, State#state.tls_state, has_app_keys(State)} of
        {idle, ?TLS_AWAITING_ENCRYPTED_EXT, _} ->
            %% Got ServerHello, have handshake keys
            {next_state, handshaking, State};
        {idle, ?TLS_AWAITING_CERT, _} ->
            {next_state, handshaking, State};
        {idle, ?TLS_AWAITING_CERT_VERIFY, _} ->
            {next_state, handshaking, State};
        {idle, ?TLS_AWAITING_FINISHED, _} ->
            {next_state, handshaking, State};
        {idle, ?TLS_HANDSHAKE_COMPLETE, true} ->
            {next_state, connected, State};
        {handshaking, ?TLS_HANDSHAKE_COMPLETE, true} ->
            {next_state, connected, State};
        _ ->
            {keep_state, State}
    end.

has_app_keys(#state{app_keys = undefined}) -> false;
has_app_keys(_) -> true.

%% Record a received packet number for ACK generation
record_received_pn(initial, PN, State) ->
    PNSpace = State#state.pn_initial,
    NewPNSpace = update_pn_space_recv(PN, PNSpace),
    State#state{pn_initial = NewPNSpace};
record_received_pn(handshake, PN, State) ->
    PNSpace = State#state.pn_handshake,
    NewPNSpace = update_pn_space_recv(PN, PNSpace),
    State#state{pn_handshake = NewPNSpace};
record_received_pn(app, PN, State) ->
    PNSpace = State#state.pn_app,
    NewPNSpace = update_pn_space_recv(PN, PNSpace),
    State#state{pn_app = NewPNSpace};
record_received_pn(_, _PN, State) ->
    State.

update_pn_space_recv(PN, PNSpace) ->
    #pn_space{largest_recv = LargestRecv, ack_ranges = Ranges} = PNSpace,
    NewLargest = case LargestRecv of
        undefined -> PN;
        L when PN > L -> PN;
        L -> L
    end,
    %% Add to ack_ranges (simple: just track largest for now)
    %% A complete implementation would maintain ACK ranges
    NewRanges = case Ranges of
        [] -> [{PN, PN}];
        [{Start, End} | Rest] when PN =:= End + 1 ->
            [{Start, PN} | Rest];
        _ ->
            [{PN, PN} | Ranges]
    end,
    PNSpace#pn_space{
        largest_recv = NewLargest,
        recv_time = erlang:monotonic_time(millisecond),
        ack_ranges = NewRanges
    }.

%% Update last activity timestamp
update_last_activity(State) ->
    State#state{last_activity = erlang:monotonic_time(millisecond)}.

%% Open a new stream
do_open_stream(#state{next_stream_id_bidi = NextId,
                      max_streams_bidi_remote = Max,
                      streams = Streams} = State) ->
    StreamCount = maps:size(maps:filter(fun(Id, _) ->
        (Id band 16#03) =:= 0  % Client-initiated bidi
    end, Streams)),
    if
        StreamCount >= Max ->
            {error, stream_limit};
        true ->
            StreamState = #stream_state{
                id = NextId,
                state = open,
                send_offset = 0,
                send_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                recv_fin = false,
                recv_buffer = <<>>,
                final_size = undefined
            },
            NewState = State#state{
                next_stream_id_bidi = NextId + 4,
                streams = maps:put(NextId, StreamState, Streams)
            },
            {ok, NextId, NewState}
    end.

%% Max stream data per packet (leave room for headers, frame overhead, AEAD tag)
%% 1200 (min MTU for QUIC) - ~50 bytes overhead = ~1150 bytes
-define(MAX_STREAM_DATA_PER_PACKET, 1100).

%% Send data on a stream (with fragmentation for large data)
do_send_data(StreamId, Data, Fin, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            DataBin = iolist_to_binary(Data),
            Offset = StreamState#stream_state.send_offset,

            %% Fragment and send data
            NewState = send_stream_data_fragmented(StreamId, Offset, DataBin, Fin, State),

            %% Update stream state
            NewStreamState = StreamState#stream_state{
                send_offset = Offset + byte_size(DataBin),
                send_fin = Fin
            },

            {ok, NewState#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Send stream data in fragments that fit in packets
send_stream_data_fragmented(StreamId, Offset, Data, Fin, State) when byte_size(Data) =< ?MAX_STREAM_DATA_PER_PACKET ->
    %% Data fits in one packet
    StreamFrame = quic_frame:encode({stream, StreamId, Offset, Data, Fin}),
    send_app_packet(StreamFrame, State);
send_stream_data_fragmented(StreamId, Offset, Data, Fin, State) ->
    %% Split data into chunks
    <<Chunk:?MAX_STREAM_DATA_PER_PACKET/binary, Rest/binary>> = Data,

    %% Send this chunk (not fin, more data coming)
    StreamFrame = quic_frame:encode({stream, StreamId, Offset, Chunk, false}),
    State1 = send_app_packet(StreamFrame, State),

    %% Send remaining data
    NewOffset = Offset + ?MAX_STREAM_DATA_PER_PACKET,
    send_stream_data_fragmented(StreamId, NewOffset, Rest, Fin, State1).

%% Send HTTP/3 headers on a stream
do_send_headers(_StreamId, _Headers, _Fin, State) ->
    %% TODO: Encode headers using QPACK and send
    {ok, State}.

%% Close a stream
do_close_stream(StreamId, ErrorCode, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Send RESET_STREAM frame
            FinalSize = StreamState#stream_state.send_offset,
            ResetFrame = quic_frame:encode({reset_stream, StreamId, ErrorCode, FinalSize}),
            NewState = send_app_packet(ResetFrame, State),
            {ok, NewState#state{
                streams = maps:remove(StreamId, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Initiate connection close
initiate_close(Reason, State) ->
    %% Send CONNECTION_CLOSE frame
    ErrorCode = case Reason of
        normal -> ?QUIC_NO_ERROR;
        _ -> ?QUIC_APPLICATION_ERROR
    end,
    CloseFrame = quic_frame:encode({connection_close, application, ErrorCode, undefined, <<>>}),

    case State#state.app_keys of
        undefined ->
            State#state{close_reason = Reason};
        _ ->
            send_app_packet(CloseFrame, State#state{close_reason = Reason})
    end.

%% Check timeouts
check_timeouts(State) ->
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - State#state.last_activity,
    if
        TimeSinceActivity > State#state.idle_timeout ->
            initiate_close(idle_timeout, State);
        true ->
            State
    end.

%% Convert state to map for debugging
state_to_map(#state{} = S) ->
    #{
        scid => S#state.scid,
        dcid => S#state.dcid,
        role => S#state.role,
        version => S#state.version,
        tls_state => S#state.tls_state,
        alpn => S#state.alpn,
        streams => maps:size(S#state.streams),
        data_sent => S#state.data_sent,
        data_received => S#state.data_received
    }.

%% Normalize ALPN list - handles binary, list of binaries, list of strings
normalize_alpn_list(undefined) ->
    [];
normalize_alpn_list(V) when is_binary(V) ->
    [V];
normalize_alpn_list([]) ->
    [];
normalize_alpn_list([H|_] = L) when is_binary(H) ->
    L;
normalize_alpn_list([H|_] = L) when is_list(H) ->
    [list_to_binary(S) || S <- L];
normalize_alpn_list([H|_] = L) when is_atom(H) ->
    [atom_to_binary(A, utf8) || A <- L];
normalize_alpn_list(_) ->
    [].
