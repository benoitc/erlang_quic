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
%%% {quic, ConnRef, {stream_data, StreamId, Data, Fin}}
%%% {quic, ConnRef, {stream_opened, StreamId}}
%%% {quic, ConnRef, {closed, Reason}}
%%%

-module(quic_connection).

-behaviour(gen_statem).

-include("quic.hrl").

%% Suppress warnings for helper functions prepared for future use
-compile([{nowarn_unused_function, [{send_handshake_ack, 1}]}]).

%% Dialyzer nowarn for functions prepared for future use and unreachable patterns
%% (code structure supports multiple ciphers/paths not yet exercised)
-dialyzer({nowarn_function, [
    send_initial_ack/1,
    select_cipher/1
]}).
-dialyzer([no_match]).

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
    send_datagram/2,
    open_stream/1,
    open_unidirectional_stream/1,
    close/2,
    close_stream/3,
    reset_stream/3,
    handle_timeout/1,
    handle_timeout/2,
    process/1,
    get_state/1,
    peername/1,
    sockname/1,
    peercert/1,
    set_owner/2,
    setopts/2,
    %% Key update (RFC 9001 Section 6)
    key_update/1,
    %% Connection migration (RFC 9000 Section 9)
    migrate/1,
    %% Server mode
    start_server/1,
    %% Stream prioritization (RFC 9218)
    set_stream_priority/4,
    get_stream_priority/2
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

%% Test exports
-ifdef(TEST).
-export([
    add_to_ack_ranges/2,
    merge_ack_ranges/1,
    convert_ack_ranges_for_encode/1,
    convert_rest_ranges/2
]).
-endif.

%% Registry table name
-define(REGISTRY, quic_connection_registry).

%% TLS handshake states (client)
-define(TLS_AWAITING_SERVER_HELLO, awaiting_server_hello).
-define(TLS_AWAITING_ENCRYPTED_EXT, awaiting_encrypted_extensions).
-define(TLS_AWAITING_CERT, awaiting_certificate).
-define(TLS_AWAITING_CERT_VERIFY, awaiting_certificate_verify).
-define(TLS_AWAITING_FINISHED, awaiting_finished).
-define(TLS_HANDSHAKE_COMPLETE, handshake_complete).

%% TLS handshake states (server)
-define(TLS_AWAITING_CLIENT_HELLO, awaiting_client_hello).
-define(TLS_AWAITING_CLIENT_FINISHED, awaiting_client_finished).

%% Max pending data entries before connection is established (prevents memory exhaustion)
-define(MAX_PENDING_DATA_ENTRIES, 1000).

%% Connection state record
-record(state, {
    %% Connection identity
    scid :: binary(),
    dcid :: binary(),
    original_dcid :: binary(),
    %% Retry handling (RFC 9000 Section 8.1)
    retry_token = <<>> :: binary(),  % Token from Retry packet for Initial resend
    retry_received = false :: boolean(),  % Whether a Retry packet has been received
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
    app_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,  % Convenience accessor (= key_state.current_keys)

    %% Key update state (RFC 9001 Section 6)
    key_state :: #key_update_state{} | undefined,

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

    %% Congestion control and loss detection
    cc_state :: quic_cc:cc_state() | undefined,
    loss_state :: quic_loss:loss_state() | undefined,
    pto_timer :: reference() | undefined,
    idle_timer :: reference() | undefined,

    %% Pending data - priority queue with 8 buckets (one per urgency 0-7)
    %% Each bucket is a queue:queue() for FIFO within same priority
    send_queue = {queue:new(), queue:new(), queue:new(), queue:new(),
                  queue:new(), queue:new(), queue:new(), queue:new()} :: tuple(),
    %% Pre-connection pending sends (simple list, processed when connected)
    pending_data = [] :: [{non_neg_integer(), iodata(), boolean()}],

    %% Close reason
    close_reason :: term(),

    %% Connection Migration (RFC 9000 Section 9)
    %% Current path (active remote address)
    current_path :: #path_state{} | undefined,
    %% Alternative paths being validated
    alt_paths = [] :: [#path_state{}],
    %% Preferred address being validated (RFC 9000 Section 9.6)
    %% Set when client is validating server's preferred address
    preferred_address :: #preferred_address{} | undefined,

    %% Connection ID Pool (RFC 9000 Section 5.1)
    %% Our CIDs that we've issued to the peer (via NEW_CONNECTION_ID)
    local_cid_pool = [] :: [#cid_entry{}],
    %% Next sequence number for our CIDs
    local_cid_seq = 1 :: non_neg_integer(),
    %% Peer's CIDs that we can use (received via NEW_CONNECTION_ID)
    peer_cid_pool = [] :: [#cid_entry{}],
    %% Local active CID limit - max peer CIDs we accept (advertised in our transport params)
    local_active_cid_limit = 2 :: non_neg_integer(),
    %% Peer's active CID limit - max CIDs we can issue to them (from their transport params)
    peer_active_cid_limit = 2 :: non_neg_integer(),

    %% Peer certificate (received during TLS handshake)
    peer_cert :: binary() | undefined,
    peer_cert_chain = [] :: [binary()],

    %% Server-specific fields
    listener :: pid() | undefined,
    server_cert :: binary() | undefined,
    server_cert_chain = [] :: [binary()],
    server_private_key :: term() | undefined,
    %% Server preferred address config (RFC 9000 Section 9.6)
    %% Set from listener options: {IPv4, IPv6} where each is {Addr, Port} | undefined
    server_preferred_address :: #preferred_address{} | undefined,

    %% Session resumption (RFC 8446 Section 4.6)
    resumption_secret :: binary() | undefined,
    max_early_data = 16384 :: non_neg_integer(),  % Default max 0-RTT data size

    %% Client-side ticket storage for session resumption
    ticket_store = #{} :: quic_ticket:ticket_store(),

    %% 0-RTT / Early Data (RFC 9001 Section 4.6)
    early_keys :: {#crypto_keys{}, binary()} | undefined,  % {Keys, EarlySecret}
    early_data_sent = 0 :: non_neg_integer(),  % Bytes of early data sent
    early_data_accepted = false :: boolean(),  % Server accepted early data

    %% QUIC-LB CID configuration (RFC 9312)
    cid_config :: #cid_config{} | undefined
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
    (try ets:delete(?REGISTRY, ConnRef) catch _:_ -> ok end),
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
-spec start_link(binary() | inet:hostname() | inet:ip_address(),
                 inet:port_number(),
                 map(),
                 pid()) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner) ->
    start_link(Host, Port, Opts, Owner, undefined).

%% @doc Start a QUIC connection with optional pre-opened socket.
-spec start_link(binary() | inet:hostname() | inet:ip_address(),
                 inet:port_number(),
                 map(),
                 pid(),
                 gen_udp:socket() | undefined) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner, Socket) ->
    gen_statem:start_link(?MODULE, [Host, Port, Opts, Owner, Socket], []).

%% @doc Initiate a connection to a QUIC server.
%% This is a convenience wrapper that starts the process and initiates handshake.
-spec connect(binary() | inet:hostname() | inet:ip_address(),
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

%% @doc Start a server-side QUIC connection.
%% Called by quic_listener when a new connection is accepted.
-spec start_server(map()) -> {ok, pid()} | {error, term()}.
start_server(Opts) ->
    gen_statem:start_link(?MODULE, {server, Opts}, []).

%% @doc Send data on a stream.
-spec send_data(pid(), non_neg_integer(), iodata(), boolean()) ->
    ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    gen_statem:call(Conn, {send_data, StreamId, Data, Fin}).

%% @doc Open a new bidirectional stream.
-spec open_stream(pid()) -> {ok, non_neg_integer()} | {error, term()}.
open_stream(Conn) ->
    gen_statem:call(Conn, open_stream, 10000).

%% @doc Open a new unidirectional stream.
-spec open_unidirectional_stream(pid()) -> {ok, non_neg_integer()} | {error, term()}.
open_unidirectional_stream(Conn) ->
    gen_statem:call(Conn, open_unidirectional_stream).

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

%% @doc Handle a timeout event with timestamp.
%% The NowMs parameter is currently unused as the connection
%% manages its own timing internally.
-spec handle_timeout(pid(), non_neg_integer()) -> non_neg_integer() | infinity.
handle_timeout(Conn, _NowMs) ->
    gen_statem:cast(Conn, handle_timeout),
    infinity.

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

%% @doc Get peer certificate (DER-encoded).
-spec peercert(pid()) -> {ok, binary()} | {error, term()}.
peercert(Conn) ->
    gen_statem:call(Conn, peercert).

%% @doc Set new owner process.
-spec set_owner(pid(), pid()) -> ok.
set_owner(Conn, NewOwner) ->
    gen_statem:cast(Conn, {set_owner, NewOwner}).

%% @doc Send a datagram.
-spec send_datagram(pid(), iodata()) -> ok | {error, term()}.
send_datagram(Conn, Data) ->
    gen_statem:call(Conn, {send_datagram, Data}).

%% @doc Set connection options.
-spec setopts(pid(), [{atom(), term()}]) -> ok | {error, term()}.
setopts(Conn, Opts) ->
    gen_statem:call(Conn, {setopts, Opts}).

%% @doc Initiate a key update (RFC 9001 Section 6).
%% This triggers a key update cycle, deriving new encryption keys.
%% Only valid when connection is in connected state.
-spec key_update(pid()) -> ok | {error, term()}.
key_update(Conn) ->
    gen_statem:call(Conn, key_update).

%% @doc Initiate connection migration.
%% This triggers path validation by sending PATH_CHALLENGE on a new path.
%% Simulates network change by rebinding the socket.
-spec migrate(pid()) -> ok | {error, term()}.
migrate(Conn) ->
    gen_statem:call(Conn, migrate).

%% @doc Set stream priority (RFC 9218).
%% Urgency: 0-7 (lower = more urgent, default 3)
%% Incremental: boolean (data can be processed incrementally)
-spec set_stream_priority(pid(), non_neg_integer(), 0..7, boolean()) ->
    ok | {error, term()}.
set_stream_priority(Conn, StreamId, Urgency, Incremental) ->
    gen_statem:call(Conn, {set_stream_priority, StreamId, Urgency, Incremental}).

%% @doc Get stream priority (RFC 9218).
%% Returns {ok, {Urgency, Incremental}} or {error, not_found}.
-spec get_stream_priority(pid(), non_neg_integer()) ->
    {ok, {0..7, boolean()}} | {error, term()}.
get_stream_priority(Conn, StreamId) ->
    gen_statem:call(Conn, {get_stream_priority, StreamId}).

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

    %% Create or use provided socket with proper cleanup on failure
    %% Pass RemoteAddr to match address family (IPv4 vs IPv6)
    case open_client_socket(Socket, RemoteAddr) of
        {ok, Sock, LocalAddr, OwnsSocket} ->
            try
                init_client_state(Host, Opts, Owner, SCID, DCID, RemoteAddr, Sock, LocalAddr)
            catch
                Class:Reason:Stack ->
                    %% Clean up socket on initialization failure
                    case OwnsSocket of
                        true -> gen_udp:close(Sock);
                        false -> ok
                    end,
                    erlang:raise(Class, Reason, Stack)
            end;
        {error, Reason} ->
            {stop, Reason}
    end;

%% Server-side initialization
init({server, Opts}) ->
    process_flag(trap_exit, true),

    %% Extract required options
    Socket = maps:get(socket, Opts),
    RemoteAddr = maps:get(remote_addr, Opts),
    InitialDCID = maps:get(initial_dcid, Opts),
    SCID = maps:get(scid, Opts),
    Cert = maps:get(cert, Opts),
    CertChain = maps:get(cert_chain, Opts, []),
    PrivateKey = maps:get(private_key, Opts),
    ALPNList = maps:get(alpn, Opts, [<<"h3">>]),
    Listener = maps:get(listener, Opts),
    %% Use client's QUIC version for key derivation (defaults to v1)
    Version = maps:get(version, Opts, ?QUIC_VERSION_1),

    %% Generate initial keys using client's DCID and version
    InitialKeys = derive_initial_keys(InitialDCID, Version),

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

    %% Initialize congestion control and loss detection
    CCState = quic_cc:new(),
    LossState = quic_loss:new(),

    %% Initialize state
    State = #state{
        scid = SCID,
        dcid = <<>>,  % Will be set from ClientHello SCID
        original_dcid = InitialDCID,
        role = server,
        version = Version,  % Use client's QUIC version
        socket = Socket,
        remote_addr = RemoteAddr,
        local_addr = undefined,
        owner = Listener,  % Listener is the owner for now
        conn_ref = ConnRef,
        verify = false,
        initial_keys = InitialKeys,
        tls_state = ?TLS_AWAITING_CLIENT_HELLO,
        alpn_list = normalize_alpn_list(ALPNList),
        pn_initial = PNSpace,
        pn_handshake = PNSpace,
        pn_app = PNSpace,
        max_data_local = maps:get(max_data, Opts, ?DEFAULT_INITIAL_MAX_DATA),
        max_data_remote = ?DEFAULT_INITIAL_MAX_DATA,
        next_stream_id_bidi = 1,  % Server-initiated bidi: 1, 5, 9, ...
        next_stream_id_uni = 3,   % Server-initiated uni: 3, 7, 11, ...
        max_streams_bidi_local = maps:get(max_streams_bidi, Opts, ?DEFAULT_MAX_STREAMS_BIDI),
        max_streams_bidi_remote = ?DEFAULT_MAX_STREAMS_BIDI,
        max_streams_uni_local = maps:get(max_streams_uni, Opts, ?DEFAULT_MAX_STREAMS_UNI),
        max_streams_uni_remote = ?DEFAULT_MAX_STREAMS_UNI,
        idle_timeout = maps:get(idle_timeout, Opts, ?DEFAULT_MAX_IDLE_TIMEOUT),
        last_activity = erlang:monotonic_time(millisecond),
        cc_state = CCState,
        loss_state = LossState,
        listener = Listener,
        server_cert = Cert,
        server_cert_chain = CertChain,
        server_private_key = PrivateKey,
        server_preferred_address = build_server_preferred_address(Opts),
        cid_config = maps:get(cid_config, Opts, undefined)
    },

    {ok, idle, State}.

%% Build preferred_address record from listener options (RFC 9000 Section 9.6)
build_server_preferred_address(Opts) ->
    PreferredIPv4 = maps:get(preferred_ipv4, Opts, undefined),
    PreferredIPv6 = maps:get(preferred_ipv6, Opts, undefined),
    case {PreferredIPv4, PreferredIPv6} of
        {undefined, undefined} ->
            undefined;
        _ ->
            %% Generate new CID (LB-aware if configured) and stateless reset token
            CIDConfig = maps:get(cid_config, Opts, undefined),
            CID = generate_connection_id(CIDConfig),
            Token = crypto:strong_rand_bytes(16),
            {IPv4Addr, IPv4Port} = case PreferredIPv4 of
                {Addr, Port} -> {Addr, Port};
                undefined -> {undefined, undefined}
            end,
            {IPv6Addr, IPv6Port} = case PreferredIPv6 of
                {Addr6, Port6} -> {Addr6, Port6};
                undefined -> {undefined, undefined}
            end,
            #preferred_address{
                ipv4_addr = IPv4Addr,
                ipv4_port = IPv4Port,
                ipv6_addr = IPv6Addr,
                ipv6_port = IPv6Port,
                cid = CID,
                stateless_reset_token = Token
            }
    end.

%% Helper to open or use provided socket for client
%% Match address family based on the remote address
open_client_socket(undefined, {IP, _Port}) ->
    AddrFamily = address_family(IP),
    case gen_udp:open(0, [binary, AddrFamily, {active, false}]) of
        {ok, S} ->
            case inet:sockname(S) of
                {ok, LA} -> {ok, S, LA, true};
                {error, Reason} ->
                    gen_udp:close(S),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
open_client_socket(S, _RemoteAddr) ->
    case inet:sockname(S) of
        {ok, LA} -> {ok, S, LA, false};
        {error, Reason} -> {error, Reason}
    end.

%% Determine address family from IP tuple
address_family(IP) when tuple_size(IP) =:= 4 -> inet;
address_family(IP) when tuple_size(IP) =:= 8 -> inet6.

%% Continue client initialization after socket is ready
init_client_state(Host, Opts, Owner, SCID, DCID, RemoteAddr, Sock, LocalAddr) ->
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

    %% Initialize congestion control and loss detection
    CCState = quic_cc:new(),
    LossState = quic_loss:new(),

    %% Extract session ticket for resumption (if provided)
    SessionTicket = maps:get(session_ticket, Opts, undefined),

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
        last_activity = erlang:monotonic_time(millisecond),
        cc_state = CCState,
        loss_state = LossState,
        %% Store session ticket for resumption
        ticket_store = case SessionTicket of
            undefined -> quic_ticket:new_store();
            Ticket -> quic_ticket:store_ticket(ServerName, Ticket, quic_ticket:new_store())
        end
    },

    {ok, idle, State}.

terminate(_Reason, _StateName, #state{socket = Socket, conn_ref = ConnRef,
                                      pto_timer = PtoTimer, idle_timer = IdleTimer,
                                      role = Role}) ->
    unregister_conn(ConnRef),
    %% Cancel any active timers
    cancel_timer(PtoTimer),
    cancel_timer(IdleTimer),
    %% Cancel delayed ACK timer from process dictionary
    case erase(ack_timer) of
        undefined -> ok;
        AckTimerRef -> cancel_timer(AckTimerRef)
    end,
    %% Only close socket for client connections (clients own their socket)
    %% Server connections share the listener's socket and must not close it
    case {Role, Socket} of
        {client, S} when S =/= undefined -> gen_udp:close(S);
        _ -> ok
    end,
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%====================================================================
%% State Functions
%%====================================================================

%% ----- IDLE STATE -----

idle(enter, _OldState, #state{role = client} = State) ->
    %% Client: Start the handshake by sending Initial packet with ClientHello
    NewState = send_client_hello(State),
    {keep_state, NewState};

idle(enter, _OldState, #state{role = server} = State) ->
    %% Server: Wait for Initial packet with ClientHello
    {keep_state, State};

idle({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

idle({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {idle, state_to_map(State)}}]};

idle({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

idle({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

idle(cast, {set_owner, NewOwner}, State) ->
    {keep_state, State#state{owner = NewOwner}};

%% 0-RTT: Allow opening streams in idle state if early keys are available
idle({call, From}, open_stream, #state{early_keys = undefined} = State) ->
    {keep_state, State, [{reply, From, {error, not_connected}}]};
idle({call, From}, open_stream, #state{early_keys = _EarlyKeys} = State) ->
    case do_open_stream(State) of
        {ok, StreamId, NewState} ->
            {keep_state, NewState, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

%% 0-RTT: Allow sending data in idle state if early keys are available
idle({call, From}, {send_data, StreamId, Data, Fin}, #state{early_keys = undefined,
                                                            pending_data = Pending} = State) ->
    case length(Pending) >= ?MAX_PENDING_DATA_ENTRIES of
        true ->
            {keep_state, State, [{reply, From, {error, pending_data_limit}}]};
        false ->
            NewPending = Pending ++ [{StreamId, Data, Fin}],
            {keep_state, State#state{pending_data = NewPending}, [{reply, From, ok}]}
    end;
idle({call, From}, {send_data, StreamId, Data, Fin}, #state{early_keys = _} = State) ->
    case do_send_zero_rtt_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

idle(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(idle, NewState);

%% Server receives packets from listener
idle(info, {quic_packet, Data, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(idle, NewState);

idle(cast, process, #state{role = client, socket = Socket} = State) ->
    %% Re-enable socket for receiving (client only - server uses listener's socket)
    inet:setopts(Socket, [{active, once}]),
    {keep_state, State};
idle(cast, process, #state{role = server} = State) ->
    %% Server connections receive via listener, don't touch socket options
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

handshaking(cast, {set_owner, NewOwner}, State) ->
    {keep_state, State#state{owner = NewOwner}};

%% 0-RTT: Allow opening streams during handshake if early keys are available
handshaking({call, From}, open_stream, #state{early_keys = undefined} = State) ->
    %% No early keys, must wait for handshake to complete
    {keep_state, State, [{reply, From, {error, not_connected}}]};
handshaking({call, From}, open_stream, #state{early_keys = _EarlyKeys} = State) ->
    %% Early keys available, can open stream for 0-RTT
    case do_open_stream(State) of
        {ok, StreamId, NewState} ->
            {keep_state, NewState, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

%% 0-RTT: Allow sending data during handshake if early keys are available
handshaking({call, From}, {send_data, StreamId, Data, Fin}, #state{early_keys = undefined,
                                                                   pending_data = Pending} = State) ->
    %% No early keys, queue the data for later (with limit to prevent memory exhaustion)
    case length(Pending) >= ?MAX_PENDING_DATA_ENTRIES of
        true ->
            {keep_state, State, [{reply, From, {error, pending_data_limit}}]};
        false ->
            NewPending = Pending ++ [{StreamId, Data, Fin}],
            {keep_state, State#state{pending_data = NewPending}, [{reply, From, ok}]}
    end;
handshaking({call, From}, {send_data, StreamId, Data, Fin}, #state{early_keys = _} = State) ->
    %% Send as 0-RTT data
    case do_send_zero_rtt_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

handshaking(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(handshaking, NewState);

%% Server receives packets from listener
handshaking(info, {quic_packet, Data, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(handshaking, NewState);

handshaking(cast, process, #state{role = client, socket = Socket} = State) ->
    %% Re-enable socket for receiving (client only - server uses listener's socket)
    inet:setopts(Socket, [{active, once}]),
    {keep_state, State};
handshaking(cast, process, #state{role = server} = State) ->
    %% Server connections receive via listener, don't touch socket options
    {keep_state, State};

handshaking(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, handshaking, State).

%% ----- CONNECTED STATE -----

connected(enter, OldState, #state{owner = Owner, conn_ref = Ref, alpn = Alpn,
                                   socket = Socket, role = Role,
                                   pending_data = Pending,
                                   transport_params = TransportParams} = State)
  when OldState =:= handshaking; OldState =:= idle ->
    %% Notify owner that connection is established
    Info = #{
        alpn => Alpn,
        alpn_protocol => Alpn
    },
    Owner ! {quic, Ref, {connected, Info}},
    %% For client connections, ensure socket is active for receiving
    %% Server connections receive via listener (quic_packet messages)
    case Role of
        client -> inet:setopts(Socket, [{active, once}]);
        server -> ok
    end,
    %% Send any data that was queued before connection established
    State1 = State#state{pending_data = []},
    State2 = send_pending_data(Pending, State1),
    %% RFC 9000 Section 9.6: Client validates server's preferred address
    State3 = case Role of
        client ->
            case maps:get(preferred_address, TransportParams, undefined) of
                undefined -> State2;
                PA when is_record(PA, preferred_address) ->
                    initiate_preferred_address_validation(PA, State2);
                _ -> State2
            end;
        server -> State2
    end,
    %% RFC 9000 Section 10.1: Start idle timer when entering connected state
    State4 = update_last_activity(State3),
    {keep_state, State4};

connected({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

connected({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {connected, state_to_map(State)}}]};

connected({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

connected({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

connected({call, From}, peercert, #state{peer_cert = undefined} = State) ->
    {keep_state, State, [{reply, From, {error, no_peercert}}]};
connected({call, From}, peercert, #state{peer_cert = Cert} = State) ->
    {keep_state, State, [{reply, From, {ok, Cert}}]};

connected(cast, {set_owner, NewOwner}, State) ->
    {keep_state, State#state{owner = NewOwner}};

connected({call, From}, {send_datagram, Data}, State) ->
    case do_send_datagram(Data, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
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

connected({call, From}, open_unidirectional_stream, State) ->
    case do_open_unidirectional_stream(State) of
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

%% Stream prioritization (RFC 9218)
connected({call, From}, {set_stream_priority, StreamId, Urgency, Incremental}, State) ->
    case do_set_stream_priority(StreamId, Urgency, Incremental, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {get_stream_priority, StreamId}, State) ->
    case do_get_stream_priority(StreamId, State) of
        {ok, Priority} ->
            {keep_state, State, [{reply, From, {ok, Priority}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {setopts, _Opts}, State) ->
    {keep_state, State, [{reply, From, ok}]};

connected({call, From}, key_update, #state{key_state = undefined} = State) ->
    {keep_state, State, [{reply, From, {error, no_keys}}]};
connected({call, From}, key_update, #state{key_state = KeyState} = State) ->
    case KeyState#key_update_state.update_state of
        idle ->
            %% Initiate key update
            NewState = initiate_key_update(State),
            {keep_state, NewState, [{reply, From, ok}]};
        _ ->
            %% Key update already in progress
            {keep_state, State, [{reply, From, {error, key_update_in_progress}}]}
    end;

%% Handle connection migration request (RFC 9000 Section 9)
connected({call, From}, migrate, #state{socket = Socket, remote_addr = RemoteAddr} = State) ->
    %% Simulate network change by rebinding socket to a new port
    %% In a real scenario, this would happen when the device changes networks
    case rebind_socket(Socket) of
        {ok, NewSocket} ->
            %% Start path validation to the peer on the new path
            NewState = State#state{socket = NewSocket},
            State1 = initiate_path_validation(RemoteAddr, NewState),
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(connected, NewState);

%% Server receives packets from listener
connected(info, {quic_packet, Data, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(connected, NewState);

connected(cast, {close, Reason}, State) ->
    NewState = initiate_close(Reason, State),
    {next_state, draining, NewState};

connected(cast, process, #state{role = client, socket = Socket} = State) ->
    %% Re-enable socket for receiving (client only - server uses listener's socket)
    inet:setopts(Socket, [{active, once}]),
    {keep_state, State};
connected(cast, process, #state{role = server} = State) ->
    %% Server connections receive via listener, don't touch socket options
    {keep_state, State};

%% Handle delayed ACK timer (RFC 9221 Section 5.2)
connected(info, {send_delayed_ack, app}, State) ->
    erase(ack_timer),
    NewState = send_app_ack(State),
    {keep_state, NewState};

connected(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, connected, State).

%% ----- DRAINING STATE -----

draining(enter, _OldState, #state{owner = Owner, conn_ref = Ref, close_reason = Reason,
                                  loss_state = LossState} = State) ->
    Owner ! {quic, Ref, {closed, Reason}},
    %% Start drain timer (3 * PTO per RFC 9000 Section 10.2)
    DrainTimeout = case LossState of
        undefined -> 3000;  % Fallback if loss state not initialized
        _ -> 3 * quic_loss:get_pto(LossState)
    end,
    TimerRef = erlang:send_after(DrainTimeout, self(), drain_timeout),
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

handle_common_event(info, pto_timeout, StateName, State)
  when StateName =:= connected; StateName =:= handshaking ->
    %% Handle PTO timeout - send probe packet
    NewState = handle_pto_timeout(State),
    {keep_state, NewState};

handle_common_event(info, pto_timeout, _StateName, State) ->
    %% Ignore PTO in other states
    {keep_state, State};

handle_common_event(info, idle_timeout, StateName, State)
  when StateName =/= draining, StateName =/= closed ->
    %% Handle idle timeout - check if we've truly been idle
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - State#state.last_activity,
    case TimeSinceActivity >= State#state.idle_timeout of
        true ->
            %% Genuine idle timeout - initiate close
            NewState = initiate_close(idle_timeout, State),
            {next_state, draining, NewState};
        false ->
            %% Spurious timeout (activity occurred) - reset timer
            {keep_state, set_idle_timer(State)}
    end;

handle_common_event(info, idle_timeout, _StateName, State) ->
    %% Ignore idle timeout in draining/closed states
    {keep_state, State};

handle_common_event(info, {'EXIT', _Pid, _Reason}, _StateName, State) ->
    {keep_state, State};

%% Return error for unhandled calls to prevent timeout
handle_common_event({call, From}, _Request, StateName, State) ->
    {keep_state, State, [{reply, From, {error, {invalid_state, StateName}}}]};

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
        max_streams_uni_local = MaxStreamsUni,
        ticket_store = TicketStore
    } = State,

    %% Look up session ticket for resumption
    SessionTicket = case quic_ticket:lookup_ticket(ServerName, TicketStore) of
        {ok, Ticket} -> Ticket;
        error -> undefined
    end,

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

    %% Build ClientHello (with or without PSK for resumption)
    ClientHelloOpts = #{
        server_name => ServerName,
        alpn => AlpnList,
        transport_params => TransportParams,
        session_ticket => SessionTicket
    },
    {ClientHello, PrivKey, _Random} = quic_tls:build_client_hello(ClientHelloOpts),

    %% Update transcript
    Transcript = ClientHello,

    %% Derive early keys if we have a session ticket for 0-RTT
    EarlyKeys = case SessionTicket of
        undefined ->
            undefined;
        #session_ticket{cipher = Cipher, resumption_secret = ResSecret} ->
            %% Derive PSK and early secret
            PSK = quic_ticket:derive_psk(ResSecret, SessionTicket),
            EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),
            %% Derive client early traffic secret from ClientHello hash
            ClientHelloHash = quic_crypto:transcript_hash(Cipher, Transcript),
            EarlyTrafficSecret = quic_crypto:derive_client_early_traffic_secret(
                Cipher, EarlySecret, ClientHelloHash),
            %% Derive traffic keys
            {Key, IV, HP} = quic_keys:derive_keys(EarlyTrafficSecret, Cipher),
            Keys = #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher},
            {Keys, EarlySecret}
    end,

    %% Create CRYPTO frame
    CryptoFrame = quic_frame:encode({crypto, 0, ClientHello}),

    %% Encrypt and send Initial packet
    NewState = send_initial_packet(CryptoFrame, State#state{
        tls_private_key = PrivKey,
        tls_transcript = Transcript,
        early_keys = EarlyKeys,
        max_early_data = case SessionTicket of
            undefined -> 0;
            #session_ticket{max_early_data = MaxEarly} -> MaxEarly
        end
    }),

    %% Enable socket for receiving
    inet:setopts(NewState#state.socket, [{active, once}]),

    NewState.

%% Server: Select cipher suite from client's list (server preference)
select_cipher(ClientCipherSuites) ->
    ServerPreference = [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
    select_first_match(ServerPreference, ClientCipherSuites).

select_first_match([], _) -> aes_128_gcm;  % Default
select_first_match([Cipher | Rest], ClientSuites) ->
    case lists:member(Cipher, ClientSuites) of
        true -> Cipher;
        false -> select_first_match(Rest, ClientSuites)
    end.

%% Server: Negotiate ALPN
negotiate_alpn(ClientALPN, ServerALPN) ->
    case [A || A <- ServerALPN, lists:member(A, ClientALPN)] of
        [First | _] -> First;
        [] -> undefined
    end.

%% Extract x25519 public key from key share entries list
extract_x25519_key(undefined) -> undefined;
extract_x25519_key([]) -> undefined;
extract_x25519_key([{?GROUP_X25519, PubKey} | _]) -> PubKey;
extract_x25519_key([_ | Rest]) -> extract_x25519_key(Rest).

%% Validate PSK from client's pre_shared_key extension
%% Returns {ok, PSK, ResumptionSecret} if valid, error otherwise
validate_psk(Identity, _Cipher, _ClientHelloMsg, #state{ticket_store = TicketStore}) ->
    %% Try to find ticket by identity - first in local store, then global ETS
    case find_ticket_by_identity(Identity, TicketStore) of
        {ok, Ticket} ->
            %% Extract resumption secret from ticket
            ResumptionSecret = Ticket#session_ticket.resumption_secret,
            %% Derive PSK from resumption secret
            PSK = quic_ticket:derive_psk(ResumptionSecret, Ticket),
            {ok, PSK, ResumptionSecret};
        error ->
            %% Try global ETS table
            case lookup_ticket_globally(Identity) of
                {ok, Ticket} ->
                    ResumptionSecret = Ticket#session_ticket.resumption_secret,
                    PSK = quic_ticket:derive_psk(ResumptionSecret, Ticket),
                    {ok, PSK, ResumptionSecret};
                error ->
                    error
            end
    end;
validate_psk(_Identity, _Cipher, _ClientHelloMsg, _State) ->
    %% No ticket store
    error.

%% Find ticket by its identity (the ticket field)
find_ticket_by_identity(Identity, Store) ->
    %% Search through all stored tickets
    Tickets = maps:values(Store),
    find_matching_ticket(Identity, Tickets).

find_matching_ticket(_Identity, []) ->
    error;
find_matching_ticket(Identity, [#session_ticket{ticket = Identity} = Ticket | _Rest]) ->
    {ok, Ticket};
find_matching_ticket(Identity, [_ | Rest]) ->
    find_matching_ticket(Identity, Rest).

%% Global ticket storage using ETS (for 0-RTT across connections)
-define(TICKET_TABLE, quic_server_tickets).
%% Ticket TTL: 7 days in milliseconds (RFC 8446 recommends max 7 days)
-define(TICKET_TTL_MS, 7 * 24 * 60 * 60 * 1000).
%% Max tickets to store (prevents unbounded memory growth)
-define(MAX_TICKETS, 10000).

store_ticket_globally(TicketIdentity, Ticket) ->
    ensure_ticket_table(),
    Now = erlang:monotonic_time(millisecond),
    %% Cleanup expired tickets periodically (1 in 100 chance on insert)
    case rand:uniform(100) of
        1 -> cleanup_expired_tickets(Now);
        _ -> ok
    end,
    %% Check table size and evict oldest if needed
    case ets:info(?TICKET_TABLE, size) >= ?MAX_TICKETS of
        true -> evict_oldest_ticket();
        false -> ok
    end,
    ets:insert(?TICKET_TABLE, {TicketIdentity, Ticket, Now}).

lookup_ticket_globally(TicketIdentity) ->
    ensure_ticket_table(),
    Now = erlang:monotonic_time(millisecond),
    case ets:lookup(?TICKET_TABLE, TicketIdentity) of
        [{_, Ticket, StoredAt}] ->
            case Now - StoredAt > ?TICKET_TTL_MS of
                true ->
                    %% Ticket expired, delete it
                    ets:delete(?TICKET_TABLE, TicketIdentity),
                    error;
                false ->
                    {ok, Ticket}
            end;
        [{_, Ticket}] ->
            %% Legacy entry without timestamp, treat as valid
            {ok, Ticket};
        [] ->
            error
    end.

cleanup_expired_tickets(Now) ->
    %% Delete all tickets older than TTL
    ets:select_delete(?TICKET_TABLE, [
        {{'_', '_', '$1'}, [{'<', '$1', {const, Now - ?TICKET_TTL_MS}}], [true]}
    ]).

evict_oldest_ticket() ->
    %% Find and delete the oldest ticket
    case ets:first(?TICKET_TABLE) of
        '$end_of_table' -> ok;
        Key -> ets:delete(?TICKET_TABLE, Key)
    end.

ensure_ticket_table() ->
    case ets:whereis(?TICKET_TABLE) of
        undefined ->
            %% Create the table - public so all connections can access it
            try
                ets:new(?TICKET_TABLE, [named_table, public, ordered_set, {read_concurrency, true}])
            catch
                error:badarg -> ok  % Table already exists (race condition)
            end;
        _ ->
            ok
    end.

%% Server: Send ServerHello in Initial packet
send_server_hello(ServerHelloMsg, State) ->
    CryptoFrame = quic_frame:encode({crypto, 0, ServerHelloMsg}),
    send_initial_packet(CryptoFrame, State).

%% Server: Send EncryptedExtensions, Certificate, CertificateVerify, Finished
send_server_handshake_flight(Cipher, _TranscriptHashAfterSH, State) ->
    #state{
        scid = SCID,
        alpn = ALPN,
        max_data_local = MaxData,
        max_streams_bidi_local = MaxStreamsBidi,
        max_streams_uni_local = MaxStreamsUni,
        server_cert = Cert,
        server_cert_chain = CertChain,
        server_private_key = PrivateKey,
        tls_transcript = Transcript,
        server_hs_secret = ServerHsSecret,
        handshake_secret = HandshakeSecret
    } = State,

    %% Build transport parameters
    TransportParams0 = #{
        original_dcid => State#state.original_dcid,  %% RFC 9000 §7.3: server MUST send this
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
    %% Add preferred_address if configured (RFC 9000 Section 9.6)
    %% Server MUST NOT send preferred_address if disable_active_migration is set
    TransportParams = case State#state.server_preferred_address of
        #preferred_address{} = PA ->
            TransportParams0#{preferred_address => PA};
        _ ->
            TransportParams0
    end,

    %% Build EncryptedExtensions
    EncExtMsg = quic_tls:build_encrypted_extensions(#{
        alpn => ALPN,
        transport_params => TransportParams
    }),

    %% Build Certificate
    AllCerts = [Cert | CertChain],
    CertMsg = quic_tls:build_certificate(<<>>, AllCerts),

    %% Update transcript after EncryptedExtensions and Certificate
    Transcript1 = <<Transcript/binary, EncExtMsg/binary, CertMsg/binary>>,
    TranscriptHashForCV = quic_crypto:transcript_hash(Cipher, Transcript1),

    %% Build CertificateVerify - select signature algorithm based on key type
    SigAlg = select_signature_algorithm(PrivateKey),
    CertVerifyMsg = quic_tls:build_certificate_verify(SigAlg, PrivateKey, TranscriptHashForCV),

    %% Update transcript after CertificateVerify
    Transcript2 = <<Transcript1/binary, CertVerifyMsg/binary>>,
    TranscriptHashForFinished = quic_crypto:transcript_hash(Cipher, Transcript2),

    %% Build server Finished
    ServerFinishedKey = quic_crypto:derive_finished_key(Cipher, ServerHsSecret),
    ServerVerifyData = quic_crypto:compute_finished_verify(Cipher, ServerFinishedKey, TranscriptHashForFinished),
    FinishedMsg = quic_tls:build_finished(ServerVerifyData),

    %% Update transcript after server Finished
    Transcript3 = <<Transcript2/binary, FinishedMsg/binary>>,
    TranscriptHashFinal = quic_crypto:transcript_hash(Cipher, Transcript3),

    %% Derive master secret and application keys
    MasterSecret = quic_crypto:derive_master_secret(Cipher, HandshakeSecret),
    ClientAppSecret = quic_crypto:derive_client_app_secret(Cipher, MasterSecret, TranscriptHashFinal),
    ServerAppSecret = quic_crypto:derive_server_app_secret(Cipher, MasterSecret, TranscriptHashFinal),

    %% Derive app keys
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientAppSecret, Cipher),
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerAppSecret, Cipher),

    ClientAppKeys = #crypto_keys{key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher},
    ServerAppKeys = #crypto_keys{key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher},

    %% Initialize key update state
    KeyState = #key_update_state{
        current_phase = 0,
        current_keys = {ClientAppKeys, ServerAppKeys},
        prev_keys = undefined,
        client_app_secret = ClientAppSecret,
        server_app_secret = ServerAppSecret,
        update_state = idle
    },

    %% Combine all messages into CRYPTO frame payload
    HandshakePayload = <<EncExtMsg/binary, CertMsg/binary, CertVerifyMsg/binary, FinishedMsg/binary>>,
    CryptoFrame = quic_frame:encode({crypto, 0, HandshakePayload}),

    %% Update state with transcript and app keys
    State1 = State#state{
        tls_transcript = Transcript3,
        master_secret = MasterSecret,
        app_keys = {ClientAppKeys, ServerAppKeys},
        key_state = KeyState
    },

    %% Send in Handshake packet
    send_handshake_packet(CryptoFrame, State1).

%% Server: Send HANDSHAKE_DONE frame after receiving client Finished
send_handshake_done(State) ->
    %% HANDSHAKE_DONE is frame type 0x1e with no payload
    Frame = quic_frame:encode(handshake_done),
    send_app_packet(Frame, State).

%% Server: Send NewSessionTicket after handshake completes
%% RFC 8446 Section 4.6.1: Server sends NewSessionTicket in post-handshake message
%% In QUIC, this is sent as a TLS handshake message in a CRYPTO frame
send_new_session_ticket(#state{resumption_secret = undefined} = State) ->
    %% No resumption secret available - skip sending ticket
    State;
send_new_session_ticket(#state{
    resumption_secret = ResumptionSecret,
    server_name = ServerName,
    max_early_data = MaxEarlyData,
    alpn = ALPN,
    handshake_keys = {ClientHsKeys, _},
    ticket_store = TicketStore
} = State) ->
    %% Get cipher from the connection
    Cipher = ClientHsKeys#crypto_keys.cipher,

    %% Create a session ticket
    Ticket = quic_ticket:create_ticket(
        case ServerName of
            undefined -> <<"">>;
            Name -> Name
        end,
        ResumptionSecret,
        MaxEarlyData,
        Cipher,
        ALPN
    ),

    %% Store ticket on server side for later PSK validation (0-RTT support)
    %% Use the ticket identity (the ticket field) as the key
    %% Store in both local map and global ETS table for cross-connection access
    TicketIdentity = Ticket#session_ticket.ticket,
    NewTicketStore = maps:put(TicketIdentity, Ticket, TicketStore),
    %% Also store in global ETS table for 0-RTT across connections
    store_ticket_globally(TicketIdentity, Ticket),

    %% Build NewSessionTicket TLS message
    TicketMsg = quic_ticket:build_new_session_ticket(Ticket),

    %% Wrap in TLS handshake message (type 4 = NewSessionTicket)
    TLSMsg = quic_tls:encode_handshake_message(?TLS_NEW_SESSION_TICKET, TicketMsg),

    %% Send in CRYPTO frame (at application level)
    CryptoFrame = quic_frame:encode({crypto, 0, TLSMsg}),
    State1 = State#state{ticket_store = NewTicketStore},
    send_app_packet(CryptoFrame, State1).

%% Send an Initial packet
send_initial_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        socket = Socket,
        remote_addr = {IP, Port},
        initial_keys = {ClientKeys, ServerKeys},
        role = Role,
        pn_initial = PNSpace,
        retry_token = RetryToken
    } = State,

    %% Select correct keys based on role:
    %% - Client sends with ClientKeys
    %% - Server sends with ServerKeys
    EncryptKeys = case Role of
        client -> ClientKeys;
        server -> ServerKeys
    end,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Encode the retry token (RFC 9000 Section 17.2.2)
    %% Token is a variable-length field preceded by a varint length
    TokenLen = byte_size(RetryToken),
    TokenLenEnc = quic_varint:encode(TokenLen),

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Build header (without packet number, for AAD)
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary,
        TokenLenEnc/binary, RetryToken/binary,  % Token length + token
        (quic_varint:encode(byte_size(PaddedPayload) + PNLen + 16))/binary  % +16 for AEAD tag
    >>,

    %% First byte: 1100 0000 | (PNLen - 1)
    FirstByte = 16#C0 bor (PNLen - 1),
    Header = <<FirstByte, HeaderBody/binary>>,

    %% AAD is the header with encoded PN appended
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt payload
    #crypto_keys{key = Key, iv = IV, hp = HP} = EncryptKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, PaddedPayload),

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
%% Coalesces ACK with small pending stream data when possible
send_app_ack(State) ->
    #state{pn_app = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;
        Ranges ->
            AckFrame = build_ack_frame(Ranges),
            %% Try to coalesce ACK with small pending stream data
            maybe_coalesce_ack_with_data(AckFrame, State)
    end.

%% Try to coalesce ACK frame with small pending stream data
maybe_coalesce_ack_with_data(AckFrame, State) ->
    case dequeue_small_stream_frame(State) of
        {ok, StreamFrame, State1} ->
            send_coalesced_frames([AckFrame, StreamFrame], State1);
        none ->
            send_app_packet(AckFrame, State)
    end.

%% Dequeue a small stream frame if available (< 500 bytes)
%% This allows coalescing ACK with small stream data
-define(SMALL_FRAME_THRESHOLD, 500).
dequeue_small_stream_frame(#state{send_queue = PQ} = State) ->
    case pqueue_peek(PQ) of
        {value, {stream_data, StreamId, Offset, Data, Fin}} when byte_size(Data) < ?SMALL_FRAME_THRESHOLD ->
            %% Remove from queue and build STREAM frame
            {{value, _}, NewPQ} = pqueue_out(PQ),
            StreamFrame = quic_frame:encode({stream, StreamId, Offset, Data, Fin}),
            {ok, StreamFrame, State#state{send_queue = NewPQ}};
        _ ->
            none
    end.

%% Send multiple frames in a single packet
send_coalesced_frames(Frames, State) ->
    Payload = iolist_to_binary(Frames),
    %% Extract decoded frame info for loss tracking
    FrameInfo = lists:map(fun decode_frame_for_tracking/1, Frames),
    send_app_packet_internal(Payload, FrameInfo, State).

%% Extract frame info for loss detection tracking
decode_frame_for_tracking(FrameBin) ->
    case quic_frame:decode(FrameBin) of
        {ok, Frame, _} -> Frame;
        _ -> unknown
    end.

%% Build an ACK frame from ranges
%% Our internal format is [{Start, End}, ...] where Start <= End
%% quic_frame expects [{LargestAcked, FirstRange}, {Gap, Range}, ...]
%% where FirstRange = LargestAcked - SmallestAcked (count)
build_ack_frame(Ranges) ->
    %% Convert from {Start, End} to encoder format
    EncoderRanges = convert_ack_ranges_for_encode(Ranges),
    AckDelay = 0,  % For simplicity
    quic_frame:encode({ack, EncoderRanges, AckDelay, undefined}).

%% Convert internal ACK ranges to encoder format
convert_ack_ranges_for_encode([{Start, End} | Rest]) ->
    %% First range: LargestAcked = End, FirstRange = End - Start
    FirstRange = End - Start,
    RestConverted = convert_rest_ranges(Start, Rest),
    [{End, FirstRange} | RestConverted].

convert_rest_ranges(_PrevStart, []) ->
    [];
convert_rest_ranges(PrevStart, [{Start, End} | Rest]) ->
    %% Gap = PrevStart - End - 2 (number of missing packets between ranges)
    Gap = PrevStart - End - 2,
    %% Range = End - Start (number of packets in this block)
    Range = End - Start,
    %% Validate: Gap and Range must be non-negative for valid ACK ranges
    case Gap >= 0 andalso Range >= 0 of
        true ->
            [{Gap, Range} | convert_rest_ranges(Start, Rest)];
        false ->
            %% Skip malformed range (defensive - shouldn't happen with proper range tracking)
            convert_rest_ranges(Start, Rest)
    end.

%% Send a Handshake packet
send_handshake_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        socket = Socket,
        remote_addr = {IP, Port},
        handshake_keys = {ClientKeys, ServerKeys},
        role = Role,
        pn_handshake = PNSpace
    } = State,

    %% Select correct keys based on role
    EncryptKeys = case Role of
        client -> ClientKeys;
        server -> ServerKeys
    end,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% First byte for Handshake: 1110 0000 | (PNLen - 1)
    FirstByte = 16#E0 bor (PNLen - 1),

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Build header (length includes PN + encrypted payload + AEAD tag)
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary,
        (quic_varint:encode(byte_size(PaddedPayload) + PNLen + 16))/binary
    >>,
    Header = <<FirstByte, HeaderBody/binary>>,

    %% AAD
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt
    #crypto_keys{key = Key, iv = IV, hp = HP} = EncryptKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, PaddedPayload),

    %% Header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    gen_udp:send(Socket, IP, Port, Packet),

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_handshake = NewPNSpace}.

%% Send a 1-RTT (application) packet (without tracking frames for retransmission)
send_app_packet(Payload, State) ->
    send_app_packet_internal(Payload, [], State).

%% Send a 1-RTT packet with explicit frames list for retransmission tracking
send_app_packet_internal(Payload, Frames, State) ->
    #state{
        dcid = DCID,
        socket = Socket,
        remote_addr = {IP, Port},
        app_keys = {ClientKeys, ServerKeys},
        role = Role,
        pn_app = PNSpace,
        cc_state = CCState,
        loss_state = LossState
    } = State,

    %% Select correct keys based on role
    EncryptKeys = case Role of
        client -> ClientKeys;
        server -> ServerKeys
    end,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Get current key phase for encoding
    KeyPhase = get_current_key_phase(State),

    %% First byte for short header: 01XX XXXX
    %% Bit 5 = spin bit (0), bits 3-4 reserved (0), bit 2 = key phase, bits 0-1 = PN length
    FirstByte = 16#40 bor (KeyPhase bsl 2) bor (PNLen - 1),

    %% Header is just first byte + DCID
    Header = <<FirstByte, DCID/binary>>,

    %% AAD
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Encrypt
    #crypto_keys{key = Key, iv = IV, hp = HP} = EncryptKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, PaddedPayload),

    %% Header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    PacketSize = byte_size(Packet),
    gen_udp:send(Socket, IP, Port, Packet),

    %% Track sent packet for loss detection and congestion control
    %% Determine if ack-eliciting (not ACK-only or padding-only)
    AckEliciting = is_ack_eliciting_payload(Payload),
    NewLossState = quic_loss:on_packet_sent(LossState, PN, PacketSize, AckEliciting, Frames),
    NewCCState = case AckEliciting of
        true -> quic_cc:on_packet_sent(CCState, PacketSize);
        false -> CCState
    end,

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State1 = State#state{
        pn_app = NewPNSpace,
        cc_state = NewCCState,
        loss_state = NewLossState
    },

    %% Set PTO timer for retransmission
    set_pto_timer(State1).

%% Pad Initial packet to minimum 1200 bytes
pad_initial_packet(Packet) when byte_size(Packet) >= 1200 ->
    Packet;
pad_initial_packet(Packet) ->
    PadLen = 1200 - byte_size(Packet),
    <<Packet/binary, 0:PadLen/unit:8>>.

%% Pad payload if needed for header protection sampling.
%% Header protection requires a 16-byte sample from the encrypted payload.
%% The sample starts at offset max(0, 4 - PNLen) into the ciphertext.
%% With worst-case PNLen=1, we need at least 3 + 16 = 19 bytes of ciphertext.
%% Since AEAD adds a 16-byte tag, plaintext needs to be >= 3 bytes.
%% We pad to 4 bytes to be safe (using PADDING frames which are 0x00).
pad_for_header_protection(Payload) when byte_size(Payload) >= 4 ->
    Payload;
pad_for_header_protection(Payload) ->
    PadLen = 4 - byte_size(Payload),
    <<Payload/binary, 0:PadLen/unit:8>>.

%%====================================================================
%% Internal Functions - Packet Processing
%%====================================================================

%% Handle incoming packet (may be coalesced with multiple QUIC packets)
handle_packet(Data, State) ->
    handle_packet_loop(Data, State).

handle_packet_loop(<<>>, #state{role = client, socket = Socket} = State) ->
    %% No more data to process - re-enable socket for client connections only
    inet:setopts(Socket, [{active, once}]),
    State;
handle_packet_loop(<<>>, #state{role = server} = State) ->
    %% No more data to process - server socket managed by listener
    State;
handle_packet_loop(Data, State) ->
    case decode_and_decrypt_packet(Data, State) of
        {ok, Type, Frames, RemainingData, NewState} ->
            %% Process frames from this packet
            State1 = process_frames_noreenbl(Type, Frames, NewState),
            %% Send ACK if packet contained ack-eliciting frames
            State2 = maybe_send_ack(Type, Frames, State1),
            %% Continue with remaining coalesced packets
            handle_packet_loop(RemainingData, State2);
        {error, stateless_reset} ->
            %% RFC 9000 Section 10.3: Stateless reset received
            %% Immediately close the connection
            maybe_reenable_socket(State),
            State#state{close_reason = stateless_reset};
        {error, Reason} when Reason =:= padding_only;
                             Reason =:= empty_packet;
                             Reason =:= invalid_fixed_bit ->
            %% End of coalesced packets (padding or invalid trailing data)
            %% This is normal, just re-enable socket and return
            maybe_reenable_socket(State),
            State;
        {error, Reason} ->
            %% Log decryption failure for debugging
            error_logger:warning_msg("[QUIC ~p] Packet decode/decrypt failed: ~p, size=~p~n",
                                     [State#state.role, Reason, byte_size(Data)]),
            %% Re-enable socket
            maybe_reenable_socket(State),
            State
    end.

%% Re-enable socket for receiving - only for client connections.
%% Server connections use listener's socket which is managed by the listener.
maybe_reenable_socket(#state{role = client, socket = Socket}) ->
    inet:setopts(Socket, [{active, once}]);
maybe_reenable_socket(#state{role = server}) ->
    ok.

%% Decode and decrypt a packet
decode_and_decrypt_packet(Data, State) ->
    %% Check header form (first bit) and fixed bit (second bit)
    %% RFC 9000 Section 17.2/17.3: Fixed bit MUST be 1
    case Data of
        <<>> ->
            %% Empty remaining data, nothing to decode
            {error, empty_packet};
        <<0:8, _/binary>> ->
            %% First byte is 0x00 - this is padding (all zeros)
            %% Skip padding by treating as end of coalesced packets
            {error, padding_only};
        <<1:1, _:7, _/binary>> ->
            %% Long header (bit 7 = 1)
            decode_long_header_packet(Data, State);
        <<0:1, 1:1, _:6, _/binary>> ->
            %% Short header (bit 7 = 0, fixed bit 6 = 1) - valid
            decode_short_header_packet(Data, State);
        <<0:1, 0:1, _:6, _/binary>> ->
            %% Short header form but fixed bit = 0 - invalid, skip as padding
            error_logger:warning_msg("[QUIC] Invalid short header: fixed bit not set, first byte=~p~n",
                                     [binary:first(Data)]),
            {error, invalid_fixed_bit};
        _ ->
            {error, invalid_packet}
    end.

%% Decode long header packet (Initial, Handshake, etc.)
decode_long_header_packet(Data, State) ->
    %% Parse unprotected header to get DCID length
    <<FirstByte, Version:32, DCIDLen, Rest/binary>> = Data,
    <<DCID:DCIDLen/binary, SCIDLen, Rest2/binary>> = Rest,
    <<SCID:SCIDLen/binary, Rest3/binary>> = Rest2,

    Type = (FirstByte bsr 4) band 2#11,

    case Type of
        0 -> %% Initial
            decode_initial_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        1 -> %% 0-RTT
            decode_zero_rtt_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        2 -> %% Handshake
            decode_handshake_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        3 -> %% Retry (RFC 9000 Section 17.2.5)
            handle_retry_packet(Data, Version, SCID, Rest3, State);
        _ ->
            {error, unsupported_packet_type}
    end.

decode_initial_packet(FullPacket, FirstByte, _DCID, PeerSCID, Rest, State) ->
    #state{initial_keys = {ClientKeys, ServerKeys}, role = Role} = State,

    %% Select correct keys based on role:
    %% - Client receives from server -> use ServerKeys
    %% - Server receives from client -> use ClientKeys
    DecryptKeys = case Role of
        client -> ServerKeys;
        server -> ClientKeys
    end,

    %% Parse token and length
    {TokenLen, Rest2} = quic_varint:decode(Rest),
    <<_Token:TokenLen/binary, Rest3/binary>> = Rest2,
    {PayloadLen, Rest4} = quic_varint:decode(Rest3),

    %% Header ends here, payload starts
    HeaderLen = byte_size(FullPacket) - byte_size(Rest4),
    <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

    %% Update DCID from peer's SCID (their SCID becomes our DCID)
    %% - Client: update dcid to server's SCID
    %% - Server: update dcid to client's SCID
    State1 = case State#state.dcid of
        <<>> -> State#state{dcid = PeerSCID};  % First packet, set DCID
        _ when State#state.dcid =:= State#state.original_dcid ->
            State#state{dcid = PeerSCID};  % Client updates dcid after first server packet
        _ -> State  % Already updated
    end,

    %% Ensure we have enough data
    case byte_size(Payload) >= PayloadLen of
        true ->
            <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
            decrypt_packet(initial, Header, FirstByte, EncryptedPayload, RemainingData, DecryptKeys, State1);
        false ->
            {error, incomplete_packet}
    end.

decode_handshake_packet(FullPacket, FirstByte, _DCID, _SCID, Rest, State) ->
    case State#state.handshake_keys of
        undefined ->
            {error, no_handshake_keys};
        {ClientKeys, ServerKeys} ->
            %% Select correct keys based on role
            DecryptKeys = case State#state.role of
                client -> ServerKeys;
                server -> ClientKeys
            end,
            %% Parse length
            {PayloadLen, Rest2} = quic_varint:decode(Rest),
            HeaderLen = byte_size(FullPacket) - byte_size(Rest2),
            <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

            case byte_size(Payload) >= PayloadLen of
                true ->
                    <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
                    decrypt_packet(handshake, Header, FirstByte, EncryptedPayload, RemainingData, DecryptKeys, State);
                false ->
                    {error, incomplete_packet}
            end
    end.

%% Decode 0-RTT packet (RFC 9001 Section 5.3)
%% Server uses early keys derived from client's PSK
decode_zero_rtt_packet(_FullPacket, _FirstByte, _DCID, _SCID, _Rest, #state{role = client}) ->
    %% Clients don't receive 0-RTT packets
    {error, unexpected_zero_rtt};
decode_zero_rtt_packet(_FullPacket, _FirstByte, _DCID, _SCID, _Rest, #state{early_keys = undefined}) ->
    %% No early keys - can't decrypt 0-RTT
    {error, no_early_keys};
decode_zero_rtt_packet(FullPacket, FirstByte, _DCID, _SCID, Rest, #state{early_keys = {EarlyKeys, _}} = State) ->
    %% Parse length
    {PayloadLen, Rest2} = quic_varint:decode(Rest),
    HeaderLen = byte_size(FullPacket) - byte_size(Rest2),
    <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

    case byte_size(Payload) >= PayloadLen of
        true ->
            <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
            decrypt_packet(zero_rtt, Header, FirstByte, EncryptedPayload, RemainingData, EarlyKeys, State);
        false ->
            {error, incomplete_packet}
    end.

%% Handle Retry packet (RFC 9000 Section 8.1, RFC 9001 Section 5.8)
%% A client receives a Retry when the server requests address validation.
handle_retry_packet(_FullPacket, _Version, _ServerSCID, _Rest,
                    #state{role = server}) ->
    %% Servers don't receive Retry packets
    {error, unexpected_retry};
handle_retry_packet(_FullPacket, _Version, _ServerSCID, _Rest,
                    #state{retry_received = true}) ->
    %% RFC 9000 Section 17.2.5.2: MUST discard subsequent Retry packets
    {error, duplicate_retry};
handle_retry_packet(FullPacket, Version, ServerSCID, Rest,
                    #state{role = client, original_dcid = OriginalDCID} = State) ->
    %% Rest contains: Retry Token + Retry Integrity Tag (16 bytes at end)
    %% There's no length field, the entire remaining data is the token + tag
    RetryTokenAndTag = Rest,

    %% Verify the integrity tag (RFC 9001 Section 5.8)
    case quic_crypto:verify_retry_integrity_tag(OriginalDCID, FullPacket, Version) of
        true ->
            %% Extract the retry token (everything except last 16 bytes)
            TagLen = 16,
            case byte_size(RetryTokenAndTag) > TagLen of
                true ->
                    TokenLen = byte_size(RetryTokenAndTag) - TagLen,
                    <<RetryToken:TokenLen/binary, _IntegrityTag:TagLen/binary>> = RetryTokenAndTag,
                    handle_valid_retry(RetryToken, ServerSCID, State);
                false ->
                    {error, invalid_retry_token}
            end;
        false ->
            {error, retry_integrity_check_failed}
    end.

%% Process a valid Retry packet
handle_valid_retry(RetryToken, ServerSCID, State) ->
    %% RFC 9000 Section 8.1.2: Client MUST use the new SCID from the Retry
    %% as the DCID for subsequent packets
    State1 = State#state{
        dcid = ServerSCID,
        retry_token = RetryToken,
        retry_received = true
    },

    %% Regenerate initial keys with the NEW DCID (ServerSCID) and current version
    {ClientKeys, ServerKeys} = derive_initial_keys(ServerSCID, State1#state.version),
    State2 = State1#state{initial_keys = {ClientKeys, ServerKeys}},

    %% Reset crypto state for a fresh Initial
    State3 = State2#state{
        crypto_offset = #{initial => 0, handshake => 0, app => 0},
        tls_transcript = <<>>
    },

    %% Reset packet number space for Initial
    State4 = reset_initial_pn_space(State3),

    %% Resend the ClientHello using send_client_hello
    %% (the retry_token field is now set, so send_initial_packet will use it)
    State5 = send_client_hello(State4),

    %% Return state with retry info, no frames to process
    {ok, retry_handled, [], <<>>, State5}.

%% Reset the initial packet number space after a Retry
reset_initial_pn_space(State) ->
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
    State#state{pn_initial = PNSpace}.

%% Check if a packet is a stateless reset (RFC 9000 Section 10.3)
check_stateless_reset(Data, _State) when byte_size(Data) < 21 ->
    %% Packet too small to be a stateless reset
    {error, decryption_failed};
check_stateless_reset(Data, #state{peer_cid_pool = PeerCIDs} = _State) ->
    %% Extract the last 16 bytes as potential reset token
    DataSize = byte_size(Data),
    TokenOffset = DataSize - 16,
    <<_:TokenOffset/binary, PotentialToken:16/binary>> = Data,

    %% Check against known reset tokens from peer's CIDs
    case find_matching_reset_token(PotentialToken, PeerCIDs) of
        {ok, _CID} ->
            %% This is a stateless reset - signal connection termination
            {error, stateless_reset};
        not_found ->
            %% Not a stateless reset, just decryption failure
            {error, decryption_failed}
    end.

%% Find if a token matches any known stateless reset token
find_matching_reset_token(_Token, []) ->
    not_found;
find_matching_reset_token(Token, [#cid_entry{stateless_reset_token = Token, cid = CID} | _]) ->
    {ok, CID};
find_matching_reset_token(Token, [_ | Rest]) ->
    find_matching_reset_token(Token, Rest).

decode_short_header_packet(Data, State) ->
    case State#state.app_keys of
        undefined ->
            %% No app keys yet - check if this might be a stateless reset
            check_stateless_reset(Data, State);
        {ClientKeys, ServerKeys} ->
            %% Select correct keys based on role
            DecryptKeys = case State#state.role of
                client -> ServerKeys;
                server -> ClientKeys
            end,
            %% Short header: first byte + DCID (our SCID that peer uses as their DCID)
            %% Short header packets don't have length field, so they consume all remaining data
            DCIDLen = byte_size(State#state.scid),
            <<FirstByte, DCID:DCIDLen/binary, EncryptedPayload/binary>> = Data,
            Header = <<FirstByte, DCID/binary>>,
            %% No remaining data after short header packet
            case decrypt_app_packet(Header, EncryptedPayload, DecryptKeys, State) of
                {error, decryption_failed} ->
                    %% Decryption failed - check if this is a stateless reset
                    check_stateless_reset(Data, State);
                Result ->
                    Result
            end
    end.

%% Decrypt an application (1-RTT) packet with key phase handling
decrypt_app_packet(Header, EncryptedPayload, ServerKeys, State) ->
    #crypto_keys{hp = HP} = ServerKeys,

    %% Remove header protection using current keys
    PNOffset = byte_size(Header),
    case quic_aead:unprotect_header(HP, Header, EncryptedPayload, PNOffset) of
        {error, Reason} ->
            {error, {header_unprotect_failed, Reason}};
        {UnprotectedHeader, PNLen} ->
            decrypt_app_packet_continue(UnprotectedHeader, PNLen, EncryptedPayload, State)
    end.

decrypt_app_packet_continue(UnprotectedHeader, PNLen, EncryptedPayload, State) ->
    %% Extract the unprotected first byte to get key_phase
    <<UnprotectedFirstByte, _/binary>> = UnprotectedHeader,
    ReceivedKeyPhase = quic_packet:decode_short_key_phase(UnprotectedFirstByte),

    %% Select appropriate decryption keys based on key_phase
    {DecryptKeys, State1} = select_decrypt_keys(ReceivedKeyPhase, State),
    %% Select correct key based on role:
    %% - Server decrypts with ClientKeys (data from client)
    %% - Client decrypts with ServerKeys (data from server)
    PeerDecryptKeys = case State1#state.role of
        server -> element(1, DecryptKeys);  % ClientKeys
        client -> element(2, DecryptKeys)   % ServerKeys
    end,

    %% Extract truncated PN and reconstruct full PN (RFC 9000 Appendix A)
    UnprotHeaderLen = byte_size(UnprotectedHeader),
    <<_:((UnprotHeaderLen - PNLen) * 8), TruncatedPN:PNLen/unit:8>> = UnprotectedHeader,
    LargestRecv = get_largest_recv(app, State1),
    PN = reconstruct_pn(LargestRecv, TruncatedPN, PNLen),
    AAD = UnprotectedHeader,
    Ciphertext = binary:part(EncryptedPayload, PNLen, byte_size(EncryptedPayload) - PNLen),

    #crypto_keys{key = Key, iv = IV} = PeerDecryptKeys,
    case quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext) of
        {ok, Plaintext} ->
            case quic_frame:decode_all(Plaintext) of
                {ok, Frames} ->
                    State2 = record_received_pn(app, PN, State1),
                    NewState = update_last_activity(State2),
                    {ok, app, Frames, <<>>, NewState};
                {error, Reason} ->
                    {error, {frame_decode_error, Reason}}
            end;
        {error, bad_tag} ->
            {error, decryption_failed}
    end.

%% Decrypt a packet
%% RemainingData is the data after this packet (for coalesced packets)
decrypt_packet(Level, Header, _FirstByte, EncryptedPayload, RemainingData, Keys, State) ->
    #crypto_keys{key = Key, iv = IV, hp = HP} = Keys,

    %% Remove header protection
    %% unprotect_header returns UnprotectedHeader which includes the unprotected PN at the end
    PNOffset = byte_size(Header),
    case quic_aead:unprotect_header(HP, Header, EncryptedPayload, PNOffset) of
        {error, Reason} ->
            {error, {header_unprotect_failed, Reason}};
        {UnprotectedHeader, PNLen} ->
            decrypt_packet_continue(Level, UnprotectedHeader, PNLen, EncryptedPayload,
                                    RemainingData, Key, IV, State)
    end.

decrypt_packet_continue(Level, UnprotectedHeader, PNLen, EncryptedPayload, RemainingData, Key, IV, State) ->
    %% Extract truncated PN and reconstruct full PN (RFC 9000 Appendix A)
    UnprotHeaderLen = byte_size(UnprotectedHeader),
    <<_:((UnprotHeaderLen - PNLen) * 8), TruncatedPN:PNLen/unit:8>> = UnprotectedHeader,
    LargestRecv = get_largest_recv(Level, State),
    PN = reconstruct_pn(LargestRecv, TruncatedPN, PNLen),

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

process_frame(_Level, {ack, Ranges, AckDelay, ECN}, State) ->
    %% Process ACK - update loss detection and congestion control
    #state{loss_state = LossState, cc_state = CCState} = State,

    %% Convert Ranges list to the format expected by quic_loss
    %% Ranges is a list of {Start, End} tuples from largest to smallest
    case Ranges of
        [] ->
            State;
        [{LargestAcked, _} | _] ->
            %% Convert ranges to ACK frame format for quic_loss
            %% quic_loss expects {ack, LargestAcked, AckDelay, FirstRange, AckRanges}
            {FirstRange, RestRanges} = ranges_to_ack_format(Ranges),
            AckFrame = {ack, LargestAcked, AckDelay, FirstRange, RestRanges},

            Now = erlang:monotonic_time(millisecond),
            {NewLossState, AckedPackets, LostPackets} =
                quic_loss:on_ack_received(LossState, AckFrame, Now),

            %% Calculate total bytes acked and lost
            AckedBytes = lists:sum([P#sent_packet.size || P <- AckedPackets]),
            LostBytes = lists:sum([P#sent_packet.size || P <- LostPackets]),

            %% Update congestion control
            CCState1 = quic_cc:on_packets_acked(CCState, AckedBytes),
            CCState2 = quic_cc:on_packets_lost(CCState1, LostBytes),

            %% If there was loss, signal congestion event
            CCState3 = case LostPackets of
                [] ->
                    CCState2;
                [#sent_packet{time_sent = SentTime} | _] ->
                    quic_cc:on_congestion_event(CCState2, SentTime)
            end,

            %% Process ECN counts if present (RFC 9002 Section 7.1)
            CCState4 = process_ecn_counts(ECN, CCState3),

            %% Check for persistent congestion (RFC 9002 Section 7.6)
            CCState5 = check_persistent_congestion(LostPackets, NewLossState, CCState4),

            State1 = State#state{
                loss_state = NewLossState,
                cc_state = CCState5
            },

            %% Retransmit lost packets
            State2 = retransmit_lost_packets(LostPackets, State1),

            %% Reset PTO timer after ACK processing
            State3 = set_pto_timer(State2),

            %% Try to send queued data now that cwnd may have freed up
            process_send_queue(State3)
    end;

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

%% PATH_CHALLENGE: Peer is probing the path, respond with PATH_RESPONSE
process_frame(app, {path_challenge, ChallengeData}, State) ->
    %% Send PATH_RESPONSE with the same data
    ResponseFrame = quic_frame:encode({path_response, ChallengeData}),
    send_app_packet(ResponseFrame, State);

%% PATH_RESPONSE: Response to our PATH_CHALLENGE
process_frame(app, {path_response, ResponseData}, State) ->
    handle_path_response(ResponseData, State);

%% NEW_CONNECTION_ID: Peer is providing a new CID for us to use
process_frame(app, {new_connection_id, SeqNum, RetirePrior, CID, ResetToken}, State) ->
    case handle_new_connection_id(SeqNum, RetirePrior, CID, ResetToken, State) of
        {error, {connection_id_limit_error, _, _}} ->
            %% RFC 9000: Exceeding active_connection_id_limit is a protocol error
            State#state{close_reason = {protocol_violation, connection_id_limit_exceeded}};
        NewState ->
            NewState
    end;

%% RETIRE_CONNECTION_ID: Peer is retiring one of our CIDs
process_frame(app, {retire_connection_id, SeqNum}, State) ->
    handle_retire_connection_id(SeqNum, State);

process_frame(_Level, {connection_close, _Type, _Code, _FrameType, _Reason}, State) ->
    State#state{close_reason = connection_closed};

%% DATAGRAM frames (RFC 9221)
process_frame(app, {datagram, Data}, #state{owner = Owner, conn_ref = Ref} = State) ->
    Owner ! {quic, Ref, {datagram, Data}},
    State;
process_frame(app, {datagram_with_length, Data}, #state{owner = Owner, conn_ref = Ref} = State) ->
    Owner ! {quic, Ref, {datagram, Data}},
    State;

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

%% Server receives ClientHello
process_tls_message(_Level, ?TLS_CLIENT_HELLO, Body, OriginalMsg,
                    #state{role = server, tls_state = ?TLS_AWAITING_CLIENT_HELLO} = State) ->
    case quic_tls:parse_client_hello(Body) of
        {ok, #{random := _ClientRandom,
               key_share := KeyShareEntries,
               cipher_suites := CipherSuites,
               alpn_protocols := ClientALPN,
               transport_params := TP,
               session_id := SessionId} = ClientHelloInfo} ->
            %% Extract x25519 public key from key share entries
            ClientPubKey = extract_x25519_key(KeyShareEntries),
            %% Select cipher suite (prefer server's order)
            Cipher = select_cipher(CipherSuites),

            %% Check for PSK (0-RTT/resumption)
            PSKInfo = maps:get(pre_shared_key, ClientHelloInfo, undefined),
            WantsEarlyData = maps:get(early_data, ClientHelloInfo, false),

            %% For normal handshake, derive early secret from zero PSK
            %% PSK-based resumption with full 0-RTT support requires additional changes
            %% to skip Certificate/CertificateVerify - implementing basic 0-RTT decryption only
            HashLen0 = case Cipher of aes_256_gcm -> 48; _ -> 32 end,
            ZeroPSK = <<0:HashLen0/unit:8>>,

            %% Check if we can derive early keys for 0-RTT decryption
            {EarlyKeys, EarlySecret} = case PSKInfo of
                #{identities := [{Identity, _Age}], binders := [_Binder]} when WantsEarlyData ->
                    %% Try to validate PSK for 0-RTT only (not full PSK resumption)
                    case validate_psk(Identity, Cipher, OriginalMsg, State) of
                        {ok, PSK, ResumptionSecret} ->
                            %% Derive early keys for 0-RTT decryption
                            ES = quic_crypto:derive_early_secret(Cipher, PSK),
                            ClientHelloHash = quic_crypto:transcript_hash(Cipher, OriginalMsg),
                            ETS = quic_crypto:derive_client_early_traffic_secret(Cipher, ES, ClientHelloHash),
                            {Key, IV, HP} = quic_keys:derive_keys(ETS, Cipher),
                            EK = #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher},
                            %% Still use zero PSK for handshake to keep Certificate flow
                            {{EK, ResumptionSecret}, quic_crypto:derive_early_secret(Cipher, ZeroPSK)};
                        error ->
                            {undefined, quic_crypto:derive_early_secret(Cipher, ZeroPSK)}
                    end;
                _ ->
                    {undefined, quic_crypto:derive_early_secret(Cipher, ZeroPSK)}
            end,

            %% Generate server key pair
            {ServerPubKey, ServerPrivKey} = quic_crypto:generate_key_pair(x25519),

            %% Compute shared secret
            SharedSecret = quic_crypto:compute_shared_secret(
                x25519, ServerPrivKey, ClientPubKey),

            %% Negotiate ALPN
            ALPN = negotiate_alpn(ClientALPN, State#state.alpn_list),

            %% Build ServerHello
            {ServerHello, _ServerPrivKey2} = quic_tls:build_server_hello(#{
                cipher => Cipher,
                key_pair => {ServerPubKey, ServerPrivKey},
                session_id => SessionId
            }),

            %% Update transcript with ClientHello
            Transcript0 = <<OriginalMsg/binary>>,
            %% Add ServerHello to transcript
            Transcript = <<Transcript0/binary, ServerHello/binary>>,
            TranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),

            %% Derive handshake secrets using already computed early secret
            HandshakeSecret = quic_crypto:derive_handshake_secret(Cipher, EarlySecret, SharedSecret),

            ClientHsSecret = quic_crypto:derive_client_handshake_secret(Cipher, HandshakeSecret, TranscriptHash),
            ServerHsSecret = quic_crypto:derive_server_handshake_secret(Cipher, HandshakeSecret, TranscriptHash),

            %% Derive handshake keys
            {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientHsSecret, Cipher),
            {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerHsSecret, Cipher),

            ClientHsKeys = #crypto_keys{key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher},
            ServerHsKeys = #crypto_keys{key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher},

            %% Update DCID from ClientHello SCID
            %% quic_tls decodes the initial_source_connection_id param as initial_scid
            ClientSCID = maps:get(initial_scid, TP, <<>>),

            State0 = State#state{
                dcid = ClientSCID,
                tls_state = ?TLS_AWAITING_CLIENT_FINISHED,
                tls_transcript = Transcript,
                tls_private_key = ServerPrivKey,
                handshake_secret = HandshakeSecret,
                client_hs_secret = ClientHsSecret,
                server_hs_secret = ServerHsSecret,
                handshake_keys = {ClientHsKeys, ServerHsKeys},
                alpn = ALPN,
                early_keys = EarlyKeys,
                early_data_accepted = (EarlyKeys =/= undefined andalso WantsEarlyData)
            },
            %% Apply peer transport params (extracts active_connection_id_limit)
            State1 = apply_peer_transport_params(TP, State0),

            %% Send ServerHello in Initial packet
            State2 = send_server_hello(ServerHello, State1),

            %% Send EncryptedExtensions, Certificate, CertificateVerify, Finished in Handshake packet
            send_server_handshake_flight(Cipher, TranscriptHash, State2);

        {error, Reason} ->
            error_logger:error_msg("[QUIC server] ClientHello parsing failed: ~p~n", [Reason]),
            State
    end;

%% Client receives ServerHello
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
            State0 = State#state{
                tls_state = ?TLS_AWAITING_CERT,
                tls_transcript = Transcript,
                alpn = Alpn
            },
            %% Apply peer transport params (extracts active_connection_id_limit)
            apply_peer_transport_params(TP, State0);
        _ ->
            State#state{
                tls_state = ?TLS_AWAITING_CERT,
                tls_transcript = Transcript
            }
    end;

process_tls_message(_Level, ?TLS_CERTIFICATE, Body, OriginalMsg, State) ->
    %% Update transcript (we don't verify certs if verify = false)
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    %% Parse and store peer certificate
    {PeerCert, PeerCertChain} = case quic_tls:parse_certificate(Body) of
        {ok, #{certificates := [First | Rest]}} ->
            {First, Rest};
        {ok, #{certificates := []}} ->
            {undefined, []};
        {error, _} ->
            {undefined, []}
    end,
    State#state{
        tls_state = ?TLS_AWAITING_CERT_VERIFY,
        tls_transcript = Transcript,
        peer_cert = PeerCert,
        peer_cert_chain = PeerCertChain
    };

process_tls_message(_Level, ?TLS_CERTIFICATE_VERIFY, _Body, OriginalMsg, State) ->
    %% Update transcript
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_state = ?TLS_AWAITING_FINISHED,
        tls_transcript = Transcript
    };

%% Client receives server's Finished
process_tls_message(_Level, ?TLS_FINISHED, Body, OriginalMsg,
                    #state{role = client, tls_state = ?TLS_AWAITING_FINISHED} = State) ->
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

                    %% Initialize key update state with app secrets for future key updates
                    KeyState = #key_update_state{
                        current_phase = 0,
                        current_keys = {ClientAppKeys, ServerAppKeys},
                        prev_keys = undefined,
                        client_app_secret = ClientAppSecret,
                        server_app_secret = ServerAppSecret,
                        update_state = idle
                    },

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
                        app_keys = {ClientAppKeys, ServerAppKeys},
                        key_state = KeyState
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

%% Server receives client's Finished
process_tls_message(_Level, ?TLS_FINISHED, Body, OriginalMsg,
                    #state{role = server, tls_state = ?TLS_AWAITING_CLIENT_FINISHED} = State) ->
    {ClientHsKeys, _} = State#state.handshake_keys,
    Cipher = ClientHsKeys#crypto_keys.cipher,

    case quic_tls:parse_finished(Body) of
        {ok, VerifyData} ->
            %% Verify client's Finished using client handshake secret
            TranscriptHash = quic_crypto:transcript_hash(Cipher, State#state.tls_transcript),
            case quic_tls:verify_finished(VerifyData, State#state.client_hs_secret, TranscriptHash, Cipher) of
                true ->
                    %% Update transcript with client Finished
                    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,

                    %% Derive resumption_master_secret (RFC 8446 Section 7.1)
                    %% resumption_master_secret = Derive-Secret(master_secret, "res master",
                    %%                                          ClientHello..client Finished)
                    FinalTranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),
                    ResumptionSecret = quic_ticket:derive_resumption_secret(
                        Cipher, State#state.master_secret, FinalTranscriptHash, <<>>),

                    %% Application keys are already derived when server sent its Finished
                    %% Mark handshake as complete
                    State1 = State#state{
                        tls_state = ?TLS_HANDSHAKE_COMPLETE,
                        tls_transcript = Transcript,
                        resumption_secret = ResumptionSecret
                    },

                    %% Send HANDSHAKE_DONE frame to client
                    State2 = send_handshake_done(State1),

                    %% Send NewSessionTicket to enable session resumption
                    send_new_session_ticket(State2);
                false ->
                    error_logger:info_msg("[QUIC] Client Finished verification failed~n", []),
                    State
            end;
        {error, _} ->
            State
    end;

%% Client receives NewSessionTicket from server (post-handshake)
%% RFC 8446 Section 4.6.1
process_tls_message(_Level, ?TLS_NEW_SESSION_TICKET, Body, _OriginalMsg,
                    #state{role = client, tls_state = ?TLS_HANDSHAKE_COMPLETE,
                           server_name = ServerName, alpn = ALPN,
                           master_secret = MasterSecret,
                           tls_transcript = Transcript,
                           handshake_keys = {ClientHsKeys, _}} = State) ->
    case quic_ticket:parse_new_session_ticket(Body) of
        {ok, #{lifetime := Lifetime, age_add := AgeAdd, nonce := Nonce,
               ticket := TicketData, max_early_data := MaxEarlyData}} ->
            Cipher = ClientHsKeys#crypto_keys.cipher,

            %% Derive resumption_master_secret from master secret
            %% The transcript should include client Finished
            FinalTranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),
            ResumptionSecret = quic_ticket:derive_resumption_secret(
                Cipher, MasterSecret, FinalTranscriptHash, <<>>),

            %% Create session ticket record
            Ticket = #session_ticket{
                server_name = case ServerName of
                    undefined -> <<"">>;
                    Name -> Name
                end,
                ticket = TicketData,
                lifetime = Lifetime,
                age_add = AgeAdd,
                nonce = Nonce,
                resumption_secret = ResumptionSecret,
                max_early_data = MaxEarlyData,
                received_at = erlang:system_time(second),
                cipher = Cipher,
                alpn = ALPN
            },

            %% Store ticket
            TicketKey = case ServerName of
                undefined -> <<"">>;
                SN -> SN
            end,
            TicketStore = quic_ticket:store_ticket(
                TicketKey, Ticket, State#state.ticket_store),

            %% Notify owner about the new ticket
            #state{owner = Owner, conn_ref = Ref} = State,
            Owner ! {quic, Ref, {session_ticket, Ticket}},

            State#state{
                ticket_store = TicketStore,
                resumption_secret = ResumptionSecret
            };
        {error, _Reason} ->
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
                recv_buffer = #{},  %% Map for out-of-order reassembly
                final_size = undefined
            }
    end,

    %% Store data in buffer at its offset (handles duplicates gracefully)
    RecvBuffer = case Stream#stream_state.recv_buffer of
        B when is_map(B) -> B;
        _ -> #{}  %% Upgrade old binary buffer format
    end,
    UpdatedBuffer = maps:put(Offset, Data, RecvBuffer),

    %% Track FIN position if received
    FinalSize = case Fin of
        true -> Offset + byte_size(Data);
        false -> Stream#stream_state.final_size
    end,

    %% Extract contiguous data starting from recv_offset and deliver it
    CurrentOffset = Stream#stream_state.recv_offset,
    {DeliverData, NewRecvOffset, NewBuffer} = extract_contiguous_data(UpdatedBuffer, CurrentOffset),

    %% Determine if we should deliver FIN (all data up to FIN has been delivered)
    DeliverFin = FinalSize =/= undefined andalso NewRecvOffset >= FinalSize,

    %% Deliver contiguous data to owner (may be empty if out-of-order)
    case DeliverData of
        <<>> ->
            ok;  %% No contiguous data to deliver yet
        _ ->
            Owner ! {quic, Ref, {stream_data, StreamId, DeliverData, DeliverFin}}
    end,

    NewStream = Stream#stream_state{
        recv_offset = NewRecvOffset,
        recv_fin = DeliverFin,
        recv_buffer = NewBuffer,
        final_size = FinalSize
    },

    %% Track connection-level data received (RFC 9000 Section 4.1)
    DataSize = byte_size(Data),
    NewDataReceived = State#state.data_received + DataSize,
    State1 = State#state{
        streams = maps:put(StreamId, NewStream, Streams),
        data_received = NewDataReceived
    },

    %% Check if we need to send MAX_STREAM_DATA to allow more data
    %% Send when we've consumed more than half our advertised limit
    RecvMaxData = Stream#stream_state.recv_max_data,
    State2 = case NewRecvOffset > (RecvMaxData div 2) of
        true ->
            %% Double the limit and send MAX_STREAM_DATA
            NewMaxStreamData = RecvMaxData * 2,
            UpdatedStream = NewStream#stream_state{recv_max_data = NewMaxStreamData},
            MaxStreamDataFrame = quic_frame:encode({max_stream_data, StreamId, NewMaxStreamData}),
            State1a = State1#state{streams = maps:put(StreamId, UpdatedStream, Streams)},
            send_app_packet(MaxStreamDataFrame, State1a);
        false ->
            State1
    end,

    %% Check if we need to send MAX_DATA for connection-level flow control
    %% Send when we've consumed more than 50% of our advertised connection window
    MaxDataLocal = State2#state.max_data_local,
    State3 = case NewDataReceived > (MaxDataLocal div 2) of
        true ->
            %% Extend the connection-level window and send MAX_DATA
            NewMaxData = NewDataReceived + MaxDataLocal,
            MaxDataFrame = quic_frame:encode({max_data, NewMaxData}),
            State2a = send_app_packet(MaxDataFrame, State2),
            State2a#state{max_data_local = NewMaxData};
        false ->
            State2
    end,

    %% ACK is sent at packet level by maybe_send_ack
    State3.

%% Extract contiguous data from buffer starting at Offset
%% Returns {Data, NewOffset, UpdatedBuffer}
extract_contiguous_data(Buffer, Offset) ->
    extract_contiguous_data(Buffer, Offset, []).

extract_contiguous_data(Buffer, Offset, Acc) ->
    case maps:take(Offset, Buffer) of
        {Data, NewBuffer} ->
            %% Found data at this offset, continue looking for next chunk
            NextOffset = Offset + byte_size(Data),
            extract_contiguous_data(NewBuffer, NextOffset, [Data | Acc]);
        error ->
            %% No data at this offset (gap in stream)
            DeliveredData = iolist_to_binary(lists:reverse(Acc)),
            {DeliveredData, Offset, Buffer}
    end.

%%====================================================================
%% Internal Functions - Helpers
%%====================================================================

%% Send ACK if packet contained any ack-eliciting frames.
%% Per RFC 9221 Section 5.2: Receivers SHOULD support delaying ACK frames
%% for packets that only contain DATAGRAM frames.
maybe_send_ack(app, Frames, State) ->
    case contains_ack_eliciting_frames(Frames) of
        true ->
            case should_delay_ack(Frames) of
                true ->
                    %% Delay ACK for datagram-only packets (up to max_ack_delay)
                    schedule_delayed_ack(app, State);
                false ->
                    send_app_ack(State)
            end;
        false ->
            State
    end;
maybe_send_ack(handshake, Frames, State) ->
    case contains_ack_eliciting_frames(Frames) of
        true -> send_handshake_ack(State);
        false -> State
    end;
maybe_send_ack(initial, Frames, State) ->
    case contains_ack_eliciting_frames(Frames) of
        true -> send_initial_ack(State);
        false -> State
    end;
maybe_send_ack(_, _, State) ->
    State.

%% Per RFC 9221 Section 5.2: Delay ACKs for packets containing only
%% non-retransmittable ack-eliciting frames (like DATAGRAM).
should_delay_ack(Frames) ->
    AckEliciting = [F || F <- Frames, is_ack_eliciting_frame(F)],
    Retransmittable = quic_loss:retransmittable_frames(AckEliciting),
    %% If all ack-eliciting frames are non-retransmittable, delay ACK
    Retransmittable =:= [].

%% Schedule a delayed ACK (up to max_ack_delay)
schedule_delayed_ack(app, State) ->
    %% Use max_ack_delay from transport params (default 25ms)
    MaxAckDelay = maps:get(max_ack_delay, State#state.transport_params, 25),
    %% Schedule ACK timer if not already set
    case get(ack_timer) of
        undefined ->
            TimerRef = erlang:send_after(MaxAckDelay, self(), {send_delayed_ack, app}),
            put(ack_timer, TimerRef),
            State;
        _ ->
            %% Timer already set, don't reschedule
            State
    end.

%% Check if any frame in the list is ack-eliciting
contains_ack_eliciting_frames([]) -> false;
contains_ack_eliciting_frames([Frame | Rest]) ->
    case is_ack_eliciting_frame(Frame) of
        true -> true;
        false -> contains_ack_eliciting_frames(Rest)
    end.

%% Check if a decoded frame is ack-eliciting
%% Per RFC 9002: ACK, PADDING, and CONNECTION_CLOSE are not ack-eliciting
is_ack_eliciting_frame(padding) -> false;
is_ack_eliciting_frame({ack, _, _, _}) -> false;
is_ack_eliciting_frame({connection_close, _, _, _, _}) -> false;
is_ack_eliciting_frame(_) -> true.

%% Check if a payload contains ack-eliciting frames
%% ACK and PADDING are not ack-eliciting, everything else is
is_ack_eliciting_payload(Payload) when is_binary(Payload) ->
    %% For encoded frames, check the first byte (frame type)
    case Payload of
        <<16#00, _/binary>> -> false;  % PADDING
        <<16#02, _/binary>> -> false;  % ACK
        <<16#03, _/binary>> -> false;  % ACK_ECN
        <<>> -> false;
        _ -> true
    end.

%% Convert ACK ranges from quic_frame format to quic_loss format
%% Input from quic_frame: [{LargestAcked, FirstRange} | [{Gap, Range}, ...]]
%% Output for quic_loss: {FirstRange, [{Gap, Range}, ...]}
ranges_to_ack_format([{_LargestAcked, FirstRange} | RestRanges]) ->
    {FirstRange, RestRanges}.

%% Process ECN counts from ACK frame (RFC 9002 Section 7.1)
%% ECN-CE indicates network congestion experienced
process_ecn_counts(undefined, CCState) ->
    %% No ECN information in this ACK
    CCState;
process_ecn_counts({_ECT0, _ECT1, ECNCE}, CCState) ->
    %% RFC 9002: An increase in ECN-CE count triggers congestion response
    quic_cc:on_ecn_ce(CCState, ECNCE).

%% Check for persistent congestion (RFC 9002 Section 7.6)
%% If lost packets span more than PTO * 3, reset to minimum window
check_persistent_congestion([], _LossState, CCState) ->
    CCState;
check_persistent_congestion(LostPackets, LossState, CCState) ->
    %% Extract packet number and time sent from lost packets
    LostInfo = [{P#sent_packet.pn, P#sent_packet.time_sent} || P <- LostPackets],
    PTO = quic_loss:get_pto(LossState),
    case quic_cc:detect_persistent_congestion(LostInfo, PTO, CCState) of
        true ->
            quic_cc:on_persistent_congestion(CCState);
        false ->
            CCState
    end.

%% Generate a connection ID
%% Uses LB config if available, otherwise random 8 bytes
generate_connection_id() ->
    crypto:strong_rand_bytes(8).

generate_connection_id(undefined) ->
    crypto:strong_rand_bytes(8);
generate_connection_id(#cid_config{} = Config) ->
    quic_lb:generate_cid(Config).

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
    derive_initial_keys(DCID, ?QUIC_VERSION_1).

%% Derive initial encryption keys with specific QUIC version
%% Version determines which salt to use (v1 vs v2)
derive_initial_keys(DCID, Version) ->
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID, Version),
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID, Version),
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

%% Select signature algorithm based on private key type
select_signature_algorithm({'ECPrivateKey', _, _, {namedCurve, {1,2,840,10045,3,1,7}}, _, _}) ->
    %% secp256r1 / P-256
    ?SIG_ECDSA_SECP256R1_SHA256;
select_signature_algorithm({'ECPrivateKey', _, _, {namedCurve, {1,3,132,0,34}}, _, _}) ->
    %% secp384r1 / P-384
    ?SIG_ECDSA_SECP384R1_SHA384;
select_signature_algorithm({'ECPrivateKey', _, _, _, _, _}) ->
    %% Default EC to P-256
    ?SIG_ECDSA_SECP256R1_SHA256;
select_signature_algorithm({'RSAPrivateKey', _, _, _, _, _, _, _, _, _, _}) ->
    ?SIG_RSA_PSS_RSAE_SHA256;
select_signature_algorithm(_) ->
    %% Default to RSA PSS
    ?SIG_RSA_PSS_RSAE_SHA256.

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

%% Get largest received PN for a given encryption level
get_largest_recv(initial, State) ->
    (State#state.pn_initial)#pn_space.largest_recv;
get_largest_recv(handshake, State) ->
    (State#state.pn_handshake)#pn_space.largest_recv;
get_largest_recv(app, State) ->
    (State#state.pn_app)#pn_space.largest_recv.

%% RFC 9000 Appendix A: Packet Number Reconstruction
%% Reconstructs the full packet number from a truncated value
reconstruct_pn(LargestPN, TruncatedPN, PNLen) ->
    PNBits = PNLen * 8,
    PNWin = 1 bsl PNBits,
    PNHWin = PNWin bsr 1,
    PNMask = PNWin - 1,
    ExpectedPN = case LargestPN of
        undefined -> 0;
        _ -> LargestPN + 1
    end,
    CandidatePN = (ExpectedPN band (bnot PNMask)) bor TruncatedPN,
    if
        CandidatePN =< ExpectedPN - PNHWin, CandidatePN < (1 bsl 62) - PNWin ->
            CandidatePN + PNWin;
        CandidatePN > ExpectedPN + PNHWin, CandidatePN >= PNWin ->
            CandidatePN - PNWin;
        true ->
            CandidatePN
    end.

update_pn_space_recv(PN, PNSpace) ->
    #pn_space{largest_recv = LargestRecv, ack_ranges = Ranges} = PNSpace,
    NewLargest = case LargestRecv of
        undefined -> PN;
        L when PN > L -> PN;
        L -> L
    end,
    %% Add to ack_ranges maintaining descending order and merging adjacent ranges
    NewRanges = add_to_ack_ranges(PN, Ranges),
    PNSpace#pn_space{
        largest_recv = NewLargest,
        recv_time = erlang:monotonic_time(millisecond),
        ack_ranges = NewRanges
    }.

%% Add a packet number to ACK ranges, maintaining descending order by Start
%% and merging adjacent/overlapping ranges
add_to_ack_ranges(PN, []) ->
    [{PN, PN}];
add_to_ack_ranges(PN, [{Start, End} | Rest]) when PN > End + 1 ->
    %% PN is above this range with a gap - insert new range before
    [{PN, PN}, {Start, End} | Rest];
add_to_ack_ranges(PN, [{Start, End} | Rest]) when PN =:= End + 1 ->
    %% PN extends this range upward
    [{Start, PN} | Rest];
add_to_ack_ranges(PN, [{Start, End} | Rest]) when PN >= Start, PN =< End ->
    %% PN already in this range (duplicate packet)
    [{Start, End} | Rest];
add_to_ack_ranges(PN, [{Start, End} | Rest]) when PN =:= Start - 1 ->
    %% PN extends this range downward - may need to merge with next range
    merge_ack_ranges([{PN, End} | Rest]);
add_to_ack_ranges(PN, [Range | Rest]) ->
    %% PN belongs somewhere in Rest
    [Range | add_to_ack_ranges(PN, Rest)].

%% Merge adjacent ranges after extending downward
merge_ack_ranges([{S1, E1}, {S2, E2} | Rest]) when E2 + 1 >= S1 ->
    %% Ranges overlap or are adjacent, merge them
    merge_ack_ranges([{S2, max(E1, E2)} | Rest]);
merge_ack_ranges(Ranges) ->
    Ranges.

%% Update last activity timestamp and reset idle timer
update_last_activity(State) ->
    State1 = State#state{last_activity = erlang:monotonic_time(millisecond)},
    set_idle_timer(State1).

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
                recv_buffer = #{},
                final_size = undefined
            },
            NewState = State#state{
                next_stream_id_bidi = NextId + 4,
                streams = maps:put(NextId, StreamState, Streams)
            },
            {ok, NextId, NewState}
    end.

%% Open a new unidirectional stream
do_open_unidirectional_stream(#state{next_stream_id_uni = NextId,
                                      max_streams_uni_remote = Max,
                                      streams = Streams} = State) ->
    StreamCount = maps:size(maps:filter(fun(Id, _) ->
        (Id band 16#03) =:= 2  % Client-initiated uni
    end, Streams)),
    if
        StreamCount >= Max ->
            {error, stream_limit};
        true ->
            %% Unidirectional streams are send-only for the initiator
            StreamState = #stream_state{
                id = NextId,
                state = open,
                send_offset = 0,
                send_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = 0,  % We don't receive on our uni streams
                recv_fin = true,    % No incoming data expected
                recv_buffer = #{},
                final_size = undefined
            },
            NewState = State#state{
                next_stream_id_uni = NextId + 4,
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

%% Send 0-RTT (early) data on a stream
%% RFC 9001 Section 4.6: 0-RTT data uses the early traffic secret
do_send_zero_rtt_data(StreamId, Data, Fin, #state{streams = Streams, early_keys = {EarlyKeys, _}} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            DataBin = iolist_to_binary(Data),
            Offset = StreamState#stream_state.send_offset,

            %% Build STREAM frame
            Frame = {stream, StreamId, Offset, DataBin, Fin},
            Payload = quic_frame:encode(Frame),

            %% Send as 0-RTT packet
            NewState = send_zero_rtt_packet(Payload, EarlyKeys, State),

            %% Update stream state and track early data sent
            NewStreamState = StreamState#stream_state{
                send_offset = Offset + byte_size(DataBin),
                send_fin = Fin
            },
            EarlyDataSent = State#state.early_data_sent + byte_size(DataBin),

            {ok, NewState#state{
                streams = maps:put(StreamId, NewStreamState, Streams),
                early_data_sent = EarlyDataSent
            }};
        error ->
            {error, unknown_stream}
    end.

%% Send a 0-RTT packet (long header, type 1)
%% RFC 9001 Section 5.3: 0-RTT packets use early traffic keys
send_zero_rtt_packet(Payload, EarlyKeys, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        socket = Socket,
        remote_addr = {IP, Port},
        version = Version,
        pn_app = PNSpace  % 0-RTT uses app PN space
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Long header for 0-RTT (type 1)
    %% First byte: 11XX XXXX where XX = type (01 for 0-RTT)
    FirstByte = 16#C0 bor (1 bsl 4) bor (PNLen - 1),  % 0xD0 base for 0-RTT

    %% Build long header
    DCIDLen = byte_size(DCID),
    SCIDLen = byte_size(SCID),
    Header = <<FirstByte, Version:32, DCIDLen, DCID/binary, SCIDLen, SCID/binary>>,

    %% Encode packet number and length
    PNBin = quic_packet:encode_pn(PN, PNLen),
    PayloadLen = byte_size(Payload) + 16,  % +16 for AEAD tag
    LengthEncoded = quic_varint:encode(PNLen + PayloadLen),

    %% AAD includes header with length but unprotected PN
    AAD = <<Header/binary, LengthEncoded/binary, PNBin/binary>>,

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Encrypt with early keys
    #crypto_keys{key = Key, iv = IV, hp = HP} = EarlyKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, PaddedPayload),

    %% Header protection
    PNOffset = byte_size(Header) + byte_size(LengthEncoded),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, LengthEncoded/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send packet
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    gen_udp:send(Socket, IP, Port, Packet),

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_app = NewPNSpace}.

%% Estimate packet overhead (header + AEAD tag + frame header)
-define(PACKET_OVERHEAD, 50).

%% Send a datagram (RFC 9221)
do_send_datagram(Data, #state{cc_state = CCState} = State) ->
    DataBin = iolist_to_binary(Data),
    PacketSize = byte_size(DataBin) + ?PACKET_OVERHEAD,

    case quic_cc:can_send(CCState, PacketSize) of
        true ->
            %% Use datagram_with_length for better framing
            Frame = {datagram_with_length, DataBin},
            Payload = quic_frame:encode(Frame),
            NewState = send_app_packet_internal(Payload, [Frame], State),
            {ok, NewState};
        false ->
            %% Datagrams are unreliable - just drop if cwnd is full
            {error, congestion_limited}
    end.

%% Send stream data in fragments that fit in packets
%% Respects congestion window by checking before each send
send_stream_data_fragmented(StreamId, Offset, Data, Fin, State) when byte_size(Data) =< ?MAX_STREAM_DATA_PER_PACKET ->
    %% Data fits in one packet - check congestion window
    #state{cc_state = CCState} = State,
    PacketSize = byte_size(Data) + ?PACKET_OVERHEAD,

    case quic_cc:can_send(CCState, PacketSize) of
        true ->
            Frame = {stream, StreamId, Offset, Data, Fin},
            Payload = quic_frame:encode(Frame),
            send_app_packet_internal(Payload, [Frame], State);
        false ->
            %% Queue the data for later sending when cwnd allows
            queue_stream_data(StreamId, Offset, Data, Fin, State)
    end;
send_stream_data_fragmented(StreamId, Offset, Data, Fin, State) ->
    %% Split data into chunks and send what we can
    #state{cc_state = CCState} = State,
    PacketSize = ?MAX_STREAM_DATA_PER_PACKET + ?PACKET_OVERHEAD,

    case quic_cc:can_send(CCState, PacketSize) of
        true ->
            <<Chunk:?MAX_STREAM_DATA_PER_PACKET/binary, Rest/binary>> = Data,
            Frame = {stream, StreamId, Offset, Chunk, false},
            Payload = quic_frame:encode(Frame),
            State1 = send_app_packet_internal(Payload, [Frame], State),
            NewOffset = Offset + ?MAX_STREAM_DATA_PER_PACKET,
            send_stream_data_fragmented(StreamId, NewOffset, Rest, Fin, State1);
        false ->
            %% Queue remaining data for later
            queue_stream_data(StreamId, Offset, Data, Fin, State)
    end.

%% Queue stream data when congestion window is full
%% Uses bucket-based priority queue for O(1) insert (RFC 9218)
queue_stream_data(StreamId, Offset, Data, Fin, #state{send_queue = PQ, streams = Streams} = State) ->
    Urgency = get_stream_urgency(StreamId, Streams),
    Entry = {stream_data, StreamId, Offset, Data, Fin},
    NewPQ = pqueue_in(Entry, Urgency, PQ),
    State#state{send_queue = NewPQ}.

%% Get stream urgency (default 3 if stream not found)
get_stream_urgency(StreamId, Streams) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream_state{urgency = Urgency}} -> Urgency;
        error -> 3  % Default urgency
    end.

%% Process send queue when congestion window frees up
%% Processes streams in priority order (lower urgency = higher priority)
process_send_queue(#state{send_queue = PQ} = State) ->
    case pqueue_out(PQ) of
        {empty, _} ->
            State;
        {{value, {stream_data, StreamId, Offset, Data, Fin}}, NewPQ} ->
            State1 = State#state{send_queue = NewPQ},
            State2 = send_stream_data_fragmented(StreamId, Offset, Data, Fin, State1),
            %% If data was queued again (cwnd still full), stop processing
            case pqueue_is_empty(State2#state.send_queue) of
                true -> State2;
                false ->
                    %% Check if we just queued more data (cwnd full)
                    case State2#state.send_queue =:= State1#state.send_queue of
                        true -> process_send_queue(State2);  % Keep processing
                        false -> State2  % New data queued, cwnd full
                    end
            end
    end.

%%--------------------------------------------------------------------
%% Priority Queue - Bucket-based implementation for urgency 0-7
%% O(1) insert, O(1) dequeue (8 buckets = constant)
%%--------------------------------------------------------------------

%% Insert entry at given urgency level (0-7)
pqueue_in(Entry, Urgency, PQ) when Urgency >= 0, Urgency =< 7 ->
    Bucket = element(Urgency + 1, PQ),
    NewBucket = queue:in(Entry, Bucket),
    setelement(Urgency + 1, PQ, NewBucket).

%% Remove and return highest priority (lowest urgency) entry
pqueue_out(PQ) ->
    pqueue_out(PQ, 0).

pqueue_out(_PQ, 8) ->
    {empty, empty_pqueue()};
pqueue_out(PQ, Urgency) ->
    Bucket = element(Urgency + 1, PQ),
    case queue:out(Bucket) of
        {empty, _} ->
            pqueue_out(PQ, Urgency + 1);
        {{value, Entry}, NewBucket} ->
            NewPQ = setelement(Urgency + 1, PQ, NewBucket),
            {{value, Entry}, NewPQ}
    end.

%% Peek at highest priority entry without removing
pqueue_peek(PQ) ->
    pqueue_peek(PQ, 0).

pqueue_peek(_PQ, 8) ->
    empty;
pqueue_peek(PQ, Urgency) ->
    Bucket = element(Urgency + 1, PQ),
    case queue:peek(Bucket) of
        empty ->
            pqueue_peek(PQ, Urgency + 1);
        {value, Entry} ->
            {value, Entry}
    end.

%% Check if priority queue is empty
pqueue_is_empty(PQ) ->
    pqueue_is_empty(PQ, 0).

pqueue_is_empty(_PQ, 8) ->
    true;
pqueue_is_empty(PQ, Urgency) ->
    case queue:is_empty(element(Urgency + 1, PQ)) of
        true -> pqueue_is_empty(PQ, Urgency + 1);
        false -> false
    end.

%% Create empty priority queue
empty_pqueue() ->
    {queue:new(), queue:new(), queue:new(), queue:new(),
     queue:new(), queue:new(), queue:new(), queue:new()}.

%% Send data that was queued before connection was established
send_pending_data([], State) ->
    State;
send_pending_data([{StreamId, Data, Fin} | Rest], State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            send_pending_data(Rest, NewState);
        {error, _Reason} ->
            %% Skip failed sends
            send_pending_data(Rest, State)
    end.

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

%% Set stream priority (RFC 9218)
do_set_stream_priority(StreamId, Urgency, Incremental, #state{streams = Streams} = State)
  when Urgency >= 0, Urgency =< 7, is_boolean(Incremental) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            NewStreamState = StreamState#stream_state{
                urgency = Urgency,
                incremental = Incremental
            },
            {ok, State#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            }};
        error ->
            {error, unknown_stream}
    end;
do_set_stream_priority(_StreamId, _Urgency, _Incremental, _State) ->
    {error, invalid_priority}.

%% Get stream priority (RFC 9218)
do_get_stream_priority(StreamId, #state{streams = Streams}) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            {ok, {StreamState#stream_state.urgency,
                  StreamState#stream_state.incremental}};
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

%%====================================================================
%% Retransmission
%%====================================================================

%% Retransmit frames from lost packets
retransmit_lost_packets([], State) ->
    State;
retransmit_lost_packets([#sent_packet{frames = Frames} | Rest], State) ->
    RetransmitFrames = quic_loss:retransmittable_frames(Frames),
    State1 = send_retransmit_frames(RetransmitFrames, State),
    retransmit_lost_packets(Rest, State1).

%% Send frames for retransmission
send_retransmit_frames([], State) ->
    State;
send_retransmit_frames(Frames, State) ->
    %% Encode all frames and send in a single packet
    Payload = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
    send_app_packet_internal(Payload, Frames, State).

%% Handle PTO timeout - send probe packet
handle_pto_timeout(#state{loss_state = LossState} = State) ->
    %% Increment PTO count
    NewLossState = quic_loss:on_pto_expired(LossState),
    State1 = State#state{loss_state = NewLossState},

    %% Send probe packet (retransmit oldest unacked or send PING)
    State2 = send_probe_packet(State1),

    %% Set new PTO timer
    set_pto_timer(State2).

%% Send a probe packet for PTO
send_probe_packet(State) ->
    case get_oldest_unacked_frames(State) of
        {ok, Frames} ->
            %% Retransmit oldest data as probe
            send_retransmit_frames(Frames, State);
        none ->
            %% No data to retransmit, send PING
            Payload = quic_frame:encode(ping),
            send_app_packet_internal(Payload, [ping], State)
    end.

%% Get frames from the oldest unacked packet for probe retransmission
get_oldest_unacked_frames(#state{loss_state = LossState}) ->
    SentPackets = quic_loss:sent_packets(LossState),
    case maps:size(SentPackets) of
        0 ->
            none;
        _ ->
            %% Find the oldest packet (lowest PN)
            {_MinPN, OldestPacket} = maps:fold(
                fun(PN, Packet, undefined) ->
                        {PN, Packet};
                   (PN, Packet, {MinPN, _}) when PN < MinPN ->
                        {PN, Packet};
                   (_PN, _Packet, Acc) ->
                        Acc
                end,
                undefined,
                SentPackets
            ),
            #sent_packet{frames = Frames} = OldestPacket,
            RetransmitFrames = quic_loss:retransmittable_frames(Frames),
            case RetransmitFrames of
                [] -> none;
                _ -> {ok, RetransmitFrames}
            end
    end.

%%====================================================================
%% PTO Timer Management
%%====================================================================

%% Set PTO timer based on current loss state
set_pto_timer(#state{loss_state = LossState, pto_timer = OldTimer} = State) ->
    cancel_timer(OldTimer),
    case quic_loss:bytes_in_flight(LossState) > 0 of
        true ->
            PTO = quic_loss:get_pto(LossState),
            TimerRef = erlang:send_after(PTO, self(), pto_timeout),
            State#state{pto_timer = TimerRef};
        false ->
            State#state{pto_timer = undefined}
    end.

%% Helper to cancel a timer reference
cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref).

%%====================================================================
%% Idle Timer Management (RFC 9000 §10.1)
%%====================================================================

%% Set idle timer based on idle_timeout configuration
set_idle_timer(#state{idle_timeout = 0} = State) ->
    State#state{idle_timer = undefined};
set_idle_timer(#state{idle_timeout = Timeout, idle_timer = OldTimer} = State) ->
    cancel_timer(OldTimer),
    TimerRef = erlang:send_after(Timeout, self(), idle_timeout),
    State#state{idle_timer = TimerRef}.

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

%%====================================================================
%% Key Update (RFC 9001 Section 6)
%%====================================================================

%% @doc Initiate a key update.
%% Derives new application secrets and keys, switches to the new key phase.
%% RFC 9001 Section 6.6: HP keys are NOT rotated during key updates.
initiate_key_update(#state{key_state = KeyState} = State) ->
    #key_update_state{
        current_phase = CurrentPhase,
        current_keys = CurrentKeys,
        client_app_secret = ClientSecret,
        server_app_secret = ServerSecret
    } = KeyState,

    %% Get cipher and HP keys from current keys (HP keys don't change)
    {OldClientKeys, OldServerKeys} = CurrentKeys,
    Cipher = OldClientKeys#crypto_keys.cipher,

    %% Derive new secrets using "quic ku" label
    {NewClientSecret, {NewClientKey, NewClientIV, _}} =
        quic_keys:derive_updated_keys(ClientSecret, Cipher),
    {NewServerSecret, {NewServerKey, NewServerIV, _}} =
        quic_keys:derive_updated_keys(ServerSecret, Cipher),

    %% Create new crypto_keys records (preserve HP keys per RFC 9001 Section 6.6)
    NewClientKeys = #crypto_keys{
        key = NewClientKey,
        iv = NewClientIV,
        hp = OldClientKeys#crypto_keys.hp,  % HP key unchanged
        cipher = Cipher
    },
    NewServerKeys = #crypto_keys{
        key = NewServerKey,
        iv = NewServerIV,
        hp = OldServerKeys#crypto_keys.hp,  % HP key unchanged
        cipher = Cipher
    },

    %% Toggle key phase
    NewPhase = 1 - CurrentPhase,

    %% Update key state
    NewKeyState = KeyState#key_update_state{
        current_phase = NewPhase,
        current_keys = {NewClientKeys, NewServerKeys},
        prev_keys = CurrentKeys,  % Keep old keys for decryption during transition
        client_app_secret = NewClientSecret,
        server_app_secret = NewServerSecret,
        update_state = initiated
    },

    State#state{
        app_keys = {NewClientKeys, NewServerKeys},
        key_state = NewKeyState
    }.

%% @doc Handle receiving a packet with a different key phase.
%% This is called when we receive a packet with a key phase that differs
%% from our current phase, indicating the peer has initiated a key update.
handle_peer_key_update(#state{key_state = KeyState} = State) ->
    #key_update_state{
        current_phase = CurrentPhase,
        current_keys = CurrentKeys,
        client_app_secret = ClientSecret,
        server_app_secret = ServerSecret,
        update_state = UpdateState
    } = KeyState,

    case UpdateState of
        initiated ->
            %% We initiated, peer responded - complete the update
            NewKeyState = KeyState#key_update_state{
                prev_keys = undefined,
                update_state = idle
            },
            State#state{key_state = NewKeyState};
        idle ->
            %% Peer initiated - we need to respond by deriving new keys
            %% RFC 9001 Section 6.6: HP keys are NOT rotated during key updates
            {OldClientKeys, OldServerKeys} = CurrentKeys,
            Cipher = OldClientKeys#crypto_keys.cipher,

            %% Derive new secrets
            {NewClientSecret, {NewClientKey, NewClientIV, _}} =
                quic_keys:derive_updated_keys(ClientSecret, Cipher),
            {NewServerSecret, {NewServerKey, NewServerIV, _}} =
                quic_keys:derive_updated_keys(ServerSecret, Cipher),

            NewClientKeys = #crypto_keys{
                key = NewClientKey,
                iv = NewClientIV,
                hp = OldClientKeys#crypto_keys.hp,  % HP key unchanged
                cipher = Cipher
            },
            NewServerKeys = #crypto_keys{
                key = NewServerKey,
                iv = NewServerIV,
                hp = OldServerKeys#crypto_keys.hp,  % HP key unchanged
                cipher = Cipher
            },

            NewPhase = 1 - CurrentPhase,
            NewKeyState = KeyState#key_update_state{
                current_phase = NewPhase,
                current_keys = {NewClientKeys, NewServerKeys},
                prev_keys = CurrentKeys,
                client_app_secret = NewClientSecret,
                server_app_secret = NewServerSecret,
                update_state = responding
            },
            State#state{
                app_keys = {NewClientKeys, NewServerKeys},
                key_state = NewKeyState
            };
        responding ->
            %% Already responding, just continue
            State
    end.

%% @doc Select the appropriate keys for decryption based on the received key phase.
%% Returns {Keys, State} where State may be updated if a key update is detected.
select_decrypt_keys(_ReceivedKeyPhase, #state{key_state = undefined} = State) ->
    %% No key state yet, use app_keys directly (should not happen in practice)
    {State#state.app_keys, State};
select_decrypt_keys(ReceivedKeyPhase, #state{key_state = KeyState} = State) ->
    #key_update_state{
        current_phase = CurrentPhase,
        current_keys = CurrentKeys,
        prev_keys = PrevKeys
    } = KeyState,

    case ReceivedKeyPhase of
        CurrentPhase ->
            %% Same phase, use current keys
            {CurrentKeys, State};
        _ ->
            %% Different phase - could be peer initiating update or using prev keys
            case PrevKeys of
                undefined ->
                    %% No previous keys, peer is initiating update
                    %% Handle the key update and decrypt with new keys
                    State1 = handle_peer_key_update(State),
                    {State1#state.key_state#key_update_state.current_keys, State1};
                _ ->
                    %% Try previous keys (during transition period)
                    {PrevKeys, State}
            end
    end.

%% @doc Get the current key phase for sending.
get_current_key_phase(#state{key_state = undefined}) -> 0;
get_current_key_phase(#state{key_state = KeyState}) ->
    KeyState#key_update_state.current_phase.

%%====================================================================
%% Connection Migration (RFC 9000 Section 9)
%%====================================================================

%% @doc Initiate path validation by sending PATH_CHALLENGE.
%% Returns updated state with the path in validating status.
-spec initiate_path_validation({inet:ip_address(), inet:port_number()}, #state{}) -> #state{}.
initiate_path_validation(RemoteAddr, State) ->
    %% Generate 8-byte random challenge data
    ChallengeData = crypto:strong_rand_bytes(8),

    %% Create or update path state
    PathState = #path_state{
        remote_addr = RemoteAddr,
        status = validating,
        challenge_data = ChallengeData,
        challenge_count = 1,
        bytes_sent = 0,
        bytes_received = 0
    },

    %% Add to alternative paths
    AltPaths = [PathState | State#state.alt_paths],

    %% Send PATH_CHALLENGE frame
    ChallengeFrame = quic_frame:encode({path_challenge, ChallengeData}),
    State1 = State#state{alt_paths = AltPaths},

    %% Note: In a full implementation, we'd send to the specific path
    %% For now, send on the current path (for testing)
    send_app_packet(ChallengeFrame, State1).

%% @doc Initiate path validation for server's preferred address (RFC 9000 Section 9.6).
%% Client validates the preferred address before migrating to it.
%% Prefers IPv6 over IPv4 when both are available.
-spec initiate_preferred_address_validation(#preferred_address{}, #state{}) -> #state{}.
initiate_preferred_address_validation(#preferred_address{cid = CID, stateless_reset_token = Token} = PA, State) ->
    %% RFC 9000 Section 9.6: Client MUST use the new CID when communicating on preferred path
    %% Add the new CID to peer's pool
    CIDEntry = #cid_entry{
        seq_num = 1,  % Preferred address CID has implicit sequence number 1
        cid = CID,
        stateless_reset_token = Token,
        status = active
    },
    State1 = State#state{
        peer_cid_pool = [CIDEntry | State#state.peer_cid_pool],
        preferred_address = PA
    },
    %% Choose address - prefer IPv6 over IPv4
    case select_preferred_addr(PA) of
        undefined ->
            %% No valid address to validate
            State1;
        RemoteAddr ->
            initiate_path_validation(RemoteAddr, State1)
    end.

%% Select the preferred address (IPv6 over IPv4)
select_preferred_addr(#preferred_address{ipv6_addr = IPv6, ipv6_port = IPv6Port})
  when IPv6 =/= undefined, IPv6Port =/= undefined ->
    {IPv6, IPv6Port};
select_preferred_addr(#preferred_address{ipv4_addr = IPv4, ipv4_port = IPv4Port})
  when IPv4 =/= undefined, IPv4Port =/= undefined ->
    {IPv4, IPv4Port};
select_preferred_addr(_) ->
    undefined.

%% @doc Rebind socket to a new local port (simulates network change).
%% Closes the old socket and creates a new one with a different ephemeral port.
-spec rebind_socket(gen_udp:socket()) -> {ok, gen_udp:socket()} | {error, term()}.
rebind_socket(OldSocket) ->
    %% Get current socket options
    {ok, [{active, Active}]} = inet:getopts(OldSocket, [active]),

    %% Close old socket
    gen_udp:close(OldSocket),

    %% Open new socket on a different ephemeral port
    case gen_udp:open(0, [binary, {active, Active}]) of
        {ok, NewSocket} ->
            {ok, NewSocket};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Handle PATH_RESPONSE frame.
%% Validates the response against pending challenges.
%% RFC 9000 Section 9.6: Auto-migrate to preferred address on validation success.
handle_path_response(ResponseData, State) ->
    %% Find the path with matching challenge data
    case find_path_by_challenge(ResponseData, State#state.alt_paths) of
        {ok, PathState, OtherPaths} ->
            %% Mark path as validated
            ValidatedPath = PathState#path_state{
                status = validated,
                challenge_data = undefined
            },
            State1 = State#state{alt_paths = [ValidatedPath | OtherPaths]},
            %% Check if this is a preferred address validation - auto-migrate
            maybe_migrate_to_preferred_address(ValidatedPath, State1);
        not_found ->
            %% Check current path (if we sent challenge on current path)
            case State#state.current_path of
                #path_state{challenge_data = ResponseData} = CurrentPath ->
                    ValidatedPath = CurrentPath#path_state{
                        status = validated,
                        challenge_data = undefined
                    },
                    State#state{current_path = ValidatedPath};
                _ ->
                    %% Unknown response, ignore
                    State
            end
    end.

%% @doc Auto-migrate to preferred address if the validated path matches.
%% RFC 9000 Section 9.6: Client SHOULD migrate to validated preferred address.
-spec maybe_migrate_to_preferred_address(#path_state{}, #state{}) -> #state{}.
maybe_migrate_to_preferred_address(ValidatedPath, #state{preferred_address = undefined} = State) ->
    %% No preferred address, just return
    State#state{alt_paths = [ValidatedPath | State#state.alt_paths]};
maybe_migrate_to_preferred_address(#path_state{remote_addr = RemoteAddr} = ValidatedPath,
                                   #state{preferred_address = PA} = State) ->
    %% Check if validated path matches the preferred address
    case is_preferred_address_path(RemoteAddr, PA) of
        true ->
            %% Migrate to preferred address using the new CID
            State1 = complete_migration(ValidatedPath, State),
            %% Switch to preferred address CID
            State2 = switch_to_preferred_cid(PA, State1),
            %% Clear the preferred_address field since migration is complete
            State2#state{preferred_address = undefined};
        false ->
            State
    end.

%% Check if remote address matches the preferred address
is_preferred_address_path({IPv4, Port}, #preferred_address{ipv4_addr = IPv4, ipv4_port = Port})
  when IPv4 =/= undefined ->
    true;
is_preferred_address_path({IPv6, Port}, #preferred_address{ipv6_addr = IPv6, ipv6_port = Port})
  when IPv6 =/= undefined ->
    true;
is_preferred_address_path(_, _) ->
    false.

%% Switch to using the CID from preferred_address
switch_to_preferred_cid(#preferred_address{cid = CID}, State) ->
    %% RFC 9000 Section 9.6: MUST use the new CID on the preferred address
    State#state{dcid = CID}.

%% Find a path by challenge data
find_path_by_challenge(_Data, []) ->
    not_found;
find_path_by_challenge(Data, [#path_state{challenge_data = Data} = Path | Rest]) ->
    {ok, Path, Rest};
find_path_by_challenge(Data, [Path | Rest]) ->
    case find_path_by_challenge(Data, Rest) of
        {ok, Found, Others} ->
            {ok, Found, [Path | Others]};
        not_found ->
            not_found
    end.

%% @doc Complete migration to a validated path.
%% Updates the current path and DCID if necessary.
-spec complete_migration(#path_state{}, #state{}) -> #state{}.
complete_migration(#path_state{status = validated} = NewPath, State) ->
    %% Update remote address
    State#state{
        remote_addr = NewPath#path_state.remote_addr,
        current_path = NewPath,
        alt_paths = lists:delete(NewPath, State#state.alt_paths)
    };
complete_migration(_, State) ->
    %% Can only migrate to validated paths
    State.

%% @doc Handle NEW_CONNECTION_ID frame from peer.
%% Adds the new CID to our pool of peer CIDs.
%% RFC 9000 Section 5.1.1: Peer must not exceed our active_connection_id_limit.
handle_new_connection_id(SeqNum, RetirePrior, CID, ResetToken, State) ->
    #state{peer_cid_pool = Pool, local_active_cid_limit = Limit} = State,

    %% Retire CIDs with seq < RetirePrior
    RetiredPool = lists:map(
        fun(#cid_entry{seq_num = S} = Entry) when S < RetirePrior ->
                Entry#cid_entry{status = retired};
           (Entry) ->
                Entry
        end, Pool),

    %% Add new CID entry
    NewEntry = #cid_entry{
        seq_num = SeqNum,
        cid = CID,
        stateless_reset_token = ResetToken,
        status = active
    },

    %% Check if already exists
    case lists:keyfind(SeqNum, #cid_entry.seq_num, RetiredPool) of
        false ->
            %% Add new entry
            NewPool = [NewEntry | RetiredPool],
            %% Count active CIDs after retirement
            ActiveCount = length([E || #cid_entry{status = active} = E <- NewPool]),
            %% RFC 9000: Peer must not exceed our limit
            case ActiveCount > Limit of
                true ->
                    %% Protocol violation - close connection
                    {error, {connection_id_limit_error, ActiveCount, Limit}};
                false ->
                    %% Send RETIRE_CONNECTION_ID for CIDs with seq < RetirePrior
                    State1 = retire_peer_cids(RetirePrior, State#state{peer_cid_pool = NewPool}),
                    State1
            end;
        _ ->
            %% Duplicate, ignore
            State#state{peer_cid_pool = RetiredPool}
    end.

%% Send RETIRE_CONNECTION_ID frames for CIDs that need to be retired
retire_peer_cids(_RetirePrior, State) ->
    %% In a full implementation, send RETIRE_CONNECTION_ID frames
    %% For now, just return state
    State.

%% @doc Apply peer transport parameters to connection state.
%% Extracts and stores the peer's active_connection_id_limit.
apply_peer_transport_params(TransportParams, State) ->
    %% Extract peer's active_connection_id_limit (default: 2 per RFC 9000)
    PeerLimit = maps:get(active_connection_id_limit, TransportParams, 2),
    State#state{
        transport_params = TransportParams,
        peer_active_cid_limit = PeerLimit
    }.

%% @doc Handle RETIRE_CONNECTION_ID frame from peer.
%% Marks the specified CID in our local pool as retired.
handle_retire_connection_id(SeqNum, State) ->
    #state{local_cid_pool = Pool} = State,
    NewPool = lists:map(
        fun(#cid_entry{seq_num = S} = Entry) when S =:= SeqNum ->
                Entry#cid_entry{status = retired};
           (Entry) ->
                Entry
        end, Pool),
    State#state{local_cid_pool = NewPool}.

