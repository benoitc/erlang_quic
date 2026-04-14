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
%%% {quic, Conn, {connected, Info}}         where Conn is the connection pid
%%% {quic, Conn, {stream_data, StreamId, Data, Fin}}
%%% {quic, Conn, {stream_opened, StreamId}}
%%% {quic, Conn, {closed, Reason}}
%%%

-module(quic_connection).

-behaviour(gen_statem).

-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("kernel/include/logger.hrl").
-define(QUIC_LOG_META, #{
    domain => [erlang_quic, connection], report_cb => fun quic_log:format_report/2
}).

%% Suppress warnings for helper functions prepared for future use
-compile([{nowarn_unused_function, [{send_handshake_ack, 1}, {contains_non_probing_frame, 1}]}]).

%% Dialyzer nowarn for functions prepared for future use and unreachable patterns
%% (code structure supports multiple ciphers/paths not yet exercised)
-dialyzer(
    {nowarn_function, [
        send_initial_ack/1,
        select_cipher/1
    ]}
).
-dialyzer([no_match]).

%% API
-export([
    start_link/4,
    start_link/5,
    connect/4,
    send_data/4,
    send_data_async/4,
    send_datagram/2,
    datagram_max_size/1,
    datagram_stats/1,
    open_stream/1,
    open_unidirectional_stream/1,
    close/2,
    close_stream/3,
    reset_stream/3,
    reset_stream_at/4,
    stop_sending/3,
    handle_timeout/1,
    handle_timeout/2,
    process/1,
    get_state/1,
    peername/1,
    sockname/1,
    peercert/1,
    set_owner/2,
    set_owner_sync/2,
    setopts/2,
    get_send_queue_info/1,
    %% Connection statistics (for liveness detection)
    get_stats/1,
    %% Peer transport parameters
    get_peer_transport_params/1,
    %% Transport-level PING (bypasses congestion control)
    send_ping/1,
    %% Key update (RFC 9001 Section 6)
    key_update/1,
    %% Connection migration (RFC 9000 Section 9)
    migrate/1,
    migrate/2,
    %% PMTU Discovery (RFC 8899)
    get_mtu/1,
    %% Server mode
    start_server/1,
    %% Stream prioritization (RFC 9218)
    set_stream_priority/4,
    get_stream_priority/2,
    %% Congestion control
    set_congestion_control/2,
    %% Stream deadlines
    set_stream_deadline/4,
    cancel_stream_deadline/2,
    get_stream_deadline/2,
    %% Connection ID management (RFC 9000 Section 5.1)
    issue_new_connection_ids/1
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
    convert_rest_ranges/2,
    check_send_queue_flow_control/4,
    test_check_flow_control/6,
    close_reason_to_code/1,
    %% Migration frame classification (RFC 9000 Section 9.1)
    is_probing_frame/1,
    contains_non_probing_frame/1,
    %% Migration notification testing
    test_complete_migration/3,
    %% Spin bit (RFC 9000 §17.4)
    update_spin_from_recv/3,
    short_header_first_byte/3,
    test_spin_state/1,
    test_spin_state_for/2,
    %% Stateless reset token derivation (RFC 9000 §10.3.2)
    generate_stateless_reset_token/2,
    test_state_with_secret/1,
    %% NEW_TOKEN frame dispatch (RFC 9000 §8.1.3)
    process_frame/3,
    test_state_for_role/1,
    test_close_reason/1
]).
-endif.

%% TLS handshake states (client)
-define(TLS_AWAITING_SERVER_HELLO, awaiting_server_hello).
-define(TLS_AWAITING_ENCRYPTED_EXT, awaiting_encrypted_extensions).
-define(TLS_AWAITING_CERT, awaiting_certificate).
-define(TLS_AWAITING_CERT_VERIFY, awaiting_certificate_verify).
-define(TLS_AWAITING_FINISHED, awaiting_finished).
-define(TLS_HANDSHAKE_COMPLETE, handshake_complete).

%% TLS handshake states (server)
-define(TLS_AWAITING_CLIENT_HELLO, awaiting_client_hello).
-define(TLS_AWAITING_CLIENT_CERT, awaiting_client_cert).
-define(TLS_AWAITING_CLIENT_CERT_VERIFY, awaiting_client_cert_verify).
-define(TLS_AWAITING_CLIENT_FINISHED, awaiting_client_finished).

%% TLS alert codes (RFC 8446 Section 6.2)
-define(TLS_ALERT_DECRYPT_ERROR, 51).

%% Max pending data entries before connection is established (prevents memory exhaustion)
-define(MAX_PENDING_DATA_ENTRIES, 1000).

%% Max send queue size in bytes (16 MB default) - prevents memory exhaustion from queued data
-define(MAX_SEND_QUEUE_BYTES, 16777216).

%% Max receive buffer size in bytes (32 MB total across all streams) - protects against malicious peers
-define(MAX_RECV_BUFFER_BYTES, 33554432).

%% Connection state record
-record(state, {
    %% Connection identity
    scid :: binary(),
    dcid :: binary(),
    original_dcid :: binary(),
    %% Retry handling (RFC 9000 Section 8.1)

    % Token from Retry packet for Initial resend
    retry_token = <<>> :: binary(),
    % Whether a Retry packet has been received
    retry_received = false :: boolean(),
    % SCID from Retry packet (for transport param validation)
    retry_scid :: binary() | undefined,
    role :: client | server,
    version = ?QUIC_VERSION_1 :: non_neg_integer(),

    %% Socket
    socket :: gen_udp:socket() | undefined,
    %% Dedicated send socket for server connections (SO_REUSEPORT)
    %% Allows each server connection to have its own batching state
    send_socket :: gen_udp:socket() | undefined,
    %% Socket state for batching (quic_socket abstraction)
    socket_state :: quic_socket:socket_state() | undefined,
    remote_addr :: {inet:ip_address(), inet:port_number()},
    local_addr :: {inet:ip_address(), inet:port_number()} | undefined,

    %% Owner process (receives {quic, Conn, Event} messages where Conn is pid())
    owner :: pid(),
    conn_ref :: reference(),

    %% Options
    server_name :: binary() | undefined,
    verify :: boolean(),

    %% Encryption keys per level
    initial_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    handshake_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    % Convenience accessor (= key_state.current_keys)
    app_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,

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
    %% Per-stream flow control limits (advertised in transport params)
    max_stream_data_bidi_local :: non_neg_integer(),
    max_stream_data_bidi_remote :: non_neg_integer(),
    max_stream_data_uni :: non_neg_integer(),
    %% Flow control auto-tuning state
    fc_last_stream_update :: integer() | undefined,
    fc_last_conn_update :: integer() | undefined,
    fc_max_receive_window :: non_neg_integer(),
    %% Cached max stream recv window (avoids O(n) scan for connection flow control)
    fc_max_stream_recv_window = ?DEFAULT_INITIAL_MAX_STREAM_DATA :: non_neg_integer(),

    %% Stream management
    streams = #{} :: #{non_neg_integer() => #stream_state{}},
    next_stream_id_bidi :: non_neg_integer(),
    next_stream_id_uni :: non_neg_integer(),
    max_streams_bidi_local :: non_neg_integer(),
    max_streams_bidi_remote :: non_neg_integer(),
    max_streams_uni_local :: non_neg_integer(),
    max_streams_uni_remote :: non_neg_integer(),
    %% RFC 9000 §4.6: peer-initiated streams already credited via
    %% MAX_STREAMS, tracked so we do not double-issue credit when state
    %% transitions are observed twice (e.g. recv-FIN then send-FIN).
    credited_peer_bidi = sets:new([{version, 2}]) :: sets:set(non_neg_integer()),
    credited_peer_uni = sets:new([{version, 2}]) :: sets:set(non_neg_integer()),

    %% Datagram support (RFC 9221)
    %% Local: our advertised max size (0 = disabled)
    max_datagram_frame_size_local = 0 :: non_neg_integer(),
    %% Remote: peer's advertised max size (0 = not supported)
    max_datagram_frame_size_remote = 0 :: non_neg_integer(),
    %% Bounded receive queue for DATAGRAM frames. `infinity' disables
    %% the cap entirely (default). When finite, we still push each
    %% datagram to the owner process, but we also drop the oldest entry
    %% in this queue when the limit is hit so that `datagram_stats/1'
    %% surfaces dropped counts for backpressure decisions.
    datagram_recv_queue_len = infinity :: non_neg_integer() | infinity,
    datagram_recv_queue = queue:new() :: queue:queue(binary()),
    datagram_recv_delivered = 0 :: non_neg_integer(),
    datagram_recv_dropped = 0 :: non_neg_integer(),
    datagram_sent = 0 :: non_neg_integer(),
    datagram_send_dropped = 0 :: non_neg_integer(),

    %% Latency spin bit (RFC 9000 §17.4). `spin_outgoing' is the bit
    %% we set on outbound 1-RTT packets; updated from `spin_recv' on
    %% receipt of a 1-RTT packet whose PN exceeds
    %% `spin_recv_largest_pn' so reordering doesn't flip the bit
    %% back. `spin_bit_enabled = false' opts out (always emit 0).
    spin_outgoing = 0 :: 0 | 1,
    spin_recv = 0 :: 0 | 1,
    spin_recv_largest_pn = -1 :: integer(),
    spin_bit_enabled = true :: boolean(),

    %% Server-wide secret used to HMAC stateless-reset tokens over a
    %% connection id (RFC 9000 §10.3.2). `undefined' preserves today's
    %% per-CID random-token fallback — acceptable for clients and for
    %% single-instance servers that don't need post-restart recovery.
    stateless_reset_secret = undefined :: binary() | undefined,

    %% RESET_STREAM_AT support (draft-ietf-quic-reliable-stream-reset-07)
    %% Local: whether we advertise support for RESET_STREAM_AT
    reset_stream_at_enabled = false :: boolean(),

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

    %% Keep-alive (RFC 9000 - PING frames for liveness)
    keep_alive_interval :: non_neg_integer() | disabled,
    keep_alive_timer :: reference() | undefined,

    %% Pacing (RFC 9002 Section 7.7)
    pacing_timer :: reference() | undefined,
    pacing_enabled = true :: boolean(),

    %% Pending data - priority queue with 8 buckets (one per urgency 0-7)
    %% Each bucket is a queue:queue() for FIFO within same priority
    send_queue = {
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new()
    } :: tuple(),
    %% Pre-connection pending sends (simple list, processed when connected)
    pending_data = [] :: [{non_neg_integer(), iodata(), boolean()}],

    %% Send queue byte tracking (prevents memory exhaustion)
    send_queue_bytes = 0 :: non_neg_integer(),
    %% Send queue version counter (for fast change detection)
    send_queue_version = 0 :: non_neg_integer(),

    %% Receive buffer byte tracking (protects against malicious peers)
    recv_buffer_bytes = 0 :: non_neg_integer(),

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

    %% Migration state machine (RFC 9000 Section 9)
    %% idle: no migration in progress
    %% validating_peer: server validating client's new address
    migration_state = idle :: idle | validating_peer,
    %% Path being validated when client sends from new address
    pending_peer_validation :: #path_state{} | undefined,
    %% Old path validation for anti-spoofing defense (RFC 9000 Section 9.3.2)
    %% When detecting apparent migration, probe both old and new paths
    old_path_validation :: #path_state{} | undefined,
    %% Timer reference for path validation timeout
    path_validation_timer :: reference() | undefined,
    %% Token for correlating path validation timeout messages
    %% Used to ignore stale timeouts from canceled validations
    path_validation_token :: reference() | undefined,
    %% Peer's disable_active_migration transport param (RFC 9000 Section 18.2)
    peer_disable_migration = false :: boolean(),
    %% Transient field: source address of the current packet being processed
    %% Set during packet processing, cleared after. Used to route PATH_RESPONSE
    %% to the address that sent the PATH_CHALLENGE (RFC 9000 Section 8.2.2).
    current_packet_source :: {inet:ip_address(), inet:port_number()} | undefined,
    %% Transient field: set to true when a non-probing frame is processed
    %% RFC 9000 Section 9.1: Only non-probing frames trigger migration
    has_non_probing_frame = false :: boolean(),

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

    %% Client certificate (for mutual TLS)
    client_cert :: binary() | undefined,
    client_cert_chain = [] :: [binary()],
    client_private_key :: term() | undefined,
    %% True if server sent CertificateRequest
    cert_request_received = false :: boolean(),

    %% Session resumption (RFC 8446 Section 4.6)
    resumption_secret :: binary() | undefined,
    % Default max 0-RTT data size
    max_early_data = 16384 :: non_neg_integer(),

    %% Client-side ticket storage for session resumption
    ticket_store = #{} :: quic_ticket:ticket_store(),

    %% 0-RTT / Early Data (RFC 9001 Section 4.6)

    % {Keys, EarlySecret}
    early_keys :: {#crypto_keys{}, binary()} | undefined,
    % Bytes of early data sent
    early_data_sent = 0 :: non_neg_integer(),
    % Server accepted early data
    early_data_accepted = false :: boolean(),

    %% QUIC-LB CID configuration (RFC 9312)
    cid_config :: #cid_config{} | undefined,

    %% Backpressure configuration (for distribution connections)
    %% Connection is congested when queue > cwnd * congestion_threshold
    congestion_threshold = 2 :: pos_integer(),

    %% Statistics - packet counts for liveness detection
    %% These count actual QUIC packets (not bytes), used by net_kernel getstat
    packets_received = 0 :: non_neg_integer(),
    packets_sent = 0 :: non_neg_integer(),

    %% Socket active mode - number of packets before socket goes passive
    %% Using {active, N} instead of {active, once} reduces inet:setopts overhead
    active_n = 100 :: pos_integer(),

    %% PMTU Discovery (RFC 8899)
    pmtu_state :: #pmtu_state{} | undefined,
    pmtu_probe_timer :: reference() | undefined,
    pmtu_raise_timer :: reference() | undefined,

    %% Timer batching dirty flags (reduce timer operations per packet)
    %% These are flushed after batch boundaries via flush_dirty_timers/1
    timer_dirty = false :: boolean(),
    pto_dirty = false :: boolean(),

    %% QLOG Tracing (draft-ietf-quic-qlog-quic-events)
    qlog_ctx :: #qlog_ctx{} | undefined
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start a QUIC connection process.
-spec start_link(
    binary() | inet:hostname() | inet:ip_address(),
    inet:port_number(),
    map(),
    pid()
) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner) ->
    start_link(Host, Port, Opts, Owner, undefined).

%% @doc Start a QUIC connection with optional pre-opened socket.
-spec start_link(
    binary() | inet:hostname() | inet:ip_address(),
    inet:port_number(),
    map(),
    pid(),
    gen_udp:socket() | undefined
) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner, Socket) ->
    gen_statem:start_link(?MODULE, [Host, Port, Opts, Owner, Socket], []).

%% @doc Initiate a connection to a QUIC server.
%% This is a convenience wrapper that starts the process and initiates handshake.
-spec connect(
    binary() | inet:hostname() | inet:ip_address(),
    inet:port_number(),
    map(),
    pid()
) -> {ok, reference(), pid()} | {error, term()}.
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

%% @doc Send data on a stream asynchronously.
%% This is faster than send_data/4 because it uses cast instead of call,
%% avoiding the round-trip latency. However, errors are silently dropped.
%% Use this for high-throughput scenarios where occasional dropped data is acceptable.
-spec send_data_async(pid(), non_neg_integer(), iodata(), boolean()) -> ok.
send_data_async(Conn, StreamId, Data, Fin) ->
    gen_statem:cast(Conn, {send_data_async, StreamId, Data, Fin}).

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

%% @doc Reset a stream with reliable delivery up to ReliableSize.
%% Data up to ReliableSize will be delivered before the reset takes effect.
%% Requires peer support via the reset_stream_at transport parameter.
-spec reset_stream_at(pid(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
reset_stream_at(Conn, StreamId, ErrorCode, ReliableSize) ->
    gen_statem:call(Conn, {reset_stream_at, StreamId, ErrorCode, ReliableSize}).

%% @doc Request peer to stop sending on a stream.
%% Sends a STOP_SENDING frame (RFC 9000 Section 19.5).
-spec stop_sending(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
stop_sending(Conn, StreamId, ErrorCode) ->
    gen_statem:call(Conn, {stop_sending, StreamId, ErrorCode}).

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

%% @doc Set new owner process (async).
-spec set_owner(pid(), pid()) -> ok.
set_owner(Conn, NewOwner) ->
    gen_statem:cast(Conn, {set_owner, NewOwner}).

%% @doc Set new owner process (synchronous).
%% Use this when you need to ensure ownership is transferred before continuing.
-spec set_owner_sync(pid(), pid()) -> ok.
set_owner_sync(Conn, NewOwner) ->
    gen_statem:call(Conn, {set_owner, NewOwner}).

%% @doc Send a datagram.
-spec send_datagram(pid(), iodata()) -> ok | {error, term()}.
send_datagram(Conn, Data) ->
    gen_statem:call(Conn, {send_datagram, Data}).

%% @doc Get maximum datagram payload size.
%% Returns 0 if peer doesn't support datagrams.
-spec datagram_max_size(pid()) -> non_neg_integer().
datagram_max_size(Conn) ->
    gen_statem:call(Conn, datagram_max_size).

-spec datagram_stats(pid()) ->
    #{
        delivered := non_neg_integer(),
        dropped_recv := non_neg_integer(),
        sent := non_neg_integer(),
        dropped_send := non_neg_integer()
    }.
datagram_stats(Conn) ->
    gen_statem:call(Conn, datagram_stats).

%% @doc Set connection options.
-spec setopts(pid(), [{atom(), term()}]) -> ok | {error, term()}.
setopts(Conn, Opts) ->
    gen_statem:call(Conn, {setopts, Opts}).

%% @doc Get send queue status for backpressure decisions.
%% Returns information about the current send queue state including
%% whether the connection is congested and should apply backpressure.
-spec get_send_queue_info(pid()) -> {ok, quic:send_queue_info()} | {error, term()}.
get_send_queue_info(Conn) ->
    gen_statem:call(Conn, get_send_queue_info).

%% @doc Get connection statistics for liveness detection.
%% Returns packet counts that can be used by net_kernel for tick checking.
%% Any QUIC packet (ACK, PING, data) counts as proof of peer liveness.
-spec get_stats(pid()) -> {ok, map()} | {error, term()}.
get_stats(Conn) ->
    gen_statem:call(Conn, get_stats).

%% @doc Get peer's transport parameters.
%% Returns the transport parameters received from the peer during handshake.
%% Useful for verifying peer capabilities (e.g., WebTransport support).
-spec get_peer_transport_params(pid()) -> {ok, map()} | {error, term()}.
get_peer_transport_params(Conn) ->
    gen_statem:call(Conn, get_peer_transport_params).

%% @doc Send a PING frame (RFC 9000).
%% PING frames bypass congestion control and are useful for liveness checks.
%% The PING elicits an ACK from the peer, confirming the connection is alive.
-spec send_ping(pid()) -> ok | {error, term()}.
send_ping(Conn) ->
    gen_statem:call(Conn, send_ping).

%% @doc Get the current MTU for the connection.
%% Returns the effective MTU discovered via DPLPMTUD (RFC 8899).
-spec get_mtu(pid()) -> {ok, pos_integer()} | {error, term()}.
get_mtu(Conn) ->
    gen_statem:call(Conn, get_mtu).

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

%% @doc Trigger connection migration with timeout option.
%% Simulates network change by rebinding the socket.
-spec migrate(pid(), timeout()) -> ok | {error, term()}.
migrate(Conn, Timeout) ->
    gen_statem:call(Conn, {migrate, #{}}, Timeout).

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

%% @doc Set the congestion control algorithm for a connection.
%% Algorithm: newreno | bbr | cubic
-spec set_congestion_control(pid(), quic_cc:cc_algorithm()) -> ok | {error, term()}.
set_congestion_control(Conn, Algorithm) ->
    gen_statem:call(Conn, {set_congestion_control, Algorithm}).

%% @doc Set a deadline for a stream.
%% TimeoutMs is milliseconds from now until expiry.
%% Options: action => reset | notify | both, error_code => non_neg_integer()
-spec set_stream_deadline(pid(), non_neg_integer(), pos_integer(), map()) ->
    ok | {error, term()}.
set_stream_deadline(Conn, StreamId, TimeoutMs, Opts) ->
    gen_statem:call(Conn, {set_stream_deadline, StreamId, TimeoutMs, Opts}).

%% @doc Cancel a stream deadline.
-spec cancel_stream_deadline(pid(), non_neg_integer()) -> ok | {error, term()}.
cancel_stream_deadline(Conn, StreamId) ->
    gen_statem:call(Conn, {cancel_stream_deadline, StreamId}).

%% @doc Get remaining time for a stream deadline.
-spec get_stream_deadline(pid(), non_neg_integer()) ->
    {ok, {non_neg_integer() | infinity, reset | notify | both}} | {error, term()}.
get_stream_deadline(Conn, StreamId) ->
    gen_statem:call(Conn, {get_stream_deadline, StreamId}).

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
    %% Extra socket opts allow binding to specific address (fix for #28)
    ExtraOpts = maps:get(extra_socket_opts, Opts, []),
    case open_client_socket(Socket, RemoteAddr, Opts, ExtraOpts) of
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

    %% Create connection reference (for internal use only)
    ConnRef = make_ref(),

    %% Initialize congestion control and loss detection
    %% Support configurable initial cwnd for distribution workloads
    CCOpts = build_cc_opts(Opts),
    CCState = quic_cc:new(CCOpts),
    LossState = quic_loss:new(),

    %% Get idle timeout for keep-alive calculation
    IdleTimeout = maps:get(idle_timeout, Opts, ?DEFAULT_MAX_IDLE_TIMEOUT),

    %% Query local address from socket (fix for #27)
    LocalAddr =
        case inet:sockname(Socket) of
            {ok, Sockname} -> Sockname;
            {error, _} -> undefined
        end,

    %% Server connections use the listener's shared socket for sending.
    %% This matches standard QUIC implementations (quic-go, quiche) where
    %% all connections share a single UDP socket, demultiplexed by Connection ID.
    %% We previously tried a separate send socket with reuseport for GSO batching,
    %% but on Linux this caused kernel packet distribution to starve the listener.
    %% For GSO optimization, the listener socket itself should be configured for it.
    SocketState = undefined,

    %% Initialize state
    State = #state{
        scid = SCID,
        % Will be set from ClientHello SCID
        dcid = <<>>,
        original_dcid = InitialDCID,
        role = server,
        % Use client's QUIC version
        version = Version,
        socket = Socket,
        %% send_socket is undefined - socket is in socket_state
        send_socket = undefined,
        socket_state = SocketState,
        remote_addr = RemoteAddr,
        local_addr = LocalAddr,
        % Listener is the owner for now
        owner = Listener,
        conn_ref = ConnRef,
        verify = maps:get(verify, Opts, false),
        initial_keys = InitialKeys,
        tls_state = ?TLS_AWAITING_CLIENT_HELLO,
        alpn_list = normalize_alpn_list(ALPNList),
        pn_initial = PNSpace,
        pn_handshake = PNSpace,
        pn_app = PNSpace,
        max_data_local = maps:get(max_data, Opts, ?DEFAULT_INITIAL_MAX_DATA),
        max_data_remote = ?DEFAULT_INITIAL_MAX_DATA,
        max_stream_data_bidi_local = maps:get(
            max_stream_data_bidi_local, Opts, ?DEFAULT_INITIAL_MAX_STREAM_DATA
        ),
        max_stream_data_bidi_remote = maps:get(
            max_stream_data_bidi_remote, Opts, ?DEFAULT_INITIAL_MAX_STREAM_DATA
        ),
        max_stream_data_uni = maps:get(max_stream_data_uni, Opts, ?DEFAULT_INITIAL_MAX_STREAM_DATA),
        fc_last_stream_update = undefined,
        fc_last_conn_update = undefined,
        fc_max_receive_window = maps:get(max_receive_window, Opts, ?DEFAULT_MAX_RECEIVE_WINDOW),
        % Server-initiated bidi: 1, 5, 9, ...
        next_stream_id_bidi = 1,
        % Server-initiated uni: 3, 7, 11, ...
        next_stream_id_uni = 3,
        max_streams_bidi_local = maps:get(max_streams_bidi, Opts, ?DEFAULT_MAX_STREAMS_BIDI),
        max_streams_bidi_remote = ?DEFAULT_MAX_STREAMS_BIDI,
        max_streams_uni_local = maps:get(max_streams_uni, Opts, ?DEFAULT_MAX_STREAMS_UNI),
        max_streams_uni_remote = ?DEFAULT_MAX_STREAMS_UNI,
        max_datagram_frame_size_local = maps:get(max_datagram_frame_size, Opts, 0),
        datagram_recv_queue_len = maps:get(datagram_recv_queue_len, Opts, infinity),
        spin_bit_enabled = maps:get(spin_bit, Opts, true),
        stateless_reset_secret = maps:get(reset_secret, Opts, undefined),
        reset_stream_at_enabled = maps:get(reset_stream_at, Opts, false),
        idle_timeout = IdleTimeout,
        keep_alive_interval = calculate_keep_alive_interval(Opts, IdleTimeout),
        keep_alive_timer = undefined,
        last_activity = erlang:monotonic_time(millisecond),
        cc_state = CCState,
        loss_state = LossState,
        listener = Listener,
        server_cert = Cert,
        server_cert_chain = CertChain,
        server_private_key = PrivateKey,
        server_preferred_address = build_server_preferred_address(Opts),
        cid_config = maps:get(cid_config, Opts, undefined),
        congestion_threshold = maps:get(congestion_threshold, Opts, 2),
        pacing_enabled = maps:get(pacing_enabled, Opts, true),
        pmtu_state = init_pmtu_state(Opts),
        qlog_ctx = quic_qlog:new(Opts, InitialDCID, server)
    },

    %% Emit qlog connection_started event
    quic_qlog:connection_started(State#state.qlog_ctx),

    {ok, idle, State}.

%% Build congestion control options from connection options.
%% Supports:
%%   - cc_algorithm: Congestion control algorithm (newreno | bbr, default: newreno)
%%   - initial_window: Initial congestion window in bytes (default: RFC 9002 formula)
%%                     Higher values improve bulk transfer throughput.
%%                     Recommended for distribution: 65536 (64KB) or higher.
%%   - minimum_window: Lower bound for cwnd after congestion events.
%%                     Defaults to RFC 9002 (2 * max_datagram_size).
%%   - min_recovery_duration: Minimum time in recovery before exit (ms, default: 100)
%%                            Prevents rapid cwnd oscillations on low-latency networks.
build_cc_opts(Opts) ->
    CCOpts = #{},
    CCOpts1 = maybe_add_cc_opt(initial_window, Opts, CCOpts),
    CCOpts2 = maybe_add_cc_opt(minimum_window, Opts, CCOpts1),
    CCOpts3 = maybe_add_cc_opt(min_recovery_duration, Opts, CCOpts2),
    %% Pass max_udp_payload_size as max_datagram_size to CC
    CCOpts4 =
        case maps:find(max_udp_payload_size, Opts) of
            {ok, Size} -> maps:put(max_datagram_size, Size, CCOpts3);
            error -> CCOpts3
        end,
    %% Add algorithm selection (default: newreno)
    case maps:find(cc_algorithm, Opts) of
        {ok, Algo} when Algo =:= newreno; Algo =:= bbr; Algo =:= cubic ->
            CCOpts4#{algorithm => Algo};
        _ ->
            CCOpts4
    end.

maybe_add_cc_opt(Key, Opts, CCOpts) ->
    case maps:find(Key, Opts) of
        {ok, V} when is_integer(V), V > 0 -> CCOpts#{Key => V};
        _ -> CCOpts
    end.

%% Initialize PMTU discovery state from options.
%% Options:
%%   - pmtu_enabled: Enable PMTU discovery (default: true)
%%   - pmtu_max_mtu: Maximum MTU to probe (default: 1500)
init_pmtu_state(Opts) ->
    PMTUOpts = #{
        pmtu_enabled => maps:get(pmtu_enabled, Opts, true),
        pmtu_max_mtu => maps:get(pmtu_max_mtu, Opts, 1500)
    },
    quic_pmtu:new(PMTUOpts).

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
            {IPv4Addr, IPv4Port} =
                case PreferredIPv4 of
                    {Addr, Port} -> {Addr, Port};
                    undefined -> {undefined, undefined}
                end,
            {IPv6Addr, IPv6Port} =
                case PreferredIPv6 of
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
%% Opts is the full options map, ExtraOpts allows socket options like {ip, Address}
open_client_socket(undefined, {IP, _Port}, Opts, ExtraOpts) ->
    AddrFamily = address_family(IP),
    %% UDP buffer sizing - larger buffers improve throughput significantly
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),
    BaseOpts = [
        binary,
        AddrFamily,
        {active, false},
        {recbuf, RecBuf},
        {sndbuf, SndBuf}
    ],
    case gen_udp:open(0, BaseOpts ++ ExtraOpts) of
        {ok, S} ->
            case inet:sockname(S) of
                {ok, LA} ->
                    {ok, S, LA, true};
                {error, Reason} ->
                    gen_udp:close(S),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
open_client_socket(S, _RemoteAddr, _Opts, _ExtraOpts) ->
    %% Pre-opened socket provided, ignore extra opts
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

    %% Create connection reference (for internal use only)
    ConnRef = make_ref(),

    %% Get server name for SNI
    ServerName =
        case maps:get(server_name, Opts, undefined) of
            undefined when is_binary(Host) -> Host;
            undefined when is_list(Host) -> list_to_binary(Host);
            SN -> SN
        end,

    %% Get ALPN list
    AlpnOpt = maps:get(alpn, Opts, [<<"h3">>]),
    AlpnList = normalize_alpn_list(AlpnOpt),

    %% Initialize congestion control and loss detection
    %% Support configurable initial cwnd for distribution workloads
    CCOpts = build_cc_opts(Opts),
    CCState = quic_cc:new(CCOpts),
    LossState = quic_loss:new(),

    %% Extract session ticket for resumption (if provided)
    SessionTicket = maps:get(session_ticket, Opts, undefined),

    %% Get idle timeout for keep-alive calculation
    IdleTimeoutClient = maps:get(idle_timeout, Opts, ?DEFAULT_MAX_IDLE_TIMEOUT),

    %% Initialize socket_state for batching (client connections only)
    %% Client connections use wrap() since they need the same socket for
    %% both sending and receiving. GSO is not available through gen_udp,
    %% but batching still provides significant throughput benefits.
    SocketState =
        case maps:get(batching, Opts, #{}) of
            #{enabled := false} ->
                undefined;
            BatchOpts ->
                {ok, SS} = quic_socket:wrap(Sock, #{batching => BatchOpts}),
                SS
        end,

    %% Initialize state
    State = #state{
        scid = SCID,
        dcid = DCID,
        original_dcid = DCID,
        role = client,
        socket = Sock,
        socket_state = SocketState,
        remote_addr = RemoteAddr,
        local_addr = LocalAddr,
        owner = Owner,
        conn_ref = ConnRef,
        server_name = ServerName,
        verify = maps:get(verify, Opts, false),
        client_cert = maps:get(cert, Opts, undefined),
        client_cert_chain = maps:get(cert_chain, Opts, []),
        client_private_key = maps:get(key, Opts, undefined),
        initial_keys = InitialKeys,
        tls_state = ?TLS_AWAITING_SERVER_HELLO,
        alpn_list = AlpnList,
        pn_initial = PNSpace,
        pn_handshake = PNSpace,
        pn_app = PNSpace,
        max_data_local = maps:get(max_data, Opts, ?DEFAULT_INITIAL_MAX_DATA),
        max_data_remote = ?DEFAULT_INITIAL_MAX_DATA,
        max_stream_data_bidi_local = maps:get(
            max_stream_data_bidi_local, Opts, ?DEFAULT_INITIAL_MAX_STREAM_DATA
        ),
        max_stream_data_bidi_remote = maps:get(
            max_stream_data_bidi_remote, Opts, ?DEFAULT_INITIAL_MAX_STREAM_DATA
        ),
        max_stream_data_uni = maps:get(max_stream_data_uni, Opts, ?DEFAULT_INITIAL_MAX_STREAM_DATA),
        fc_last_stream_update = undefined,
        fc_last_conn_update = undefined,
        fc_max_receive_window = maps:get(max_receive_window, Opts, ?DEFAULT_MAX_RECEIVE_WINDOW),
        % Client-initiated bidi: 0, 4, 8, ...
        next_stream_id_bidi = 0,
        % Client-initiated uni: 2, 6, 10, ...
        next_stream_id_uni = 2,
        max_streams_bidi_local = maps:get(max_streams_bidi, Opts, ?DEFAULT_MAX_STREAMS_BIDI),
        max_streams_bidi_remote = ?DEFAULT_MAX_STREAMS_BIDI,
        max_streams_uni_local = maps:get(max_streams_uni, Opts, ?DEFAULT_MAX_STREAMS_UNI),
        max_streams_uni_remote = ?DEFAULT_MAX_STREAMS_UNI,
        max_datagram_frame_size_local = maps:get(max_datagram_frame_size, Opts, 0),
        datagram_recv_queue_len = maps:get(datagram_recv_queue_len, Opts, infinity),
        spin_bit_enabled = maps:get(spin_bit, Opts, true),
        stateless_reset_secret = maps:get(reset_secret, Opts, undefined),
        reset_stream_at_enabled = maps:get(reset_stream_at, Opts, false),
        idle_timeout = IdleTimeoutClient,
        keep_alive_interval = calculate_keep_alive_interval(Opts, IdleTimeoutClient),
        keep_alive_timer = undefined,
        last_activity = erlang:monotonic_time(millisecond),
        cc_state = CCState,
        loss_state = LossState,
        %% Store session ticket for resumption
        ticket_store =
            case SessionTicket of
                undefined -> quic_ticket:new_store();
                Ticket -> quic_ticket:store_ticket(ServerName, Ticket, quic_ticket:new_store())
            end,
        congestion_threshold = maps:get(congestion_threshold, Opts, 2),
        pacing_enabled = maps:get(pacing_enabled, Opts, true),
        active_n = maps:get(active_n, Opts, 100),
        pmtu_state = init_pmtu_state(Opts),
        qlog_ctx = quic_qlog:new(Opts, DCID, client)
    },

    %% Emit qlog connection_started event
    quic_qlog:connection_started(State#state.qlog_ctx),

    {ok, idle, State}.

terminate(
    Reason,
    StateName,
    #state{
        socket = Socket,
        send_socket = SendSocket,
        socket_state = SocketState,
        pto_timer = PtoTimer,
        idle_timer = IdleTimer,
        keep_alive_timer = KeepAliveTimer,
        pacing_timer = PacingTimer,
        role = Role,
        qlog_ctx = QlogCtx
    } = State
) ->
    %% If we're not already draining/closed, try to send CONNECTION_CLOSE
    %% No owner notification here - either already notified (draining) or owner is dead
    case StateName of
        draining ->
            ok;
        closed ->
            ok;
        _ ->
            try
                %% Use close_reason from state if set, otherwise use terminate reason
                CloseReason =
                    case State#state.close_reason of
                        undefined -> Reason;
                        R -> R
                    end,
                send_connection_close(CloseReason, State)
            catch
                _:_ -> ok
            end
    end,
    %% Flush any batched packets before closing and close owned sockets
    case SocketState of
        undefined ->
            ok;
        _ ->
            try
                _ = quic_socket:flush(SocketState),
                %% Close socket_state (respects owns_socket flag)
                _ = quic_socket:close(SocketState)
            catch
                _:_ -> ok
            end
    end,
    %% Cancel any active timers
    cancel_timer(PtoTimer),
    cancel_timer(IdleTimer),
    cancel_timer(KeepAliveTimer),
    cancel_timer(PacingTimer),
    %% Cancel delayed ACK timer from process dictionary
    case erase(ack_timer) of
        undefined -> ok;
        AckTimerRef -> cancel_timer(AckTimerRef)
    end,
    %% Close dedicated send socket for server connections (SO_REUSEPORT socket)
    case SendSocket of
        undefined -> ok;
        _ -> gen_udp:close(SendSocket)
    end,
    %% Only close socket for client connections (clients own their socket)
    %% Server connections share the listener's socket and must not close it
    case {Role, Socket} of
        {client, S} when S =/= undefined -> gen_udp:close(S);
        _ -> ok
    end,
    %% Close QLOG trace file
    quic_qlog:close(QlogCtx),
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
idle({call, From}, {set_owner, NewOwner}, State) ->
    {keep_state, State#state{owner = NewOwner}, [{reply, From, ok}]};
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
idle(
    {call, From},
    {send_data, StreamId, Data, Fin},
    #state{
        early_keys = undefined,
        pending_data = Pending
    } = State
) ->
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
    %% Flush batched packets and timers after processing incoming data
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    check_state_transition(idle, FlushedState);
%% Server receives packets from listener
idle(info, {quic_packet, Data, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packet(Data, State),
    %% Flush batched packets and timers after processing incoming data
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    check_state_transition(idle, FlushedState);
%% Server receives batched packets from listener (GRO optimization)
idle(info, {quic_packets, Packets, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packets_batch(Packets, State),
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    check_state_transition(idle, FlushedState);
idle(cast, process, #state{role = client, socket = Socket, active_n = N} = State) ->
    %% Re-enable socket for receiving (client only - server uses listener's socket)
    inet:setopts(Socket, [{active, N}]),
    {keep_state, State};
idle(cast, process, #state{role = server} = State) ->
    %% Server connections receive via listener, don't touch socket options
    {keep_state, State};
idle(cast, {close, Reason}, State) ->
    %% Close in idle state - no keys yet, just transition to draining
    emit_qlog_state_change(idle, draining, State),
    State1 = initiate_close(Reason, State),
    NewState = flush_dirty_timers(flush_socket_batch(State1)),
    {next_state, draining, NewState};
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
handshaking({call, From}, {set_owner, NewOwner}, State) ->
    {keep_state, State#state{owner = NewOwner}, [{reply, From, ok}]};
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
handshaking(
    {call, From},
    {send_data, StreamId, Data, Fin},
    #state{
        early_keys = undefined,
        pending_data = Pending
    } = State
) ->
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
    %% Flush batched packets and timers after processing incoming data
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    check_state_transition(handshaking, FlushedState);
%% Server receives packets from listener
handshaking(info, {quic_packet, Data, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packet(Data, State),
    %% Flush batched packets and timers after processing incoming data
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    check_state_transition(handshaking, FlushedState);
%% Server receives batched packets from listener (GRO optimization)
handshaking(info, {quic_packets, Packets, _RemoteAddr}, #state{role = server} = State) ->
    NewState = handle_packets_batch(Packets, State),
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    check_state_transition(handshaking, FlushedState);
handshaking(cast, process, #state{role = client, socket = Socket, active_n = N} = State) ->
    %% Re-enable socket for receiving (client only - server uses listener's socket)
    inet:setopts(Socket, [{active, N}]),
    {keep_state, State};
handshaking(cast, process, #state{role = server} = State) ->
    %% Server connections receive via listener, don't touch socket options
    {keep_state, State};
handshaking(cast, {close, Reason}, State) ->
    %% Close during handshake - may not have app keys yet
    emit_qlog_state_change(handshaking, draining, State),
    State1 = initiate_close(Reason, State),
    NewState = flush_dirty_timers(flush_socket_batch(State1)),
    {next_state, draining, NewState};
handshaking(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, handshaking, State).

%% ----- CONNECTED STATE -----

connected(
    enter,
    OldState,
    #state{
        owner = Owner,
        alpn = Alpn,
        socket = Socket,
        role = Role,
        pending_data = Pending,
        transport_params = TransportParams,
        active_n = ActiveN
    } = State
) when
    OldState =:= handshaking; OldState =:= idle
->
    %% Notify owner that connection is established
    Info = #{
        alpn => Alpn,
        alpn_protocol => Alpn,
        transport_params => TransportParams
    },
    Owner ! {quic, self(), {connected, Info}},
    %% For client connections, ensure socket is active for receiving
    %% Server connections receive via listener (quic_packet messages)
    case Role of
        client -> inet:setopts(Socket, [{active, ActiveN}]);
        server -> ok
    end,
    %% Send any data that was queued before connection established
    State1 = State#state{pending_data = []},
    State2 = send_pending_data(Pending, State1),
    %% RFC 9000 Section 9.6: Client validates server's preferred address
    State3 =
        case Role of
            client ->
                case maps:get(preferred_address, TransportParams, undefined) of
                    undefined ->
                        State2;
                    PA when is_record(PA, preferred_address) ->
                        initiate_preferred_address_validation(PA, State2);
                    _ ->
                        State2
                end;
            server ->
                State2
        end,
    %% RFC 9000 Section 10.1: Start idle timer when entering connected state
    State4 = update_last_activity(State3),
    %% RFC 8899: Initialize PMTU discovery after handshake
    State5 = init_pmtu_probing(TransportParams, State4),
    {keep_state, State5};
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
connected({call, From}, datagram_max_size, #state{max_datagram_frame_size_remote = Size} = State) ->
    {keep_state, State, [{reply, From, Size}]};
connected({call, From}, datagram_stats, State) ->
    {keep_state, State, [{reply, From, datagram_stats_snapshot(State)}]};
connected({call, From}, {set_owner, NewOwner}, #state{alpn = Alpn, transport_params = TP} = State) ->
    %% Notify new owner that connection is already established
    Info = #{alpn => Alpn, alpn_protocol => Alpn, transport_params => TP},
    NewOwner ! {quic, self(), {connected, Info}},
    {keep_state, State#state{owner = NewOwner}, [{reply, From, ok}]};
connected(cast, {set_owner, NewOwner}, #state{alpn = Alpn, transport_params = TP} = State) ->
    %% Notify new owner that connection is already established
    Info = #{alpn => Alpn, alpn_protocol => Alpn, transport_params => TP},
    NewOwner ! {quic, self(), {connected, Info}},
    {keep_state, State#state{owner = NewOwner}};
connected({call, From}, {send_datagram, Data}, State) ->
    case do_send_datagram(Data, State) of
        {ok, NewState} ->
            %% Event-driven flush: flush batch and timers after user API call
            FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
            {keep_state, FlushedState, [{reply, From, ok}]};
        {error, Reason, NewState} ->
            {keep_state, NewState, [{reply, From, {error, Reason}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            %% Event-driven flush: flush batch and timers after user API call
            FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
            {keep_state, FlushedState, [{reply, From, ok}]};
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
%% RESET_STREAM_AT: Reset with reliable delivery up to ReliableSize
%% (draft-ietf-quic-reliable-stream-reset-07)
connected({call, From}, {reset_stream_at, StreamId, ErrorCode, ReliableSize}, State) ->
    case do_reset_stream_at(StreamId, ErrorCode, ReliableSize, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
%% STOP_SENDING: Request peer to stop sending on a stream (RFC 9000 Section 19.5)
connected({call, From}, {stop_sending, StreamId, ErrorCode}, State) ->
    case do_stop_sending(StreamId, ErrorCode, State) of
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
%% Congestion control
connected({call, From}, {set_congestion_control, Algorithm}, State) ->
    case do_set_congestion_control(Algorithm, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
%% Stream deadlines
connected({call, From}, {set_stream_deadline, StreamId, TimeoutMs, Opts}, State) ->
    case do_set_stream_deadline(StreamId, TimeoutMs, Opts, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {cancel_stream_deadline, StreamId}, State) ->
    case do_cancel_stream_deadline(StreamId, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {get_stream_deadline, StreamId}, State) ->
    case do_get_stream_deadline(StreamId, State) of
        {ok, Result} ->
            {keep_state, State, [{reply, From, {ok, Result}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {setopts, _Opts}, State) ->
    {keep_state, State, [{reply, From, ok}]};
connected(
    {call, From},
    get_send_queue_info,
    #state{
        send_queue_bytes = Bytes,
        cc_state = CCState,
        congestion_threshold = Threshold
    } = State
) ->
    Cwnd = quic_cc:cwnd(CCState),
    InFlight = quic_cc:bytes_in_flight(CCState),
    InRecovery = quic_cc:in_recovery(CCState),
    %% Congested if queue > cwnd * threshold OR in recovery with queue > cwnd
    Congested = (Bytes > Cwnd * Threshold) orelse (InRecovery andalso Bytes > Cwnd),
    Info = #{
        bytes => Bytes,
        cwnd => Cwnd,
        in_flight => InFlight,
        in_recovery => InRecovery,
        congested => Congested
    },
    {keep_state, State, [{reply, From, {ok, Info}}]};
connected(
    {call, From},
    get_stats,
    #state{
        packets_received = PacketsRecv,
        packets_sent = PacketsSent,
        data_received = DataRecv,
        data_sent = DataSent
    } = State
) ->
    %% Return packet counts for liveness detection
    %% net_kernel uses recv count to verify peer is alive
    Stats = #{
        packets_received => PacketsRecv,
        packets_sent => PacketsSent,
        data_received => DataRecv,
        data_sent => DataSent
    },
    {keep_state, State, [{reply, From, {ok, Stats}}]};
connected({call, From}, get_peer_transport_params, #state{transport_params = TP} = State) ->
    {keep_state, State, [{reply, From, {ok, TP}}]};
connected({call, From}, send_ping, State) ->
    %% Send PING frame - bypasses congestion control
    NewState = send_keep_alive_ping(State),
    {keep_state, NewState, [{reply, From, ok}]};
connected({call, From}, get_mtu, State) ->
    MTU = get_current_mtu(State),
    {keep_state, State, [{reply, From, {ok, MTU}}]};
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
connected({call, From}, migrate, #state{peer_disable_migration = true} = State) ->
    %% Peer disabled migration via transport params
    {keep_state, State, [{reply, From, {error, migration_disabled}}]};
connected({call, From}, migrate, #state{socket = Socket, remote_addr = RemoteAddr} = State) ->
    %% Simulate network change by rebinding socket to a new port
    %% In a real scenario, this would happen when the device changes networks
    case rebind_socket(Socket) of
        {ok, NewSocket} ->
            %% RFC 9000 Section 9.5: Use fresh CID to prevent path linkability
            State1 = switch_to_fresh_cid(State),
            %% Start path validation to the peer on the new path
            State2 = State1#state{socket = NewSocket},
            State3 = initiate_path_validation(RemoteAddr, State2),
            {keep_state, State3, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
%% Handle migration with options
connected({call, From}, {migrate, _Opts}, #state{peer_disable_migration = true} = State) ->
    {keep_state, State, [{reply, From, {error, migration_disabled}}]};
connected(
    {call, From}, {migrate, _Opts}, #state{socket = Socket, remote_addr = RemoteAddr} = State
) ->
    case rebind_socket(Socket) of
        {ok, NewSocket} ->
            State1 = switch_to_fresh_cid(State),
            State2 = State1#state{socket = NewSocket},
            State3 = initiate_path_validation(RemoteAddr, State2),
            {keep_state, State3, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
connected(info, {udp, Socket, IP, Port, Data}, #state{socket = Socket} = State) ->
    %% Track packet source for PATH_RESPONSE routing (RFC 9000 Section 8.2.2)
    State1 = State#state{current_packet_source = {IP, Port}},
    NewState = handle_packet(Data, State1),
    %% Clear packet source and flush
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
    FinalState = FlushedState#state{current_packet_source = undefined},
    check_state_transition(connected, FinalState);
%% Server receives packets from listener
connected(info, {quic_packet, Data, RemoteAddr}, #state{role = server} = State) ->
    %% Track packet source for PATH_RESPONSE routing (RFC 9000 Section 8.2.2)
    %% Clear has_non_probing_frame before processing - will be set by process_frame_track_probing
    State1 = State#state{current_packet_source = RemoteAddr, has_non_probing_frame = false},
    %% Process packet FIRST to classify frames
    NewState = handle_packet(Data, State1),
    %% RFC 9000 Section 9.1: Only trigger migration if packet contains non-probing frames
    NewState2 =
        case NewState#state.has_non_probing_frame of
            true -> maybe_handle_address_change(RemoteAddr, byte_size(Data), NewState);
            false -> NewState
        end,
    %% Clear transient fields and flush
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState2)),
    FinalState = FlushedState#state{
        current_packet_source = undefined, has_non_probing_frame = false
    },
    check_state_transition(connected, FinalState);
%% Server receives batched packets from listener (GRO optimization)
connected(info, {quic_packets, Packets, RemoteAddr}, #state{role = server} = State) ->
    %% Track packet source for PATH_RESPONSE routing (RFC 9000 Section 8.2.2)
    %% Clear has_non_probing_frame before processing - will be set by process_frame_track_probing
    State1 = State#state{current_packet_source = RemoteAddr, has_non_probing_frame = false},
    %% Process packets FIRST to classify frames
    NewState = handle_packets_batch(Packets, State1),
    %% RFC 9000 Section 9.1: Only trigger migration if any packet contains non-probing frames
    NewState2 =
        case NewState#state.has_non_probing_frame of
            true ->
                TotalSize = lists:sum([byte_size(P) || P <- Packets]),
                maybe_handle_address_change(RemoteAddr, TotalSize, NewState);
            false ->
                NewState
        end,
    %% Clear transient fields and flush
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState2)),
    FinalState = FlushedState#state{
        current_packet_source = undefined, has_non_probing_frame = false
    },
    check_state_transition(connected, FinalState);
%% Path validation timeout - stay on current path if validation fails
%% Match on token (not timer ref) to correlate with specific validation attempt
connected(
    info,
    {path_validation_timeout, Token},
    #state{path_validation_token = Token} = State
) when Token =/= undefined ->
    %% Token matches - this is the current validation attempt
    _ = cancel_timer(State#state.path_validation_timer),
    State1 = State#state{path_validation_timer = undefined, path_validation_token = undefined},
    handle_path_validation_timeout(State1);
connected(info, {path_validation_timeout, _StaleToken}, State) ->
    %% Stale token from canceled validation - ignore
    {keep_state, State};
connected(cast, {close, Reason}, State) ->
    emit_qlog_state_change(connected, draining, State),
    State1 = initiate_close(Reason, State),
    NewState = flush_dirty_timers(flush_socket_batch(State1)),
    {next_state, draining, NewState};
%% Async send data - fire-and-forget for high throughput
connected(cast, {send_data_async, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            %% Event-driven flush: flush batch and timers after user API call
            FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),
            {keep_state, FlushedState};
        {error, _Reason} ->
            %% Silently drop errors in async mode
            {keep_state, State}
    end;
connected(cast, process, #state{role = client, socket = Socket, active_n = N} = State) ->
    %% Re-enable socket for receiving (client only - server uses listener's socket)
    inet:setopts(Socket, [{active, N}]),
    {keep_state, State};
connected(cast, process, #state{role = server} = State) ->
    %% Server connections receive via listener, don't touch socket options
    {keep_state, State};
%% Handle delayed ACK timer (RFC 9221 Section 5.2)
%% Validates reference to ignore stale timer events
connected(info, {send_delayed_ack, app, Ref}, State) ->
    case get(ack_timer) of
        Ref when Ref =/= undefined ->
            erase(ack_timer),
            State1 = send_app_ack(State),
            NewState = flush_dirty_timers(flush_socket_batch(State1)),
            {keep_state, NewState};
        _ ->
            %% Stale timer - ignore
            {keep_state, State}
    end;
%% Handle PMTU probe timeout (RFC 8899)
%% Validates reference to ignore stale timer events
connected(
    info, {pmtu_probe_timeout, Ref}, #state{pmtu_probe_timer = Ref, pmtu_state = PMTUState} = State
) when
    Ref =/= undefined
->
    NewPMTUState = quic_pmtu:on_probe_timeout(PMTUState),
    State1 = State#state{
        pmtu_state = NewPMTUState,
        pmtu_probe_timer = undefined
    },
    %% Retry probing if needed
    State2 = maybe_send_pmtu_probe(State1),
    {keep_state, State2};
connected(info, {pmtu_probe_timeout, _StaleRef}, State) ->
    %% Stale PMTU probe timer - ignore
    {keep_state, State};
%% Handle PMTU raise timer (periodic re-probing)
%% Validates reference to ignore stale timer events
connected(
    info, {pmtu_raise_timeout, Ref}, #state{pmtu_raise_timer = Ref, pmtu_state = PMTUState} = State
) when
    Ref =/= undefined
->
    %% Probe higher from current MTU (don't reset to base)
    NewPMTUState = quic_pmtu:on_raise_timer(PMTUState),
    State1 = State#state{
        pmtu_state = NewPMTUState,
        pmtu_raise_timer = undefined
    },
    State2 = maybe_send_pmtu_probe(State1),
    {keep_state, State2};
connected(info, {pmtu_raise_timeout, _StaleRef}, State) ->
    %% Stale PMTU raise timer - ignore
    {keep_state, State};
%% Handle stream deadline expiry
connected(info, {stream_deadline, StreamId}, State) ->
    case handle_stream_deadline_expired(StreamId, State) of
        {ok, NewState} ->
            {keep_state, NewState};
        {error, _Reason} ->
            %% Stream already closed or doesn't exist
            {keep_state, State}
    end;
connected(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, connected, State).

%% ----- DRAINING STATE -----

draining(
    enter,
    _OldState,
    #state{
        owner = Owner,
        close_reason = Reason,
        loss_state = LossState,
        qlog_ctx = QlogCtx
    } = State
) ->
    %% Extract reason phrase for qlog
    ReasonPhrase =
        case Reason of
            {app_error, _, Phrase} -> Phrase;
            {peer_closed, application, _, Phrase} -> Phrase;
            {peer_closed, transport, _, _, Phrase} -> Phrase;
            _ -> undefined
        end,
    %% Emit qlog connection_closed event
    quic_qlog:connection_closed(QlogCtx, close_reason_to_code(Reason), ReasonPhrase),

    Owner ! {quic, self(), {closed, Reason}},
    %% Start drain timer (3 * PTO per RFC 9000 Section 10.2)
    DrainTimeout =
        case LossState of
            % Fallback if loss state not initialized
            undefined -> 3000;
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
draining(cast, {close, _Reason}, State) ->
    %% Ignore duplicate close requests - already draining
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
handle_common_event(info, {pto_timeout, Ref}, StateName, #state{pto_timer = Ref} = State) when
    Ref =/= undefined andalso (StateName =:= connected orelse StateName =:= handshaking)
->
    %% Handle PTO timeout - send probe packet
    NewState = handle_pto_timeout(State#state{pto_timer = undefined}),
    {keep_state, NewState};
handle_common_event(info, {pto_timeout, _StaleRef}, _StateName, State) ->
    %% Ignore stale PTO timer (ref doesn't match or wrong state)
    {keep_state, State};
handle_common_event(info, {pacing_timeout, Ref}, connected, #state{pacing_timer = Ref} = State) when
    Ref =/= undefined
->
    %% Handle pacing timeout - process send queue
    NewState = handle_pacing_timeout(State#state{pacing_timer = undefined}),
    {keep_state, NewState};
handle_common_event(info, {pacing_timeout, _StaleRef}, _StateName, State) ->
    %% Ignore stale pacing timer (ref doesn't match or wrong state)
    {keep_state, State};
handle_common_event(info, {idle_timeout, Ref}, StateName, #state{idle_timer = Ref} = State) when
    Ref =/= undefined andalso StateName =/= draining andalso StateName =/= closed
->
    %% Handle idle timeout - check if we've truly been idle
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - State#state.last_activity,
    case TimeSinceActivity >= State#state.idle_timeout of
        true ->
            %% Genuine idle timeout - initiate close
            NewState = initiate_close(idle_timeout, State#state{idle_timer = undefined}),
            {next_state, draining, NewState};
        false ->
            %% Spurious timeout (activity occurred) - reset timer
            {keep_state, set_idle_timer(State#state{idle_timer = undefined})}
    end;
handle_common_event(info, {idle_timeout, _StaleRef}, _StateName, State) ->
    %% Ignore stale idle timer (ref doesn't match or wrong state)
    {keep_state, State};
handle_common_event(
    info, {keep_alive_timeout, Ref}, connected, #state{keep_alive_timer = Ref} = State
) when
    Ref =/= undefined
->
    %% Send keep-alive PING and reset timer
    State1 = send_keep_alive_ping(State#state{keep_alive_timer = undefined}),
    State2 = flush_dirty_timers(flush_socket_batch(State1)),
    {keep_state, set_keep_alive_timer(State2)};
handle_common_event(info, {keep_alive_timeout, _StaleRef}, _StateName, State) ->
    %% Ignore stale keep-alive timer (ref doesn't match or wrong state)
    {keep_state, State};
%% Handle socket going passive ({active, N} exhausted)
%% Re-enable socket to continue receiving packets
handle_common_event(
    info,
    {udp_passive, Socket},
    _StateName,
    #state{role = client, socket = Socket, active_n = N} = State
) ->
    inet:setopts(Socket, [{active, N}]),
    {keep_state, State};
handle_common_event(info, {udp_passive, _Socket}, _StateName, State) ->
    %% Server connections or different socket - ignore
    {keep_state, State};
handle_common_event(info, {'EXIT', _Pid, _Reason}, _StateName, State) ->
    %% EXIT signals are handled in terminate/3 callback
    %% Just ignore here - the process will terminate anyway if it's from parent
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
        max_stream_data_bidi_local = MaxStreamDataBidiLocal,
        max_stream_data_bidi_remote = MaxStreamDataBidiRemote,
        max_stream_data_uni = MaxStreamDataUni,
        max_streams_bidi_local = MaxStreamsBidi,
        max_streams_uni_local = MaxStreamsUni,
        max_datagram_frame_size_local = MaxDatagramSize,
        ticket_store = TicketStore
    } = State,

    %% Look up session ticket for resumption
    SessionTicket =
        case quic_ticket:lookup_ticket(ServerName, TicketStore) of
            {ok, Ticket} -> Ticket;
            error -> undefined
        end,

    %% Build transport parameters
    TransportParams0 = #{
        initial_scid => SCID,
        initial_max_data => MaxData,
        initial_max_stream_data_bidi_local => MaxStreamDataBidiLocal,
        initial_max_stream_data_bidi_remote => MaxStreamDataBidiRemote,
        initial_max_stream_data_uni => MaxStreamDataUni,
        initial_max_streams_bidi => MaxStreamsBidi,
        initial_max_streams_uni => MaxStreamsUni,
        max_idle_timeout => State#state.idle_timeout,
        active_connection_id_limit => 2,
        max_udp_payload_size => get_local_max_udp_payload_size(State)
    },
    %% Add max_datagram_frame_size if datagrams are enabled (RFC 9221)
    TransportParams1 =
        case MaxDatagramSize of
            0 -> TransportParams0;
            _ -> TransportParams0#{max_datagram_frame_size => MaxDatagramSize}
        end,
    %% Add reset_stream_at if enabled (draft-ietf-quic-reliable-stream-reset-07)
    TransportParams =
        case State#state.reset_stream_at_enabled of
            false -> TransportParams1;
            true -> TransportParams1#{reset_stream_at => true}
        end,

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
    EarlyKeys =
        case SessionTicket of
            undefined ->
                undefined;
            #session_ticket{cipher = Cipher, resumption_secret = ResSecret} ->
                %% Derive PSK and early secret
                PSK = quic_ticket:derive_psk(ResSecret, SessionTicket),
                EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),
                %% Derive client early traffic secret from ClientHello hash
                ClientHelloHash = quic_crypto:transcript_hash(Cipher, Transcript),
                EarlyTrafficSecret = quic_crypto:derive_client_early_traffic_secret(
                    Cipher, EarlySecret, ClientHelloHash
                ),
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
        max_early_data =
            case SessionTicket of
                undefined -> 0;
                #session_ticket{max_early_data = MaxEarly} -> MaxEarly
            end
    }),

    %% Event-driven flush: flush batch and timers after sending ClientHello
    %% Critical for handshake - must send immediately
    FlushedState = flush_dirty_timers(flush_socket_batch(NewState)),

    %% Enable socket for receiving (use {active, N} for better throughput)
    inet:setopts(FlushedState#state.socket, [{active, FlushedState#state.active_n}]),

    FlushedState.

%% Server: Select cipher suite from client's list (server preference)
%% ClientCipherSuites is a list of TLS cipher suite codes (integers)
%% Convert to atoms for internal use
select_cipher(ClientCipherSuites) ->
    %% Convert client's cipher suite codes to atoms
    ClientCiphers = [cipher_code_to_atom(C) || C <- ClientCipherSuites],
    ServerPreference = [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
    select_first_match(ServerPreference, ClientCiphers).

% Default
select_first_match([], _) ->
    aes_128_gcm;
select_first_match([Cipher | Rest], ClientSuites) ->
    case lists:member(Cipher, ClientSuites) of
        true -> Cipher;
        false -> select_first_match(Rest, ClientSuites)
    end.

%% Convert TLS cipher suite code to internal atom
cipher_code_to_atom(?TLS_AES_128_GCM_SHA256) -> aes_128_gcm;
cipher_code_to_atom(?TLS_AES_256_GCM_SHA384) -> aes_256_gcm;
cipher_code_to_atom(?TLS_CHACHA20_POLY1305_SHA256) -> chacha20_poly1305;
cipher_code_to_atom(_) -> unknown.

%% Convert internal cipher atom to TLS cipher suite code
%% Used when building ServerHello to send the correct cipher suite to client
cipher_atom_to_code(aes_128_gcm) -> ?TLS_AES_128_GCM_SHA256;
cipher_atom_to_code(aes_256_gcm) -> ?TLS_AES_256_GCM_SHA384;
cipher_atom_to_code(chacha20_poly1305) -> ?TLS_CHACHA20_POLY1305_SHA256;
cipher_atom_to_code(_) -> ?TLS_AES_128_GCM_SHA256.

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
                % Table already exists (race condition)
                error:badarg -> ok
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
        verify = Verify,
        max_data_local = MaxData,
        max_stream_data_bidi_local = MaxStreamDataBidiLocal,
        max_stream_data_bidi_remote = MaxStreamDataBidiRemote,
        max_stream_data_uni = MaxStreamDataUni,
        max_streams_bidi_local = MaxStreamsBidi,
        max_streams_uni_local = MaxStreamsUni,
        max_datagram_frame_size_local = MaxDatagramSize,
        server_cert = Cert,
        server_cert_chain = CertChain,
        server_private_key = PrivateKey,
        tls_transcript = Transcript,
        server_hs_secret = ServerHsSecret,
        handshake_secret = HandshakeSecret
    } = State,

    %% Build transport parameters
    TransportParams0 = #{
        %% RFC 9000 §7.3: server MUST send this
        original_dcid => State#state.original_dcid,
        initial_scid => SCID,
        initial_max_data => MaxData,
        initial_max_stream_data_bidi_local => MaxStreamDataBidiLocal,
        initial_max_stream_data_bidi_remote => MaxStreamDataBidiRemote,
        initial_max_stream_data_uni => MaxStreamDataUni,
        initial_max_streams_bidi => MaxStreamsBidi,
        initial_max_streams_uni => MaxStreamsUni,
        max_idle_timeout => State#state.idle_timeout,
        active_connection_id_limit => 2,
        max_udp_payload_size => get_local_max_udp_payload_size(State)
    },
    %% Add max_datagram_frame_size if datagrams are enabled (RFC 9221)
    TransportParams1 =
        case MaxDatagramSize of
            0 -> TransportParams0;
            _ -> TransportParams0#{max_datagram_frame_size => MaxDatagramSize}
        end,
    %% Add reset_stream_at if enabled (draft-ietf-quic-reliable-stream-reset-07)
    TransportParams2 =
        case State#state.reset_stream_at_enabled of
            false -> TransportParams1;
            true -> TransportParams1#{reset_stream_at => true}
        end,
    %% Add preferred_address if configured (RFC 9000 Section 9.6)
    %% Server MUST NOT send preferred_address if disable_active_migration is set
    TransportParams =
        case State#state.server_preferred_address of
            #preferred_address{} = PA ->
                TransportParams2#{preferred_address => PA};
            _ ->
                TransportParams2
        end,

    %% Build EncryptedExtensions
    EncExtMsg = quic_tls:build_encrypted_extensions(#{
        alpn => ALPN,
        transport_params => TransportParams
    }),

    %% Build CertificateRequest if verify is enabled (RFC 8446 Section 4.3.2)
    %% CertificateRequest MUST be sent between EncryptedExtensions and Certificate
    CertReqMsg =
        case Verify of
            true -> quic_tls:build_certificate_request(<<>>);
            false -> <<>>
        end,

    %% Build Certificate
    AllCerts = [Cert | CertChain],
    CertMsg = quic_tls:build_certificate(<<>>, AllCerts),

    %% Update transcript after EncryptedExtensions, CertificateRequest, and Certificate
    Transcript1 = <<Transcript/binary, EncExtMsg/binary, CertReqMsg/binary, CertMsg/binary>>,
    TranscriptHashForCV = quic_crypto:transcript_hash(Cipher, Transcript1),

    %% Build CertificateVerify - select signature algorithm based on key type
    SigAlg = select_signature_algorithm(PrivateKey),
    CertVerifyMsg = quic_tls:build_certificate_verify(SigAlg, PrivateKey, TranscriptHashForCV),

    %% Update transcript after CertificateVerify
    Transcript2 = <<Transcript1/binary, CertVerifyMsg/binary>>,
    TranscriptHashForFinished = quic_crypto:transcript_hash(Cipher, Transcript2),

    %% Build server Finished
    ServerFinishedKey = quic_crypto:derive_finished_key(Cipher, ServerHsSecret),
    ServerVerifyData = quic_crypto:compute_finished_verify(
        Cipher, ServerFinishedKey, TranscriptHashForFinished
    ),
    FinishedMsg = quic_tls:build_finished(ServerVerifyData),

    %% Update transcript after server Finished
    Transcript3 = <<Transcript2/binary, FinishedMsg/binary>>,
    TranscriptHashFinal = quic_crypto:transcript_hash(Cipher, Transcript3),

    %% Derive master secret and application keys
    MasterSecret = quic_crypto:derive_master_secret(Cipher, HandshakeSecret),

    ClientAppSecret = quic_crypto:derive_client_app_secret(
        Cipher, MasterSecret, TranscriptHashFinal
    ),
    ServerAppSecret = quic_crypto:derive_server_app_secret(
        Cipher, MasterSecret, TranscriptHashFinal
    ),

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
    %% Include CertificateRequest if verify is enabled
    HandshakePayload =
        <<EncExtMsg/binary, CertReqMsg/binary, CertMsg/binary, CertVerifyMsg/binary,
            FinishedMsg/binary>>,
    CryptoFrame = quic_frame:encode({crypto, 0, HandshakePayload}),

    %% Determine next TLS state based on verify option
    %% If verify=true, we expect Certificate from client next
    %% If verify=false, we expect Finished from client next
    NextTlsState =
        case Verify of
            true -> ?TLS_AWAITING_CLIENT_CERT;
            false -> ?TLS_AWAITING_CLIENT_FINISHED
        end,

    %% Update state with transcript and app keys
    State1 = State#state{
        tls_state = NextTlsState,
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
    send_frame(handshake_done, State).

%% Server: Send NewSessionTicket after handshake completes
%% RFC 8446 Section 4.6.1: Server sends NewSessionTicket in post-handshake message
%% In QUIC, this is sent as a TLS handshake message in a CRYPTO frame
send_new_session_ticket(#state{resumption_secret = undefined} = State) ->
    %% No resumption secret available - skip sending ticket
    State;
send_new_session_ticket(
    #state{
        resumption_secret = ResumptionSecret,
        server_name = ServerName,
        max_early_data = MaxEarlyData,
        alpn = ALPN,
        handshake_keys = {ClientHsKeys, _},
        ticket_store = TicketStore
    } = State
) ->
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
    CryptoFrame = {crypto, 0, TLSMsg},
    State1 = State#state{ticket_store = NewTicketStore},
    send_frame(CryptoFrame, State1).

%% Send an Initial packet
send_initial_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        initial_keys = {ClientKeys, ServerKeys},
        role = Role,
        pn_initial = PNSpace,
        retry_token = RetryToken
    } = State,

    %% Select correct keys based on role:
    %% - Client sends with ClientKeys
    %% - Server sends with ServerKeys
    EncryptKeys =
        case Role of
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

    %% Build header prefix (without packet number)
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8,
        DCID/binary,
        (byte_size(SCID)):8,
        SCID/binary,
        % Token length + token
        TokenLenEnc/binary,
        RetryToken/binary,
        % +16 for AEAD tag
        (quic_varint:encode(byte_size(PaddedPayload) + PNLen + 16))/binary
    >>,

    %% First byte: 1100 0000 | (PNLen - 1)
    FirstByte = 16#C0 bor (PNLen - 1),
    HeaderPrefix = <<FirstByte, HeaderBody/binary>>,

    %% Protect packet (encrypt + header protection in single call)
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EncryptKeys,
    Packet = quic_aead:protect_long_packet(
        Cipher, Key, IV, HP, PN, HeaderPrefix, PaddedPayload
    ),

    %% Pad Initial packets to at least 1200 bytes
    PaddedPacket = pad_initial_packet(Packet),

    %% Send
    do_socket_send(PaddedPacket, State),

    %% Emit qlog packet_sent event
    quic_qlog:packet_sent(State#state.qlog_ctx, #{
        packet_type => initial,
        packet_number => PN,
        length => byte_size(PaddedPacket)
    }),

    %% Update packet number space and packet counter
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    apply_pending_socket_state(State#state{
        pn_initial = NewPNSpace,
        packets_sent = State#state.packets_sent + 1
    }).

%% Send an Initial ACK packet
send_initial_ack(State) ->
    #state{pn_initial = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            % Nothing to ACK
            State;
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
            %% Build ACK frame tuple (not encoded yet)
            AckFrameTuple = build_ack_frame_tuple(Ranges),
            %% Try to coalesce ACK with small pending stream data
            maybe_coalesce_ack_with_data(AckFrameTuple, State)
    end.

%% Try to coalesce ACK frame with small pending stream data
%% Takes frame tuples (not encoded) to avoid re-decode overhead
maybe_coalesce_ack_with_data(AckFrameTuple, State) ->
    case dequeue_small_stream_frame_tuple(State) of
        {ok, StreamFrameTuple, State1} ->
            %% Send coalesced frames - pass tuples directly
            send_frame_tuples([AckFrameTuple, StreamFrameTuple], State1);
        none ->
            %% Single frame - encode and send
            send_app_packet_internal(quic_frame:encode(AckFrameTuple), [AckFrameTuple], State)
    end.

%% Dequeue a small stream frame tuple if available (< 500 bytes)
%% Returns the frame tuple (not encoded) to avoid re-decode overhead
-define(SMALL_FRAME_THRESHOLD, 500).
dequeue_small_stream_frame_tuple(#state{send_queue = PQ} = State) ->
    case pqueue_peek(PQ) of
        {value, {stream_data, StreamId, Offset, Data, Fin, DataSize}} when
            DataSize < ?SMALL_FRAME_THRESHOLD
        ->
            %% Remove from queue and return frame tuple (not encoded)
            {{value, _}, NewPQ} = pqueue_out(PQ),
            StreamFrameTuple = {stream, StreamId, Offset, Data, Fin},
            {ok, StreamFrameTuple, State#state{send_queue = NewPQ}};
        _ ->
            none
    end.

%% Send multiple frame tuples in a single packet
%% Takes frame tuples, encodes them, and passes directly to loss tracking
send_frame_tuples(FrameTuples, State) ->
    Payload = iolist_to_binary([quic_frame:encode(F) || F <- FrameTuples]),
    send_app_packet_internal(Payload, FrameTuples, State).

%% Build an ACK frame tuple (not encoded) from ranges
%% Used by send_app_ack for coalescing without re-decode overhead
build_ack_frame_tuple(Ranges) ->
    EncoderRanges = convert_ack_ranges_for_encode(Ranges),
    AckDelay = 0,
    {ack, EncoderRanges, AckDelay, undefined}.

%% Build an ACK frame from ranges (encoded)
%% Our internal format is [{Start, End}, ...] where Start <= End
%% quic_frame expects [{LargestAcked, FirstRange}, {Gap, Range}, ...]
%% where FirstRange = LargestAcked - SmallestAcked (count)
build_ack_frame(Ranges) ->
    quic_frame:encode(build_ack_frame_tuple(Ranges)).

%% Convert internal ACK ranges to encoder format
%% Limits ranges to MAX_ACK_RANGE (65536) to prevent receiver rejection
convert_ack_ranges_for_encode([{Start, End} | Rest]) ->
    %% First range: LargestAcked = End, FirstRange = End - Start
    %% Cap FirstRange at 65536 to stay within receiver's MAX_ACK_RANGE limit
    FirstRange = min(End - Start, 65536),
    %% Adjust Start for the capped range
    AdjustedStart = End - FirstRange,
    RestConverted = convert_rest_ranges(AdjustedStart, Rest),
    [{End, FirstRange} | RestConverted].

convert_rest_ranges(_PrevStart, []) ->
    [];
convert_rest_ranges(PrevStart, [{Start, End} | Rest]) ->
    %% Gap = PrevStart - End - 2 (number of missing packets between ranges)
    Gap = PrevStart - End - 2,
    %% Range = End - Start (number of packets in this block)
    Range = End - Start,
    %% Validate: Gap and Range must be non-negative for valid ACK ranges
    %% Also check that Range doesn't exceed MAX_ACK_RANGE (65536) to prevent receiver rejection
    case Gap >= 0 andalso Range >= 0 andalso Range =< 65536 of
        true ->
            [{Gap, Range} | convert_rest_ranges(Start, Rest)];
        false ->
            %% Skip malformed range (defensive - shouldn't happen with proper range tracking)
            %% Use PrevStart (not Start) to maintain correct gap calculation for next range
            convert_rest_ranges(PrevStart, Rest)
    end.

%% Send a Handshake packet
send_handshake_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        handshake_keys = {ClientKeys, ServerKeys},
        role = Role,
        pn_handshake = PNSpace
    } = State,

    %% Select correct keys based on role
    EncryptKeys =
        case Role of
            client -> ClientKeys;
            server -> ServerKeys
        end,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% First byte for Handshake: 1110 0000 | (PNLen - 1)
    FirstByte = 16#E0 bor (PNLen - 1),

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Build header prefix (length includes PN + encrypted payload + AEAD tag)
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8,
        DCID/binary,
        (byte_size(SCID)):8,
        SCID/binary,
        (quic_varint:encode(byte_size(PaddedPayload) + PNLen + 16))/binary
    >>,
    HeaderPrefix = <<FirstByte, HeaderBody/binary>>,

    %% Protect packet (encrypt + header protection in single call)
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EncryptKeys,
    Packet = quic_aead:protect_long_packet(
        Cipher, Key, IV, HP, PN, HeaderPrefix, PaddedPayload
    ),
    do_socket_send(Packet, State),

    %% Emit qlog packet_sent event
    quic_qlog:packet_sent(State#state.qlog_ctx, #{
        packet_type => handshake,
        packet_number => PN,
        length => byte_size(Packet)
    }),

    %% Update PN space and packet counter
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    apply_pending_socket_state(State#state{
        pn_handshake = NewPNSpace,
        packets_sent = State#state.packets_sent + 1
    }).

%% Send a 1-RTT (application) packet with a single frame (avoid encode/decode roundtrip)
%% This is the preferred send function - encodes once and passes frame for loss tracking
send_frame(Frame, State) ->
    Payload = quic_frame:encode(Frame),
    send_app_packet_internal(Payload, [Frame], State).

%% Send a 1-RTT (application) packet with pre-encoded binary payload
%% Decodes the payload to extract frame info for loss tracking
%% Note: Prefer send_frame/2 when frame tuple is available
send_app_packet(Payload, State) when is_binary(Payload) ->
    %% Try to decode the frame for proper loss tracking
    FrameInfo =
        case quic_frame:decode(Payload) of
            {Frame, _Rest} when is_tuple(Frame); is_atom(Frame) -> [Frame];
            % Fall back to empty if decode fails
            _ -> []
        end,
    send_app_packet_internal(Payload, FrameInfo, State).

%% Send a 1-RTT packet with explicit frames list for retransmission tracking
send_app_packet_internal(Payload, Frames, State) ->
    #state{
        dcid = DCID,
        app_keys = {ClientKeys, ServerKeys},
        role = Role,
        pn_app = PNSpace,
        cc_state = CCState,
        loss_state = LossState
    } = State,

    %% Select correct keys based on role
    EncryptKeys =
        case Role of
            client -> ClientKeys;
            server -> ServerKeys
        end,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Get current key phase for encoding
    KeyPhase = get_current_key_phase(State),

    %% First byte for short header: 01XX XXXX
    %% Bit 5 = spin bit (0), bits 3-4 reserved (0), bit 2 = key phase, bits 0-1 = PN length
    FirstByte = short_header_first_byte(KeyPhase, PNLen, State),

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Protect packet (encrypt + header protection in single call)
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EncryptKeys,
    Packet = quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, PN, FirstByte, DCID, PaddedPayload
    ),
    PacketSize = byte_size(Packet),
    SendResult = do_socket_send(Packet, State),

    %% Handle send result - only track packet and update state if send succeeded
    case SendResult of
        ok ->
            %% Emit qlog packet_sent event
            quic_qlog:packet_sent(State#state.qlog_ctx, #{
                packet_type => one_rtt,
                packet_number => PN,
                length => PacketSize,
                frames => Frames
            }),

            %% Track sent packet for loss detection and congestion control
            %% Determine if ack-eliciting by checking the actual frames list
            %% This properly handles coalesced packets with multiple frames
            AckEliciting = contains_ack_eliciting_frames(Frames),
            NewLossState = quic_loss:on_packet_sent(
                LossState, PN, PacketSize, AckEliciting, Frames
            ),
            NewCCState =
                case AckEliciting of
                    true -> quic_cc:on_packet_sent(CCState, PacketSize);
                    false -> CCState
                end,

            %% Update PN space and packet counter for liveness detection
            NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
            State1 = apply_pending_socket_state(State#state{
                pn_app = NewPNSpace,
                cc_state = NewCCState,
                loss_state = NewLossState,
                packets_sent = State#state.packets_sent + 1
            }),

            %% Update activity timestamp on successful send
            %% This prevents idle timeout during long one-way transfers
            State2 = update_last_activity(State1),

            %% Mark PTO dirty for batched timer reset (actual reset at flush)
            mark_pto_dirty(State2);
        {error, Reason} ->
            %% Send failed - do NOT track packet as sent to avoid CC/loss inconsistency
            %% The data will be re-sent via the PTO timeout mechanism
            ?LOG_WARNING(
                #{
                    what => udp_send_failed,
                    reason => Reason,
                    pn => PN,
                    size => PacketSize
                },
                ?QUIC_LOG_META
            ),
            %% Still bump PN to avoid reusing packet numbers
            NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
            State#state{pn_app = NewPNSpace}
    end.

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

%% @doc Pad payload for path validation to reach 1200 bytes.
%% RFC 9000 Section 8.2.1: Path validation packets MUST be padded to at least
%% 1200 bytes to verify PMTU and prevent amplification attacks.
%% PADDING frames (0x00 bytes) are added to the payload BEFORE AEAD protection.
-spec pad_for_path_validation(binary(), binary()) -> binary().
pad_for_path_validation(Payload, DCID) ->
    %% Estimate final packet size after protection:
    %% - Short header: 1 (flags) + DCID length + 1-4 (PN) ~= 1 + len(DCID) + 2
    %% - Payload (with padding) + AEAD tag (16 bytes)
    HeaderSize = 1 + byte_size(DCID) + 2,
    AEADTagSize = 16,
    MinPacketSize = 1200,
    CurrentSize = HeaderSize + byte_size(Payload) + AEADTagSize,
    case CurrentSize >= MinPacketSize of
        true ->
            Payload;
        false ->
            PadLen = MinPacketSize - CurrentSize,
            %% PADDING frames are 0x00 bytes - add them to the payload
            PaddingFrames = binary:copy(<<0>>, PadLen),
            <<Payload/binary, PaddingFrames/binary>>
    end.

%%====================================================================
%% Internal Functions - Frame Classification (RFC 9000 Section 9.1)
%%====================================================================

%% @doc Check if a frame is a probing frame.
%% RFC 9000 Section 9.1: Probing frames are PATH_CHALLENGE, PATH_RESPONSE,
%% NEW_CONNECTION_ID, and PADDING. Only non-probing frames trigger migration.
-spec is_probing_frame(term()) -> boolean().
is_probing_frame(padding) -> true;
is_probing_frame({padding, _}) -> true;
is_probing_frame({path_challenge, _}) -> true;
is_probing_frame({path_response, _}) -> true;
is_probing_frame({new_connection_id, _, _, _, _}) -> true;
is_probing_frame(_) -> false.

%% @doc Check if a list of frames contains any non-probing frame.
%% RFC 9000 Section 9.1: Only packets containing non-probing frames trigger migration.
-spec contains_non_probing_frame([term()]) -> boolean().
contains_non_probing_frame([]) ->
    false;
contains_non_probing_frame([Frame | Rest]) ->
    case is_probing_frame(Frame) of
        true -> contains_non_probing_frame(Rest);
        false -> true
    end.

%%====================================================================
%% Internal Functions - Packet Processing
%%====================================================================

%% Handle incoming packet (may be coalesced with multiple QUIC packets)
handle_packet(Data, State) ->
    handle_packet_loop(Data, State).

%% Handle batch of packets from GRO - process all without re-entering gen_statem
%% This is more efficient than receiving multiple messages
handle_packets_batch([], State) ->
    State;
handle_packets_batch([Packet | Rest], State) ->
    NewState = handle_packet_loop(Packet, State),
    handle_packets_batch(Rest, NewState).

handle_packet_loop(<<>>, #state{role = client, socket = Socket, active_n = N} = State) ->
    %% No more data to process - re-enable socket for client connections
    %% Note: With {active, N}, calling setopts resets the counter, so this is optional
    %% but provides safety in case socket went passive during processing
    inet:setopts(Socket, [{active, N}]),
    State;
handle_packet_loop(<<>>, #state{role = server} = State) ->
    %% No more data to process - server socket managed by listener
    State;
handle_packet_loop(Data, State) ->
    case decode_and_decrypt_packet(Data, State) of
        {ok, Type, Frames, RemainingData, NewState, processed} ->
            %% Frames already processed by streaming decode
            %% Emit qlog packet_received event
            quic_qlog:packet_received(NewState#state.qlog_ctx, #{
                packet_type => Type,
                frames => Frames
            }),

            %% Increment packet counter for liveness detection
            NewState1 = NewState#state{
                packets_received = NewState#state.packets_received + 1
            },

            %% Emit qlog frames_processed event
            quic_qlog:frames_processed(NewState1#state.qlog_ctx, Frames),

            %% Send ACK if packet contained ack-eliciting frames
            State2 = maybe_send_ack(Type, Frames, NewState1),
            %% Continue with remaining coalesced packets
            handle_packet_loop(RemainingData, State2);
        {ok, Type, Frames, RemainingData, NewState} ->
            %% Legacy path - frames need to be processed
            quic_qlog:packet_received(NewState#state.qlog_ctx, #{
                packet_type => Type,
                frames => Frames
            }),

            NewState1 = NewState#state{
                packets_received = NewState#state.packets_received + 1
            },
            State1 = process_frames_noreenbl(Type, Frames, NewState1),
            quic_qlog:frames_processed(State1#state.qlog_ctx, Frames),
            State2 = maybe_send_ack(Type, Frames, State1),
            handle_packet_loop(RemainingData, State2);
        {error, stateless_reset} ->
            %% RFC 9000 Section 10.3: Stateless reset received
            %% Immediately close the connection
            maybe_reenable_socket(State),
            State#state{close_reason = stateless_reset};
        {error, Reason} when
            Reason =:= padding_only;
            Reason =:= empty_packet;
            Reason =:= invalid_fixed_bit
        ->
            %% End of coalesced packets (padding or invalid trailing data)
            %% This is normal, just re-enable socket and return
            maybe_reenable_socket(State),
            State;
        {error, Reason} ->
            %% Log decryption failure for debugging
            ?LOG_WARNING(
                #{
                    what => packet_decode_decrypt_failed,
                    role => State#state.role,
                    reason => Reason,
                    size => byte_size(Data)
                },
                ?QUIC_LOG_META
            ),
            %% Re-enable socket
            maybe_reenable_socket(State),
            State
    end.

%% Re-enable socket for receiving - only for client connections.
%% Server connections use listener's socket which is managed by the listener.
%% With {active, N}, this resets the counter (provides safety margin).
maybe_reenable_socket(#state{role = client, socket = Socket, active_n = N}) ->
    inet:setopts(Socket, [{active, N}]);
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
            ?LOG_WARNING(
                #{
                    what => invalid_short_header_fixed_bit,
                    first_byte => binary:first(Data)
                },
                ?QUIC_LOG_META
            ),
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
        %% Initial
        0 ->
            decode_initial_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        %% 0-RTT
        1 ->
            decode_zero_rtt_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        %% Handshake
        2 ->
            decode_handshake_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        %% Retry (RFC 9000 Section 17.2.5)
        3 ->
            handle_retry_packet(Data, Version, SCID, Rest3, State);
        _ ->
            {error, unsupported_packet_type}
    end.

decode_initial_packet(FullPacket, FirstByte, _DCID, PeerSCID, Rest, State) ->
    #state{initial_keys = {ClientKeys, ServerKeys}, role = Role} = State,

    %% Select correct keys based on role:
    %% - Client receives from server -> use ServerKeys
    %% - Server receives from client -> use ClientKeys
    DecryptKeys =
        case Role of
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
    State1 =
        case State#state.dcid of
            <<>> ->
                % First packet, set DCID
                State#state{dcid = PeerSCID};
            _ when State#state.dcid =:= State#state.original_dcid ->
                % Client updates dcid after first server packet
                State#state{dcid = PeerSCID};
            _ ->
                % Already updated
                State
        end,

    %% Ensure we have enough data
    case byte_size(Payload) >= PayloadLen of
        true ->
            <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
            decrypt_packet(
                initial, Header, FirstByte, EncryptedPayload, RemainingData, DecryptKeys, State1
            );
        false ->
            {error, incomplete_packet}
    end.

decode_handshake_packet(FullPacket, FirstByte, _DCID, _SCID, Rest, State) ->
    case State#state.handshake_keys of
        undefined ->
            {error, no_handshake_keys};
        {ClientKeys, ServerKeys} ->
            %% Select correct keys based on role
            DecryptKeys =
                case State#state.role of
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
                    decrypt_packet(
                        handshake,
                        Header,
                        FirstByte,
                        EncryptedPayload,
                        RemainingData,
                        DecryptKeys,
                        State
                    );
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
decode_zero_rtt_packet(
    FullPacket, FirstByte, _DCID, _SCID, Rest, #state{early_keys = {EarlyKeys, _}} = State
) ->
    %% Parse length
    {PayloadLen, Rest2} = quic_varint:decode(Rest),
    HeaderLen = byte_size(FullPacket) - byte_size(Rest2),
    <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

    case byte_size(Payload) >= PayloadLen of
        true ->
            <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
            decrypt_packet(
                zero_rtt, Header, FirstByte, EncryptedPayload, RemainingData, EarlyKeys, State
            );
        false ->
            {error, incomplete_packet}
    end.

%% Handle Retry packet (RFC 9000 Section 8.1, RFC 9001 Section 5.8)
%% A client receives a Retry when the server requests address validation.
handle_retry_packet(
    _FullPacket,
    _Version,
    _ServerSCID,
    _Rest,
    #state{role = server}
) ->
    %% Servers don't receive Retry packets
    {error, unexpected_retry};
handle_retry_packet(
    _FullPacket,
    _Version,
    _ServerSCID,
    _Rest,
    #state{retry_received = true}
) ->
    %% RFC 9000 Section 17.2.5.2: MUST discard subsequent Retry packets
    {error, duplicate_retry};
handle_retry_packet(
    FullPacket,
    Version,
    ServerSCID,
    Rest,
    #state{role = client, original_dcid = OriginalDCID} = State
) ->
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
    %% Store retry_scid for later validation of transport params (RFC 9000 Section 7.3)
    State1 = State#state{
        dcid = ServerSCID,
        retry_token = RetryToken,
        retry_received = true,
        retry_scid = ServerSCID
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
            ?LOG_WARNING(#{what => no_app_keys_short_header}, ?QUIC_LOG_META),
            %% No app keys yet - check if this might be a stateless reset
            check_stateless_reset(Data, State);
        {ClientKeys, ServerKeys} ->
            %% Select correct keys based on role
            DecryptKeys =
                case State#state.role of
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
                    ?LOG_WARNING(#{what => short_header_decryption_failed}, ?QUIC_LOG_META),
                    %% Decryption failed - check if this is a stateless reset
                    check_stateless_reset(Data, State);
                {ok, _Type, _Frames, _Remaining, _NewState} = Result ->
                    Result;
                Other ->
                    Other
            end
    end.

%% Decrypt an application (1-RTT) packet with key phase handling
%% Uses 2-stage API: unprotect header to get key_phase, then decrypt with selected keys
decrypt_app_packet(Header, EncryptedPayload, CurrentKeys, State) ->
    #crypto_keys{hp = HP} = CurrentKeys,
    PNOffset = byte_size(Header),

    %% Stage 1: Unprotect header to get key_phase and PN info
    case quic_aead:unprotect_short_header(HP, Header, EncryptedPayload, PNOffset) of
        {error, Reason} ->
            {error, Reason};
        {ok, KeyPhase, PNLen, TruncatedPN, UnprotectedHeader} ->
            %% Select keys based on key_phase
            {DecryptKeys, State1} = select_decrypt_keys(KeyPhase, State),
            PeerDecryptKeys =
                case State1#state.role of
                    % ClientKeys
                    server -> element(1, DecryptKeys);
                    % ServerKeys
                    client -> element(2, DecryptKeys)
                end,

            %% Stage 2: Decrypt with selected keys
            #crypto_keys{key = Key, iv = IV, cipher = Cipher} = PeerDecryptKeys,
            LargestRecv = get_largest_recv(app, State1),
            case
                quic_aead:decrypt_short_payload(
                    Cipher,
                    Key,
                    IV,
                    UnprotectedHeader,
                    PNLen,
                    TruncatedPN,
                    EncryptedPayload,
                    LargestRecv
                )
            of
                {ok, PN, Plaintext} ->
                    <<UnprotectedFirstByte, _/binary>> = UnprotectedHeader,
                    State2 = update_spin_from_recv(
                        UnprotectedFirstByte, PN, record_received_pn(app, PN, State1)
                    ),
                    State3 = update_last_activity(State2),
                    %% Use streaming decode for efficiency
                    case decode_and_process_streaming(app, Plaintext, State3) of
                        {ok, NewState, Frames} ->
                            {ok, app, Frames, <<>>, NewState, processed};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, decryption_failed} ->
                    {error, decryption_failed}
            end
    end.

%% Decrypt a long header packet (Initial/Handshake)
%% RemainingData is the data after this packet (for coalesced packets)
decrypt_packet(Level, Header, _FirstByte, EncryptedPayload, RemainingData, Keys, State) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = Keys,
    LargestRecv = get_largest_recv(Level, State),

    %% Unprotect and decrypt in single call
    case
        quic_aead:unprotect_long_packet(Cipher, Key, IV, HP, Header, EncryptedPayload, LargestRecv)
    of
        {error, Reason} ->
            {error, Reason};
        {ok, PN, _UnprotectedHeader, Plaintext} ->
            %% Track received packet number for ACK generation
            State1 = record_received_pn(Level, PN, State),
            State2 = update_last_activity(State1),
            %% Use streaming decode for efficiency
            case decode_and_process_streaming(Level, Plaintext, State2) of
                {ok, NewState, Frames} ->
                    {ok, Level, Frames, RemainingData, NewState, processed};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% Process decoded frames without re-enabling socket (for coalesced packets)
process_frames_noreenbl(_Level, [], State) ->
    State;
process_frames_noreenbl(Level, [Frame | Rest], State) ->
    NewState = process_frame_track_probing(Level, Frame, State),
    process_frames_noreenbl(Level, Rest, NewState).

%% Streaming decode and process - decodes and processes frames without building intermediate list
%% Returns {ok, State, FrameList} where FrameList is accumulated for qlog/ACK tracking
%% This is more efficient than decode_all + process_frames for typical packets
decode_and_process_streaming(Level, Plaintext, State) ->
    decode_and_process_streaming(Level, Plaintext, State, []).

decode_and_process_streaming(_Level, <<>>, State, Acc) ->
    {ok, State, lists:reverse(Acc)};
decode_and_process_streaming(Level, Data, State, Acc) ->
    case quic_frame:decode(Data) of
        {error, Reason} ->
            {error, {frame_decode_error, Reason}};
        {Frame, Rest} ->
            NewState = process_frame_track_probing(Level, Frame, State),
            decode_and_process_streaming(Level, Rest, NewState, [Frame | Acc])
    end.

%% @doc Process a frame and track if it's a non-probing frame.
%% RFC 9000 Section 9.1: Only packets containing non-probing frames trigger migration.
-spec process_frame_track_probing(atom(), term(), #state{}) -> #state{}.
process_frame_track_probing(Level, Frame, State) ->
    %% Update has_non_probing_frame flag if this is a non-probing frame
    State1 =
        case State#state.has_non_probing_frame of
            true ->
                %% Already set, skip check
                State;
            false ->
                case is_probing_frame(Frame) of
                    true -> State;
                    false -> State#state{has_non_probing_frame = true}
                end
        end,
    process_frame(Level, Frame, State1).

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
            case quic_loss:on_ack_received(LossState, AckFrame, Now) of
                {error, ack_range_too_large} ->
                    %% RFC 9000: Invalid ACK range is a protocol violation
                    ?LOG_ERROR(#{what => invalid_ack_range}, ?QUIC_LOG_META),
                    State;
                {NewLossState, AckedPackets, LostPackets, AckMeta} ->
                    %% Use pre-computed metadata from quic_loss (avoids redundant scanning)
                    AckedBytes = maps:get(acked_bytes, AckMeta, 0),
                    LargestAckedSentTime = maps:get(largest_ae_time, AckMeta, Now),
                    HasAckEliciting = maps:get(has_ack_eliciting, AckMeta, false),
                    LostBytes = maps:get(lost_bytes, AckMeta, 0),
                    LargestLostSentTime = maps:get(largest_lost_sent_time, AckMeta, undefined),

                    %% Only update CC ACK processing if there are ack-eliciting packets
                    %% When only non-ack-eliciting packets are ACKed, skip on_packets_acked
                    %% to prevent false recovery exit (LargestAckedSentTime=Now would always
                    %% satisfy > RecoveryStart after min_duration). Loss handling is done
                    %% separately by on_packets_lost and on_congestion_event.
                    CCState1 =
                        case HasAckEliciting of
                            false ->
                                %% No ack-eliciting acks - skip CC ACK update entirely
                                CCState;
                            true ->
                                quic_cc:on_packets_acked(CCState, AckedBytes, LargestAckedSentTime)
                        end,
                    CCState2 = quic_cc:on_packets_lost(CCState1, LostBytes),

                    %% If there was loss, signal congestion event using pre-computed sent time
                    CCState3 =
                        case LargestLostSentTime of
                            undefined ->
                                CCState2;
                            _ ->
                                quic_cc:on_congestion_event(CCState2, LargestLostSentTime)
                        end,

                    %% Process ECN counts if present (RFC 9002 Section 7.1)
                    CCState4 = process_ecn_counts(ECN, CCState3),

                    %% Check for persistent congestion (RFC 9002 Section 7.6)
                    CCState5 = check_persistent_congestion(LostPackets, NewLossState, CCState4),

                    %% Update pacing rate based on new RTT estimate (RFC 9002 Section 7.7)
                    %% Only update pacing when we have a real RTT sample to avoid
                    %% using the default 100ms RTT which causes excessive pacing delays
                    CCState6 =
                        case quic_loss:has_rtt_sample(NewLossState) of
                            true ->
                                SmoothedRTT = quic_loss:smoothed_rtt(NewLossState),
                                quic_cc:update_pacing_rate(CCState5, SmoothedRTT);
                            false ->
                                CCState5
                        end,

                    State1 = State#state{
                        loss_state = NewLossState,
                        cc_state = CCState6
                    },

                    %% Emit qlog packets_acked event
                    AckedPNs = [P#sent_packet.pn || P <- AckedPackets],
                    RTTSample =
                        case AckedPackets of
                            [] -> undefined;
                            _ -> Now - LargestAckedSentTime
                        end,
                    quic_qlog:packets_acked(State1#state.qlog_ctx, AckedPNs, #{
                        rtt_sample => RTTSample
                    }),

                    %% Emit qlog packet_lost events
                    lists:foreach(
                        fun(#sent_packet{pn = LostPN}) ->
                            quic_qlog:packet_lost(State1#state.qlog_ctx, #{
                                packet_number => LostPN,
                                reason => timeout
                            })
                        end,
                        LostPackets
                    ),

                    %% Handle PMTU probe ACKs
                    State2 = lists:foldl(
                        fun(#sent_packet{pn = PN}, S) ->
                            handle_pmtu_probe_ack(PN, S)
                        end,
                        State1,
                        AckedPackets
                    ),

                    %% Handle PMTU probe losses
                    %% Pass packet size directly since packets are removed from sent_packets
                    State3 = lists:foldl(
                        fun(#sent_packet{pn = PN, size = Size}, S) ->
                            handle_pmtu_probe_loss(PN, Size, S)
                        end,
                        State2,
                        LostPackets
                    ),

                    %% Retransmit lost packets
                    State4 = retransmit_lost_packets(LostPackets, State3),

                    %% Reset PTO timer after ACK processing
                    State5 = set_pto_timer(State4),

                    %% Try to send queued data now that cwnd may have freed up
                    State6 = process_send_queue(State5),
                    %% Event-driven flush: flush batch and timers after ACK processing
                    flush_dirty_timers(flush_socket_batch(State6))
                %% close inner case (on_ack_received)
            end
        %% close outer case (Ranges)
    end;
%% HANDSHAKE_DONE: Server confirms handshake complete
%% RFC 9000 Section 19.20: Only server can send, only in 1-RTT (app level)
process_frame(app, handshake_done, #state{role = client} = State) ->
    %% Server confirmed handshake complete (client receiving from server)
    State;
process_frame(app, handshake_done, #state{role = server} = State) ->
    %% Protocol violation: server received HANDSHAKE_DONE (only client should receive)
    ?LOG_WARNING(
        #{what => invalid_handshake_done_frame, reason => server_received}, ?QUIC_LOG_META
    ),
    State#state{close_reason = {protocol_violation, handshake_done_from_client}};
process_frame(Level, handshake_done, State) when Level =/= app ->
    %% Protocol violation: HANDSHAKE_DONE must be in 1-RTT packets
    ?LOG_WARNING(#{what => invalid_handshake_done_level, level => Level}, ?QUIC_LOG_META),
    State#state{close_reason = {protocol_violation, handshake_done_wrong_level}};
process_frame(app, {stream, StreamId, Offset, Data, Fin}, State) ->
    process_stream_data(StreamId, Offset, Data, Fin, State);
%% MAX_DATA: Peer is increasing connection-level flow control limit
%% RFC 9000 Section 19.9: MAX_DATA is only allowed in 1-RTT packets
process_frame(app, {max_data, MaxData}, #state{max_data_remote = Current} = State) ->
    case MaxData > Current of
        true ->
            %% Limit increased - try to drain queued data
            State1 = State#state{max_data_remote = MaxData},
            State2 = process_send_queue(State1),
            %% Event-driven flush: flush batch and timers after flow control opens
            flush_dirty_timers(flush_socket_batch(State2));
        false ->
            %% Monotonic: ignore if not increasing (per RFC 9000)
            State
    end;
process_frame(Level, {max_data, _}, State) when Level =/= app ->
    %% Protocol violation: MAX_DATA only allowed in 1-RTT packets
    ?LOG_WARNING(#{what => invalid_max_data_level, level => Level}, ?QUIC_LOG_META),
    State#state{close_reason = {protocol_violation, max_data_wrong_level}};
%% MAX_STREAM_DATA: Peer is increasing stream-level flow control limit
%% RFC 9000 Section 19.10: MAX_STREAM_DATA is only allowed in 1-RTT packets
process_frame(app, {max_stream_data, StreamId, MaxData}, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream_state{send_max_data = Current} = Stream} ->
            ?LOG_DEBUG(
                #{
                    what => received_max_stream_data,
                    stream_id => StreamId,
                    new_limit => MaxData,
                    current_limit => Current,
                    will_update => MaxData > Current
                },
                ?QUIC_LOG_META
            ),
            case MaxData > Current of
                true ->
                    NewStream = Stream#stream_state{send_max_data = MaxData},
                    State1 = State#state{streams = maps:put(StreamId, NewStream, Streams)},
                    %% Limit increased - try to drain queued data
                    State2 = process_send_queue(State1),
                    %% Event-driven flush: flush batch and timers after stream flow control opens
                    flush_dirty_timers(flush_socket_batch(State2));
                false ->
                    %% Monotonic: ignore if not increasing
                    State
            end;
        error ->
            ?LOG_DEBUG(
                #{
                    what => received_max_stream_data_unknown_stream,
                    stream_id => StreamId,
                    new_limit => MaxData
                },
                ?QUIC_LOG_META
            ),
            State
    end;
process_frame(Level, {max_stream_data, _, _}, State) when Level =/= app ->
    %% Protocol violation: MAX_STREAM_DATA only allowed in 1-RTT packets
    ?LOG_WARNING(#{what => invalid_max_stream_data_level, level => Level}, ?QUIC_LOG_META),
    State#state{close_reason = {protocol_violation, max_stream_data_wrong_level}};
%% MAX_STREAMS: Peer is increasing the number of streams we can open
%% RFC 9000 Section 19.11: MAX_STREAMS is only allowed in 1-RTT packets
process_frame(app, {max_streams, bidi, Max}, #state{max_streams_bidi_remote = Current} = State) ->
    case Max > Current of
        true ->
            State#state{max_streams_bidi_remote = Max};
        false ->
            State
    end;
process_frame(app, {max_streams, uni, Max}, #state{max_streams_uni_remote = Current} = State) ->
    case Max > Current of
        true ->
            State#state{max_streams_uni_remote = Max};
        false ->
            State
    end;
process_frame(Level, {max_streams, _, _}, State) when Level =/= app ->
    %% Protocol violation: MAX_STREAMS only allowed in 1-RTT packets
    ?LOG_WARNING(#{what => invalid_max_streams_level, level => Level}, ?QUIC_LOG_META),
    State#state{close_reason = {protocol_violation, max_streams_wrong_level}};
%% PATH_CHALLENGE: Peer is probing the path, respond with PATH_RESPONSE
%% RFC 9000 Section 8.2.2: PATH_RESPONSE MUST be sent on the path where the
%% PATH_CHALLENGE was received (to the source address of that packet).
process_frame(app, {path_challenge, ChallengeData}, State) ->
    %% Send PATH_RESPONSE to the address that sent the PATH_CHALLENGE
    SourceAddr = State#state.current_packet_source,
    case SourceAddr of
        {_IP, _Port} ->
            %% Send padded PATH_RESPONSE to the source address
            send_path_response_to_addr(SourceAddr, ChallengeData, State);
        undefined ->
            %% Fallback: no source tracked (shouldn't happen in normal flow)
            %% Send via normal send_frame to current remote_addr
            send_frame({path_response, ChallengeData}, State)
    end;
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
process_frame(_Level, {connection_close, Type, Code, FrameType, ReasonPhrase}, State) ->
    %% Preserve peer error details for owner notification
    CloseReason =
        case Type of
            application ->
                {peer_closed, application, Code, ReasonPhrase};
            transport ->
                {peer_closed, transport, Code, FrameType, ReasonPhrase}
        end,
    State#state{close_reason = CloseReason};
%% RESET_STREAM: Peer is aborting a stream they initiated or we initiated for sending
%% RFC 9000 Section 19.4
process_frame(
    app,
    {reset_stream, StreamId, ErrorCode, FinalSize},
    #state{owner = Owner, streams = Streams} = State
) ->
    %% RFC 9000 Section 4.5: Validate final size against any previously known value
    case maps:find(StreamId, Streams) of
        {ok, #stream_state{final_size = ExistingFinalSize}} when
            ExistingFinalSize =/= undefined andalso ExistingFinalSize =/= FinalSize
        ->
            %% FINAL_SIZE_ERROR: RESET_STREAM has different final size than previously known
            ?LOG_WARNING(
                #{
                    what => final_size_error,
                    stream_id => StreamId,
                    existing => ExistingFinalSize,
                    reset_stream => FinalSize
                },
                ?QUIC_LOG_META
            ),
            CloseFrame =
                {connection_close, transport, ?QUIC_FINAL_SIZE_ERROR, 0,
                    <<"RESET_STREAM final size mismatch">>},
            send_frame(CloseFrame, State#state{close_reason = final_size_error});
        {ok, Stream} ->
            %% Mark stream as reset, store final size for flow control accounting
            NewStreams = maps:put(
                StreamId,
                Stream#stream_state{
                    state = reset,
                    final_size = FinalSize
                },
                Streams
            ),
            Owner ! {quic, self(), {stream_reset, StreamId, ErrorCode}},
            State#state{streams = NewStreams};
        error ->
            %% Unknown stream - notify owner and create minimal state to track reset
            Owner ! {quic, self(), {stream_opened, StreamId}},
            NewStreams = maps:put(
                StreamId,
                #stream_state{
                    id = StreamId,
                    state = reset,
                    final_size = FinalSize
                },
                Streams
            ),
            Owner ! {quic, self(), {stream_reset, StreamId, ErrorCode}},
            State#state{streams = NewStreams}
    end;
%% RESET_STREAM_AT: Peer is aborting a stream with reliable delivery guarantee
%% draft-ietf-quic-reliable-stream-reset-07
process_frame(
    app,
    {reset_stream_at, StreamId, ErrorCode, FinalSize, ReliableSize},
    #state{owner = Owner, streams = Streams} = State
) ->
    %% Validate: ReliableSize <= FinalSize (FRAME_ENCODING_ERROR per spec)
    case ReliableSize > FinalSize of
        true ->
            CloseFrame =
                {connection_close, transport, ?QUIC_FRAME_ENCODING_ERROR, 0,
                    <<"RESET_STREAM_AT reliable_size > final_size">>},
            send_frame(CloseFrame, State#state{close_reason = frame_encoding_error});
        false ->
            case maps:find(StreamId, Streams) of
                {ok, #stream_state{final_size = ExistingFinalSize}} when
                    ExistingFinalSize =/= undefined andalso ExistingFinalSize =/= FinalSize
                ->
                    %% STREAM_STATE_ERROR: FinalSize changed
                    CloseFrame =
                        {connection_close, transport, ?QUIC_STREAM_STATE_ERROR, 0,
                            <<"RESET_STREAM_AT final_size changed">>},
                    send_frame(CloseFrame, State#state{close_reason = stream_state_error});
                {ok, #stream_state{reset_error = ExistingError}} when
                    ExistingError =/= undefined andalso ExistingError =/= ErrorCode
                ->
                    %% STREAM_STATE_ERROR: ErrorCode changed
                    CloseFrame =
                        {connection_close, transport, ?QUIC_STREAM_STATE_ERROR, 0,
                            <<"RESET_STREAM_AT error_code changed">>},
                    send_frame(CloseFrame, State#state{close_reason = stream_state_error});
                {ok, #stream_state{reset_reliable_size = ExistingReliable}} when
                    ExistingReliable =/= undefined andalso ReliableSize > ExistingReliable
                ->
                    %% Spec: Ignore if ReliableSize increased (not an error, just ignore)
                    State;
                {ok, Stream} ->
                    %% Valid RESET_STREAM_AT - update stream state
                    NewStreams = maps:put(
                        StreamId,
                        Stream#stream_state{
                            state = reset,
                            final_size = FinalSize,
                            reset_reliable_size = ReliableSize,
                            reset_error = ErrorCode
                        },
                        Streams
                    ),
                    %% Notify owner - same message as RESET_STREAM
                    Owner ! {quic, self(), {stream_reset, StreamId, ErrorCode}},
                    State#state{streams = NewStreams};
                error ->
                    %% Unknown stream - notify owner and create minimal state
                    Owner ! {quic, self(), {stream_opened, StreamId}},
                    NewStreams = maps:put(
                        StreamId,
                        #stream_state{
                            id = StreamId,
                            state = reset,
                            final_size = FinalSize,
                            reset_reliable_size = ReliableSize,
                            reset_error = ErrorCode
                        },
                        Streams
                    ),
                    Owner ! {quic, self(), {stream_reset, StreamId, ErrorCode}},
                    State#state{streams = NewStreams}
            end
    end;
%% STOP_SENDING: Peer wants us to stop sending on a stream
%% RFC 9000 Section 19.5
process_frame(
    app,
    {stop_sending, StreamId, ErrorCode},
    #state{owner = Owner, streams = Streams} = State
) ->
    %% Clear any queued data for this stream and mark as stopped
    NewStreams =
        case maps:find(StreamId, Streams) of
            {ok, Stream} ->
                maps:put(
                    StreamId,
                    Stream#stream_state{
                        state = stopped,
                        % Clear queued data
                        send_buffer = []
                    },
                    Streams
                );
            error ->
                %% Unknown stream - notify owner and create minimal state
                Owner ! {quic, self(), {stream_opened, StreamId}},
                maps:put(
                    StreamId,
                    #stream_state{
                        id = StreamId,
                        state = stopped
                    },
                    Streams
                )
        end,
    %% Notify owner - they should stop sending and may send RESET_STREAM
    Owner ! {quic, self(), {stop_sending, StreamId, ErrorCode}},
    %% Also remove from send queue and adjust byte count
    {NewSendQueue, RemovedBytes} = remove_stream_from_queue(StreamId, State#state.send_queue),
    NewQueueBytes = State#state.send_queue_bytes - RemovedBytes,
    State#state{streams = NewStreams, send_queue = NewSendQueue, send_queue_bytes = NewQueueBytes};
%% STREAM_DATA_BLOCKED: Peer is blocked by stream-level flow control
%% RFC 9000 Section 19.13: Receipt opens the stream (Section 3.2)
process_frame(
    app,
    {stream_data_blocked, StreamId, _Limit},
    #state{owner = Owner, streams = Streams} = State
) ->
    case maps:is_key(StreamId, Streams) of
        true ->
            %% Stream already exists, nothing to do (informational frame)
            State;
        false ->
            %% New stream from peer - notify owner
            Owner ! {quic, self(), {stream_opened, StreamId}},
            %% Create minimal stream state
            InitSendMaxData = get_peer_stream_limit(bidi_peer_initiated, State),
            InitRecvMaxData = get_local_recv_limit(bidi_peer_initiated, State),
            NewStream = #stream_state{
                id = StreamId,
                state = open,
                send_max_data = InitSendMaxData,
                recv_max_data = InitRecvMaxData
            },
            State#state{streams = maps:put(StreamId, NewStream, Streams)}
    end;
%% DATA_BLOCKED: Peer is blocked by connection-level flow control (informational)
%% RFC 9000 Section 19.12: DATA_BLOCKED is only allowed in 1-RTT packets
process_frame(app, {data_blocked, _Limit}, State) ->
    %% Informational - no action needed
    State;
process_frame(Level, {data_blocked, _}, State) when Level =/= app ->
    %% Protocol violation: DATA_BLOCKED only allowed in 1-RTT packets
    ?LOG_WARNING(#{what => invalid_data_blocked_level, level => Level}, ?QUIC_LOG_META),
    State#state{close_reason = {protocol_violation, data_blocked_wrong_level}};
%% DATAGRAM frames (RFC 9221)
%% RFC 9221: MUST terminate with PROTOCOL_VIOLATION if receiving DATAGRAM
%% without having advertised support (max_datagram_frame_size = 0)
process_frame(app, {datagram, _Data}, #state{max_datagram_frame_size_local = 0} = State) ->
    send_protocol_violation(<<"unexpected DATAGRAM frame">>, State);
process_frame(
    app, {datagram_with_length, _Data}, #state{max_datagram_frame_size_local = 0} = State
) ->
    send_protocol_violation(<<"unexpected DATAGRAM frame">>, State);
%% RFC 9221: MUST terminate with PROTOCOL_VIOLATION if receiving oversized DATAGRAM
process_frame(app, {datagram, Data}, #state{max_datagram_frame_size_local = Max} = State) when
    byte_size(Data) > Max
->
    send_protocol_violation(<<"DATAGRAM frame too large">>, State);
process_frame(
    app, {datagram_with_length, Data}, #state{max_datagram_frame_size_local = Max} = State
) when byte_size(Data) > Max ->
    send_protocol_violation(<<"DATAGRAM frame too large">>, State);
process_frame(app, {datagram, Data}, State) ->
    deliver_datagram(Data, State);
process_frame(app, {datagram_with_length, Data}, State) ->
    deliver_datagram(Data, State);
%% NEW_TOKEN (RFC 9000 §8.1.3): servers MUST treat receipt as
%% PROTOCOL_VIOLATION. Clients accept and currently discard; caching
%% the token for reconnect-without-retry reuse depends on server-side
%% token issuance + validation, which aren't implemented yet and are
%% tracked as a follow-up.
process_frame(app, {new_token, _}, #state{role = server} = State) ->
    send_protocol_violation(<<"NEW_TOKEN received by server">>, State);
process_frame(app, {new_token, _}, #state{role = client} = State) ->
    State;
process_frame(_Level, _Frame, State) ->
    %% Ignore unknown frames
    State.

%% Helper to remove a stream from the send queue (tuple of 8 queues)
%% Returns {NewPQ, RemovedBytes} to allow adjusting send_queue_bytes
remove_stream_from_queue(StreamId, PQ) ->
    %% Filter out entries for this stream from all 8 priority buckets
    %% Queue entries are 6-tuples: {stream_data, StreamId, Offset, Data, Fin, DataSize}
    {NewQueues, RemovedBytes} =
        lists:foldl(
            fun(I, {Queues, Bytes}) ->
                Q = element(I, PQ),
                %% Calculate bytes to remove before filtering (use cached DataSize)
                BytesToRemove = queue:fold(
                    fun({stream_data, SId, _, _Data, _, DataSize}, Acc) ->
                        case SId of
                            StreamId -> Acc + DataSize;
                            _ -> Acc
                        end
                    end,
                    0,
                    Q
                ),
                %% Filter to keep only other streams
                Kept = queue:filter(
                    fun({stream_data, SId, _, _, _, _}) -> SId =/= StreamId end, Q
                ),
                {[Kept | Queues], Bytes + BytesToRemove}
            end,
            {[], 0},
            lists:seq(1, 8)
        ),
    {list_to_tuple(lists:reverse(NewQueues)), RemovedBytes}.

%% Buffer CRYPTO data and process when complete messages are available
buffer_crypto_data(Level, Offset, Data, State) ->
    LevelAtom =
        case Level of
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
process_tls_message(
    _Level,
    ?TLS_CLIENT_HELLO,
    Body,
    OriginalMsg,
    #state{role = server, tls_state = ?TLS_AWAITING_CLIENT_HELLO} = State
) ->
    case quic_tls:parse_client_hello(Body) of
        {ok,
            #{
                random := _ClientRandom,
                key_share := KeyShareEntries,
                cipher_suites := CipherSuites,
                alpn_protocols := ClientALPN,
                transport_params := TP,
                session_id := SessionId
            } = ClientHelloInfo} ->
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
            HashLen0 =
                case Cipher of
                    aes_256_gcm -> 48;
                    _ -> 32
                end,
            ZeroPSK = <<0:HashLen0/unit:8>>,

            %% Check if we can derive early keys for 0-RTT decryption
            {EarlyKeys, EarlySecret} =
                case PSKInfo of
                    #{identities := [{Identity, _Age}], binders := [_Binder]} when WantsEarlyData ->
                        %% Try to validate PSK for 0-RTT only (not full PSK resumption)
                        case validate_psk(Identity, Cipher, OriginalMsg, State) of
                            {ok, PSK, ResumptionSecret} ->
                                %% Derive early keys for 0-RTT decryption
                                ES = quic_crypto:derive_early_secret(Cipher, PSK),
                                ClientHelloHash = quic_crypto:transcript_hash(Cipher, OriginalMsg),
                                ETS = quic_crypto:derive_client_early_traffic_secret(
                                    Cipher, ES, ClientHelloHash
                                ),
                                {Key, IV, HP} = quic_keys:derive_keys(ETS, Cipher),
                                EK = #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher},
                                %% Still use zero PSK for handshake to keep Certificate flow
                                {
                                    {EK, ResumptionSecret},
                                    quic_crypto:derive_early_secret(Cipher, ZeroPSK)
                                };
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
                x25519, ServerPrivKey, ClientPubKey
            ),

            %% Negotiate ALPN
            ALPN = negotiate_alpn(ClientALPN, State#state.alpn_list),

            %% Build ServerHello
            %% RFC 8446: cipher_suite must be the integer code, not atom
            {ServerHello, _ServerPrivKey2} = quic_tls:build_server_hello(#{
                cipher_suite => cipher_atom_to_code(Cipher),
                key_pair => {ServerPubKey, ServerPrivKey},
                session_id => SessionId
            }),

            %% Update transcript with ClientHello
            Transcript0 = <<OriginalMsg/binary>>,
            %% Add ServerHello to transcript
            Transcript = <<Transcript0/binary, ServerHello/binary>>,
            TranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),

            %% Derive handshake secrets using already computed early secret
            HandshakeSecret = quic_crypto:derive_handshake_secret(
                Cipher, EarlySecret, SharedSecret
            ),

            ClientHsSecret = quic_crypto:derive_client_handshake_secret(
                Cipher, HandshakeSecret, TranscriptHash
            ),
            ServerHsSecret = quic_crypto:derive_server_handshake_secret(
                Cipher, HandshakeSecret, TranscriptHash
            ),

            %% Derive handshake keys
            {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientHsSecret, Cipher),
            {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerHsSecret, Cipher),

            ClientHsKeys = #crypto_keys{
                key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher
            },
            ServerHsKeys = #crypto_keys{
                key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher
            },

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
            ?LOG_ERROR(#{what => client_hello_parse_failed, reason => Reason}, ?QUIC_LOG_META),
            State
    end;
%% Client receives ServerHello
process_tls_message(_Level, ?TLS_SERVER_HELLO, Body, OriginalMsg, State) ->
    case quic_tls:parse_server_hello(Body) of
        {ok, #{public_key := ServerPubKey, cipher := Cipher}} ->
            %% Compute shared secret
            SharedSecret = quic_crypto:compute_shared_secret(
                x25519, State#state.tls_private_key, ServerPubKey
            ),

            %% Update transcript - USE ORIGINAL BYTES FROM WIRE
            Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
            %% Use cipher-appropriate hash for transcript
            TranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),

            %% Derive handshake secrets (cipher-aware for SHA-384 with AES-256-GCM)
            HashLen =
                case Cipher of
                    % SHA-384
                    aes_256_gcm -> 48;
                    % SHA-256
                    _ -> 32
                end,
            EarlySecret = quic_crypto:derive_early_secret(Cipher, <<0:HashLen/unit:8>>),
            HandshakeSecret = quic_crypto:derive_handshake_secret(
                Cipher, EarlySecret, SharedSecret
            ),

            ClientHsSecret = quic_crypto:derive_client_handshake_secret(
                Cipher, HandshakeSecret, TranscriptHash
            ),
            ServerHsSecret = quic_crypto:derive_server_handshake_secret(
                Cipher, HandshakeSecret, TranscriptHash
            ),

            %% Derive handshake keys
            {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientHsSecret, Cipher),
            {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerHsSecret, Cipher),

            ClientHsKeys = #crypto_keys{
                key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher
            },
            ServerHsKeys = #crypto_keys{
                key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher
            },

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
%% Client receives server Certificate
process_tls_message(
    _Level,
    ?TLS_CERTIFICATE,
    Body,
    OriginalMsg,
    #state{role = client, tls_state = ?TLS_AWAITING_CERT} = State
) ->
    %% Update transcript (we don't verify certs if verify = false)
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    %% Parse and store peer certificate
    {PeerCert, PeerCertChain} =
        case quic_tls:parse_certificate(Body) of
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
%% Client receives server CertificateVerify
process_tls_message(
    _Level,
    ?TLS_CERTIFICATE_VERIFY,
    _Body,
    OriginalMsg,
    #state{role = client, tls_state = ?TLS_AWAITING_CERT_VERIFY} = State
) ->
    %% Update transcript
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_state = ?TLS_AWAITING_FINISHED,
        tls_transcript = Transcript
    };
%% Client receives server's Finished
process_tls_message(
    _Level,
    ?TLS_FINISHED,
    Body,
    OriginalMsg,
    #state{role = client, tls_state = ?TLS_AWAITING_FINISHED} = State
) ->
    %% Get cipher from handshake keys for cipher-aware operations
    {ClientHsKeys, _} = State#state.handshake_keys,
    Cipher = ClientHsKeys#crypto_keys.cipher,

    %% Verify server Finished
    case quic_tls:parse_finished(Body) of
        {ok, VerifyData} ->
            TranscriptHash = quic_crypto:transcript_hash(Cipher, State#state.tls_transcript),
            case
                quic_tls:verify_finished(
                    VerifyData, State#state.server_hs_secret, TranscriptHash, Cipher
                )
            of
                true ->
                    %% Update transcript with server Finished - USE ORIGINAL BYTES
                    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
                    TranscriptHashFinal = quic_crypto:transcript_hash(Cipher, Transcript),

                    %% Derive master secret and application keys (cipher-aware)
                    MasterSecret = quic_crypto:derive_master_secret(
                        Cipher, State#state.handshake_secret
                    ),
                    ClientAppSecret = quic_crypto:derive_client_app_secret(
                        Cipher, MasterSecret, TranscriptHashFinal
                    ),
                    ServerAppSecret = quic_crypto:derive_server_app_secret(
                        Cipher, MasterSecret, TranscriptHashFinal
                    ),

                    %% Derive app keys
                    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(
                        ClientAppSecret, Cipher
                    ),
                    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(
                        ServerAppSecret, Cipher
                    ),

                    ClientAppKeys = #crypto_keys{
                        key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher
                    },
                    ServerAppKeys = #crypto_keys{
                        key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher
                    },

                    %% Initialize key update state with app secrets for future key updates
                    KeyState = #key_update_state{
                        current_phase = 0,
                        current_keys = {ClientAppKeys, ServerAppKeys},
                        prev_keys = undefined,
                        client_app_secret = ClientAppSecret,
                        server_app_secret = ServerAppSecret,
                        update_state = idle
                    },

                    %% If server requested client certificate (CertificateRequest received),
                    %% send Certificate and optionally CertificateVerify before Finished
                    %% RFC 8446 Section 4.4.2: client MUST send Certificate if server sent CertificateRequest
                    {CertPayload, Transcript2} =
                        case State#state.cert_request_received of
                            true ->
                                case State#state.client_cert of
                                    undefined ->
                                        %% No client cert - send empty Certificate, no CertificateVerify
                                        EmptyCertMsg = quic_tls:build_certificate(<<>>, []),
                                        {EmptyCertMsg, <<Transcript/binary, EmptyCertMsg/binary>>};
                                    ClientCert ->
                                        %% Have client cert - send Certificate + CertificateVerify
                                        AllClientCerts = [
                                            ClientCert | State#state.client_cert_chain
                                        ],
                                        ClientCertMsg = quic_tls:build_certificate(
                                            <<>>, AllClientCerts
                                        ),
                                        T1 = <<Transcript/binary, ClientCertMsg/binary>>,
                                        TranscriptHashCV = quic_crypto:transcript_hash(Cipher, T1),
                                        SigAlg = select_signature_algorithm(
                                            State#state.client_private_key
                                        ),
                                        ClientCertVerifyMsg = quic_tls:build_certificate_verify_client(
                                            SigAlg, State#state.client_private_key, TranscriptHashCV
                                        ),
                                        {
                                            <<ClientCertMsg/binary, ClientCertVerifyMsg/binary>>,
                                            <<T1/binary, ClientCertVerifyMsg/binary>>
                                        }
                                end;
                            false ->
                                %% No CertificateRequest - send nothing before Finished
                                {<<>>, Transcript}
                        end,

                    %% Compute client Finished using updated transcript
                    TranscriptHash2 = quic_crypto:transcript_hash(Cipher, Transcript2),
                    ClientFinishedKey = quic_crypto:derive_finished_key(
                        Cipher, State#state.client_hs_secret
                    ),
                    ClientVerifyData = quic_crypto:compute_finished_verify(
                        Cipher, ClientFinishedKey, TranscriptHash2
                    ),
                    ClientFinishedMsg = quic_tls:build_finished(ClientVerifyData),

                    %% Combine Certificate(+CertificateVerify) and Finished into one payload
                    HandshakePayload = <<CertPayload/binary, ClientFinishedMsg/binary>>,
                    CryptoFrame = quic_frame:encode({crypto, 0, HandshakePayload}),

                    State1 = State#state{
                        tls_state = ?TLS_HANDSHAKE_COMPLETE,
                        tls_transcript = <<Transcript2/binary, ClientFinishedMsg/binary>>,
                        master_secret = MasterSecret,
                        app_keys = {ClientAppKeys, ServerAppKeys},
                        key_state = KeyState
                    },

                    %% Send client Certificate(+CertificateVerify)+Finished in Handshake packet
                    send_handshake_packet(CryptoFrame, State1);
                false ->
                    %% Verification failed
                    State
            end;
        {error, _} ->
            State
    end;
%% Server receives client's Finished
process_tls_message(
    _Level,
    ?TLS_FINISHED,
    Body,
    OriginalMsg,
    #state{role = server, tls_state = ?TLS_AWAITING_CLIENT_FINISHED} = State
) ->
    {ClientHsKeys, _} = State#state.handshake_keys,
    Cipher = ClientHsKeys#crypto_keys.cipher,

    case quic_tls:parse_finished(Body) of
        {ok, VerifyData} ->
            %% Verify client's Finished using client handshake secret
            TranscriptHash = quic_crypto:transcript_hash(Cipher, State#state.tls_transcript),
            case
                quic_tls:verify_finished(
                    VerifyData, State#state.client_hs_secret, TranscriptHash, Cipher
                )
            of
                true ->
                    %% Update transcript with client Finished
                    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,

                    %% Derive resumption_master_secret (RFC 8446 Section 7.1)
                    %% resumption_master_secret = Derive-Secret(master_secret, "res master",
                    %%                                          ClientHello..client Finished)
                    FinalTranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),
                    ResumptionSecret = quic_ticket:derive_resumption_secret(
                        Cipher, State#state.master_secret, FinalTranscriptHash, <<>>
                    ),

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
                    State
            end;
        {error, _} ->
            State
    end;
%% Client receives NewSessionTicket from server (post-handshake)
%% RFC 8446 Section 4.6.1
process_tls_message(
    _Level,
    ?TLS_NEW_SESSION_TICKET,
    Body,
    _OriginalMsg,
    #state{
        role = client,
        tls_state = ?TLS_HANDSHAKE_COMPLETE,
        server_name = ServerName,
        alpn = ALPN,
        master_secret = MasterSecret,
        tls_transcript = Transcript,
        handshake_keys = {ClientHsKeys, _}
    } = State
) ->
    case quic_ticket:parse_new_session_ticket(Body) of
        {ok, #{
            lifetime := Lifetime,
            age_add := AgeAdd,
            nonce := Nonce,
            ticket := TicketData,
            max_early_data := MaxEarlyData
        }} ->
            Cipher = ClientHsKeys#crypto_keys.cipher,

            %% Derive resumption_master_secret from master secret
            %% The transcript should include client Finished
            FinalTranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),
            ResumptionSecret = quic_ticket:derive_resumption_secret(
                Cipher, MasterSecret, FinalTranscriptHash, <<>>
            ),

            %% Create session ticket record
            Ticket = #session_ticket{
                server_name =
                    case ServerName of
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
            TicketKey =
                case ServerName of
                    undefined -> <<"">>;
                    SN -> SN
                end,
            TicketStore = quic_ticket:store_ticket(
                TicketKey, Ticket, State#state.ticket_store
            ),

            %% Notify owner about the new ticket
            #state{owner = Owner} = State,
            Owner ! {quic, self(), {session_ticket, Ticket}},

            State#state{
                ticket_store = TicketStore,
                resumption_secret = ResumptionSecret
            };
        {error, _Reason} ->
            State
    end;
%% Client receives CertificateRequest from server (mutual TLS)
process_tls_message(
    _Level,
    ?TLS_CERTIFICATE_REQUEST,
    _Body,
    OriginalMsg,
    #state{role = client} = State
) ->
    %% Update transcript and mark that server wants client certificate
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_transcript = Transcript,
        cert_request_received = true
    };
%% Server receives client Certificate (when verify=true)
process_tls_message(
    _Level,
    ?TLS_CERTIFICATE,
    Body,
    OriginalMsg,
    #state{role = server, tls_state = ?TLS_AWAITING_CLIENT_CERT} = State
) ->
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    case quic_tls:parse_certificate(Body) of
        {ok, #{certificates := [First | Rest]}} ->
            %% Client sent certificate - expect CertificateVerify next
            State#state{
                tls_state = ?TLS_AWAITING_CLIENT_CERT_VERIFY,
                tls_transcript = Transcript,
                peer_cert = First,
                peer_cert_chain = Rest
            };
        {ok, #{certificates := []}} ->
            %% Empty certificate - no CertificateVerify, wait for Finished
            State#state{
                tls_state = ?TLS_AWAITING_CLIENT_FINISHED,
                tls_transcript = Transcript,
                peer_cert = undefined,
                peer_cert_chain = []
            };
        {error, _} ->
            %% Parse error - treat as empty
            State#state{
                tls_state = ?TLS_AWAITING_CLIENT_FINISHED,
                tls_transcript = Transcript,
                peer_cert = undefined,
                peer_cert_chain = []
            }
    end;
%% Server receives client CertificateVerify (when verify=true and client sent cert)
process_tls_message(
    _Level,
    ?TLS_CERTIFICATE_VERIFY,
    Body,
    OriginalMsg,
    #state{
        role = server,
        tls_state = ?TLS_AWAITING_CLIENT_CERT_VERIFY,
        peer_cert = PeerCert
    } = State
) when PeerCert =/= undefined ->
    %% Get cipher for transcript hash
    {ClientHsKeys, _} = State#state.handshake_keys,
    Cipher = ClientHsKeys#crypto_keys.cipher,

    %% Verify signature (transcript is BEFORE CertificateVerify)
    TranscriptHash = quic_crypto:transcript_hash(Cipher, State#state.tls_transcript),
    case quic_tls:verify_certificate_verify(Body, PeerCert, TranscriptHash, client) of
        true ->
            Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
            State#state{
                tls_state = ?TLS_AWAITING_CLIENT_FINISHED,
                tls_transcript = Transcript
            };
        false ->
            %% Signature verification failed - send TLS decrypt_error alert
            %% RFC 8446: decrypt_error (51) for signature verification failure
            ?LOG_ERROR(#{what => client_cert_verify_failed}, ?QUIC_LOG_META),
            send_tls_alert(?TLS_ALERT_DECRYPT_ERROR, State)
    end;
process_tls_message(_Level, _Type, _Body, _OriginalMsg, State) ->
    State.

%%====================================================================
%% Internal Functions - Stream Processing
%%====================================================================

process_stream_data(StreamId, Offset, Data, Fin, State) ->
    #state{role = Role} = State,

    %% RFC 9000 Section 2.1: Validate stream direction
    %% Cannot receive on locally-initiated unidirectional streams
    case validate_receive_stream(StreamId, Role) of
        {error, Reason} ->
            ?LOG_WARNING(
                #{what => invalid_receive_stream, stream_id => StreamId, reason => Reason},
                ?QUIC_LOG_META
            ),
            % Silently ignore (could send STREAM_STATE_ERROR)
            State;
        ok ->
            process_stream_data_validated(StreamId, Offset, Data, Fin, State)
    end.

%% Validate that we can receive on this stream
validate_receive_stream(StreamId, Role) ->
    IsUni = (StreamId band 2) =/= 0,
    IsLocallyInitiated =
        case Role of
            client -> (StreamId band 1) =:= 0;
            server -> (StreamId band 1) =:= 1
        end,
    case {IsUni, IsLocallyInitiated} of
        {true, true} ->
            %% Cannot receive on our own unidirectional stream
            {error, stream_state_error};
        _ ->
            ok
    end.

process_stream_data_validated(StreamId, Offset, Data, Fin, State) ->
    #state{
        owner = Owner,
        streams = Streams,
        max_data_local = MaxDataLocal,
        data_received = DataReceived,
        recv_buffer_bytes = RecvBufferBytes
    } = State,

    DataSize = byte_size(Data),

    %% Get or create stream state
    Stream =
        case maps:find(StreamId, Streams) of
            {ok, S} ->
                S;
            error ->
                %% New stream from peer - notify owner
                Owner ! {quic, self(), {stream_opened, StreamId}},
                %% Use peer's limits for streams they initiate
                InitSendMaxData = get_peer_stream_limit(bidi_peer_initiated, State),
                InitRecvMaxData = get_local_recv_limit(bidi_peer_initiated, State),
                ?LOG_DEBUG(
                    #{
                        what => stream_created_peer_initiated,
                        stream_id => StreamId,
                        init_send_max_data => InitSendMaxData,
                        init_recv_max_data => InitRecvMaxData
                    },
                    ?QUIC_LOG_META
                ),
                #stream_state{
                    id = StreamId,
                    state = open,
                    send_offset = 0,
                    send_max_data = InitSendMaxData,
                    send_fin = false,
                    send_buffer = [],
                    recv_offset = 0,
                    recv_max_data = InitRecvMaxData,
                    recv_fin = false,
                    recv_buffer = #{},
                    final_size = undefined
                }
        end,

    %% RFC 9000 Section 4.1: Check receive flow control limits BEFORE buffering
    EndOffset = Offset + DataSize,
    RecvMaxData = Stream#stream_state.recv_max_data,

    %% Check if this would exceed our receive buffer limit (malicious peer protection)
    RecvBuffer =
        case Stream#stream_state.recv_buffer of
            B when is_map(B) -> B;
            _ -> #{}
        end,
    CurrentOffset = Stream#stream_state.recv_offset,
    IsDuplicate = Offset < CurrentOffset orelse maps:is_key(Offset, RecvBuffer),

    %% Only check buffer limit for new (non-duplicate) data
    BufferOverflow =
        case IsDuplicate of
            true -> false;
            false -> RecvBufferBytes + DataSize > ?MAX_RECV_BUFFER_BYTES
        end,

    case {EndOffset > RecvMaxData, DataReceived + DataSize > MaxDataLocal, BufferOverflow} of
        {true, _, _} ->
            %% Stream-level flow control violation - RFC 9000 Section 4.1
            ?LOG_WARNING(
                #{
                    what => stream_flow_control_violation,
                    stream_id => StreamId,
                    end_offset => EndOffset,
                    recv_max_data => RecvMaxData
                },
                ?QUIC_LOG_META
            ),
            %% Send FLOW_CONTROL_ERROR and close connection
            CloseFrame =
                {connection_close, transport, ?QUIC_FLOW_CONTROL_ERROR, 0,
                    <<"stream flow control violation">>},
            send_frame(CloseFrame, State#state{close_reason = stream_flow_control_error});
        {_, true, _} ->
            %% Connection-level flow control violation - RFC 9000 Section 4.1
            ?LOG_WARNING(
                #{
                    what => connection_flow_control_violation,
                    recv => DataReceived + DataSize,
                    max => MaxDataLocal
                },
                ?QUIC_LOG_META
            ),
            %% Send FLOW_CONTROL_ERROR and close connection
            CloseFrame =
                {connection_close, transport, ?QUIC_FLOW_CONTROL_ERROR, 0,
                    <<"connection flow control violation">>},
            send_frame(CloseFrame, State#state{close_reason = connection_flow_control_error});
        {_, _, true} ->
            %% Receive buffer overflow - malicious peer sending too much out-of-order data
            ?LOG_WARNING(
                #{
                    what => recv_buffer_overflow,
                    stream_id => StreamId,
                    recv_buffer_bytes => RecvBufferBytes,
                    data_size => DataSize,
                    max_bytes => ?MAX_RECV_BUFFER_BYTES
                },
                ?QUIC_LOG_META
            ),
            %% Send FLOW_CONTROL_ERROR and close connection
            CloseFrame =
                {connection_close, transport, ?QUIC_FLOW_CONTROL_ERROR, 0,
                    <<"recv buffer overflow">>},
            send_frame(CloseFrame, State#state{close_reason = recv_buffer_overflow});
        _ ->
            %% Flow control OK - check final size consistency before buffering

            %% RFC 9000 Section 4.5: Validate final size when FIN received
            ExistingFinalSize = Stream#stream_state.final_size,
            FinalSizeError =
                Fin andalso
                    ExistingFinalSize =/= undefined andalso
                    ExistingFinalSize =/= EndOffset,

            case FinalSizeError of
                true ->
                    %% FINAL_SIZE_ERROR: FIN indicates different final size
                    ?LOG_WARNING(
                        #{
                            what => final_size_error,
                            stream_id => StreamId,
                            existing => ExistingFinalSize,
                            fin_offset => EndOffset
                        },
                        ?QUIC_LOG_META
                    ),
                    CloseFrame =
                        {connection_close, transport, ?QUIC_FINAL_SIZE_ERROR, 0,
                            <<"FIN final size mismatch">>},
                    send_frame(CloseFrame, State#state{close_reason = final_size_error});
                false ->
                    %% Track FIN position if received
                    FinalSize =
                        case Fin of
                            true -> EndOffset;
                            false -> ExistingFinalSize
                        end,

                    %% Fast path: in-order delivery with empty buffer
                    %% Avoids maps:put and extract_contiguous_data for common case
                    {DeliverData, NewRecvOffset, NewBuffer, DeliverFin} =
                        case Offset =:= CurrentOffset andalso map_size(RecvBuffer) =:= 0 of
                            true ->
                                %% In-order with empty buffer: deliver directly
                                {Data, EndOffset, RecvBuffer, Fin};
                            false ->
                                %% Out-of-order or buffer has data: use buffer path
                                UpdatedBuffer = maps:put(Offset, Data, RecvBuffer),
                                {ExtractedData, ExtractedOffset, ExtractedBuffer} =
                                    extract_contiguous_data(UpdatedBuffer, CurrentOffset),
                                ExtractedFin =
                                    FinalSize =/= undefined andalso ExtractedOffset >= FinalSize,
                                {ExtractedData, ExtractedOffset, ExtractedBuffer, ExtractedFin}
                        end,

                    %% Deliver contiguous data to owner
                    %% RFC 9000: Also deliver FIN-only notification when no data but FIN received
                    case {DeliverData, DeliverFin, Fin} of
                        {<<>>, false, _} ->
                            %% No contiguous data to deliver yet
                            ok;
                        {<<>>, true, _} ->
                            %% FIN-only delivery (all data already delivered)
                            Owner ! {quic, self(), {stream_data, StreamId, <<>>, true}};
                        {_, _, _} ->
                            Owner ! {quic, self(), {stream_data, StreamId, DeliverData, DeliverFin}}
                    end,

                    NewStream = Stream#stream_state{
                        recv_offset = NewRecvOffset,
                        recv_fin = DeliverFin,
                        recv_buffer = NewBuffer,
                        final_size = FinalSize
                    },

                    %% Track connection-level data received - only count NEW bytes, not duplicates
                    NewBytesReceived =
                        case IsDuplicate of
                            true -> 0;
                            false -> DataSize
                        end,
                    NewDataReceivedVal = DataReceived + NewBytesReceived,

                    %% Update receive buffer bytes tracking
                    %% Net change: add new bytes, subtract delivered bytes
                    DeliveredBytes = byte_size(DeliverData),
                    NewRecvBufferBytes = max(
                        0, RecvBufferBytes + NewBytesReceived - DeliveredBytes
                    ),

                    State1Pre = State#state{
                        streams = maps:put(StreamId, NewStream, Streams),
                        data_received = NewDataReceivedVal,
                        recv_buffer_bytes = NewRecvBufferBytes
                    },
                    %% RFC 9000 §4.6: extend MAX_STREAMS when the peer-
                    %% initiated stream becomes fully closed.
                    State1 = maybe_credit_peer_stream(StreamId, State1Pre),

                    %% Check if we need to send MAX_STREAM_DATA to allow more data
                    %% Send when we've consumed more than half our advertised limit
                    %% RTT-based auto-tuning: double if fast consumption, linear if slow
                    Threshold = RecvMaxData div 2,
                    WillSendMaxStreamData = NewRecvOffset > Threshold,
                    ?LOG_DEBUG(
                        #{
                            what => max_stream_data_check,
                            stream_id => StreamId,
                            recv_offset => NewRecvOffset,
                            recv_max_data => RecvMaxData,
                            threshold => Threshold,
                            will_send => WillSendMaxStreamData
                        },
                        ?QUIC_LOG_META
                    ),
                    State2 =
                        case WillSendMaxStreamData of
                            true ->
                                Now = erlang:monotonic_time(millisecond),
                                SmoothedRTT = quic_loss:smoothed_rtt(State1#state.loss_state),
                                MaxWindow = State1#state.fc_max_receive_window,
                                LastStreamUpdate = State1#state.fc_last_stream_update,
                                InitialStreamWindow = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                                %% Check if consumption is fast (< 4*RTT since last update)
                                FastConsumption =
                                    case LastStreamUpdate of
                                        undefined ->
                                            true;
                                        _ ->
                                            (Now - LastStreamUpdate) <
                                                (SmoothedRTT * ?AUTO_TUNE_RTT_FACTOR)
                                    end,
                                NewMaxStreamData =
                                    case FastConsumption of
                                        true ->
                                            %% Double (aggressive growth for fast consumption)
                                            min(RecvMaxData * 2, MaxWindow);
                                        false ->
                                            %% Linear (conservative growth for slow consumption)
                                            min(RecvMaxData + InitialStreamWindow, MaxWindow)
                                    end,
                                UpdatedStream = NewStream#stream_state{
                                    recv_max_data = NewMaxStreamData
                                },
                                MaxStreamDataFrame = {max_stream_data, StreamId, NewMaxStreamData},
                                %% Update cached max stream recv window
                                NewCachedMax = max(
                                    NewMaxStreamData, State1#state.fc_max_stream_recv_window
                                ),
                                State1a = State1#state{
                                    streams = maps:put(StreamId, UpdatedStream, Streams),
                                    fc_last_stream_update = Now,
                                    fc_max_stream_recv_window = NewCachedMax
                                },
                                send_frame(MaxStreamDataFrame, State1a);
                            false ->
                                State1
                        end,

                    %% Check if we need to send MAX_DATA for connection-level flow control
                    %% Send when we've consumed more than 50% of our advertised connection window
                    %% RTT-based auto-tuning with connection/stream multiplier enforcement
                    MaxDataLocalVal = State2#state.max_data_local,
                    State3 =
                        case NewDataReceivedVal > (MaxDataLocalVal div 2) of
                            true ->
                                Now2 = erlang:monotonic_time(millisecond),
                                SmoothedRTT2 = quic_loss:smoothed_rtt(State2#state.loss_state),
                                MaxWindow2 = State2#state.fc_max_receive_window,
                                LastConnUpdate = State2#state.fc_last_conn_update,
                                InitialConnWindow = ?DEFAULT_INITIAL_MAX_DATA,
                                %% Check if consumption is fast (< 4*RTT since last update)
                                FastConsumption2 =
                                    case LastConnUpdate of
                                        undefined ->
                                            true;
                                        _ ->
                                            (Now2 - LastConnUpdate) <
                                                (SmoothedRTT2 * ?AUTO_TUNE_RTT_FACTOR)
                                    end,
                                %% Calculate new window based on RTT-aware growth
                                BaseNewMaxData =
                                    case FastConsumption2 of
                                        true ->
                                            %% Double (aggressive growth)
                                            min(
                                                (NewDataReceivedVal + MaxDataLocalVal) * 2,
                                                MaxWindow2
                                            );
                                        false ->
                                            %% Linear (conservative growth)
                                            min(
                                                NewDataReceivedVal + MaxDataLocalVal +
                                                    InitialConnWindow,
                                                MaxWindow2
                                            )
                                    end,
                                %% Ensure connection window >= 1.5x largest stream window
                                MaxStreamWindow = get_max_stream_recv_window(State2),
                                MinConnWindow = trunc(
                                    MaxStreamWindow * ?CONNECTION_FLOW_CONTROL_MULTIPLIER
                                ),
                                NewMaxData = max(BaseNewMaxData, MinConnWindow),
                                MaxDataFrame = {max_data, NewMaxData},
                                State2a = send_frame(MaxDataFrame, State2),
                                State2a#state{
                                    max_data_local = NewMaxData,
                                    fc_last_conn_update = Now2
                                };
                            false ->
                                State2
                        end,

                    %% ACK is sent at packet level by maybe_send_ack
                    State3
                % end of FinalSizeError case
            end
    end.

%% Extract contiguous data from buffer starting at Offset
%% Returns {Data, NewOffset, UpdatedBuffer}
%% Uses binary append accumulator - O(1) amortized due to refc binary optimization
extract_contiguous_data(Buffer, Offset) ->
    extract_contiguous_data(Buffer, Offset, <<>>).

extract_contiguous_data(Buffer, Offset, Acc) ->
    case maps:take(Offset, Buffer) of
        {Data, NewBuffer} ->
            %% Found data at this offset, continue looking for next chunk
            %% Binary append is O(1) amortized due to Erlang's pre-allocation
            NextOffset = Offset + byte_size(Data),
            extract_contiguous_data(NewBuffer, NextOffset, <<Acc/binary, Data/binary>>);
        error ->
            %% No data at this offset (gap in stream)
            {Acc, Offset, Buffer}
    end.

%% Get the maximum stream receive window across all streams.
%% Used to ensure connection window >= 1.5x largest stream window.
%% Uses cached value to avoid O(n) scan on every call.
get_max_stream_recv_window(#state{fc_max_stream_recv_window = CachedMax}) ->
    CachedMax.

%%====================================================================
%% Internal Functions - Helpers
%%====================================================================

%% Send a packet via quic_socket (with batching) or gen_udp fallback.
%% For client connections with socket_state, uses quic_socket batching.
%% For server connections (shared socket), sends directly via gen_udp.
do_socket_send(Packet, #state{socket_state = undefined, socket = Socket, remote_addr = {IP, Port}}) ->
    %% No socket_state - use gen_udp directly (server or legacy path)
    gen_udp:send(Socket, IP, Port, Packet);
do_socket_send(Packet, #state{socket_state = SocketState, remote_addr = {IP, Port}}) ->
    %% Use quic_socket with batching
    case quic_socket:send(SocketState, IP, Port, Packet) of
        {ok, NewSocketState} ->
            %% Update socket_state in process dictionary for later retrieval
            put(pending_socket_state, NewSocketState),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%% Apply pending socket state updates after send operations
apply_pending_socket_state(#state{socket_state = undefined} = State) ->
    State;
apply_pending_socket_state(State) ->
    case erase(pending_socket_state) of
        undefined -> State;
        NewSocketState -> State#state{socket_state = NewSocketState}
    end.

%% Flush any batched packets (call before timers or idle periods)
flush_socket_batch(#state{socket_state = undefined} = State) ->
    State;
flush_socket_batch(#state{socket_state = SocketState} = State) ->
    case quic_socket:flush(SocketState) of
        {ok, NewSocketState} ->
            State#state{socket_state = NewSocketState};
        {error, _} ->
            State
    end.

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
%% Uses unique reference in message to detect stale timer events
schedule_delayed_ack(app, State) ->
    %% Use max_ack_delay from transport params (default 25ms)
    MaxAckDelay = maps:get(max_ack_delay, State#state.transport_params, 25),
    %% Schedule ACK timer if not already set
    case get(ack_timer) of
        undefined ->
            Ref = make_ref(),
            erlang:send_after(MaxAckDelay, self(), {send_delayed_ack, app, Ref}),
            put(ack_timer, Ref),
            State;
        _ ->
            %% Timer already set, don't reschedule
            State
    end.

%% Check if any frame in the list is ack-eliciting
contains_ack_eliciting_frames([]) ->
    false;
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
        {ok, IP} ->
            {IP, Port};
        _ ->
            case inet:getaddr(Host, inet6) of
                {ok, IP} -> {IP, Port};
                _ -> {{127, 0, 0, 1}, Port}
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
select_signature_algorithm({'ECPrivateKey', _, _, {namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, _, _}) ->
    %% secp256r1 / P-256
    ?SIG_ECDSA_SECP256R1_SHA256;
select_signature_algorithm({'ECPrivateKey', _, _, {namedCurve, {1, 3, 132, 0, 34}}, _, _}) ->
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
    %% First check if connection should be closing (CONNECTION_CLOSE received)
    case State#state.close_reason of
        {peer_closed, _, _, _} ->
            %% Peer sent APPLICATION CONNECTION_CLOSE, transition to draining
            emit_qlog_state_change(CurrentState, draining, State),
            {next_state, draining, State};
        {peer_closed, _, _, _, _} ->
            %% Peer sent TRANSPORT CONNECTION_CLOSE, transition to draining
            emit_qlog_state_change(CurrentState, draining, State),
            {next_state, draining, State};
        connection_closed ->
            %% Legacy: Peer sent CONNECTION_CLOSE, transition to draining
            emit_qlog_state_change(CurrentState, draining, State),
            {next_state, draining, State};
        stateless_reset ->
            %% Received stateless reset, transition to draining
            emit_qlog_state_change(CurrentState, draining, State),
            {next_state, draining, State};
        _ ->
            %% Check for TLS handshake state transitions
            case {CurrentState, State#state.tls_state, has_app_keys(State)} of
                {idle, ?TLS_AWAITING_ENCRYPTED_EXT, _} ->
                    %% Got ServerHello, have handshake keys
                    emit_qlog_state_change(idle, handshaking, State),
                    {next_state, handshaking, State};
                {idle, ?TLS_AWAITING_CERT, _} ->
                    emit_qlog_state_change(idle, handshaking, State),
                    {next_state, handshaking, State};
                {idle, ?TLS_AWAITING_CERT_VERIFY, _} ->
                    emit_qlog_state_change(idle, handshaking, State),
                    {next_state, handshaking, State};
                {idle, ?TLS_AWAITING_FINISHED, _} ->
                    emit_qlog_state_change(idle, handshaking, State),
                    {next_state, handshaking, State};
                {idle, ?TLS_HANDSHAKE_COMPLETE, true} ->
                    emit_qlog_state_change(idle, connected, State),
                    {next_state, connected, State};
                {handshaking, ?TLS_HANDSHAKE_COMPLETE, true} ->
                    emit_qlog_state_change(handshaking, connected, State),
                    {next_state, connected, State};
                _ ->
                    {keep_state, State}
            end
    end.

%% Helper to emit qlog connection_state_updated event
emit_qlog_state_change(OldState, NewState, #state{qlog_ctx = Ctx}) ->
    quic_qlog:connection_state_updated(Ctx, OldState, NewState).

%% Convert close reason to error code for qlog
close_reason_to_code(connection_closed) -> 0;
close_reason_to_code(stateless_reset) -> stateless_reset;
close_reason_to_code(idle_timeout) -> idle_timeout;
close_reason_to_code(normal) -> 0;
close_reason_to_code({app_error, Code, _}) when is_integer(Code) -> Code;
close_reason_to_code({peer_closed, application, Code, _}) when is_integer(Code) -> Code;
close_reason_to_code({peer_closed, transport, Code, _, _}) when is_integer(Code) -> Code;
close_reason_to_code({error, Code}) when is_integer(Code) -> Code;
close_reason_to_code({error, application_error}) -> ?QUIC_APPLICATION_ERROR;
close_reason_to_code({application_error, Code, _}) when is_integer(Code) -> Code;
close_reason_to_code(Reason) when is_atom(Reason) -> Reason;
close_reason_to_code(_) -> unknown.

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
record_received_pn(zero_rtt, PN, State) ->
    %% 0-RTT uses the same PN space as 1-RTT (app)
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
    (State#state.pn_app)#pn_space.largest_recv;
get_largest_recv(zero_rtt, State) ->
    %% 0-RTT uses the same PN space as 1-RTT (app)
    (State#state.pn_app)#pn_space.largest_recv.

update_pn_space_recv(PN, PNSpace) ->
    #pn_space{largest_recv = LargestRecv, ack_ranges = Ranges} = PNSpace,
    NewLargest =
        case LargestRecv of
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

%% Update last activity timestamp with dirty flag (batched timer reset)
%% The actual timer reset happens in flush_dirty_timers/1 at batch boundaries
update_last_activity(State) ->
    mark_activity_dirty(State).

%% Mark activity dirty - defers timer reset until batch flush
mark_activity_dirty(State) ->
    State#state{
        last_activity = erlang:monotonic_time(millisecond),
        timer_dirty = true
    }.

%% Mark PTO dirty - defers PTO timer reset until batch flush
mark_pto_dirty(State) ->
    State#state{pto_dirty = true}.

%% Flush dirty timers at batch boundaries
%% This batches multiple timer operations into a single reset per batch
flush_dirty_timers(#state{timer_dirty = false, pto_dirty = false} = State) ->
    State;
flush_dirty_timers(State) ->
    State1 =
        case State#state.timer_dirty of
            true ->
                S1 = set_idle_timer(State),
                set_keep_alive_timer(S1#state{timer_dirty = false});
            false ->
                State
        end,
    case State1#state.pto_dirty of
        true ->
            set_pto_timer(State1#state{pto_dirty = false});
        false ->
            State1
    end.

%% RFC 9000 §4.6: as peer-initiated streams reach their final state we
%% extend the MAX_STREAMS credit by one and send a MAX_STREAMS frame so
%% the peer can keep opening streams. Each stream is credited at most
%% once (tracked via credited_peer_bidi/credited_peer_uni sets).
maybe_credit_peer_stream(StreamId, State) ->
    case maps:find(StreamId, State#state.streams) of
        error ->
            State;
        {ok, Stream} ->
            case classify_peer_stream(StreamId, State#state.role) of
                {peer, bidi} ->
                    case stream_fully_closed_bidi(Stream) of
                        true -> credit_peer_bidi(StreamId, State);
                        false -> State
                    end;
                {peer, uni} ->
                    case stream_fully_closed_uni(Stream) of
                        true -> credit_peer_uni(StreamId, State);
                        false -> State
                    end;
                local ->
                    State
            end
    end.

%% Bidi stream is final when both directions have FIN'd.
stream_fully_closed_bidi(#stream_state{recv_fin = true, send_fin = true}) -> true;
stream_fully_closed_bidi(_) -> false.

%% Peer-initiated uni streams are receive-only on our side; FIN from peer
%% closes them.
stream_fully_closed_uni(#stream_state{recv_fin = true}) -> true;
stream_fully_closed_uni(_) -> false.

%% Stream ID layout (RFC 9000 §2.1):
%%   bit 0 = initiator (0 client, 1 server)
%%   bit 1 = direction (0 bidi, 1 uni)
classify_peer_stream(StreamId, Role) ->
    Initiator = StreamId band 1,
    Uni = (StreamId band 2) =/= 0,
    PeerInitiated =
        case Role of
            server -> Initiator =:= 0;
            client -> Initiator =:= 1
        end,
    case {PeerInitiated, Uni} of
        {true, false} -> {peer, bidi};
        {true, true} -> {peer, uni};
        _ -> local
    end.

credit_peer_bidi(StreamId, #state{credited_peer_bidi = Set} = State) ->
    case sets:is_element(StreamId, Set) of
        true ->
            State;
        false ->
            NewMax = State#state.max_streams_bidi_local + 1,
            State1 = State#state{
                max_streams_bidi_local = NewMax,
                credited_peer_bidi = sets:add_element(StreamId, Set)
            },
            send_frame({max_streams, bidi, NewMax}, State1)
    end.

credit_peer_uni(StreamId, #state{credited_peer_uni = Set} = State) ->
    case sets:is_element(StreamId, Set) of
        true ->
            State;
        false ->
            NewMax = State#state.max_streams_uni_local + 1,
            State1 = State#state{
                max_streams_uni_local = NewMax,
                credited_peer_uni = sets:add_element(StreamId, Set)
            },
            send_frame({max_streams, uni, NewMax}, State1)
    end.

%% Open a new stream
%% Stream ID patterns: Bit 0=initiator (0=client, 1=server), Bit 1=type (0=bidi, 1=uni)
%% Client bidi=0x00, Server bidi=0x01, Client uni=0x02, Server uni=0x03
do_open_stream(
    #state{
        role = Role,
        next_stream_id_bidi = NextId,
        max_streams_bidi_remote = Max,
        streams = Streams
    } = State
) ->
    %% RFC 9000 §4.6: Check cumulative stream count against peer's limit.
    LocalPattern =
        case Role of
            % Client-initiated bidi = 0x00
            client -> 0;
            % Server-initiated bidi = 0x01
            server -> 1
        end,
    StreamIndex = (NextId - LocalPattern) div 4,
    if
        StreamIndex >= Max ->
            {error, stream_limit};
        true ->
            %% Get peer's limit for streams WE initiate (bidi_remote from their perspective)
            SendMaxData = get_peer_stream_limit(bidi_local_initiated, State),
            RecvMaxData = get_local_recv_limit(bidi_local_initiated, State),
            ?LOG_DEBUG(
                #{
                    what => stream_created_local_initiated,
                    stream_id => NextId,
                    send_max_data => SendMaxData,
                    recv_max_data => RecvMaxData
                },
                ?QUIC_LOG_META
            ),
            StreamState = #stream_state{
                id = NextId,
                state = open,
                send_offset = 0,
                send_max_data = SendMaxData,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = RecvMaxData,
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
do_open_unidirectional_stream(
    #state{
        role = Role,
        next_stream_id_uni = NextId,
        max_streams_uni_remote = Max,
        streams = Streams
    } = State
) ->
    %% RFC 9000 §4.6: MAX_STREAMS value of N permits opening streams with IDs
    %% less than 4*N + stream_type_offset. Check against NextId (cumulative count
    %% of streams opened) rather than current map size, since completed streams
    %% remain in the map but should not block opening new ones once the peer
    %% has increased the limit via MAX_STREAMS frames.
    LocalPattern =
        case Role of
            % Client-initiated uni = 0x02
            client -> 2;
            % Server-initiated uni = 0x03
            server -> 3
        end,
    StreamIndex = (NextId - LocalPattern) div 4,
    if
        StreamIndex >= Max ->
            {error, stream_limit};
        true ->
            %% Unidirectional streams are send-only for the initiator
            %% Get peer's limit for uni streams we initiate
            SendMaxData = get_peer_stream_limit(uni_local_initiated, State),
            StreamState = #stream_state{
                id = NextId,
                state = open,
                send_offset = 0,
                send_max_data = SendMaxData,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                % We don't receive on our uni streams
                recv_max_data = 0,
                % No incoming data expected
                recv_fin = true,
                recv_buffer = #{},
                final_size = undefined
            },
            NewState = State#state{
                next_stream_id_uni = NextId + 4,
                streams = maps:put(NextId, StreamState, Streams)
            },
            {ok, NextId, NewState}
    end.

%% Default max stream data per packet (leave room for headers, frame overhead, AEAD tag)
%% Used when PMTU discovery is disabled or not yet complete
%% 1200 (min MTU for QUIC) - ~100 bytes overhead = 1100 bytes
-define(DEFAULT_MAX_STREAM_DATA_PER_PACKET, 1100).

%% Packet overhead: short header (1 + DCID ~8) + PN (1-4) + frame header (~10) + AEAD tag (16)
-define(STREAM_PACKET_OVERHEAD, 100).

%% @doc Calculate max stream data per packet based on current PMTU.
-spec get_max_stream_data_per_packet(#state{}) -> pos_integer().
get_max_stream_data_per_packet(#state{pmtu_state = undefined}) ->
    ?DEFAULT_MAX_STREAM_DATA_PER_PACKET;
get_max_stream_data_per_packet(#state{pmtu_state = PMTUState}) ->
    MTU = quic_pmtu:current_mtu(PMTUState),
    max(MTU - ?STREAM_PACKET_OVERHEAD, ?DEFAULT_MAX_STREAM_DATA_PER_PACKET).

%% @doc Get the peer's stream data limit for a given stream type.
%% RFC 9000 Section 4.1: Each endpoint independently sets flow control limits.
%% - bidi_local_initiated: Bidi stream we opened, use peer's initial_max_stream_data_bidi_remote
%% - bidi_peer_initiated: Bidi stream peer opened, use peer's initial_max_stream_data_bidi_local
%% - uni_local_initiated: Uni stream we opened, use peer's initial_max_stream_data_uni
get_peer_stream_limit(StreamType, #state{transport_params = TP}) ->
    Result =
        case StreamType of
            bidi_local_initiated ->
                maps:get(
                    peer_max_stream_data_bidi_remote,
                    TP,
                    maps:get(
                        initial_max_stream_data_bidi_remote, TP, ?DEFAULT_INITIAL_MAX_STREAM_DATA
                    )
                );
            bidi_peer_initiated ->
                maps:get(
                    peer_max_stream_data_bidi_local,
                    TP,
                    maps:get(
                        initial_max_stream_data_bidi_local, TP, ?DEFAULT_INITIAL_MAX_STREAM_DATA
                    )
                );
            uni_local_initiated ->
                maps:get(
                    peer_max_stream_data_uni,
                    TP,
                    maps:get(initial_max_stream_data_uni, TP, ?DEFAULT_INITIAL_MAX_STREAM_DATA)
                )
        end,
    ?LOG_DEBUG(
        #{
            what => get_peer_stream_limit,
            stream_type => StreamType,
            result => Result,
            tp_keys => maps:keys(TP)
        },
        ?QUIC_LOG_META
    ),
    Result.

%% Get our local receive limit for a stream (what we advertised to peer)
%% - bidi_local_initiated: Bidi stream we opened, use our max_stream_data_bidi_remote
%% - bidi_peer_initiated: Bidi stream peer opened, use our max_stream_data_bidi_local
%% - uni_peer_initiated: Uni stream peer opened, use our max_stream_data_uni
get_local_recv_limit(StreamType, #state{
    max_stream_data_bidi_local = BidiLocal,
    max_stream_data_bidi_remote = BidiRemote,
    max_stream_data_uni = Uni
}) ->
    case StreamType of
        bidi_local_initiated -> BidiRemote;
        bidi_peer_initiated -> BidiLocal;
        uni_peer_initiated -> Uni
    end.

%% @doc Check if stream is locally or peer initiated.
%% RFC 9000 Section 2.1: Stream ID format determines initiator and type.
%% Bit 0: 0=client-initiated, 1=server-initiated
%% Bit 1: 0=bidirectional, 1=unidirectional
is_locally_initiated(StreamId, #state{role = Role}) ->
    ClientInitiated = (StreamId band 1) =:= 0,
    case Role of
        client -> ClientInitiated;
        server -> not ClientInitiated
    end.

%% @doc Check if stream is unidirectional.
is_unidirectional(StreamId) ->
    (StreamId band 2) =/= 0.

%% @doc Validate stream direction for sending.
%% RFC 9000 Section 2.1: Cannot send on peer's unidirectional streams.
can_send_on_stream(StreamId, State) ->
    case is_unidirectional(StreamId) of
        false ->
            %% Bidirectional - can always send
            true;
        true ->
            %% Unidirectional - can only send if we initiated it
            is_locally_initiated(StreamId, State)
    end.

%% Send data on a stream (with fragmentation for large data)
%% Now includes flow control checks at connection and stream level
do_send_data(
    StreamId,
    Data,
    Fin,
    #state{
        streams = Streams,
        max_data_remote = MaxDataRemote,
        data_sent = DataSent
    } = State
) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Check stream direction (can't send on peer's uni streams)
            case can_send_on_stream(StreamId, State) of
                false ->
                    ?LOG_WARNING(
                        #{what => send_on_peer_uni_stream, stream_id => StreamId}, ?QUIC_LOG_META
                    ),
                    {error, stream_state_error};
                true ->
                    %% Use iolist_size to avoid premature flattening
                    %% Data is only flattened when needed for chunking or frame encoding
                    DataSize = iolist_size(Data),
                    Offset = StreamState#stream_state.send_offset,
                    SendMaxData = StreamState#stream_state.send_max_data,

                    %% Check connection-level flow control
                    ConnectionAllowed = MaxDataRemote - DataSent,
                    %% Check stream-level flow control
                    StreamAllowed = SendMaxData - Offset,

                    %% Log flow control status for debugging
                    ?LOG_DEBUG(
                        #{
                            what => send_data_flow_check,
                            stream_id => StreamId,
                            data_size => DataSize,
                            offset => Offset,
                            send_max_data => SendMaxData,
                            stream_allowed => StreamAllowed,
                            max_data_remote => MaxDataRemote,
                            data_sent => DataSent,
                            connection_allowed => ConnectionAllowed
                        },
                        ?QUIC_LOG_META
                    ),

                    case {DataSize =< ConnectionAllowed, DataSize =< StreamAllowed} of
                        {false, _} ->
                            %% Connection-level flow control blocked
                            %% RFC 9000: Don't queue data beyond flow control limits.
                            %% Send DATA_BLOCKED and return error to caller.
                            %% Caller should retry after receiving MAX_DATA from peer.
                            ?LOG_DEBUG(
                                #{
                                    what => connection_flow_control_blocked,
                                    need => DataSize,
                                    allowed => ConnectionAllowed
                                },
                                ?QUIC_LOG_META
                            ),
                            %% RFC 9000 Section 19.12: DATA_BLOCKED reports the connection data limit
                            BlockedFrame = {data_blocked, MaxDataRemote},
                            _FinalState = send_frame(BlockedFrame, State),
                            {error, {flow_control_blocked, connection}};
                        {_, false} ->
                            %% Stream-level flow control blocked
                            %% RFC 9000: Don't queue data beyond flow control limits.
                            %% Send STREAM_DATA_BLOCKED and return error to caller.
                            %% Caller should retry after receiving MAX_STREAM_DATA from peer.
                            ?LOG_DEBUG(
                                #{
                                    what => stream_flow_control_blocked,
                                    stream_id => StreamId,
                                    need => DataSize,
                                    allowed => StreamAllowed
                                },
                                ?QUIC_LOG_META
                            ),
                            %% RFC 9000 Section 19.13: STREAM_DATA_BLOCKED reports the stream data limit
                            BlockedFrame = {stream_data_blocked, StreamId, SendMaxData},
                            _FinalState = send_frame(BlockedFrame, State),
                            {error, {flow_control_blocked, {stream, StreamId}}};
                        {true, true} ->
                            %% Flow control allows sending
                            %% Fragment and send data - congestion control may partially
                            %% send and queue the remainder
                            case
                                send_stream_data_fragmented_tracked(
                                    StreamId, Offset, Data, Fin, State
                                )
                            of
                                {error, send_queue_full} ->
                                    {error, send_queue_full};
                                {NewState, BytesSent} ->
                                    %% Advance send_offset by full DataSize (not just BytesSent),
                                    %% because any unsent remainder was queued with correct offsets
                                    %% and subsequent sends must not overlap.
                                    case maps:find(StreamId, NewState#state.streams) of
                                        {ok, UpdatedStream} ->
                                            FinalStream = UpdatedStream#stream_state{
                                                send_offset = Offset + DataSize,
                                                send_fin = (Fin andalso BytesSent =:= DataSize)
                                            },
                                            FinalState0 = NewState#state{
                                                streams = maps:put(
                                                    StreamId, FinalStream, NewState#state.streams
                                                ),
                                                data_sent = NewState#state.data_sent + BytesSent
                                            },
                                            %% RFC 9000 §4.6: extend MAX_STREAMS when this
                                            %% peer-initiated stream is now fully closed.
                                            FinalState = maybe_credit_peer_stream(
                                                StreamId, FinalState0
                                            ),
                                            {ok, FinalState};
                                        error ->
                                            {ok, NewState}
                                    end
                            end
                    end
            end;
        error ->
            {error, unknown_stream}
    end.

%% Send 0-RTT (early) data on a stream
%% RFC 9001 Section 4.6: 0-RTT data uses the early traffic secret
do_send_zero_rtt_data(
    StreamId, Data, Fin, #state{streams = Streams, early_keys = {EarlyKeys, _}} = State
) ->
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

            FinalState0 = NewState#state{
                streams = maps:put(StreamId, NewStreamState, Streams),
                early_data_sent = EarlyDataSent
            },
            %% RFC 9000 §4.6: extend MAX_STREAMS once this stream is fully
            %% closed (covers the rare 0-RTT FIN-from-server case).
            {ok, maybe_credit_peer_stream(StreamId, FinalState0)};
        error ->
            {error, unknown_stream}
    end.

%% Send a 0-RTT packet (long header, type 1)
%% RFC 9001 Section 5.3: 0-RTT packets use early traffic keys
send_zero_rtt_packet(Payload, EarlyKeys, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        % 0-RTT uses app PN space
        pn_app = PNSpace
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Pad payload if needed for header protection sampling
    PaddedPayload = pad_for_header_protection(Payload),

    %% Long header for 0-RTT (type 1)
    %% First byte: 11XX XXXX where XX = type (01 for 0-RTT)
    % 0xD0 base for 0-RTT
    FirstByte = 16#C0 bor (1 bsl 4) bor (PNLen - 1),

    %% Build header prefix (includes Length field, but not PN)
    DCIDLen = byte_size(DCID),
    SCIDLen = byte_size(SCID),
    % +16 for AEAD tag
    PayloadLen = byte_size(PaddedPayload) + 16,
    LengthEncoded = quic_varint:encode(PNLen + PayloadLen),
    HeaderPrefix =
        <<FirstByte, Version:32, DCIDLen, DCID/binary, SCIDLen, SCID/binary, LengthEncoded/binary>>,

    %% Protect packet (encrypt + header protection in single call)
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EarlyKeys,
    Packet = quic_aead:protect_long_packet(
        Cipher, Key, IV, HP, PN, HeaderPrefix, PaddedPayload
    ),
    do_socket_send(Packet, State),

    %% Update PN space and packet counter
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    apply_pending_socket_state(State#state{
        pn_app = NewPNSpace,
        packets_sent = State#state.packets_sent + 1
    }).

%% Estimate packet overhead (header + AEAD tag + frame header).
%% Kept as a macro for the stream-chunking paths that sized themselves
%% against it historically.
-define(PACKET_OVERHEAD, 50).

%% Build the short-header first byte, folding in the outgoing spin
%% bit (RFC 9000 §17.4) when enabled. Bit layout:
%%   bit 7 = 0        (fixed header form)
%%   bit 6 = 1        (fixed 1-RTT marker)
%%   bit 5 = spin     (RFC 9000 §17.4)
%%   bits 4-3 = reserved (0)
%%   bit 2   = key phase
%%   bits 1-0 = PN length - 1
short_header_first_byte(KeyPhase, PNLen, #state{
    spin_outgoing = Spin, spin_bit_enabled = true
}) ->
    16#40 bor (Spin bsl 5) bor (KeyPhase bsl 2) bor (PNLen - 1);
short_header_first_byte(KeyPhase, PNLen, #state{spin_bit_enabled = false}) ->
    16#40 bor (KeyPhase bsl 2) bor (PNLen - 1).

%% Update the spin-bit tracking state from a received 1-RTT packet.
%% RFC 9000 §17.4 only updates on packets whose PN is greater than any
%% previously received on this path so that reorderings don't flip the
%% edge. Client mirrors the received bit; server inverts it.
update_spin_from_recv(
    FirstByte, PN, #state{spin_recv_largest_pn = Largest, role = Role} = State
) when PN > Largest ->
    RecvSpin = (FirstByte bsr 5) band 1,
    Outgoing =
        case State#state.spin_bit_enabled of
            false -> State#state.spin_outgoing;
            true when Role =:= client -> RecvSpin;
            true when Role =:= server -> 1 - RecvSpin
        end,
    State#state{
        spin_recv = RecvSpin,
        spin_recv_largest_pn = PN,
        spin_outgoing = Outgoing
    };
update_spin_from_recv(_FirstByte, _PN, State) ->
    State.

%% Short-header packet overhead for a DATAGRAM frame on the 1-RTT level:
%%   1 byte flags
%%   + DCID length (no length byte on short header)
%%   + up to 4 bytes packet number
%%   + 16 bytes AEAD tag
%%   + 1 byte frame type (0x31 DATAGRAM_WITH_LEN)
%%   + up to 2 bytes length varint (covers lengths up to 16383).
%% That leaves `pmtu - datagram_overhead(State)` as the upper bound on
%% the payload we can fit in a single UDP datagram without fragmenting.
datagram_overhead(#state{dcid = Dcid}) ->
    1 + byte_size(Dcid) + 4 + 16 + 1 + 2.

%% Deliver an inbound DATAGRAM to the owner and account for it in the
%% bounded recv queue. When the queue has no cap (`infinity') we keep
%% today's zero-overhead push-to-mailbox behaviour. With a finite cap
%% the oldest entry is dropped so a slow owner can detect back-pressure
%% via datagram_stats/1 without the mailbox growing unbounded.
deliver_datagram(
    Data,
    #state{
        owner = Owner,
        datagram_recv_queue = Queue,
        datagram_recv_queue_len = Cap,
        datagram_recv_delivered = Delivered,
        datagram_recv_dropped = Dropped
    } = State
) ->
    Owner ! {quic, self(), {datagram, Data}},
    case Cap of
        infinity ->
            State#state{datagram_recv_delivered = Delivered + 1};
        Max when is_integer(Max), Max >= 0 ->
            {Queue1, Dropped1} =
                case queue:len(Queue) >= Max of
                    true ->
                        Trimmed = queue_drop_oldest(Queue),
                        {queue:in(Data, Trimmed), Dropped + 1};
                    false ->
                        {queue:in(Data, Queue), Dropped}
                end,
            State#state{
                datagram_recv_queue = Queue1,
                datagram_recv_delivered = Delivered + 1,
                datagram_recv_dropped = Dropped1
            }
    end.

queue_drop_oldest(Q) ->
    case queue:out(Q) of
        {{value, _}, Rest} -> Rest;
        {empty, _} -> Q
    end.

%% Stats snapshot used by quic:datagram_stats/1.
datagram_stats_snapshot(#state{
    datagram_recv_delivered = Delivered,
    datagram_recv_dropped = RDropped,
    datagram_sent = Sent,
    datagram_send_dropped = SDropped
}) ->
    #{
        delivered => Delivered,
        dropped_recv => RDropped,
        sent => Sent,
        dropped_send => SDropped
    }.

%% Send a datagram (RFC 9221)
%% RFC 9221: MUST NOT send DATAGRAM frames until receiving peer's max_datagram_frame_size
%% and MUST NOT send frames larger than peer's advertised value.
%% Additionally clamp to the current PMTU budget so we don't emit a UDP
%% payload the network will black-hole.
do_send_datagram(_Data, #state{max_datagram_frame_size_remote = 0}) ->
    %% Peer didn't advertise datagram support
    {error, datagrams_not_supported};
do_send_datagram(
    Data, #state{max_datagram_frame_size_remote = PeerMax, cc_state = CCState} = State
) ->
    DataBin = iolist_to_binary(Data),
    DataSize = byte_size(DataBin),
    PmtuBudget = max(0, get_local_max_udp_payload_size(State) - datagram_overhead(State)),
    if
        DataSize > PeerMax ->
            {error, datagram_too_large};
        DataSize > PmtuBudget ->
            {error, datagram_too_large_for_path};
        true ->
            case quic_cc:can_send(CCState, DataSize + datagram_overhead(State)) of
                true ->
                    %% Use datagram_with_length for better framing
                    Frame = {datagram_with_length, DataBin},
                    Payload = quic_frame:encode(Frame),
                    State1 = send_app_packet_internal(Payload, [Frame], State),
                    {ok, State1#state{datagram_sent = State#state.datagram_sent + 1}};
                false ->
                    %% Datagrams are unreliable - just drop if cwnd is full
                    {error, congestion_limited, State#state{
                        datagram_send_dropped = State#state.datagram_send_dropped + 1
                    }}
            end
    end.

%% Send stream data in fragments, tracking how many bytes were actually sent
%% Returns {NewState, BytesSent} where BytesSent is the count of bytes actually transmitted
%% (not queued due to congestion)
send_stream_data_fragmented_tracked(StreamId, Offset, Data, Fin, State) ->
    send_stream_data_fragmented_tracked(StreamId, Offset, Data, Fin, State, 0).

send_stream_data_fragmented_tracked(StreamId, Offset, Data, Fin, State, BytesSentSoFar) ->
    %% Calculate max chunk size based on current PMTU
    MaxChunkSize = get_max_stream_data_per_packet(State),
    DataSize = iolist_size(Data),

    case DataSize =< MaxChunkSize of
        true ->
            %% Data fits in one packet - can pass iolist directly
            %% Frame encoder will handle flattening
            send_stream_single_packet(StreamId, Offset, Data, Fin, State, BytesSentSoFar);
        false ->
            %% Split data into chunks - need binary for pattern matching
            DataBin = iolist_to_binary(Data),
            send_stream_chunked(StreamId, Offset, DataBin, Fin, State, BytesSentSoFar, MaxChunkSize)
    end.

%% @doc Send stream data that fits in a single packet.
%% Data can be iolist - flattening deferred to frame encoder
send_stream_single_packet(StreamId, Offset, Data, Fin, State, BytesSentSoFar) ->
    #state{cc_state = CCState, pacing_enabled = PacingEnabled, streams = Streams} = State,
    DataSize = iolist_size(Data),
    PacketSize = DataSize + ?PACKET_OVERHEAD,
    %% Control streams (urgency 0) can exceed cwnd to prevent tick blocking
    Urgency = get_stream_urgency(StreamId, Streams),
    CanSend =
        case Urgency of
            0 -> quic_cc:can_send_control(CCState, PacketSize);
            _ -> quic_cc:can_send(CCState, PacketSize)
        end,
    case CanSend of
        true ->
            %% Cwnd allows - check pacing
            case PacingEnabled andalso not quic_cc:pacing_allows(CCState, PacketSize) of
                true ->
                    %% Pacing blocked - queue data and set pacing timer
                    Delay = quic_cc:pacing_delay(CCState, PacketSize),
                    ?LOG_DEBUG(
                        #{
                            what => stream_data_paced,
                            stream_id => StreamId,
                            data_size => DataSize,
                            pacing_delay_ms => Delay
                        },
                        ?QUIC_LOG_META
                    ),
                    case queue_stream_data(StreamId, Offset, Data, Fin, State) of
                        {ok, QueuedState} ->
                            PacedState = maybe_set_pacing_timer(Delay, QueuedState),
                            {PacedState, BytesSentSoFar};
                        {error, send_queue_full} ->
                            {error, send_queue_full}
                    end;
                false ->
                    %% Pacing allows - send immediately and consume tokens
                    {_Allowed, NewCCState} = quic_cc:get_pacing_tokens(CCState, PacketSize),
                    State1 = State#state{cc_state = NewCCState},
                    %% Flatten data for frame encoding
                    DataBin = iolist_to_binary(Data),
                    Frame = {stream, StreamId, Offset, DataBin, Fin},
                    Payload = quic_frame:encode(Frame),
                    NewState = send_app_packet_internal(Payload, [Frame], State1),
                    {NewState, BytesSentSoFar + DataSize}
            end;
        false ->
            %% Queue the data for later sending when cwnd allows
            ?LOG_DEBUG(
                #{
                    what => stream_data_queued_cwnd,
                    stream_id => StreamId,
                    data_size => DataSize,
                    offset => Offset,
                    cwnd => quic_cc:cwnd(CCState),
                    bytes_in_flight => quic_cc:bytes_in_flight(CCState),
                    available_cwnd => quic_cc:available_cwnd(CCState)
                },
                ?QUIC_LOG_META
            ),
            case queue_stream_data(StreamId, Offset, Data, Fin, State) of
                {ok, QueuedState} ->
                    % Return bytes sent so far, not including queued
                    {QueuedState, BytesSentSoFar};
                {error, send_queue_full} ->
                    {error, send_queue_full}
            end
    end.

%% @doc Send stream data that requires chunking.
send_stream_chunked(StreamId, Offset, Data, Fin, State, BytesSentSoFar, MaxChunkSize) ->
    #state{cc_state = CCState, pacing_enabled = PacingEnabled, streams = Streams} = State,
    PacketSize = MaxChunkSize + ?PACKET_OVERHEAD,
    %% Control streams (urgency 0) can exceed cwnd to prevent tick blocking
    Urgency = get_stream_urgency(StreamId, Streams),
    CanSend =
        case Urgency of
            0 -> quic_cc:can_send_control(CCState, PacketSize);
            _ -> quic_cc:can_send(CCState, PacketSize)
        end,
    case CanSend of
        true ->
            %% Cwnd allows - check pacing
            case PacingEnabled andalso not quic_cc:pacing_allows(CCState, PacketSize) of
                true ->
                    %% Pacing blocked - queue remaining data and set timer
                    Delay = quic_cc:pacing_delay(CCState, PacketSize),
                    ?LOG_DEBUG(
                        #{
                            what => stream_data_paced_large,
                            stream_id => StreamId,
                            data_size => byte_size(Data),
                            pacing_delay_ms => Delay
                        },
                        ?QUIC_LOG_META
                    ),
                    case queue_stream_data(StreamId, Offset, Data, Fin, State) of
                        {ok, QueuedState} ->
                            PacedState = maybe_set_pacing_timer(Delay, QueuedState),
                            {PacedState, BytesSentSoFar};
                        {error, send_queue_full} ->
                            {error, send_queue_full}
                    end;
                false ->
                    %% Pacing allows - consume tokens and send
                    {_Allowed, NewCCState} = quic_cc:get_pacing_tokens(CCState, PacketSize),
                    State0 = State#state{cc_state = NewCCState},
                    <<Chunk:MaxChunkSize/binary, Rest/binary>> = Data,
                    Frame = {stream, StreamId, Offset, Chunk, false},
                    Payload = quic_frame:encode(Frame),
                    State1 = send_app_packet_internal(Payload, [Frame], State0),
                    NewOffset = Offset + MaxChunkSize,
                    NewBytesSent = BytesSentSoFar + MaxChunkSize,
                    send_stream_data_fragmented_tracked(
                        StreamId, NewOffset, Rest, Fin, State1, NewBytesSent
                    )
            end;
        false ->
            %% Queue remaining data for later
            ?LOG_DEBUG(
                #{
                    what => stream_data_queued_cwnd_large,
                    stream_id => StreamId,
                    total_data_size => byte_size(Data),
                    offset => Offset,
                    bytes_sent_so_far => BytesSentSoFar,
                    cwnd => quic_cc:cwnd(CCState),
                    bytes_in_flight => quic_cc:bytes_in_flight(CCState),
                    available_cwnd => quic_cc:available_cwnd(CCState)
                },
                ?QUIC_LOG_META
            ),
            case queue_stream_data(StreamId, Offset, Data, Fin, State) of
                {ok, QueuedState} ->
                    % Return bytes sent so far
                    {QueuedState, BytesSentSoFar};
                {error, send_queue_full} ->
                    {error, send_queue_full}
            end
    end.

%% Queue stream data when congestion window is full
%% Uses bucket-based priority queue for O(1) insert (RFC 9218)
%% Returns {ok, State} | {error, send_queue_full} if queue limit exceeded
%% Entry format: {stream_data, StreamId, Offset, Data, Fin, DataSize}
%% DataSize is cached to avoid repeated iolist_size calls
queue_stream_data(
    StreamId,
    Offset,
    Data,
    Fin,
    #state{
        send_queue = PQ,
        streams = Streams,
        send_queue_bytes = QueueBytes,
        send_queue_version = Version
    } = State
) ->
    DataSize = iolist_size(Data),
    NewQueueBytes = QueueBytes + DataSize,
    case NewQueueBytes > ?MAX_SEND_QUEUE_BYTES of
        true ->
            ?LOG_WARNING(
                #{
                    what => send_queue_full,
                    stream_id => StreamId,
                    queue_bytes => QueueBytes,
                    data_size => DataSize,
                    max_bytes => ?MAX_SEND_QUEUE_BYTES
                },
                ?QUIC_LOG_META
            ),
            {error, send_queue_full};
        false ->
            Urgency = get_stream_urgency(StreamId, Streams),
            %% Cache DataSize in entry to avoid repeated iolist_size calls
            Entry = {stream_data, StreamId, Offset, Data, Fin, DataSize},
            NewPQ = pqueue_in(Entry, Urgency, PQ),
            NewVersion = Version + 1,
            {ok, State#state{
                send_queue = NewPQ,
                send_queue_bytes = NewQueueBytes,
                send_queue_version = NewVersion
            }}
    end.

%% Get stream urgency (default 3 if stream not found)
get_stream_urgency(StreamId, Streams) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream_state{urgency = Urgency}} -> Urgency;
        % Default urgency
        error -> 3
    end.

%% Process send queue when congestion window frees up
%% Processes streams in priority order (lower urgency = higher priority)
%% IMPORTANT: Must check BOTH congestion control AND flow control before sending
process_send_queue(#state{send_queue = PQ} = State) ->
    case pqueue_peek(PQ) of
        empty ->
            State;
        {value, {stream_data, StreamId, Offset, _Data, _Fin, DataSize}} ->
            %% Check flow control BEFORE dequeuing
            %% Use the Offset stored in the queue entry, not stream.send_offset,
            %% because send_offset may have advanced past this queued data's position.
            %% DataSize is cached in entry to avoid repeated iolist_size calls.
            case check_send_queue_flow_control(StreamId, Offset, DataSize, State) of
                ok ->
                    %% Flow control allows - dequeue and try to send
                    process_send_queue_entry(State);
                {blocked, _Reason} ->
                    %% Flow control blocked - leave in queue, wait for MAX_DATA
                    State
            end
    end.

%% Check flow control limits for queued data
%% Returns ok | {blocked, connection | {stream, StreamId}}
%% Takes the Offset from the queue entry since stream.send_offset may have
%% advanced past queued data positions (per PR #16 fix).
check_send_queue_flow_control(StreamId, Offset, DataSize, #state{
    max_data_remote = MaxDataRemote,
    data_sent = DataSent,
    streams = Streams
}) ->
    %% Check connection-level flow control
    ConnectionAllowed = MaxDataRemote - DataSent,
    case DataSize =< ConnectionAllowed of
        false ->
            {blocked, connection};
        true ->
            %% Check stream-level flow control using the queue entry's Offset
            case maps:find(StreamId, Streams) of
                {ok, #stream_state{send_max_data = SendMaxData}} ->
                    %% Data at Offset with DataSize must fit within SendMaxData
                    case Offset + DataSize =< SendMaxData of
                        false ->
                            {blocked, {stream, StreamId}};
                        true ->
                            ok
                    end;
                error ->
                    %% Stream not found - allow (will fail later)
                    ok
            end
    end.

%% Actually process the queue entry (called after flow control check passes)
process_send_queue_entry(
    #state{send_queue = PQ, send_queue_bytes = QueueBytes} = State
) ->
    case pqueue_out(PQ) of
        {empty, _} ->
            State;
        {{value, {stream_data, StreamId, Offset, Data, Fin, DataSize}}, NewPQ} ->
            %% Decrement queue bytes for dequeued data (DataSize cached in entry)
            %% (if data is re-queued, queue_stream_data will increment appropriately)
            DecrementedQueueBytes = max(0, QueueBytes - DataSize),
            State1 = State#state{send_queue = NewPQ, send_queue_bytes = DecrementedQueueBytes},
            case send_stream_data_fragmented_tracked(StreamId, Offset, Data, Fin, State1) of
                {error, send_queue_full} ->
                    ?LOG_WARNING(
                        #{
                            what => send_queue_overflow_on_requeue,
                            stream_id => StreamId,
                            data_size => DataSize
                        },
                        ?QUIC_LOG_META
                    ),
                    State1;
                {State2, BytesSent} ->
                    %% Only update data_sent for connection-level flow control accounting.
                    %% send_offset was already advanced when the data was first queued
                    %% (in do_send_data) to prevent offset overlap bugs.
                    State3 =
                        case BytesSent > 0 of
                            true ->
                                State2#state{
                                    data_sent = State2#state.data_sent + BytesSent
                                };
                            false ->
                                State2
                        end,
                    %% If data was queued again (cwnd still full), stop processing
                    case pqueue_is_empty(State3#state.send_queue) of
                        true ->
                            State3;
                        false ->
                            %% Check if we just queued more data (cwnd full)
                            %% Use version counter for fast comparison (avoids structural equality on 8-tuple)
                            case
                                State3#state.send_queue_version =:= State1#state.send_queue_version
                            of
                                % Keep processing (check flow control again)
                                true -> process_send_queue(State3);
                                % New data queued, cwnd full
                                false -> State3
                            end
                    end
            end
    end.

%%--------------------------------------------------------------------
%% Priority Queue - Bucket-based implementation for urgency 0-7
%% O(1) insert, O(1) dequeue (8 buckets = constant)
%%--------------------------------------------------------------------
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
    {
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new()
    }.

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
            %% Cancel deadline timer if any
            case StreamState#stream_state.deadline_timer of
                undefined -> ok;
                Timer -> erlang:cancel_timer(Timer)
            end,
            %% Send RESET_STREAM frame
            FinalSize = StreamState#stream_state.send_offset,
            ResetFrame = {reset_stream, StreamId, ErrorCode, FinalSize},
            NewState = send_frame(ResetFrame, State),
            {ok, NewState#state{
                streams = maps:remove(StreamId, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Request peer to stop sending on a stream (RFC 9000 Section 19.5)
do_stop_sending(StreamId, ErrorCode, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, _StreamState} ->
            %% Send STOP_SENDING frame
            StopFrame = {stop_sending, StreamId, ErrorCode},
            NewState = send_frame(StopFrame, State),
            {ok, NewState};
        error ->
            {error, unknown_stream}
    end.

%% RESET_STREAM_AT: Reset stream with reliable delivery up to ReliableSize
%% (draft-ietf-quic-reliable-stream-reset-07)
do_reset_stream_at(
    StreamId,
    ErrorCode,
    ReliableSize,
    #state{streams = Streams, transport_params = TP} = State
) ->
    case maps:get(reset_stream_at, TP, false) of
        false ->
            {error, not_supported};
        true ->
            case maps:find(StreamId, Streams) of
                {ok, StreamState} ->
                    do_reset_stream_at_with_stream(
                        StreamId, ErrorCode, ReliableSize, StreamState, State
                    );
                error ->
                    {error, unknown_stream}
            end
    end.

do_reset_stream_at_with_stream(StreamId, ErrorCode, ReliableSize, StreamState, State) ->
    FinalSize = StreamState#stream_state.send_offset,
    case validate_reset_stream_at(ReliableSize, FinalSize, ErrorCode, StreamState) of
        ok ->
            execute_reset_stream_at(
                StreamId,
                ErrorCode,
                ReliableSize,
                FinalSize,
                StreamState,
                State
            );
        {error, _} = Error ->
            Error
    end.

validate_reset_stream_at(ReliableSize, FinalSize, ErrorCode, StreamState) ->
    ExistingReliable = StreamState#stream_state.reset_reliable_size,
    ExistingError = StreamState#stream_state.reset_error,
    case ReliableSize > FinalSize of
        true ->
            {error, {invalid_reliable_size, ReliableSize, FinalSize}};
        false ->
            validate_reset_stream_at_constraints(
                ReliableSize,
                ErrorCode,
                ExistingReliable,
                ExistingError
            )
    end.

validate_reset_stream_at_constraints(ReliableSize, ErrorCode, ExistingReliable, ExistingError) ->
    case ExistingReliable =/= undefined andalso ReliableSize > ExistingReliable of
        true ->
            {error, cannot_increase_reliable_size};
        false ->
            case ExistingError =/= undefined andalso ErrorCode =/= ExistingError of
                true ->
                    {error, cannot_change_error_code};
                false ->
                    ok
            end
    end.

execute_reset_stream_at(
    StreamId,
    ErrorCode,
    ReliableSize,
    FinalSize,
    StreamState,
    #state{streams = Streams} = State
) ->
    %% Cancel deadline timer if any
    case StreamState#stream_state.deadline_timer of
        undefined -> ok;
        Timer -> erlang:cancel_timer(Timer)
    end,
    %% Send RESET_STREAM_AT frame
    Frame = {reset_stream_at, StreamId, ErrorCode, FinalSize, ReliableSize},
    NewState = send_frame(Frame, State),
    %% Truncate send buffer beyond ReliableSize
    TruncatedBuffer = truncate_send_buffer(StreamState#stream_state.send_buffer, ReliableSize),
    UpdatedStream = StreamState#stream_state{
        state = reset,
        reset_reliable_size = ReliableSize,
        reset_error = ErrorCode,
        send_buffer = TruncatedBuffer,
        deadline_timer = undefined
    },
    {ok, NewState#state{streams = maps:put(StreamId, UpdatedStream, Streams)}}.

%% Truncate send buffer to only keep data up to ReliableSize
truncate_send_buffer(Buffer, ReliableSize) when is_list(Buffer) ->
    lists:filter(
        fun({Offset, _Data}) ->
            %% Keep chunk if it starts before ReliableSize
            Offset < ReliableSize
        end,
        Buffer
    );
truncate_send_buffer(Buffer, _ReliableSize) ->
    %% Empty or other buffer type - return as-is
    Buffer.

%% Set stream priority (RFC 9218)
do_set_stream_priority(StreamId, Urgency, Incremental, #state{streams = Streams} = State) when
    Urgency >= 0, Urgency =< 7, is_boolean(Incremental)
->
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
            {ok, {StreamState#stream_state.urgency, StreamState#stream_state.incremental}};
        error ->
            {error, unknown_stream}
    end.

%% Set congestion control algorithm
do_set_congestion_control(Algorithm, #state{cc_state = OldCC} = State) when
    Algorithm =:= newreno; Algorithm =:= bbr; Algorithm =:= cubic
->
    NewCC = quic_cc:new(Algorithm, #{
        max_datagram_size => quic_cc:max_datagram_size(OldCC)
    }),
    {ok, State#state{cc_state = NewCC}};
do_set_congestion_control(_Algorithm, _State) ->
    {error, invalid_algorithm}.

%% Set stream deadline
do_set_stream_deadline(StreamId, TimeoutMs, Opts, #state{streams = Streams} = State) when
    is_integer(TimeoutMs), TimeoutMs > 0
->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Cancel existing deadline timer if any
            case StreamState#stream_state.deadline_timer of
                undefined -> ok;
                OldTimer -> erlang:cancel_timer(OldTimer)
            end,
            %% Calculate absolute deadline
            Now = erlang:system_time(millisecond),
            Deadline = Now + TimeoutMs,
            %% Parse options
            Action = maps:get(action, Opts, both),
            ErrorCode = maps:get(error_code, Opts, ?QUIC_STREAM_DEADLINE_EXCEEDED),
            %% Start new timer
            TimerRef = erlang:send_after(TimeoutMs, self(), {stream_deadline, StreamId}),
            NewStreamState = StreamState#stream_state{
                deadline = Deadline,
                deadline_timer = TimerRef,
                deadline_action = Action,
                deadline_error_code = ErrorCode
            },
            {ok, State#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            }};
        error ->
            {error, unknown_stream}
    end;
do_set_stream_deadline(_StreamId, _TimeoutMs, _Opts, _State) ->
    {error, invalid_timeout}.

%% Cancel stream deadline
do_cancel_stream_deadline(StreamId, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Cancel timer if exists
            case StreamState#stream_state.deadline_timer of
                undefined -> ok;
                Timer -> erlang:cancel_timer(Timer)
            end,
            NewStreamState = StreamState#stream_state{
                deadline = undefined,
                deadline_timer = undefined
            },
            {ok, State#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Get stream deadline info
do_get_stream_deadline(StreamId, #state{streams = Streams}) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream_state{deadline = undefined}} ->
            {error, no_deadline};
        {ok, #stream_state{deadline = infinity, deadline_action = Action}} ->
            {ok, {infinity, Action}};
        {ok, #stream_state{deadline = Deadline, deadline_action = Action}} ->
            Now = erlang:system_time(millisecond),
            Remaining = max(0, Deadline - Now),
            {ok, {Remaining, Action}};
        error ->
            {error, unknown_stream}
    end.

%% Handle stream deadline expiration
handle_stream_deadline_expired(
    StreamId,
    #state{
        streams = Streams,
        owner = Owner
    } = State
) ->
    case maps:find(StreamId, Streams) of
        {ok,
            #stream_state{
                deadline_action = Action,
                deadline_error_code = ErrorCode,
                state = StreamState
            } = Stream} when StreamState =/= closed, StreamState =/= reset ->
            %% Clear the deadline timer from stream state
            Stream1 = Stream#stream_state{
                deadline = undefined,
                deadline_timer = undefined
            },
            Streams1 = maps:put(StreamId, Stream1, Streams),
            State1 = State#state{streams = Streams1},
            %% Notify owner if requested
            case Action of
                notify ->
                    Owner ! {quic, self(), {stream_deadline, StreamId}},
                    {ok, State1};
                reset ->
                    do_close_stream_deadline(StreamId, ErrorCode, State1);
                both ->
                    Owner ! {quic, self(), {stream_deadline, StreamId}},
                    do_close_stream_deadline(StreamId, ErrorCode, State1)
            end;
        {ok, _ClosedStream} ->
            %% Stream already closed
            {error, stream_closed};
        error ->
            %% Stream doesn't exist
            {error, unknown_stream}
    end.

%% Close stream due to deadline expiry (sends RESET_STREAM)
do_close_stream_deadline(StreamId, ErrorCode, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Send RESET_STREAM frame
            FinalSize = StreamState#stream_state.send_offset,
            ResetFrame = {reset_stream, StreamId, ErrorCode, FinalSize},
            NewState = send_frame(ResetFrame, State),
            %% Mark stream as reset but keep in map for cleanup
            NewStreamState = StreamState#stream_state{
                state = reset,
                send_buffer = [],
                deadline = undefined,
                deadline_timer = undefined
            },
            {ok, NewState#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Initiate connection close
initiate_close(Reason, #state{path_validation_timer = PathTimer} = State) ->
    %% Cancel path validation timer if active
    cancel_timer(PathTimer),
    State1 = State#state{path_validation_timer = undefined, path_validation_token = undefined},
    %% Send CONNECTION_CLOSE frame
    {ErrorCode, ReasonPhrase} =
        case Reason of
            normal ->
                {?QUIC_NO_ERROR, <<>>};
            {app_error, Code, Phrase} when is_integer(Code), is_binary(Phrase) ->
                {Code, Phrase};
            _ ->
                {?QUIC_APPLICATION_ERROR, <<>>}
        end,
    CloseFrame = {connection_close, application, ErrorCode, undefined, ReasonPhrase},
    case State1#state.app_keys of
        undefined ->
            %% No keys yet - cannot send frame, just set close_reason
            State1#state{close_reason = Reason};
        _ ->
            send_frame(CloseFrame, State1#state{close_reason = Reason})
    end.

%% Send PROTOCOL_VIOLATION transport error (RFC 9000)
%% Used when a peer violates the protocol (e.g., RFC 9221 datagram violations)
send_protocol_violation(Reason, State) ->
    CloseFrame = {connection_close, transport, ?QUIC_PROTOCOL_VIOLATION, 0, Reason},
    case State#state.app_keys of
        undefined ->
            State#state{close_reason = {protocol_violation, Reason}};
        _ ->
            send_frame(CloseFrame, State#state{close_reason = {protocol_violation, Reason}})
    end.

%% Send CONNECTION_CLOSE frame during terminate (best effort)
%% This is called when the process is terminating unexpectedly
send_connection_close(_Reason, #state{app_keys = undefined}) ->
    %% No app keys yet, can't send encrypted close frame
    ok;
send_connection_close(Reason, State) ->
    {ErrorCode, ReasonPhrase} =
        case Reason of
            normal ->
                {?QUIC_NO_ERROR, <<>>};
            shutdown ->
                {?QUIC_NO_ERROR, <<>>};
            {shutdown, _} ->
                {?QUIC_NO_ERROR, <<>>};
            {app_error, Code, Phrase} when is_integer(Code), is_binary(Phrase) ->
                {Code, Phrase};
            _ ->
                {?QUIC_APPLICATION_ERROR, <<>>}
        end,
    CloseFrame = {connection_close, application, ErrorCode, undefined, ReasonPhrase},
    %% Best effort send - ignore errors since we're terminating anyway
    try
        send_frame(CloseFrame, State)
    catch
        _:_ -> ok
    end,
    ok.

%% Send TLS alert as QUIC crypto error and close connection
%% QUIC crypto errors are 0x100 + TLS alert code (RFC 9001 Section 4.8)
send_tls_alert(AlertCode, State) ->
    ErrorCode = ?QUIC_CRYPTO_ERROR_BASE + AlertCode,
    CloseFrame = {connection_close, transport, ErrorCode, 0, <<"certificate verify failed">>},
    case State#state.handshake_keys of
        undefined ->
            State#state{close_reason = {tls_alert, AlertCode}};
        _ ->
            send_frame(CloseFrame, State#state{close_reason = {tls_alert, AlertCode}})
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
%% IMPORTANT: Retransmissions must respect congestion control to prevent
%% bytes_in_flight from exceeding cwnd. Packets that can't be sent immediately
%% will be retried on the next PTO timeout or when cwnd allows.
retransmit_lost_packets([], State) ->
    State;
retransmit_lost_packets([#sent_packet{frames = Frames} | Rest], State) ->
    RetransmitFrames = quic_loss:retransmittable_frames(Frames),
    %% Filter out stream data beyond ReliableSize (RESET_STREAM_AT spec requirement)
    FilteredFrames = filter_reset_stream_at_data(RetransmitFrames, State),
    State1 = send_retransmit_frames_cc(FilteredFrames, State),
    retransmit_lost_packets(Rest, State1).

%% Filter stream data beyond ReliableSize for streams with RESET_STREAM_AT
%% Per draft-ietf-quic-reliable-stream-reset-07: Data beyond ReliableSize
%% SHOULD NOT be retransmitted
filter_reset_stream_at_data(Frames, #state{streams = Streams}) ->
    lists:filter(
        fun(Frame) ->
            case Frame of
                {stream, StreamId, Offset, _Data, _Fin} ->
                    case maps:find(StreamId, Streams) of
                        {ok, #stream_state{reset_reliable_size = RS}} when RS =/= undefined ->
                            %% Only retransmit if frame starts before ReliableSize
                            Offset < RS;
                        _ ->
                            %% No RESET_STREAM_AT - always retransmit
                            true
                    end;
                _ ->
                    %% Non-stream frames - always retransmit
                    true
            end
        end,
        Frames
    ).

%% Send frames for retransmission with congestion control check
send_retransmit_frames_cc([], State) ->
    State;
send_retransmit_frames_cc(Frames, #state{cc_state = CCState} = State) ->
    %% Encode all frames and check size
    Payload = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
    PacketSize = byte_size(Payload) + 50,

    %% Check if CC allows sending this retransmission
    %% Use can_send_control to allow small overage for retransmissions
    case quic_cc:can_send_control(CCState, PacketSize) of
        true ->
            send_app_packet_internal(Payload, Frames, State);
        false ->
            %% CC doesn't allow - defer retransmission
            %% The PTO mechanism will eventually retry this data
            ?LOG_DEBUG(
                #{
                    what => retransmit_deferred_by_cc,
                    packet_size => PacketSize,
                    cwnd => quic_cc:cwnd(CCState),
                    bytes_in_flight => quic_cc:bytes_in_flight(CCState)
                },
                ?QUIC_LOG_META
            ),
            State
    end.

%% Handle PTO timeout - send probe packet
handle_pto_timeout(#state{loss_state = LossState} = State) ->
    %% Increment PTO count
    NewLossState = quic_loss:on_pto_expired(LossState),
    State1 = State#state{loss_state = NewLossState},

    %% Send probe packet (retransmit oldest unacked or send PING)
    State2 = send_probe_packet(State1),

    %% Flush immediately - probe packets and timers must not be batched
    State3 = flush_dirty_timers(flush_socket_batch(State2)),

    %% Set new PTO timer
    set_pto_timer(State3).

%% Send a probe packet for PTO
%% PTO probes are allowed to use control_allowance per RFC 9002
send_probe_packet(State) ->
    case get_oldest_unacked_frames(State) of
        {ok, Frames} ->
            %% Retransmit oldest data as probe with CC check
            send_retransmit_frames_cc(Frames, State);
        none ->
            %% No data to retransmit, send PING (always allowed as control)
            Payload = quic_frame:encode(ping),
            send_app_packet_internal(Payload, [ping], State)
    end.

%% Get frames from the oldest unacked packet for probe retransmission
%% Uses cached oldest_unacked from loss_state for O(1) lookup
get_oldest_unacked_frames(#state{loss_state = LossState}) ->
    case quic_loss:oldest_unacked(LossState) of
        none ->
            none;
        {ok, #sent_packet{frames = Frames}} ->
            RetransmitFrames = quic_loss:retransmittable_frames(Frames),
            case RetransmitFrames of
                [] -> none;
                _ -> {ok, RetransmitFrames}
            end
    end.

%% Send keep-alive PING frame (RFC 9000 - transport-level liveness)
%% PING frames bypass flow control and ensure connection stays alive
send_keep_alive_ping(#state{app_keys = undefined} = State) ->
    %% No app keys yet, skip PING
    State;
send_keep_alive_ping(State) ->
    Payload = quic_frame:encode(ping),
    send_app_packet_internal(Payload, [ping], State).

%%====================================================================
%% PTO Timer Management
%%====================================================================

%% Set PTO timer based on current loss state
%% Uses unique reference in message to detect stale timer events
set_pto_timer(#state{loss_state = LossState, pto_timer = OldTimer} = State) ->
    cancel_timer(OldTimer),
    case quic_loss:bytes_in_flight(LossState) > 0 of
        true ->
            PTO = quic_loss:get_pto(LossState),
            Ref = make_ref(),
            erlang:send_after(PTO, self(), {pto_timeout, Ref}),
            State#state{pto_timer = Ref};
        false ->
            State#state{pto_timer = undefined}
    end.

%% Helper to cancel a timer reference
cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref).

%% Handle pacing timeout - drain queued data
%% Note: pacing_timer is already set to undefined by the handler before calling this
handle_pacing_timeout(#state{send_queue = PQ} = State) ->
    ?LOG_DEBUG(#{what => pacing_timeout_fired, queue_empty => pqueue_is_empty(PQ)}, ?QUIC_LOG_META),
    %% Check if there's queued data
    case pqueue_is_empty(PQ) of
        true ->
            State;
        false ->
            %% Process the send queue
            State1 = process_send_queue(State),
            %% If there's still queued data and pacing is blocking, set another timer
            State2 = maybe_reschedule_pacing(State1),
            %% Event-driven flush: flush batch and timers after pacing timeout processing
            flush_dirty_timers(flush_socket_batch(State2))
    end.

%% Check if we need to reschedule pacing timer after processing queue
maybe_reschedule_pacing(#state{send_queue = PQ, cc_state = CCState, pacing_enabled = true} = State) ->
    case pqueue_is_empty(PQ) of
        true ->
            State;
        false ->
            %% Check if pacing would block the next send
            MaxChunkSize = get_max_stream_data_per_packet(State),
            PacketSize = MaxChunkSize + ?PACKET_OVERHEAD,
            case quic_cc:can_send(CCState, PacketSize) of
                true ->
                    %% Cwnd allows, check pacing
                    case quic_cc:pacing_allows(CCState, PacketSize) of
                        true ->
                            %% Can send now - no timer needed
                            State;
                        false ->
                            %% Pacing blocked - set timer
                            Delay = quic_cc:pacing_delay(CCState, PacketSize),
                            maybe_set_pacing_timer(Delay, State)
                    end;
                false ->
                    %% Cwnd blocked - no pacing timer needed
                    State
            end
    end;
maybe_reschedule_pacing(State) ->
    State.

%%====================================================================
%% Idle Timer Management (RFC 9000 §10.1)
%%====================================================================

%% Set idle timer based on idle_timeout configuration
%% Uses unique reference in message to detect stale timer events
set_idle_timer(#state{idle_timeout = 0} = State) ->
    State#state{idle_timer = undefined};
set_idle_timer(#state{idle_timeout = Timeout, idle_timer = OldTimer} = State) ->
    cancel_timer(OldTimer),
    Ref = make_ref(),
    erlang:send_after(Timeout, self(), {idle_timeout, Ref}),
    State#state{idle_timer = Ref}.

%%====================================================================
%% Keep-Alive Timer Management (RFC 9000 - PING frames)
%%====================================================================

%% Calculate keep-alive interval from options and idle timeout
%% Default: disabled (opt-in to preserve idle_timeout semantics)
%% Set to 'auto' for half of idle timeout, or specify explicit interval
calculate_keep_alive_interval(Opts, IdleTimeout) ->
    case maps:get(keep_alive_interval, Opts, disabled) of
        disabled -> disabled;
        0 -> disabled;
        auto when IdleTimeout =:= 0 -> disabled;
        auto -> max(5000, IdleTimeout div 2);
        Interval when is_integer(Interval), Interval >= 5000 -> Interval;
        Interval when is_integer(Interval) -> 5000
    end.

%% Set keep-alive timer
%% Uses unique reference in message to detect stale timer events
set_keep_alive_timer(#state{keep_alive_interval = disabled} = State) ->
    State#state{keep_alive_timer = undefined};
set_keep_alive_timer(
    #state{
        keep_alive_interval = Interval,
        keep_alive_timer = OldTimer
    } = State
) ->
    cancel_timer(OldTimer),
    Ref = make_ref(),
    erlang:send_after(Interval, self(), {keep_alive_timeout, Ref}),
    State#state{keep_alive_timer = Ref}.

%%====================================================================
%% Pacing Timer Management (RFC 9002 §7.7)
%%====================================================================

%% Set pacing timer if not already set
%% Only sets a timer if there's data queued and no existing timer
%% Uses unique reference in message to detect stale timer events
maybe_set_pacing_timer(0, State) ->
    %% No delay - don't set timer
    State;
maybe_set_pacing_timer(_Delay, #state{pacing_timer = Ref} = State) when Ref =/= undefined ->
    %% Timer already set - leave it
    State;
maybe_set_pacing_timer(Delay, #state{pacing_timer = undefined} = State) ->
    %% Set new pacing timer
    ?LOG_DEBUG(#{what => pacing_timer_set, delay_ms => Delay}, ?QUIC_LOG_META),
    Ref = make_ref(),
    erlang:send_after(Delay, self(), {pacing_timeout, Ref}),
    State#state{pacing_timer = Ref}.

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
        data_received => S#state.data_received,
        send_queue_bytes => S#state.send_queue_bytes,
        recv_buffer_bytes => S#state.recv_buffer_bytes,
        max_data_local => S#state.max_data_local,
        fc_last_stream_update => S#state.fc_last_stream_update,
        fc_last_conn_update => S#state.fc_last_conn_update,
        fc_max_receive_window => S#state.fc_max_receive_window
    }.

%% Normalize ALPN list - handles binary, list of binaries, list of strings
normalize_alpn_list(undefined) ->
    [];
normalize_alpn_list(V) when is_binary(V) ->
    [V];
normalize_alpn_list([]) ->
    [];
normalize_alpn_list([H | _] = L) when is_binary(H) ->
    L;
normalize_alpn_list([H | _] = L) when is_list(H) ->
    [list_to_binary(S) || S <- L];
normalize_alpn_list([H | _] = L) when is_atom(H) ->
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
        % HP key unchanged
        hp = OldClientKeys#crypto_keys.hp,
        cipher = Cipher
    },
    NewServerKeys = #crypto_keys{
        key = NewServerKey,
        iv = NewServerIV,
        % HP key unchanged
        hp = OldServerKeys#crypto_keys.hp,
        cipher = Cipher
    },

    %% Toggle key phase
    NewPhase = 1 - CurrentPhase,

    %% Update key state
    NewKeyState = KeyState#key_update_state{
        current_phase = NewPhase,
        current_keys = {NewClientKeys, NewServerKeys},
        % Keep old keys for decryption during transition
        prev_keys = CurrentKeys,
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
                % HP key unchanged
                hp = OldClientKeys#crypto_keys.hp,
                cipher = Cipher
            },
            NewServerKeys = #crypto_keys{
                key = NewServerKey,
                iv = NewServerIV,
                % HP key unchanged
                hp = OldServerKeys#crypto_keys.hp,
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
get_current_key_phase(#state{key_state = KeyState}) -> KeyState#key_update_state.current_phase.

%%====================================================================
%% Connection Migration (RFC 9000 Section 9)
%%====================================================================

%% @doc Initiate path validation by sending PATH_CHALLENGE to the new path.
%% RFC 9000 Section 8.2: PATH_CHALLENGE must be sent to the path being validated.
%% Returns updated state with the path in validating status.
-spec initiate_path_validation({inet:ip_address(), inet:port_number()}, #state{}) -> #state{}.
initiate_path_validation(RemoteAddr, #state{dcid = CurrentDCID} = State) ->
    %% Generate 8-byte random challenge data
    ChallengeData = crypto:strong_rand_bytes(8),

    %% Create path state for the new path
    %% Track the CID being used on this path (RFC 9000 Section 9.5)
    PathState = #path_state{
        remote_addr = RemoteAddr,
        status = validating,
        challenge_data = ChallengeData,
        challenge_count = 1,
        bytes_sent = 0,
        bytes_received = 0,
        dcid = CurrentDCID
    },

    %% Add to alternative paths
    AltPaths = [PathState | State#state.alt_paths],
    State1 = State#state{alt_paths = AltPaths},

    %% Send PATH_CHALLENGE to the new path address
    send_path_challenge(RemoteAddr, ChallengeData, State1).

%% @doc Send PATH_CHALLENGE frame to a specific address.
%% This is used for path validation where the probe must go to the new path.
%% Uses the same packet encoding as send_frame but sends to a different address.
-spec send_path_challenge({inet:ip_address(), inet:port_number()}, binary(), #state{}) -> #state{}.
send_path_challenge(
    {IP, Port},
    ChallengeData,
    #state{
        socket = Socket,
        dcid = DCID,
        app_keys = AppKeys,
        role = Role,
        pn_app = PNSpace
    } = State
) ->
    %% Check we have app keys for encryption
    case AppKeys of
        {ClientKeys, ServerKeys} when ClientKeys =/= undefined, ServerKeys =/= undefined ->
            %% Select correct keys based on role
            EncryptKeys =
                case Role of
                    client -> ClientKeys;
                    server -> ServerKeys
                end,

            %% Build PATH_CHALLENGE frame
            ChallengeFrame = {path_challenge, ChallengeData},
            Payload = quic_frame:encode(ChallengeFrame),
            %% RFC 9000 Section 8.2.1: Pad to 1200 bytes for path validation
            PaddedPayload = pad_for_path_validation(Payload, DCID),

            %% Get packet number and key phase
            PN = PNSpace#pn_space.next_pn,
            PNLen = quic_packet:pn_length(PN),
            KeyPhase = get_current_key_phase(State),

            %% Build first byte for short header
            FirstByte = short_header_first_byte(KeyPhase, PNLen, State),

            %% Encrypt packet
            #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EncryptKeys,
            Packet = quic_aead:protect_short_packet(
                Cipher, Key, IV, HP, PN, FirstByte, DCID, PaddedPayload
            ),

            %% Send to the specific path address (not current remote_addr)
            case gen_udp:send(Socket, IP, Port, Packet) of
                ok ->
                    %% Update path bytes_sent for anti-amplification tracking
                    PacketSize = byte_size(Packet),
                    State1 = update_path_bytes_sent(IP, Port, PacketSize, State),
                    %% Increment packet number
                    NewPnApp = PNSpace#pn_space{next_pn = PN + 1},
                    State1#state{pn_app = NewPnApp};
                {error, _Reason} ->
                    State
            end;
        _ ->
            %% No app keys yet, can't send path validation
            ?LOG_DEBUG(#{what => path_challenge_no_keys}, ?QUIC_LOG_META),
            State
    end.

%% @doc Send PATH_RESPONSE to a specific address with proper 1200-byte padding.
%% RFC 9000 Section 8.2.1: PATH_RESPONSE MUST be padded to at least 1200 bytes.
%% RFC 9000 Section 8.2.2: PATH_RESPONSE MUST be sent to the source address of
%% the packet containing the PATH_CHALLENGE.
-spec send_path_response_to_addr(
    {inet:ip_address(), inet:port_number()},
    binary(),
    #state{}
) -> #state{}.
send_path_response_to_addr(
    {IP, Port},
    ResponseData,
    #state{
        socket = Socket,
        dcid = DCID,
        app_keys = AppKeys,
        role = Role,
        pn_app = PNSpace
    } = State
) ->
    case AppKeys of
        {ClientKeys, ServerKeys} when ClientKeys =/= undefined, ServerKeys =/= undefined ->
            EncryptKeys =
                case Role of
                    client -> ClientKeys;
                    server -> ServerKeys
                end,

            %% Build PATH_RESPONSE frame
            ResponseFrame = {path_response, ResponseData},
            Payload = quic_frame:encode(ResponseFrame),
            %% RFC 9000 Section 8.2.1: Pad to 1200 bytes for path validation
            PaddedPayload = pad_for_path_validation(Payload, DCID),

            %% Get packet number and key phase
            PN = PNSpace#pn_space.next_pn,
            PNLen = quic_packet:pn_length(PN),
            KeyPhase = get_current_key_phase(State),

            %% Build first byte for short header
            FirstByte = short_header_first_byte(KeyPhase, PNLen, State),

            %% Encrypt packet
            #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EncryptKeys,
            Packet = quic_aead:protect_short_packet(
                Cipher, Key, IV, HP, PN, FirstByte, DCID, PaddedPayload
            ),

            %% Send to the address that sent the PATH_CHALLENGE (not current remote_addr)
            case gen_udp:send(Socket, IP, Port, Packet) of
                ok ->
                    %% Increment packet number
                    NewPnApp = PNSpace#pn_space{next_pn = PN + 1},
                    State#state{pn_app = NewPnApp};
                {error, _Reason} ->
                    State
            end;
        _ ->
            %% No app keys yet
            ?LOG_DEBUG(#{what => path_response_no_keys}, ?QUIC_LOG_META),
            State
    end.

%% @doc Update bytes_sent for anti-amplification tracking on a path.
-spec update_path_bytes_sent(inet:ip_address(), inet:port_number(), non_neg_integer(), #state{}) ->
    #state{}.
update_path_bytes_sent(IP, Port, Bytes, #state{alt_paths = AltPaths} = State) ->
    NewAltPaths = lists:map(
        fun
            (#path_state{remote_addr = {PathIP, PathPort}} = PS) when
                PathIP =:= IP, PathPort =:= Port
            ->
                PS#path_state{bytes_sent = PS#path_state.bytes_sent + Bytes};
            (PS) ->
                PS
        end,
        AltPaths
    ),
    State#state{alt_paths = NewAltPaths}.

%% @doc Initiate path validation for server's preferred address (RFC 9000 Section 9.6).
%% Client validates the preferred address before migrating to it.
%% Prefers IPv6 over IPv4 when both are available.
-spec initiate_preferred_address_validation(#preferred_address{}, #state{}) -> #state{}.
initiate_preferred_address_validation(
    #preferred_address{cid = CID, stateless_reset_token = Token} = PA, State
) ->
    %% RFC 9000 Section 9.6: Client MUST use the new CID when communicating on preferred path
    %% Add the new CID to peer's pool
    CIDEntry = #cid_entry{
        % Preferred address CID has implicit sequence number 1
        seq_num = 1,
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
select_preferred_addr(#preferred_address{ipv6_addr = IPv6, ipv6_port = IPv6Port}) when
    IPv6 =/= undefined, IPv6Port =/= undefined
->
    {IPv6, IPv6Port};
select_preferred_addr(#preferred_address{ipv4_addr = IPv4, ipv4_port = IPv4Port}) when
    IPv4 =/= undefined, IPv4Port =/= undefined
->
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

%%====================================================================
%% Server-Side Address Change Detection (RFC 9000 Section 9)
%%====================================================================

%% @doc Detect type of peer address change.
%% Returns same_path, nat_rebinding (port change only), or new_path (IP change).
-spec detect_peer_address_change(
    {inet:ip_address(), inet:port_number()},
    #state{}
) -> same_path | nat_rebinding | new_path.
detect_peer_address_change(PacketAddr, #state{remote_addr = CurrentAddr}) ->
    case PacketAddr of
        CurrentAddr ->
            same_path;
        {IP, _Port} when IP =:= element(1, CurrentAddr) ->
            %% Same IP, different port - NAT rebinding
            nat_rebinding;
        _ ->
            %% Different IP - active migration
            new_path
    end.

%% @doc Handle potential address change from peer.
%% RFC 9000 Section 9: Server must validate new paths before accepting migration.
-spec maybe_handle_address_change(
    {inet:ip_address(), inet:port_number()},
    non_neg_integer(),
    #state{}
) -> #state{}.
maybe_handle_address_change(RemoteAddr, _Data, #state{remote_addr = RemoteAddr} = State) ->
    %% Same address, no change
    State;
%% NOTE: peer_disable_migration does NOT affect handling peer address changes.
%% RFC 9000 Section 18.2: disable_active_migration only means the RECEIVER should
%% not migrate to a new local address. It does NOT mean ignore peer address changes.
%% The check for peer_disable_migration is correctly placed in migrate/1 API only.
maybe_handle_address_change(NewAddr, DataSize, #state{migration_state = validating_peer} = State) ->
    %% Already validating a path - update bytes received for anti-amplification
    update_pending_path_bytes_received(NewAddr, DataSize, State);
maybe_handle_address_change(NewAddr, DataSize, State) ->
    %% New address detected - initiate path validation
    case detect_peer_address_change(NewAddr, State) of
        same_path ->
            State;
        nat_rebinding ->
            initiate_peer_path_validation(NewAddr, true, DataSize, State);
        new_path ->
            initiate_peer_path_validation(NewAddr, false, DataSize, State)
    end.

%% @doc Update bytes_received for pending path validation (anti-amplification).
-spec update_pending_path_bytes_received(
    {inet:ip_address(), inet:port_number()},
    non_neg_integer(),
    #state{}
) -> #state{}.
update_pending_path_bytes_received(
    NewAddr,
    Size,
    #state{pending_peer_validation = #path_state{remote_addr = NewAddr} = PathState} = State
) ->
    NewPath = PathState#path_state{
        bytes_received = PathState#path_state.bytes_received + Size
    },
    State#state{pending_peer_validation = NewPath};
update_pending_path_bytes_received(_NewAddr, _Size, State) ->
    %% Address doesn't match pending validation
    State.

%% @doc Initiate path validation for peer's new address.
%% RFC 9000 Section 8.2: Send PATH_CHALLENGE to validate the new path.
%% RFC 9000 Section 9.3.2: Also probe the old path to defend against spoofing.
-spec initiate_peer_path_validation(
    {inet:ip_address(), inet:port_number()},
    boolean(),
    non_neg_integer(),
    #state{}
) -> #state{}.
initiate_peer_path_validation(NewAddr, IsNATRebinding, DataSize, State) ->
    %% Create path state for the new address
    NewChallengeData = crypto:strong_rand_bytes(8),
    NewPathState = #path_state{
        remote_addr = NewAddr,
        status = validating,
        challenge_data = NewChallengeData,
        challenge_count = 1,
        bytes_sent = 0,
        bytes_received = DataSize,
        is_nat_rebinding = IsNATRebinding
    },

    %% RFC 9000 Section 9.3.2: Also probe the old path to defend against spoofing
    %% An attacker on-path could copy a packet with spoofed source address
    OldAddr = State#state.remote_addr,
    OldChallengeData = crypto:strong_rand_bytes(8),
    OldPathState = #path_state{
        remote_addr = OldAddr,
        status = validating,
        challenge_data = OldChallengeData,
        challenge_count = 1,
        bytes_sent = 0,
        bytes_received = 0,
        is_nat_rebinding = false
    },

    State1 = State#state{
        pending_peer_validation = NewPathState,
        old_path_validation = OldPathState,
        migration_state = validating_peer
    },

    %% Send PATH_CHALLENGE to both addresses
    State2 = send_path_challenge_to_addr(NewAddr, NewChallengeData, State1),
    State3 = send_path_challenge_to_old_addr(OldAddr, OldChallengeData, State2),
    start_path_validation_timer(State3).

%% @doc Send PATH_CHALLENGE to old path address for anti-spoofing validation.
-spec send_path_challenge_to_old_addr(
    {inet:ip_address(), inet:port_number()},
    binary(),
    #state{}
) -> #state{}.
send_path_challenge_to_old_addr(Addr, ChallengeData, State) ->
    %% Reuse existing send_path_challenge logic
    State1 = send_path_challenge(Addr, ChallengeData, State),
    %% Update old path bytes_sent for tracking
    case State1#state.old_path_validation of
        #path_state{} = PathState ->
            % Padded probe packet
            PacketSize = 1200,
            NewPath = PathState#path_state{
                bytes_sent = PathState#path_state.bytes_sent + PacketSize
            },
            State1#state{old_path_validation = NewPath};
        undefined ->
            State1
    end.

%% @doc Send PATH_CHALLENGE to a specific address for peer validation.
%% Similar to send_path_challenge but used for validating peer's new address.
-spec send_path_challenge_to_addr(
    {inet:ip_address(), inet:port_number()},
    binary(),
    #state{}
) -> #state{}.
send_path_challenge_to_addr(Addr, ChallengeData, State) ->
    %% Reuse existing send_path_challenge logic
    State1 = send_path_challenge(Addr, ChallengeData, State),
    %% Update pending path bytes_sent for anti-amplification
    case State1#state.pending_peer_validation of
        #path_state{} = PathState ->
            %% Estimate packet size (short header + PATH_CHALLENGE frame)
            PacketSize = 50,
            NewPath = PathState#path_state{
                bytes_sent = PathState#path_state.bytes_sent + PacketSize
            },
            State1#state{pending_peer_validation = NewPath};
        undefined ->
            State1
    end.

%% @doc Start path validation timer (3 * PTO).
%% RFC 9000 Section 8.2.4: Use PTO-based timeout for path validation.
%% Uses a token to correlate timeout messages with specific validation attempts,
%% allowing stale timeouts from canceled validations to be ignored.
-spec start_path_validation_timer(#state{}) -> #state{}.
start_path_validation_timer(
    #state{loss_state = LossState, path_validation_timer = OldTimer} = State
) ->
    %% Cancel any existing timer
    cancel_timer(OldTimer),
    %% Calculate timeout as 3 * PTO
    Timeout =
        case LossState of
            undefined -> 3000;
            _ -> 3 * quic_loss:get_pto(LossState)
        end,
    %% Use same token for both message and state - enables stale timeout detection
    ValidationToken = make_ref(),
    TimerRef = erlang:send_after(Timeout, self(), {path_validation_timeout, ValidationToken}),
    State#state{
        path_validation_timer = TimerRef,
        path_validation_token = ValidationToken
    }.

%% @doc Handle path validation timeout.
%% RFC 9000 Section 8.2.4: Validation fails after timeout, stay on current path.
-spec handle_path_validation_timeout(#state{}) -> {keep_state, #state{}}.
handle_path_validation_timeout(#state{pending_peer_validation = PathState} = State) ->
    %% Mark path as failed, stay on current path
    case PathState of
        #path_state{challenge_count = Count} when Count < 3 ->
            %% Retry PATH_CHALLENGE
            ChallengeData = crypto:strong_rand_bytes(8),
            NewPathState = PathState#path_state{
                challenge_data = ChallengeData,
                challenge_count = Count + 1
            },
            State1 = State#state{pending_peer_validation = NewPathState},
            State2 = send_path_challenge_to_addr(
                PathState#path_state.remote_addr, ChallengeData, State1
            ),
            State3 = start_path_validation_timer(State2),
            {keep_state, State3};
        _ ->
            %% Max retries reached, give up on this path
            State1 = State#state{
                pending_peer_validation = undefined,
                old_path_validation = undefined,
                migration_state = idle,
                path_validation_timer = undefined,
                path_validation_token = undefined
            },
            {keep_state, State1}
    end.

%% @doc Handle PATH_RESPONSE frame.
%% Validates the response against pending challenges.
%% RFC 9000 Section 9.6: Auto-migrate to preferred address on validation success.
%% RFC 9000 Section 9.3.2: Check both new and old path for anti-spoofing defense.
handle_path_response(ResponseData, State) ->
    %% First check if this is a response to peer address validation (server validating client)
    case check_peer_validation_response(ResponseData, State) of
        {new_path_validated, PendingPath, State1} ->
            %% New path validated - check migration decision
            decide_migration_after_new_path_validated(PendingPath, State1);
        {old_path_validated, State1} ->
            %% Old path validated - confirms peer is real (anti-spoofing)
            %% Wait for new path validation or timeout
            State1;
        no_match ->
            %% Check alt_paths (client validating paths)
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
            end
    end.

%% @doc Check if PATH_RESPONSE matches new or old path validation challenge.
%% RFC 9000 Section 9.3.2: Both old and new paths are probed during migration.
-spec check_peer_validation_response(binary(), #state{}) ->
    {new_path_validated, #path_state{}, #state{}}
    | {old_path_validated, #state{}}
    | no_match.
check_peer_validation_response(ResponseData, State) ->
    %% Check new path (pending_peer_validation)
    case State#state.pending_peer_validation of
        #path_state{challenge_data = ResponseData} = PendingPath ->
            %% New path validated
            ValidatedPath = PendingPath#path_state{status = validated, challenge_data = undefined},
            State1 = State#state{pending_peer_validation = ValidatedPath},
            {new_path_validated, ValidatedPath, State1};
        _ ->
            %% Check old path
            case State#state.old_path_validation of
                #path_state{challenge_data = ResponseData} = OldPath ->
                    %% Old path validated - confirms peer is real (anti-spoofing signal)
                    ValidatedOldPath = OldPath#path_state{
                        status = validated, challenge_data = undefined
                    },
                    State1 = State#state{old_path_validation = ValidatedOldPath},
                    {old_path_validated, State1};
                _ ->
                    no_match
            end
    end.

%% @doc Decide migration after new path is validated.
%% RFC 9000 Section 9.3.2: Old path validation is an anti-spoofing signal.
%% If both paths validate, accept migration (peer is legitimate).
%% If new path validates but old fails/pending, accept migration (old path might have issues).
-spec decide_migration_after_new_path_validated(#path_state{}, #state{}) -> #state{}.
decide_migration_after_new_path_validated(ValidatedNewPath, State) ->
    %% New path is validated - proceed with migration
    %% Old path validation is informational (anti-spoofing defense)
    handle_peer_path_validated(ValidatedNewPath, State).

%% @doc Handle successful peer path validation (server accepting client's new address).
%% RFC 9000 Section 9: Complete migration to the validated peer address.
-spec handle_peer_path_validated(#path_state{}, #state{}) -> #state{}.
handle_peer_path_validated(PendingPath, #state{path_validation_timer = Timer} = State) ->
    %% Cancel validation timer
    cancel_timer(Timer),
    %% RFC 9000 Section 9.5: Use fresh CID on new path for unlinkability
    State1 = switch_to_fresh_cid(State),
    NewDCID = State1#state.dcid,
    %% Mark path as validated with the CID used on this path
    ValidatedPath = PendingPath#path_state{
        status = validated,
        challenge_data = undefined,
        dcid = NewDCID
    },
    %% Complete migration to the new peer address
    State2 = complete_migration(ValidatedPath, State1),
    %% Clear pending validation state including old path validation
    State2#state{
        pending_peer_validation = undefined,
        old_path_validation = undefined,
        migration_state = idle,
        path_validation_timer = undefined,
        path_validation_token = undefined
    }.

%% @doc Auto-migrate to preferred address if the validated path matches.
%% RFC 9000 Section 9.6: Client SHOULD migrate to validated preferred address.
-spec maybe_migrate_to_preferred_address(#path_state{}, #state{}) -> #state{}.
maybe_migrate_to_preferred_address(ValidatedPath, #state{preferred_address = undefined} = State) ->
    %% No preferred address, just return
    State#state{alt_paths = [ValidatedPath | State#state.alt_paths]};
maybe_migrate_to_preferred_address(
    #path_state{remote_addr = RemoteAddr} = ValidatedPath,
    #state{preferred_address = PA} = State
) ->
    %% Check if validated path matches the preferred address
    case is_preferred_address_path(RemoteAddr, PA) of
        true ->
            %% Migrate to preferred address
            State1 = complete_migration(ValidatedPath, State),
            %% RFC 9000 Section 9.6: MUST use the new CID on the preferred address
            %% Switch CID BEFORE sending any packets (including PMTU probes)
            State2 = switch_to_preferred_cid(PA, State1),
            %% Clear the preferred_address field since migration is complete
            State3 = State2#state{preferred_address = undefined},
            %% Now start PMTU probing on the new path with correct CID
            maybe_send_pmtu_probe(State3);
        false ->
            State
    end.

%% Check if remote address matches the preferred address
is_preferred_address_path({IPv4, Port}, #preferred_address{ipv4_addr = IPv4, ipv4_port = Port}) when
    IPv4 =/= undefined
->
    true;
is_preferred_address_path({IPv6, Port}, #preferred_address{ipv6_addr = IPv6, ipv6_port = Port}) when
    IPv6 =/= undefined
->
    true;
is_preferred_address_path(_, _) ->
    false.

%% Switch to using the CID from preferred_address
switch_to_preferred_cid(#preferred_address{cid = CID}, State) ->
    %% RFC 9000 Section 9.6: MUST use the new CID on the preferred address
    State#state{dcid = CID}.

%% @doc Switch to a fresh CID from the peer's CID pool.
%% RFC 9000 Section 9.5: Using a fresh CID on a new path prevents linkability.
-spec switch_to_fresh_cid(#state{}) -> #state{}.
switch_to_fresh_cid(#state{peer_cid_pool = Pool, dcid = CurrentDCID} = State) ->
    case find_unused_cid(Pool, CurrentDCID) of
        {ok, NewCID} ->
            State#state{dcid = NewCID};
        not_found ->
            %% No spare CID available, continue with current
            State
    end.

%% @doc Find an unused CID from the pool (different from current DCID).
-spec find_unused_cid([#cid_entry{}], binary()) -> {ok, binary()} | not_found.
find_unused_cid([], _CurrentCID) ->
    not_found;
find_unused_cid([#cid_entry{cid = CID, status = active} | _Rest], CurrentCID) when
    CID =/= CurrentCID
->
    {ok, CID};
find_unused_cid([_ | Rest], CurrentCID) ->
    find_unused_cid(Rest, CurrentCID).

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
%% Updates the current path and conditionally resets state based on migration type.
%% Note: Does NOT start PMTU probing - caller must call maybe_send_pmtu_probe/1
%% after any required CID switches (e.g., for preferred address migration).
-spec complete_migration(#path_state{}, #state{}) -> #state{}.
%% NAT rebinding: preserve CC, loss, and PMTU state (same network path)
%% RFC 9002 Section 9.4: NAT rebinding does not indicate a new path
complete_migration(
    #path_state{status = validated, is_nat_rebinding = true} = NewPath,
    State
) ->
    %% Same network path (only port changed) - keep existing state
    State#state{
        remote_addr = NewPath#path_state.remote_addr,
        current_path = NewPath,
        alt_paths = lists:delete(NewPath, State#state.alt_paths),
        migration_state = idle,
        pending_peer_validation = undefined
    };
%% Active migration: reset CC, loss, and PMTU (different network path)
%% RFC 9002 Section 9.4: Reset congestion state on path change
complete_migration(
    #path_state{status = validated, is_nat_rebinding = false} = NewPath,
    #state{
        owner = Owner,
        current_path = OldPath,
        pmtu_state = PMTUState,
        pmtu_probe_timer = ProbeTimer,
        pmtu_raise_timer = RaiseTimer
    } = State
) ->
    %% Notify owner of path change (for logging/monitoring)
    OldAddr =
        case OldPath of
            #path_state{remote_addr = A} -> A;
            undefined -> undefined
        end,
    Owner ! {quic, self(), {path_changed, OldAddr, NewPath#path_state.remote_addr}},

    %% RFC 8899: Reset PMTU on path change
    %% Cancel PMTU timers before resetting state
    cancel_timer(ProbeTimer),
    cancel_timer(RaiseTimer),
    NewPMTUState = quic_pmtu:on_path_change(PMTUState),

    %% RFC 9002 Section 9.4: Reset congestion controller on path change
    %% The new path may have different RTT and bandwidth characteristics
    NewCCState = quic_cc:new(#{}),
    NewLossState = quic_loss:new(),

    State#state{
        remote_addr = NewPath#path_state.remote_addr,
        current_path = NewPath,
        alt_paths = lists:delete(NewPath, State#state.alt_paths),
        pmtu_state = NewPMTUState,
        pmtu_probe_timer = undefined,
        pmtu_raise_timer = undefined,
        %% Reset CC and loss detection for new path
        cc_state = NewCCState,
        loss_state = NewLossState
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
        fun
            (#cid_entry{seq_num = S} = Entry) when S < RetirePrior ->
                Entry#cid_entry{status = retired};
            (Entry) ->
                Entry
        end,
        Pool
    ),

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
%% RFC 9000 Section 19.16: Retires CIDs with sequence numbers less than RetirePrior
retire_peer_cids(RetirePrior, #state{peer_cid_pool = Pool} = State) ->
    %% Find CIDs to retire and send RETIRE_CONNECTION_ID for each
    {NewPool, State1} = lists:foldl(
        fun
            (#cid_entry{seq_num = SeqNum, status = active} = Entry, {AccPool, AccState}) when
                SeqNum < RetirePrior
            ->
                %% Send RETIRE_CONNECTION_ID frame
                Frame = {retire_connection_id, SeqNum},
                AccState1 = send_frame(Frame, AccState),
                %% Mark as retired in pool
                RetiredEntry = Entry#cid_entry{status = retired},
                {[RetiredEntry | AccPool], AccState1};
            (Entry, {AccPool, AccState}) ->
                %% Keep as-is
                {[Entry | AccPool], AccState}
        end,
        {[], State},
        Pool
    ),
    State1#state{peer_cid_pool = lists:reverse(NewPool)}.

%% @doc Issue new connection IDs to the peer.
%% RFC 9000 Section 5.1.1: Generates new CIDs with stateless reset tokens.
-spec issue_new_connection_ids(#state{}) -> #state{}.
issue_new_connection_ids(
    #state{
        local_cid_pool = Pool,
        peer_active_cid_limit = PeerLimit
    } = State
) ->
    %% Count current active CIDs
    ActiveCount = length([E || #cid_entry{status = active} = E <- Pool]),

    %% Issue new CIDs up to peer's limit
    case ActiveCount < PeerLimit of
        true ->
            %% Need to issue more CIDs
            NumToIssue = PeerLimit - ActiveCount,
            issue_cids(NumToIssue, State);
        false ->
            State
    end.

%% Helper to issue N new connection IDs
issue_cids(0, State) ->
    State;
issue_cids(N, #state{local_cid_pool = Pool} = State) when N > 0 ->
    %% Get next sequence number
    NextSeqNum =
        case Pool of
            % seq 0 is the initial CID
            [] -> 1;
            _ -> lists:max([E#cid_entry.seq_num || E <- Pool]) + 1
        end,

    %% Generate new CID (8 bytes recommended by RFC 9000)
    NewCID = crypto:strong_rand_bytes(8),

    %% Generate stateless reset token (16 bytes)
    ResetToken = generate_stateless_reset_token(NewCID, State),

    %% Create entry
    NewEntry = #cid_entry{
        seq_num = NextSeqNum,
        cid = NewCID,
        stateless_reset_token = ResetToken,
        status = active
    },

    %% Send NEW_CONNECTION_ID frame
    Frame = {new_connection_id, NextSeqNum, 0, NewCID, ResetToken},
    State1 = send_frame(Frame, State),

    %% Add to pool and continue
    NewPool = [NewEntry | Pool],
    issue_cids(N - 1, State1#state{local_cid_pool = NewPool}).

%% @doc Generate a stateless reset token for a connection ID.
%% RFC 9000 §10.3.2 requires the token to be hard for an external
%% observer to guess. When a server-wide secret is configured, derive
%% the token deterministically via HMAC-SHA256 so the same CID always
%% maps to the same token — letting a listener reply with a matching
%% stateless reset for a CID whose per-connection state it no longer
%% holds. Without a secret we fall back to per-CID random bytes.
-spec generate_stateless_reset_token(binary(), #state{}) -> binary().
generate_stateless_reset_token(_CID, #state{stateless_reset_secret = undefined}) ->
    crypto:strong_rand_bytes(16);
generate_stateless_reset_token(CID, #state{stateless_reset_secret = Secret}) when
    is_binary(Secret), byte_size(Secret) >= 32
->
    <<Token:16/binary, _/binary>> = crypto:mac(hmac, sha256, Secret, CID),
    Token.

%% @doc Validate connection ID parameters from peer transport params.
%% RFC 9000 Section 7.3: Endpoints MUST validate connection ID parameters.
%% - initial_source_connection_id must match SCID in Initial packet
%% - original_destination_connection_id (server only) must match original DCID
%% - retry_source_connection_id (if Retry used) must match Retry packet SCID
-spec validate_connection_id_params(map(), #state{}) -> ok | {error, term()}.
validate_connection_id_params(TransportParams, #state{role = client} = State) ->
    %% Client validates server's transport params
    #state{
        original_dcid = OriginalDCID,
        dcid = CurrentDCID,
        retry_received = RetryReceived,
        retry_scid = RetrySCID
    } = State,

    %% Server must include original_destination_connection_id matching our original DCID
    case maps:get(original_dcid, TransportParams, undefined) of
        undefined ->
            {error, missing_original_dcid};
        OriginalDCID ->
            %% Matches - continue validation
            validate_initial_scid(TransportParams, CurrentDCID, RetryReceived, RetrySCID);
        Other ->
            {error, {original_dcid_mismatch, expected, OriginalDCID, got, Other}}
    end;
validate_connection_id_params(TransportParams, #state{role = server} = State) ->
    %% Server validates client's transport params
    #state{dcid = ClientSCID} = State,

    %% Client must include initial_source_connection_id matching their SCID
    case maps:get(initial_scid, TransportParams, undefined) of
        undefined ->
            {error, missing_initial_scid};
        ClientSCID ->
            ok;
        Other ->
            {error, {initial_scid_mismatch, expected, ClientSCID, got, Other}}
    end.

%% Helper to validate initial_scid and retry_scid for client
validate_initial_scid(TransportParams, CurrentDCID, RetryReceived, RetrySCID) ->
    %% Server's initial_source_connection_id must match current DCID
    case maps:get(initial_scid, TransportParams, undefined) of
        undefined ->
            {error, missing_initial_scid};
        CurrentDCID ->
            %% Matches - check retry_scid if Retry was used
            validate_retry_scid(TransportParams, RetryReceived, RetrySCID);
        Other ->
            {error, {initial_scid_mismatch, expected, CurrentDCID, got, Other}}
    end.

validate_retry_scid(_TransportParams, false, _RetrySCID) ->
    %% No Retry received - server MUST NOT include retry_source_connection_id
    ok;
validate_retry_scid(TransportParams, true, RetrySCID) ->
    %% Retry was received - server MUST include matching retry_source_connection_id
    case maps:get(retry_scid, TransportParams, undefined) of
        undefined ->
            {error, missing_retry_scid_after_retry};
        RetrySCID ->
            ok;
        Other ->
            {error, {retry_scid_mismatch, expected, RetrySCID, got, Other}}
    end.

%% @doc Apply peer transport parameters to connection state.
%% Extracts flow control limits, stream limits, and CID limit from peer's transport params.
%% RFC 9000 Section 7.4: Transport parameters are applied after the handshake completes.
%% RFC 9000 Section 7.3: Validates connection ID parameters before applying.
apply_peer_transport_params(TransportParams, State) ->
    case validate_connection_id_params(TransportParams, State) of
        ok ->
            apply_peer_transport_params_internal(TransportParams, State);
        {error, Reason} ->
            ?LOG_ERROR(
                #{what => connection_id_validation_failed, reason => Reason}, ?QUIC_LOG_META
            ),
            State#state{close_reason = {transport_parameter_error, Reason}}
    end.

%% Internal function to apply transport params after CID validation passes
apply_peer_transport_params_internal(TransportParams, State) ->
    %% Extract peer's active_connection_id_limit (default: 2 per RFC 9000)
    PeerCIDLimit = maps:get(active_connection_id_limit, TransportParams, 2),

    %% Extract connection-level flow control: how much WE can send to THEM
    %% Peer's initial_max_data tells us the max bytes we can send on this connection
    MaxDataRemote = maps:get(initial_max_data, TransportParams, ?DEFAULT_INITIAL_MAX_DATA),

    %% Extract stream-level flow control limits for streams we send on
    %% initial_max_stream_data_bidi_remote: limit for streams WE initiate (from peer's perspective, we're "remote")
    %% initial_max_stream_data_bidi_local: limit for streams THEY initiate (from peer's perspective, they're "local")
    %% initial_max_stream_data_uni: limit for unidirectional streams we initiate
    MaxStreamDataBidiRemote = maps:get(
        initial_max_stream_data_bidi_remote,
        TransportParams,
        ?DEFAULT_INITIAL_MAX_STREAM_DATA
    ),
    MaxStreamDataBidiLocal = maps:get(
        initial_max_stream_data_bidi_local,
        TransportParams,
        ?DEFAULT_INITIAL_MAX_STREAM_DATA
    ),
    MaxStreamDataUni = maps:get(
        initial_max_stream_data_uni,
        TransportParams,
        ?DEFAULT_INITIAL_MAX_STREAM_DATA
    ),

    ?LOG_DEBUG(
        #{
            what => apply_peer_transport_params,
            max_data_remote => MaxDataRemote,
            max_stream_data_bidi_remote => MaxStreamDataBidiRemote,
            max_stream_data_bidi_local => MaxStreamDataBidiLocal,
            max_stream_data_uni => MaxStreamDataUni,
            raw_params => TransportParams
        },
        ?QUIC_LOG_META
    ),

    %% Extract stream limits: how many streams WE can open
    MaxStreamsBidi = maps:get(initial_max_streams_bidi, TransportParams, ?DEFAULT_MAX_STREAMS_BIDI),
    MaxStreamsUni = maps:get(initial_max_streams_uni, TransportParams, ?DEFAULT_MAX_STREAMS_UNI),

    %% Extract max_datagram_frame_size (RFC 9221): peer's max datagram size
    %% Default is 0 (datagrams not supported)
    MaxDatagramFrameSize = maps:get(max_datagram_frame_size, TransportParams, 0),

    %% Extract disable_active_migration (RFC 9000 Section 18.2)
    %% If true, peer has indicated they don't want to receive traffic from different addresses
    PeerDisableMigration = maps:get(disable_active_migration, TransportParams, false),

    %% Store stream data limits in state for use when opening streams
    %% These tell us how much we can send on different stream types
    State#state{
        transport_params = maps:merge(TransportParams, #{
            %% Store parsed limits for easy access
            peer_max_stream_data_bidi_remote => MaxStreamDataBidiRemote,
            peer_max_stream_data_bidi_local => MaxStreamDataBidiLocal,
            peer_max_stream_data_uni => MaxStreamDataUni
        }),
        peer_active_cid_limit = PeerCIDLimit,
        %% Connection-level send limit
        max_data_remote = MaxDataRemote,
        %% Stream limits (how many streams we can open)
        max_streams_bidi_remote = MaxStreamsBidi,
        max_streams_uni_remote = MaxStreamsUni,
        %% Datagram size limit (RFC 9221)
        max_datagram_frame_size_remote = MaxDatagramFrameSize,
        %% Migration disabled by peer (RFC 9000 Section 18.2)
        peer_disable_migration = PeerDisableMigration
    }.

%% @doc Handle RETIRE_CONNECTION_ID frame from peer.
%% Marks the specified CID in our local pool as retired.
handle_retire_connection_id(SeqNum, State) ->
    #state{local_cid_pool = Pool} = State,
    NewPool = lists:map(
        fun
            (#cid_entry{seq_num = S} = Entry) when S =:= SeqNum ->
                Entry#cid_entry{status = retired};
            (Entry) ->
                Entry
        end,
        Pool
    ),
    State#state{local_cid_pool = NewPool}.

%%====================================================================
%% PMTU Discovery (RFC 8899)
%%====================================================================

%% @doc Initialize PMTU probing after handshake completes.
%% Uses peer's max_udp_payload_size from transport parameters.
-spec init_pmtu_probing(map(), #state{}) -> #state{}.
init_pmtu_probing(TransportParams, #state{pmtu_state = PMTUState} = State) ->
    PeerMaxUdp = maps:get(max_udp_payload_size, TransportParams, undefined),
    NewPMTUState = quic_pmtu:on_connection_established(PeerMaxUdp, PMTUState),
    State1 = State#state{pmtu_state = NewPMTUState},
    %% Start probing if enabled and should probe
    maybe_send_pmtu_probe(State1).

%% @doc Send a PMTU probe packet if conditions are met.
-spec maybe_send_pmtu_probe(#state{}) -> #state{}.
maybe_send_pmtu_probe(#state{pmtu_state = undefined} = State) ->
    State;
maybe_send_pmtu_probe(#state{pmtu_state = PMTUState} = State) ->
    case quic_pmtu:should_probe(PMTUState) of
        true ->
            send_pmtu_probe(State);
        false ->
            %% Check if search is complete and set raise timer
            case quic_pmtu:get_state(PMTUState) of
                search_complete ->
                    maybe_set_pmtu_raise_timer(State);
                _ ->
                    State
            end
    end.

%% @doc Send a PMTU probe packet.
-spec send_pmtu_probe(#state{}) -> #state{}.
send_pmtu_probe(#state{pmtu_state = PMTUState, pn_app = PNSpace} = State) ->
    %% Calculate header size (approximate)
    HeaderSize = 50,
    {ProbeSize, Frames} = quic_pmtu:create_probe_packet(PMTUState, HeaderSize),

    case Frames of
        [] ->
            %% No frames to send
            State;
        _ ->
            %% Get packet number for this probe
            PacketNumber = PNSpace#pn_space.next_pn,

            %% Record probe sent (returns generation for stale detection)
            {_Gen, NewPMTUState} = quic_pmtu:on_probe_sent(PacketNumber, PMTUState),

            %% Send the probe packet
            State1 = State#state{pmtu_state = NewPMTUState},
            State2 = send_pmtu_probe_packet(ProbeSize, Frames, State1),

            %% Set probe timeout
            set_pmtu_probe_timer(State2)
    end.

%% @doc Send the actual PMTU probe packet.
%% Uses the existing send_app_packet infrastructure with PING + PADDING.
-spec send_pmtu_probe_packet(pos_integer(), list(), #state{}) -> #state{}.
send_pmtu_probe_packet(_ProbeSize, _Frames, #state{app_keys = undefined} = State) ->
    %% No keys available yet
    State;
send_pmtu_probe_packet(ProbeSize, Frames, #state{dcid = DCID, pn_app = PNSpace} = State) ->
    %% Encode PING + explicit PADDING frames
    EncodedFrames = encode_pmtu_frames(Frames),

    %% Calculate extra padding needed to reach target probe size
    %% Account for: header (1 + DCID), PN (1-4), auth tag (16)
    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),
    HeaderLen = 1 + byte_size(DCID),
    AuthTagLen = 16,
    PayloadLen = byte_size(EncodedFrames),
    CurrentSize = HeaderLen + PNLen + PayloadLen + AuthTagLen,
    ExtraPadding = max(0, ProbeSize - CurrentSize),

    %% Add extra padding to frame payload
    PaddedFrames = <<EncodedFrames/binary, (binary:copy(<<0>>, ExtraPadding))/binary>>,

    %% Use existing send_app_packet which handles all encryption/tracking
    send_app_packet(PaddedFrames, State).

%% @doc Encode PMTU probe frames (PING + PADDING).
-spec encode_pmtu_frames([term()]) -> binary().
encode_pmtu_frames(Frames) ->
    lists:foldl(
        fun
            (ping, Acc) ->
                <<Acc/binary, ?FRAME_PING>>;
            ({padding, N}, Acc) ->
                Padding = binary:copy(<<0>>, N),
                <<Acc/binary, Padding/binary>>
        end,
        <<>>,
        Frames
    ).

%% @doc Set the PMTU probe timeout timer.
%% Uses 5x smoothed RTT as probe timeout (quic-go pattern).
%% This is more responsive than 5x PTO and follows quic-go's approach.
%% Uses unique reference in message to detect stale timer events
-spec set_pmtu_probe_timer(#state{}) -> #state{}.
set_pmtu_probe_timer(#state{pmtu_probe_timer = OldTimer, loss_state = LossState} = State) ->
    cancel_timer(OldTimer),
    %% Use 5x smoothed RTT as probe timeout (quic-go pattern)
    %% With reasonable minimum for very low RTT networks
    Timeout =
        case LossState of
            undefined ->
                ?PMTU_DEFAULT_PROBE_TIMEOUT;
            _ ->
                SRTT = quic_loss:smoothed_rtt(LossState),
                max(1000, 5 * SRTT)
        end,
    Ref = make_ref(),
    erlang:send_after(Timeout, self(), {pmtu_probe_timeout, Ref}),
    State#state{pmtu_probe_timer = Ref}.

%% @doc Set the PMTU raise timer for periodic re-probing.
%% Uses unique reference in message to detect stale timer events
-spec maybe_set_pmtu_raise_timer(#state{}) -> #state{}.
maybe_set_pmtu_raise_timer(#state{pmtu_raise_timer = undefined} = State) ->
    Ref = make_ref(),
    erlang:send_after(?PMTU_DEFAULT_RAISE_INTERVAL, self(), {pmtu_raise_timeout, Ref}),
    State#state{pmtu_raise_timer = Ref};
maybe_set_pmtu_raise_timer(State) ->
    State.

%% @doc Handle ACK of a potential PMTU probe packet.
-spec handle_pmtu_probe_ack(non_neg_integer(), #state{}) -> #state{}.
handle_pmtu_probe_ack(_PacketNumber, #state{pmtu_state = undefined} = State) ->
    State;
handle_pmtu_probe_ack(PacketNumber, #state{pmtu_state = PMTUState, cc_state = CCState} = State) ->
    case quic_pmtu:get_state(PMTUState) of
        searching ->
            %% Check if this ACK is for our probe packet
            case PMTUState#pmtu_state.probe_pn of
                PacketNumber ->
                    %% This is our probe - process it with generation check
                    Gen = quic_pmtu:get_generation(PMTUState),
                    OldMTU = quic_pmtu:current_mtu(PMTUState),
                    NewPMTUState = quic_pmtu:on_probe_acked(PacketNumber, Gen, PMTUState),
                    NewMTU = quic_pmtu:current_mtu(NewPMTUState),

                    %% Update congestion control if MTU changed
                    NewCCState =
                        case NewMTU > OldMTU of
                            true -> quic_cc:update_mtu(CCState, NewMTU);
                            false -> CCState
                        end,

                    %% Cancel probe timer and continue probing
                    cancel_timer(State#state.pmtu_probe_timer),
                    State1 = State#state{
                        pmtu_state = NewPMTUState,
                        cc_state = NewCCState,
                        pmtu_probe_timer = undefined
                    },
                    maybe_send_pmtu_probe(State1);
                _ ->
                    %% ACK for non-probe packet - ignore for PMTU
                    State
            end;
        _ ->
            %% Not searching, just reset black hole counter on any ACK
            NewPMTUState = quic_pmtu:on_packet_acked(PMTUState),
            State#state{pmtu_state = NewPMTUState}
    end.

%% @doc Handle loss of a potential PMTU probe packet.
%% PacketSize is passed directly since lost packets are removed from sent_packets
%% before this function is called.
-spec handle_pmtu_probe_loss(non_neg_integer(), non_neg_integer(), #state{}) -> #state{}.
handle_pmtu_probe_loss(_PacketNumber, _PacketSize, #state{pmtu_state = undefined} = State) ->
    State;
handle_pmtu_probe_loss(
    PacketNumber, PacketSize, #state{pmtu_state = PMTUState, cc_state = CCState} = State
) ->
    case quic_pmtu:get_state(PMTUState) of
        searching ->
            %% Check if this loss is for our probe packet
            case PMTUState#pmtu_state.probe_pn of
                PacketNumber ->
                    Gen = quic_pmtu:get_generation(PMTUState),
                    NewPMTUState = quic_pmtu:on_probe_lost(PacketNumber, Gen, PMTUState),
                    State1 = State#state{pmtu_state = NewPMTUState},
                    maybe_send_pmtu_probe(State1);
                _ ->
                    %% Loss of non-probe packet - ignore for PMTU
                    State
            end;
        search_complete ->
            %% Track loss for black hole detection
            %% Only count losses of large packets (near current MTU)
            OldMTU = quic_pmtu:current_mtu(PMTUState),
            NewPMTUState = quic_pmtu:on_packet_lost(PacketSize, PMTUState),
            NewMTU = quic_pmtu:current_mtu(NewPMTUState),

            %% Update congestion control if MTU decreased (black hole)
            NewCCState =
                case NewMTU < OldMTU of
                    true ->
                        quic_cc:update_mtu(CCState, NewMTU);
                    false ->
                        CCState
                end,

            State#state{
                pmtu_state = NewPMTUState,
                cc_state = NewCCState
            };
        _ ->
            State
    end.

%% @doc Get the current MTU for sending.
-spec get_current_mtu(#state{}) -> pos_integer().
get_current_mtu(#state{pmtu_state = undefined}) ->
    ?DEFAULT_MAX_UDP_PAYLOAD_SIZE;
get_current_mtu(#state{pmtu_state = PMTUState}) ->
    quic_pmtu:current_mtu(PMTUState).

%% @doc Get the local max UDP payload size for transport parameters.
%% Returns the configured max MTU from PMTU state, or the default if not configured.
-spec get_local_max_udp_payload_size(#state{}) -> pos_integer().
get_local_max_udp_payload_size(#state{pmtu_state = undefined}) ->
    ?DEFAULT_MAX_UDP_PAYLOAD_SIZE;
get_local_max_udp_payload_size(#state{pmtu_state = PMTUState}) ->
    PMTUState#pmtu_state.max_mtu.

%%====================================================================
%% Test Helpers
%%====================================================================

-ifdef(TEST).
%% Inspect the spin-bit state of a #state{} from tests without
%% exposing the record definition.
-spec test_spin_state(#state{}) ->
    #{
        outgoing := 0 | 1,
        recv := 0 | 1,
        largest_pn := integer(),
        enabled := boolean()
    }.
test_spin_state(#state{
    spin_outgoing = O,
    spin_recv = R,
    spin_recv_largest_pn = L,
    spin_bit_enabled = E
}) ->
    #{outgoing => O, recv => R, largest_pn => L, enabled => E}.

%% Minimal #state{} for spin-bit unit tests.
-spec test_spin_state_for(client | server, boolean()) -> #state{}.
test_spin_state_for(Role, Enabled) ->
    #state{role = Role, spin_bit_enabled = Enabled}.

%% Minimal #state{} for stateless-reset tests.
-spec test_state_with_secret(binary() | undefined) -> #state{}.
test_state_with_secret(Secret) ->
    #state{stateless_reset_secret = Secret}.

%% Minimal #state{} scoped to role for frame-dispatch tests.
-spec test_state_for_role(client | server) -> #state{}.
test_state_for_role(Role) ->
    #state{role = Role, app_keys = undefined}.

-spec test_close_reason(#state{}) -> term().
test_close_reason(#state{close_reason = R}) -> R.

%% Test helper for check_send_queue_flow_control/3.
%% Wraps the internal function to avoid exposing #state{} record.
%% RFC 9000 Section 4.1: Connection-level flow control (max_data)
%% RFC 9000 Section 4.2: Stream-level flow control (max_stream_data)
test_check_flow_control(StreamId, Offset, DataSize, MaxDataRemote, DataSent, StreamsMap) ->
    Streams = maps:map(
        fun(_K, {SendMaxData, SendOffset}) ->
            #stream_state{send_max_data = SendMaxData, send_offset = SendOffset}
        end,
        StreamsMap
    ),
    State = #state{
        max_data_remote = MaxDataRemote,
        data_sent = DataSent,
        streams = Streams
    },
    check_send_queue_flow_control(StreamId, Offset, DataSize, State).

%% Test helper for complete_migration/2.
%% Tests that path_changed notification is sent to owner on active migration.
%% Returns {ok, notified} if notification was sent, {ok, not_notified} for NAT rebinding.
-spec test_complete_migration(
    Owner :: pid(),
    OldPath :: #path_state{} | undefined,
    NewPath :: #path_state{}
) -> {ok, notified | not_notified}.
test_complete_migration(Owner, OldPath, NewPath) ->
    %% Create minimal state for testing
    State = #state{
        owner = Owner,
        current_path = OldPath,
        %% Minimal required fields for complete_migration
        pmtu_state = quic_pmtu:new(),
        pmtu_probe_timer = undefined,
        pmtu_raise_timer = undefined,
        alt_paths = []
    },
    %% Call complete_migration - it will send message to Owner if active migration
    _ = complete_migration(NewPath, State),
    %% Check if owner received the notification
    receive
        {quic, _, {path_changed, _, _}} -> {ok, notified}
    after 0 ->
        {ok, not_notified}
    end.
-endif.
