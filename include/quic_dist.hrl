%%% -*- erlang -*-
%%%
%%% QUIC Distribution Records and Constants
%%% Erlang Distribution over QUIC (RFC 9000)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-ifndef(QUIC_DIST_HRL).
-define(QUIC_DIST_HRL, true).

%%====================================================================
%% Distribution Constants
%%====================================================================

%% ALPN protocol identifier for Erlang distribution
-define(QUIC_DIST_ALPN, <<"erlang-dist">>).

%% Stream types

% Stream 0: Control (handshake, tick, signals)
-define(QUIC_DIST_CONTROL_STREAM, 0).
% Streams 4,8,12... for data messages
-define(QUIC_DIST_DATA_STREAM_BASE, 4).

%% Stream urgency levels (RFC 9218)

% Control stream - highest priority
-define(QUIC_DIST_URGENCY_CONTROL, 0).
% Link/monitor signals
-define(QUIC_DIST_URGENCY_SIGNAL, 2).
% High priority data
-define(QUIC_DIST_URGENCY_DATA_HIGH, 4).
% Normal data messages
-define(QUIC_DIST_URGENCY_DATA_NORMAL, 5).
% Low priority data
-define(QUIC_DIST_URGENCY_DATA_LOW, 6).

%% Default number of data streams
-define(QUIC_DIST_DATA_STREAMS, 4).

%% Message length prefixes

% 2-byte length prefix during handshake
-define(QUIC_DIST_HS_LEN_SIZE, 2).
% 4-byte length prefix post-handshake
-define(QUIC_DIST_MSG_LEN_SIZE, 4).

%% Tick interval (milliseconds)
-define(QUIC_DIST_TICK_INTERVAL, 60000).

%% Control message types (1-byte tag, sent on control stream only)
-define(QUIC_DIST_MSG_TICK, 1).
-define(QUIC_DIST_MSG_TICK_ACK, 2).

%% Idle timeout for distribution connections (5 minutes)
%% Longer than default to allow for infrequent cluster traffic
-define(QUIC_DIST_IDLE_TIMEOUT, 300000).

%% Keep-alive interval for distribution connections (150 seconds = half of idle timeout)
%% QUIC-level PING frames ensure liveness without relying on application-layer ticks
-define(QUIC_DIST_KEEP_ALIVE_INTERVAL, 150000).

%% Distribution backpressure thresholds (can be overridden via config)
%% Congested when queue > cwnd * congestion threshold
-define(DEFAULT_QUEUE_CONGESTION_THRESHOLD, 2).
%% Max messages to pull from VM per dist_data notification (prevents burst)
-define(DEFAULT_MAX_PULL_PER_NOTIFICATION, 16).
%% Retry interval when congested (ms)
-define(DEFAULT_BACKPRESSURE_RETRY_MS, 10).

%% Default ports
-define(QUIC_DIST_DEFAULT_PORT, 4433).
-define(QUIC_DIST_PORT_RANGE_START, 4433).
-define(QUIC_DIST_PORT_RANGE_END, 4532).

%%====================================================================
%% Controller States
%%====================================================================

-define(QUIC_DIST_STATE_INIT, init).
-define(QUIC_DIST_STATE_HANDSHAKING, handshaking).
-define(QUIC_DIST_STATE_CONNECTED, connected).
-define(QUIC_DIST_STATE_DRAINING, draining).

%%====================================================================
%% Records
%%====================================================================

%% Distribution configuration from vm.args or sys.config
-record(quic_dist_config, {
    %% TLS certificate/key
    cert_file :: binary() | undefined,
    key_file :: binary() | undefined,
    cacert_file :: binary() | undefined,
    cert :: binary() | undefined,
    key :: term() | undefined,
    cacert :: binary() | undefined,
    verify = verify_none :: verify_none | verify_peer,

    %% Discovery
    discovery_module = quic_discovery_static :: module(),
    nodes = [] :: [{node(), {inet:ip_address() | string(), inet:port_number()}}],
    dns_domain :: binary() | undefined,

    %% Load balancer
    lb_enabled = false :: boolean(),
    lb_server_id = auto :: auto | binary(),
    lb_key :: binary() | undefined,

    %% Backpressure tuning
    congestion_threshold = ?DEFAULT_QUEUE_CONGESTION_THRESHOLD :: pos_integer(),
    max_pull_per_notification = ?DEFAULT_MAX_PULL_PER_NOTIFICATION :: pos_integer(),
    backpressure_retry_ms = ?DEFAULT_BACKPRESSURE_RETRY_MS :: pos_integer(),

    %% Pacing
    pacing_enabled = true :: boolean()
}).

%% Listener state
-record(quic_dist_listener, {
    server_name :: atom(),
    port :: inet:port_number(),
    acceptor :: pid() | undefined,
    config :: #quic_dist_config{}
}).

%% Connection controller state
-record(quic_dist_conn, {
    %% Connection identity (Conn is the connection pid, receives {quic, Conn, Event} messages)
    conn :: pid(),
    node :: node() | undefined,
    role :: client | server,

    %% Streams
    control_stream :: non_neg_integer() | undefined,
    data_streams = [] :: [non_neg_integer()],
    next_data_stream_idx = 0 :: non_neg_integer(),

    %% Buffers (for partial message reassembly)
    recv_buffer = <<>> :: binary(),
    recv_expected = 0 :: non_neg_integer(),

    %% State tracking
    handshake_complete = false :: boolean(),
    tick_pending = false :: boolean(),
    last_tick :: non_neg_integer() | undefined,

    %% Distribution protocol callbacks
    f_send :: fun((term()) -> ok | {error, term()}) | undefined,
    f_recv ::
        fun((non_neg_integer(), non_neg_integer()) -> {ok, binary()} | {error, term()})
        | undefined,

    %% Session ticket for 0-RTT
    session_ticket :: term() | undefined
}).

%% Handshake data for dist_util
-record(quic_hs_data, {
    kernel_pid :: pid(),
    other_node :: node(),
    this_node :: node(),
    socket :: term(),
    timer :: reference() | undefined,
    this_flags :: integer(),
    other_flags :: integer(),
    other_version :: integer(),
    f_send :: function(),
    f_recv :: function(),
    f_setopts_pre_nodeup :: function(),
    f_setopts_post_nodeup :: function(),
    f_getll :: function(),
    f_address :: function(),
    mf_tick :: function(),
    mf_getstat :: function(),
    request_type :: atom(),
    mf_setopts :: function(),
    mf_getopts :: function()
}).

%% Stream data message wrapper
-record(quic_dist_msg, {
    stream_id :: non_neg_integer(),
    data :: binary(),
    fin = false :: boolean()
}).

%%====================================================================
%% User Stream Support
%%====================================================================

%% User stream thresholds
%% Distribution uses streams 0 (control) and 4,8,12,16 (client data) or 1,5,9,13 (server data)
%% User streams start above these reserved ranges

% Client-initiated user streams start at 20 (above 0,4,8,12,16)
-define(USER_STREAM_THRESHOLD_CLIENT, 20).
% Server-initiated user streams start at 17 (above 1,5,9,13)
-define(USER_STREAM_THRESHOLD_SERVER, 17).

%% Application error code for refused streams (no acceptor available)
-define(STREAM_REFUSED, 16#100).

%% User stream priority constraints
%% User streams CANNOT have priority < 16 (reserved for distribution)
-define(USER_STREAM_MIN_PRIORITY, 16).
-define(USER_STREAM_DEFAULT_PRIORITY, 128).

%% User stream state record
-record(user_stream, {
    id :: non_neg_integer(),
    owner :: pid(),
    monitor :: reference(),
    %% Stream priority (16=highest user, 255=lowest)
    priority = ?USER_STREAM_DEFAULT_PRIORITY :: 16..255,
    recv_fin = false :: boolean(),
    send_fin = false :: boolean()
}).

% QUIC_DIST_HRL
-endif.
