%%% -*- erlang -*-
%%%
%%% QUIC protocol constants and records
%%% RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
%%%

-ifndef(QUIC_HRL).
-define(QUIC_HRL, true).

%%====================================================================
%% QUIC Version
%%====================================================================

-define(QUIC_VERSION_1, 16#00000001).
-define(QUIC_VERSION_2, 16#6b3343cf).

%%====================================================================
%% Packet Types (Long Header)
%%====================================================================

-define(PACKET_TYPE_INITIAL, 16#00).
-define(PACKET_TYPE_0RTT, 16#01).
-define(PACKET_TYPE_HANDSHAKE, 16#02).
-define(PACKET_TYPE_RETRY, 16#03).

%%====================================================================
%% Frame Types (RFC 9000 Section 12.4)
%%====================================================================

-define(FRAME_PADDING, 16#00).
-define(FRAME_PING, 16#01).
-define(FRAME_ACK, 16#02).
-define(FRAME_ACK_ECN, 16#03).
-define(FRAME_RESET_STREAM, 16#04).
-define(FRAME_STOP_SENDING, 16#05).
-define(FRAME_CRYPTO, 16#06).
-define(FRAME_NEW_TOKEN, 16#07).
% 0x08-0x0f depending on flags
-define(FRAME_STREAM, 16#08).
-define(FRAME_MAX_DATA, 16#10).
-define(FRAME_MAX_STREAM_DATA, 16#11).
-define(FRAME_MAX_STREAMS_BIDI, 16#12).
-define(FRAME_MAX_STREAMS_UNI, 16#13).
-define(FRAME_DATA_BLOCKED, 16#14).
-define(FRAME_STREAM_DATA_BLOCKED, 16#15).
-define(FRAME_STREAMS_BLOCKED_BIDI, 16#16).
-define(FRAME_STREAMS_BLOCKED_UNI, 16#17).
-define(FRAME_NEW_CONNECTION_ID, 16#18).
-define(FRAME_RETIRE_CONNECTION_ID, 16#19).
-define(FRAME_PATH_CHALLENGE, 16#1a).
-define(FRAME_PATH_RESPONSE, 16#1b).
-define(FRAME_CONNECTION_CLOSE, 16#1c).
-define(FRAME_CONNECTION_CLOSE_APP, 16#1d).
-define(FRAME_HANDSHAKE_DONE, 16#1e).

%% DATAGRAM Frames (RFC 9221)
-define(FRAME_DATAGRAM, 16#30).
-define(FRAME_DATAGRAM_WITH_LEN, 16#31).

%%====================================================================
%% Stream Frame Flags (bits 0-2 of frame type 0x08-0x0f)
%%====================================================================

% Offset field present
-define(STREAM_FLAG_OFF, 16#04).
% Length field present
-define(STREAM_FLAG_LEN, 16#02).
% Final frame for stream
-define(STREAM_FLAG_FIN, 16#01).

%%====================================================================
%% Transport Error Codes (RFC 9000 Section 20.1)
%%====================================================================

-define(QUIC_NO_ERROR, 16#00).
-define(QUIC_INTERNAL_ERROR, 16#01).
-define(QUIC_CONNECTION_REFUSED, 16#02).
-define(QUIC_FLOW_CONTROL_ERROR, 16#03).
-define(QUIC_STREAM_LIMIT_ERROR, 16#04).
-define(QUIC_STREAM_STATE_ERROR, 16#05).
-define(QUIC_FINAL_SIZE_ERROR, 16#06).
-define(QUIC_FRAME_ENCODING_ERROR, 16#07).
-define(QUIC_TRANSPORT_PARAMETER_ERROR, 16#08).
-define(QUIC_CONNECTION_ID_LIMIT_ERROR, 16#09).
-define(QUIC_PROTOCOL_VIOLATION, 16#0a).
-define(QUIC_INVALID_TOKEN, 16#0b).
-define(QUIC_APPLICATION_ERROR, 16#0c).
-define(QUIC_CRYPTO_BUFFER_EXCEEDED, 16#0d).
-define(QUIC_KEY_UPDATE_ERROR, 16#0e).
-define(QUIC_AEAD_LIMIT_REACHED, 16#0f).
-define(QUIC_NO_VIABLE_PATH, 16#10).
% 0x100-0x1ff for TLS alerts
-define(QUIC_CRYPTO_ERROR_BASE, 16#100).

%%====================================================================
%% HTTP/3 Error Codes (RFC 9114 Section 8.1)
%%====================================================================

-define(H3_NO_ERROR, 16#100).
-define(H3_GENERAL_PROTOCOL_ERROR, 16#101).
-define(H3_INTERNAL_ERROR, 16#102).
-define(H3_STREAM_CREATION_ERROR, 16#103).
-define(H3_CLOSED_CRITICAL_STREAM, 16#104).
-define(H3_FRAME_UNEXPECTED, 16#105).
-define(H3_FRAME_ERROR, 16#106).
-define(H3_EXCESSIVE_LOAD, 16#107).
-define(H3_ID_ERROR, 16#108).
-define(H3_SETTINGS_ERROR, 16#109).
-define(H3_MISSING_SETTINGS, 16#10a).
-define(H3_REQUEST_REJECTED, 16#10b).
-define(H3_REQUEST_CANCELLED, 16#10c).
-define(H3_REQUEST_INCOMPLETE, 16#10d).
-define(H3_MESSAGE_ERROR, 16#10e).
-define(H3_CONNECT_ERROR, 16#10f).
-define(H3_VERSION_FALLBACK, 16#110).

%%====================================================================
%% Transport Parameters (RFC 9000 Section 18.2)
%%====================================================================

-define(TP_ORIGINAL_DCID, 16#00).
-define(TP_MAX_IDLE_TIMEOUT, 16#01).
-define(TP_STATELESS_RESET_TOKEN, 16#02).
-define(TP_MAX_UDP_PAYLOAD_SIZE, 16#03).
-define(TP_INITIAL_MAX_DATA, 16#04).
-define(TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 16#05).
-define(TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 16#06).
-define(TP_INITIAL_MAX_STREAM_DATA_UNI, 16#07).
-define(TP_INITIAL_MAX_STREAMS_BIDI, 16#08).
-define(TP_INITIAL_MAX_STREAMS_UNI, 16#09).
-define(TP_ACK_DELAY_EXPONENT, 16#0a).
-define(TP_MAX_ACK_DELAY, 16#0b).
-define(TP_DISABLE_ACTIVE_MIGRATION, 16#0c).
-define(TP_PREFERRED_ADDRESS, 16#0d).
-define(TP_ACTIVE_CONNECTION_ID_LIMIT, 16#0e).
-define(TP_INITIAL_SCID, 16#0f).
-define(TP_RETRY_SCID, 16#10).

%%====================================================================
%% Crypto Constants
%%====================================================================

%% Initial salt for QUIC v1 (RFC 9001 Section 5.2)
%% 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
-define(QUIC_V1_INITIAL_SALT,
    <<16#38, 16#76, 16#2c, 16#f7, 16#f5, 16#59, 16#34, 16#b3, 16#4d, 16#17, 16#9a, 16#e6, 16#a4,
        16#c8, 16#0c, 16#ad, 16#cc, 16#bb, 16#7f, 16#0a>>
).

%% Initial salt for QUIC v2 (RFC 9369 Section 5.2)
-define(QUIC_V2_INITIAL_SALT,
    <<16#0d, 16#be, 16#91, 16#3e, 16#26, 16#56, 16#d1, 16#93, 16#83, 16#14, 16#86, 16#ac, 16#d1,
        16#64, 16#9b, 16#f5, 16#77, 16#95, 16#c0, 16#80>>
).

%% HKDF labels
-define(QUIC_LABEL_CLIENT_IN, <<"client in">>).
-define(QUIC_LABEL_SERVER_IN, <<"server in">>).
-define(QUIC_LABEL_QUIC_KEY, <<"quic key">>).
-define(QUIC_LABEL_QUIC_IV, <<"quic iv">>).
-define(QUIC_LABEL_QUIC_HP, <<"quic hp">>).
-define(QUIC_LABEL_QUIC_KU, <<"quic ku">>).

%%====================================================================
%% TLS 1.3 Message Types (RFC 8446 Section 4)
%%====================================================================

-define(TLS_CLIENT_HELLO, 1).
-define(TLS_SERVER_HELLO, 2).
-define(TLS_NEW_SESSION_TICKET, 4).
-define(TLS_END_OF_EARLY_DATA, 5).
-define(TLS_ENCRYPTED_EXTENSIONS, 8).
-define(TLS_CERTIFICATE, 11).
-define(TLS_CERTIFICATE_REQUEST, 13).
-define(TLS_CERTIFICATE_VERIFY, 15).
-define(TLS_FINISHED, 20).
-define(TLS_KEY_UPDATE, 24).
-define(TLS_MESSAGE_HASH, 254).

%%====================================================================
%% TLS 1.3 Extension Types (RFC 8446 Section 4.2)
%%====================================================================

-define(EXT_SERVER_NAME, 0).
-define(EXT_SUPPORTED_GROUPS, 10).
-define(EXT_SIGNATURE_ALGORITHMS, 13).
-define(EXT_ALPN, 16).
% RFC 8446 Section 4.2.11
-define(EXT_PRE_SHARED_KEY, 41).
% RFC 8446 Section 4.2.10
-define(EXT_EARLY_DATA, 42).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_PSK_KEY_EXCHANGE_MODES, 45).
-define(EXT_KEY_SHARE, 51).
-define(EXT_QUIC_TRANSPORT_PARAMS, 57).

%%====================================================================
%% TLS 1.3 Named Groups (RFC 8446 Section 4.2.7)
%%====================================================================

-define(GROUP_SECP256R1, 16#0017).
-define(GROUP_SECP384R1, 16#0018).
-define(GROUP_SECP521R1, 16#0019).
-define(GROUP_X25519, 16#001d).
-define(GROUP_X448, 16#001e).

%%====================================================================
%% TLS 1.3 Signature Algorithms (RFC 8446 Section 4.2.3)
%%====================================================================

-define(SIG_RSA_PKCS1_SHA256, 16#0401).
-define(SIG_RSA_PKCS1_SHA384, 16#0501).
-define(SIG_RSA_PKCS1_SHA512, 16#0601).
-define(SIG_ECDSA_SECP256R1_SHA256, 16#0403).
-define(SIG_ECDSA_SECP384R1_SHA384, 16#0503).
-define(SIG_ECDSA_SECP521R1_SHA512, 16#0603).
-define(SIG_RSA_PSS_RSAE_SHA256, 16#0804).
-define(SIG_RSA_PSS_RSAE_SHA384, 16#0805).
-define(SIG_RSA_PSS_RSAE_SHA512, 16#0806).
-define(SIG_ED25519, 16#0807).
-define(SIG_ED448, 16#0808).

%%====================================================================
%% TLS 1.3 Cipher Suites (RFC 8446 Section B.4)
%%====================================================================

-define(TLS_AES_128_GCM_SHA256, 16#1301).
-define(TLS_AES_256_GCM_SHA384, 16#1302).
-define(TLS_CHACHA20_POLY1305_SHA256, 16#1303).

%%====================================================================
%% TLS Versions
%%====================================================================

-define(TLS_VERSION_1_2, 16#0303).
-define(TLS_VERSION_1_3, 16#0304).

%%====================================================================
%% Default Values
%%====================================================================

-define(DEFAULT_MAX_UDP_PAYLOAD_SIZE, 1200).
% 30 seconds
-define(DEFAULT_MAX_IDLE_TIMEOUT, 30000).
-define(DEFAULT_MAX_STREAMS_BIDI, 100).
-define(DEFAULT_MAX_STREAMS_UNI, 100).
% 1MB
-define(DEFAULT_INITIAL_MAX_DATA, 1048576).
% 256KB
-define(DEFAULT_INITIAL_MAX_STREAM_DATA, 262144).
-define(DEFAULT_ACK_DELAY_EXPONENT, 3).
% 25ms
-define(DEFAULT_MAX_ACK_DELAY, 25).

%%====================================================================
%% Records
%%====================================================================

%% Crypto keys for an encryption level
-record(crypto_keys, {
    key :: binary(),
    iv :: binary(),
    hp :: binary(),
    cipher :: aes_128_gcm | aes_256_gcm | chacha20_poly1305
}).

%% Key Update State (RFC 9001 Section 6)
%% Tracks the key phase and keys for 1-RTT packet encryption.
%% Maintains both current and previous keys for decryption during key update.
-record(key_update_state, {
    %% Current key phase (0 or 1), toggles on each key update
    current_phase = 0 :: 0 | 1,

    %% Current keys for sending and receiving
    current_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,

    %% Previous keys for decryption (kept during key update transition)
    %% Set to undefined when no key update is in progress
    prev_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,

    %% Application traffic secrets (needed for deriving next keys)
    client_app_secret :: binary() | undefined,
    server_app_secret :: binary() | undefined,

    %% Key update state machine
    %% idle: normal operation, no key update in progress
    %% initiated: we sent a packet with new key phase, awaiting response
    %% responding: we received a packet with new key phase, transitioning
    update_state = idle :: idle | initiated | responding
}).

%% Path State for Connection Migration (RFC 9000 Section 9)
%% Tracks the validation state and metrics for a network path.
-record(path_state, {
    %% Remote address for this path
    remote_addr :: {inet:ip_address(), inet:port_number()},

    %% Path validation status
    %% unknown: path not yet validated
    %% validating: PATH_CHALLENGE sent, waiting for PATH_RESPONSE
    %% validated: PATH_RESPONSE received successfully
    %% failed: validation failed (timeout or mismatch)
    status = unknown :: unknown | validating | validated | failed,

    %% PATH_CHALLENGE data (8 bytes) for validation
    challenge_data :: binary() | undefined,

    %% Number of PATH_CHALLENGE attempts
    challenge_count = 0 :: non_neg_integer(),

    %% Anti-amplification: bytes sent/received on this path
    bytes_sent = 0 :: non_neg_integer(),
    bytes_received = 0 :: non_neg_integer(),

    %% RTT estimation for this path
    rtt :: non_neg_integer() | undefined
}).

%% Preferred Address for Server Migration (RFC 9000 Section 9.6)
%% Server advertises this to clients for connection migration.
-record(preferred_address, {
    %% IPv4 address (optional)
    ipv4_addr :: inet:ip4_address() | undefined,
    ipv4_port :: inet:port_number() | undefined,
    %% IPv6 address (optional)
    ipv6_addr :: inet:ip6_address() | undefined,
    ipv6_port :: inet:port_number() | undefined,
    %% Connection ID for the preferred address
    cid :: binary(),
    %% Stateless reset token (16 bytes)
    stateless_reset_token :: binary()
}).

%% Session Ticket for 0-RTT (RFC 9001 Section 4.6)
%% Stores session ticket information for resumption.
-record(session_ticket, {
    %% Server name (SNI) this ticket is valid for
    server_name :: binary(),

    %% Ticket data (opaque to client)
    ticket :: binary(),

    %% Ticket lifetime in seconds
    lifetime :: non_neg_integer(),

    %% Ticket age add (for obfuscation)
    age_add :: non_neg_integer(),

    %% Ticket nonce (for PSK derivation)
    nonce :: binary(),

    %% Resumption master secret (for deriving PSK)
    resumption_secret :: binary(),

    %% Max early data size (0 = no early data)
    max_early_data :: non_neg_integer(),

    %% When this ticket was received
    received_at :: non_neg_integer(),

    %% Cipher suite used for the original connection
    cipher :: atom(),

    %% ALPN used for the original connection
    alpn :: binary() | undefined
}).

%% Connection ID Entry for CID Pool (RFC 9000 Section 5.1)
%% Manages multiple connection IDs for connection migration.
-record(cid_entry, {
    %% Sequence number assigned by the peer
    seq_num :: non_neg_integer(),

    %% The connection ID
    cid :: binary(),

    %% Stateless reset token (16 bytes, optional for seq 0)
    stateless_reset_token :: binary() | undefined,

    %% Status: active (can be used), retired (no longer valid)
    status = active :: active | retired
}).

%% Stream state
-record(stream_state, {
    id :: non_neg_integer(),
    state :: idle | open | half_closed_local | half_closed_remote | closed,

    %% Send state
    send_offset :: non_neg_integer(),
    send_max_data :: non_neg_integer(),
    send_fin :: boolean(),
    send_buffer :: iolist(),

    %% Receive state
    recv_offset :: non_neg_integer(),
    recv_max_data :: non_neg_integer(),
    recv_fin :: boolean(),
    %% #{Offset => Data} for out-of-order reassembly
    recv_buffer :: map(),

    %% Final size (set when FIN received)
    final_size :: non_neg_integer() | undefined,

    %% Stream Priority (RFC 9218)
    %% Urgency: 0-7 (lower = more urgent, default 3)
    %% Incremental: boolean (data can be processed incrementally)
    urgency = 3 :: 0..7,
    incremental = false :: boolean()
}).

%% Sent packet info for loss detection
-record(sent_packet, {
    pn :: non_neg_integer(),
    time_sent :: non_neg_integer(),
    ack_eliciting :: boolean(),
    in_flight :: boolean(),
    size :: non_neg_integer(),
    frames :: [term()]
}).

%% Packet number space
-record(pn_space, {
    %% Send state
    next_pn :: non_neg_integer(),
    largest_acked :: non_neg_integer() | undefined,

    %% Receive state
    largest_recv :: non_neg_integer() | undefined,
    recv_time :: non_neg_integer() | undefined,
    ack_ranges :: [{non_neg_integer(), non_neg_integer()}],
    ack_eliciting_in_flight :: non_neg_integer(),

    %% Loss detection
    loss_time :: non_neg_integer() | undefined,
    sent_packets :: #{non_neg_integer() => #sent_packet{}}
}).

%% QUIC packet
-record(quic_packet, {
    type :: initial | handshake | zero_rtt | one_rtt | retry,
    version :: non_neg_integer() | undefined,
    dcid :: binary(),
    scid :: binary() | undefined,
    token :: binary() | undefined,
    pn :: non_neg_integer() | undefined,
    % frames list or encrypted payload
    payload :: binary() | [term()]
}).

%% Connection state
-record(conn_state, {
    %% Connection IDs

    % Source Connection ID
    scid :: binary(),
    % Destination Connection ID
    dcid :: binary(),
    % Original DCID (for Initial packets)
    original_dcid :: binary(),

    %% Connection state
    state :: idle | handshaking | connected | draining | closed,
    role :: client | server,
    version :: non_neg_integer(),

    %% Socket
    socket :: gen_udp:socket() | undefined,
    remote_addr :: {inet:ip_address(), inet:port_number()},
    local_addr :: {inet:ip_address(), inet:port_number()},

    %% Owner process
    owner :: pid(),

    %% Crypto state (per encryption level)
    initial_keys :: #crypto_keys{} | undefined,
    handshake_keys :: #crypto_keys{} | undefined,
    app_keys :: #crypto_keys{} | undefined,

    %% TLS state
    tls_state :: term(),
    alpn :: binary() | undefined,

    %% Flow control
    max_data_local :: non_neg_integer(),
    max_data_remote :: non_neg_integer(),
    data_sent :: non_neg_integer(),
    data_received :: non_neg_integer(),

    %% Stream management
    streams :: #{non_neg_integer() => #stream_state{}},
    next_stream_id_bidi :: non_neg_integer(),
    next_stream_id_uni :: non_neg_integer(),
    max_streams_bidi_local :: non_neg_integer(),
    max_streams_bidi_remote :: non_neg_integer(),
    max_streams_uni_local :: non_neg_integer(),
    max_streams_uni_remote :: non_neg_integer(),

    %% Packet numbers
    pn_space_initial :: #pn_space{},
    pn_space_handshake :: #pn_space{},
    pn_space_app :: #pn_space{},

    %% Timers
    idle_timeout :: non_neg_integer(),
    last_activity :: non_neg_integer(),

    %% Transport parameters
    transport_params :: map()
}).

%%====================================================================
%% QUIC-LB (RFC 9312) - QUIC Load Balancer Configuration
%%====================================================================

%% Config Rotation for unroutable packets (CR bits = 0b111)
-define(LB_CR_UNROUTABLE, 7).
%% Maximum server ID length (1-15 bytes)
-define(LB_MAX_SERVER_ID_LEN, 15).
%% Maximum nonce length (4-18 bytes)
-define(LB_MAX_NONCE_LEN, 18).
%% Minimum nonce length
-define(LB_MIN_NONCE_LEN, 4).

%% QUIC-LB Configuration record
%% Defines how the load balancer encodes server identity in CIDs
-record(lb_config, {
    %% Config rotation bits (0-6, 7 = unroutable)
    config_rotation = 0 :: 0..6,
    %% Encoding algorithm
    algorithm = plaintext :: plaintext | stream_cipher | block_cipher,
    %% Server ID (1-15 bytes identifying this server)
    server_id :: binary(),
    %% Length of server ID in bytes
    server_id_len :: 1..15,
    %% Length of nonce in bytes (4-18)
    nonce_len = 4 :: 4..18,
    %% Encryption key (16 bytes for AES-128, required for cipher algorithms)
    key :: binary() | undefined
}).

%% CID generation configuration record
%% Combines LB config with additional parameters for CID generation
-record(cid_config, {
    %% Optional LB config (undefined = use random CIDs)
    lb_config :: #lb_config{} | undefined,
    %% Target CID length (1-20 bytes)
    cid_len = 8 :: 1..20,
    %% Reset secret for stateless reset token generation
    reset_secret :: binary() | undefined
}).

% QUIC_HRL
-endif.
