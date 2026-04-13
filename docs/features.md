# erlang_quic Features

## Core Protocol (RFC 9000)

### Connection Management
- [x] Connection establishment with TLS 1.3 handshake
- [x] Connection close (immediate and draining states)
- [x] Idle timeout enforcement (configurable via `idle_timeout` option)
- [x] Version negotiation
- [x] Retry packets for address validation

### Streams
- [x] Bidirectional streams (client and server initiated)
- [x] Unidirectional streams
- [x] Stream prioritization (RFC 9218) with 8 urgency levels
- [x] Incremental delivery flag support
- [x] RESET_STREAM_AT extension (draft-ietf-quic-reliable-stream-reset-07)

### Flow Control
- [x] Connection-level flow control (MAX_DATA)
- [x] Stream-level flow control (MAX_STREAM_DATA)
- [x] MAX_STREAMS limits (bidirectional and unidirectional)

### Packet Handling
- [x] Initial, Handshake, and 1-RTT packet types
- [x] Short header (1-RTT) packets
- [x] Packet number encoding (1-4 bytes)
- [x] Packet number reconstruction per RFC 9000 Appendix A
- [x] Coalesced packets
- [x] Frame coalescing (ACK + small stream data in single packet)

### Connection Migration (RFC 9000 Section 9)
- [x] PATH_CHALLENGE / PATH_RESPONSE validation
- [x] Active connection migration (`quic:migrate/1`, `quic:migrate/2`)
- [x] Preferred address handling (RFC 9000 Section 9.6)
- [x] Server-side address change detection (NAT rebinding and active migration)
- [x] Congestion control reset on path change (RFC 9002 Section 9.4)
- [x] CID rotation on migration for path unlinkability (RFC 9000 Section 9.5)
- [x] `disable_active_migration` transport parameter support
- [x] Path validation timeout with retry (3 * PTO, up to 3 attempts)

### Connection ID Management
- [x] Multiple connection IDs
- [x] NEW_CONNECTION_ID frames
- [x] RETIRE_CONNECTION_ID frames
- [x] Active connection ID limit

## Loss Detection & Congestion Control (RFC 9002)

### Loss Detection
- [x] Packet loss detection
- [x] Probe timeout (PTO)
- [x] RTT measurement (smoothed RTT, RTT variance)

### Congestion Control
- [x] Pluggable congestion control behavior
- [x] NewReno (default, RFC 9002)
- [x] CUBIC (RFC 9438)
- [x] BBR (Bottleneck Bandwidth and RTT)
- [x] HyStart++ slow start (RFC 9406) for all algorithms
- [x] Slow start with improved exit detection
- [x] Congestion avoidance
- [x] Recovery on packet loss
- [x] Persistent congestion detection (resets cwnd after PTO * 3)
- [x] ECN support (ECN-CE triggers congestion response)
- [x] Packet pacing (RFC 9002 Section 7.7) to prevent bursts
- [x] RTT-based flow control auto-tuning

## Path MTU Discovery (RFC 8899 - DPLPMTUD)

- [x] Binary search probing for optimal MTU
- [x] Integration with peer's `max_udp_payload_size` transport parameter
- [x] Black hole detection and recovery
- [x] Automatic MTU reset on connection migration
- [x] Periodic re-probing for MTU increases
- [x] Congestion control integration (updates cwnd-related parameters)

## TLS 1.3 Integration (RFC 9001)

### Handshake
- [x] Full TLS 1.3 handshake
- [x] ALPN negotiation
- [x] Transport parameters exchange
- [x] Certificate verification

### Encryption
- [x] AES-128-GCM cipher suite
- [x] AES-256-GCM cipher suite
- [x] ChaCha20-Poly1305 cipher suite
- [x] Header protection
- [x] Key derivation (HKDF)

### Key Management
- [x] Initial secrets derivation
- [x] Handshake secrets
- [x] Application secrets
- [x] Key updates (RFC 9001 Section 6)

### Session Resumption
- [x] Session tickets (NewSessionTicket)
- [x] PSK-based resumption
- [x] 0-RTT early data

## QUIC Version 2 (RFC 9369)

- [x] Version 2 (0x6b3343cf) support
- [x] Updated initial salt
- [x] Updated retry integrity tag key

## QUIC-LB Load Balancer Support (RFC 9312)

- [x] Server ID encoding in Connection IDs for LB routing
- [x] Config rotation bits for LB coordination
- [x] Variable CID length support (1-20 bytes)
- [x] Three encoding algorithms:
  - Plaintext: Server ID visible in CID (no encryption)
  - Stream Cipher: AES-128-CTR encryption
  - Block Cipher: Feistel network for variable lengths
- [x] LB-aware CID generation in listener and connection

## Reliable Stream Reset (draft-ietf-quic-reliable-stream-reset-07)

RESET_STREAM_AT allows resetting a stream while ensuring data up to a specified
offset is reliably delivered. Required for WebTransport where stream headers
must be received even if the stream is immediately reset.

### Features
- [x] Frame type 0x24 (RESET_STREAM_AT) encode/decode
- [x] Transport parameter negotiation (0x17f7586d2cb571)
- [x] Reliable delivery guarantee up to ReliableSize
- [x] Retransmission filtering (data beyond ReliableSize not retransmitted)
- [x] Validation: ReliableSize cannot exceed FinalSize
- [x] Validation: ReliableSize cannot be increased after initial reset
- [x] Validation: ErrorCode cannot change after initial reset

### Usage

```erlang
%% Enable in connection options (both client and server)
Opts = #{reset_stream_at => true, alpn => [<<"webtransport">>]},
{ok, Conn} = quic:connect(Host, Port, Opts, self()),

%% Send stream header (e.g., WebTransport session ID)
{ok, StreamId} = quic:open_stream(Conn),
ok = quic:send_data(Conn, StreamId, Header, false),

%% Reset stream but ensure header is delivered
ok = quic:reset_stream_at(Conn, StreamId, ErrorCode, byte_size(Header)).
```

## HTTP/3 (RFC 9114)

### Core
- [x] HTTP/3 client and server (`quic_h3`, `quic_h3_connection`)
- [x] ALPN `h3` negotiation, SETTINGS, control stream, GOAWAY
- [x] Request/response streams with trailers
- [x] Interim 1xx responses (request and push streams)
- [x] CONNECT tunnels (§4.4) and extended CONNECT (`:protocol`, RFC 9220)
- [x] Per-stream handler registration for body-data routing

### QPACK header compression (RFC 9204)
- [x] Static and dynamic tables
- [x] Huffman encoding + EOS-padding-validated decoding
- [x] Encoder-stream instructions (Set Dynamic Table Capacity, Insert,
      Duplicate) with capacity bounded by advertised limit
- [x] Decoder-stream instructions (Section Ack, Stream Cancellation,
      Insert Count Increment)
- [x] Blocked-streams limit enforcement per `SETTINGS_QPACK_BLOCKED_STREAMS`
- [x] Eviction guard against entries referenced by unacknowledged sections

### Server push (RFC 9114 §4.6)
- [x] `MAX_PUSH_ID`, `PUSH_PROMISE`, `CANCEL_PUSH`, push streams
- [x] Cacheable-method enforcement (only GET/HEAD may be pushed)
- [x] Duplicate `PUSH_PROMISE` allowed when headers identical,
      `H3_GENERAL_PROTOCOL_ERROR` when they differ

### Extensible priorities (RFC 9218)
- [x] `priority` request/response header
- [x] `PRIORITY_UPDATE_REQUEST` and `PRIORITY_UPDATE_PUSH` frames with
      strict Structured-Fields framing

### Malformed-message enforcement (RFC 9114 §4.1.2, §4.2)
- [x] Uppercase field names rejected
- [x] Invalid field name/value characters rejected
- [x] Connection-specific fields (`connection`, `keep-alive`, `upgrade`,
      `proxy-connection`, `transfer-encoding`) rejected
- [x] `te` restricted to `trailers`
- [x] `:status` limited to 100..599, request pseudo-headers rejected on
      responses
- [x] `:authority` / `Host` consistency, empty values and userinfo rejected
- [x] Duplicate `Content-Length` must match; incomplete server-side
      requests reset with `H3_REQUEST_INCOMPLETE`
- [x] Reserved HTTP/2 frame types (0x02/0x06/0x08/0x09) and HTTP/2
      settings IDs rejected
- [x] 1 MiB frame-size ceiling, QPACK prefixed-int shift cap,
      unknown SETTINGS IDs silently dropped

## API

### Connection
- `quic:connect/3,4` - Connect to server
- `quic:close/1,2,3` - Close connection (with optional app error code)
- `quic:peername/1` - Get peer address
- `quic:sockname/1` - Get local address
- `quic:peercert/1` - Get peer certificate
- `quic:migrate/1,2` - Trigger connection migration (with optional timeout)

### Datagrams (RFC 9221)
- `quic:send_datagram/2` - Send unreliable datagram
- `quic:datagram_max_size/1` - Get max datagram size (0 if unsupported)

### Streams
- `quic:open_stream/1` - Open bidirectional stream
- `quic:open_unidirectional_stream/1` - Open unidirectional stream
- `quic:send/3,4` - Send data on stream
- `quic:close_stream/2,3` - Close stream
- `quic:reset_stream/3` - Reset stream with error code
- `quic:reset_stream_at/4` - Reset stream with reliable delivery up to specified size
- `quic:set_stream_priority/4` - Set stream priority (urgency, incremental)
- `quic:get_stream_priority/2` - Get stream priority

### Server
- `quic:listen/2` - Start listener
- `quic:accept/1,2` - Accept connection
- `quic:close_listener/1` - Close listener

### Multi-Pool Server Management
- `quic:start_server/3` - Start named server pool
- `quic:stop_server/1` - Stop named server
- `quic:get_server_info/1` - Get server information
- `quic:get_server_port/1` - Get server listening port
- `quic:get_server_connections/1` - Get server connection PIDs
- `quic:which_servers/0` - List all running servers

### Load Balancer (RFC 9312)
- `quic_lb:new_config/1` - Create LB configuration from options map
- `quic_lb:new_cid_config/1` - Create CID generation configuration
- `quic_lb:generate_cid/1` - Generate CID with encoded server_id
- `quic_lb:decode_server_id/2` - Extract server_id from CID
- `quic_lb:is_lb_routable/1` - Check if CID has valid LB routing bits
- `quic_lb:get_config_rotation/1` - Get config rotation bits from CID
- `quic_lb:expected_cid_len/1` - Calculate expected CID length from config

### Options
- `idle_timeout` - Connection idle timeout in milliseconds (0 to disable)
- `max_data` - Connection-level flow control limit
- `max_stream_data` - Stream-level flow control limit
- `max_datagram_frame_size` - Max datagram size to accept (0 = disabled, default: 0)
- `reset_stream_at` - Enable RESET_STREAM_AT extension (default: false)
- `alpn` - ALPN protocols list
- `verify` - Certificate verification mode
- `preferred_ipv4` - Server preferred IPv4 address
- `preferred_ipv6` - Server preferred IPv6 address
- `pool_size` - Number of listener processes for server pools (default: 1)
- `connection_handler` - Callback for handling new connections
- `lb_config` - QUIC-LB configuration map for load balancer routing
- `keep_alive_interval` - Keep-alive PING interval (`disabled`, `auto`, or milliseconds)
- `pmtu_enabled` - Enable Path MTU Discovery (default: true)
- `pmtu_max_mtu` - Maximum MTU to probe (default: 1500)
- `recbuf` - UDP receive buffer size in bytes (default: 7MB)
- `sndbuf` - UDP send buffer size in bytes (default: 7MB)

### PMTU Discovery
- `quic:get_mtu/1` - Get current effective MTU for a connection

## Erlang Distribution (quic_dist)

QUIC-based Erlang distribution protocol implementation.

### Features
- [x] Full distribution protocol over QUIC transport
- [x] TLS 1.3 encryption built-in (no separate SSL setup)
- [x] 0-RTT session resumption for fast reconnection
- [x] Multiple streams: control (urgency 0) + data (urgency 4-6)
- [x] Stream prioritization for tick/control messages
- [x] QUIC-level liveness detection (packet counts, not blocked by flow control)
- [x] Keep-alive PING frames for transport liveness
- [x] Backpressure mechanism for congestion control
- [x] Session ticket storage for 0-RTT

### Modules
- `quic_dist` - Distribution protocol callbacks
- `quic_dist_controller` - Per-connection state machine
- `quic_dist_sup` - Distribution supervisor
- `quic_dist_tickets` - Session ticket storage
- `quic_epmd` - EPMD replacement module

### Discovery Backends
- `quic_discovery_static` - Static node configuration
- `quic_discovery_dns` - DNS SRV-based discovery
- Custom backends via `quic_discovery` behaviour

### Distribution API
- `quic:get_stats/1` - Get packet counts for liveness detection
- `quic:send_ping/1` - Send transport-level PING frame

## Interop Runner Compliance

All 10 QUIC Interop Runner test cases pass:

| Test Case | Status |
|-----------|--------|
| handshake | Pass |
| transfer | Pass |
| retry | Pass |
| keyupdate | Pass |
| chacha20 | Pass |
| multiconnect | Pass |
| v2 | Pass |
| resumption | Pass |
| zerortt | Pass |
| connectionmigration | Pass |
