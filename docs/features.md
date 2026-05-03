# erlang_quic Features

## Core Protocol (RFC 9000)

### Connection Management
- [x] Connection establishment with TLS 1.3 handshake
- [x] Connection close (immediate and draining states)
- [x] Idle timeout enforcement (configurable via `idle_timeout` option)
- [x] Version negotiation
- [x] Retry packets for address validation
- [x] Latency spin bit (RFC 9000 §17.4) with `spin_bit => true | false`
- [x] NEW_TOKEN frame dispatch (server rejects peer-received tokens per §8.1.3); client caches received tokens keyed by `{Host, Port}` and reuses them in the Initial of the next connect to the same endpoint
- [x] Stateless reset (RFC 9000 §10.3): listener emits resets for orphan packets; per-connection `NEW_CONNECTION_ID` tokens share the listener's HMAC secret so they match orphan-path tokens
- [x] Server-side address validation (RFC 9000 §8.1): opt in with `address_validation => always` on `quic:start_server/3`. Listener emits a Retry packet with an HMAC-signed retry token when a client Initial arrives without one; subsequent Initials carrying a valid token skip retry and spawn a connection that echoes `retry_source_connection_id`. Server issues a NEW_TOKEN after handshake so the next reconnect skips retry entirely

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
- `quic:datagram_stats/1` - Delivered / dropped / sent counters (backpressure)

### HTTP Datagrams (RFC 9297)
- `quic_h3:send_datagram/3` - Send an HTTP datagram bound to a request stream
- `quic_h3:h3_datagrams_enabled/1` - Whether both sides negotiated support
- `quic_h3:max_datagram_size/2` - Max payload per datagram for a given stream
- Owner event: `{quic_h3, Conn, {datagram, StreamId, Payload}}`
- Set `h3_datagram_enabled => true` on `connect/3` / `start_server/3` to enable.
  CONNECT-UDP (RFC 9298) builds on this in a separate library.

### HTTP/3 Extension Streams
- `quic_h3:open_bidi_stream/1,2` - Open a client-initiated bidi stream;
  with a non-negative `SignalType` varint the stream is pre-claimed and
  inbound bytes route as `{stream_type_data, bidi, ...}` owner messages
  instead of HTTP/3 request frames (e.g. WebTransport's `0x41`)
- `stream_type_handler` option on `start_server/3` claims peer-initiated
  uni / bidi streams whose first varint matches a caller-supplied filter
- Owner events: `{stream_type_open, Direction, StreamId, VarintType}`,
  `{stream_type_data, Direction, StreamId, Data, Fin}`,
  `{stream_type_closed, Direction, StreamId}`,
  `{stream_type_reset, Direction, StreamId, ErrorCode}`,
  `{stream_type_stop_sending, Direction, StreamId, ErrorCode}`
- Per-connection owner override via `connection_handler` callback on
  `start_server/3` for hosting many sessions on one listener

### Streams
- `quic:open_stream/1` - Open bidirectional stream
- `quic:open_unidirectional_stream/1` - Open unidirectional stream
- `quic:send/3,4` - Send data on stream
- `quic:close_stream/2,3` - Close stream
- `quic:reset_stream/3` - Reset stream with error code
- `quic:reset_stream_at/4` - Reset stream with reliable delivery up to specified size
- `quic:set_stream_priority/4` - Set stream priority (urgency, incremental)
- `quic:get_stream_priority/2` - Get stream priority

### Server / Multi-Pool Server Management
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
- `datagram_recv_queue_len` - Bounded receive queue for inbound datagrams (default: `infinity`; drops oldest on overflow, tracked via `datagram_stats/1`)
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
- `server_send_batching` - Per-connection send batching on the server (default: true). On Linux + `socket_backend => socket` with UDP_SEGMENT, outgoing packets are coalesced into GSO super-datagrams via `sendmsg` cmsg; neutral on macOS / gen_udp. Set to `false` to fall back to direct `gen_udp:send/4`

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
- `quic_dist_auth` - Optional auth-handshake behaviour

### Discovery Backends
- `quic_discovery_static` - Static node configuration
- `quic_discovery_dns` - DNS SRV-based discovery
- Custom backends via `quic_discovery` behaviour

### Distribution API
- `quic:get_stats/1` - Get packet counts for liveness detection
- `quic:send_ping/1` - Send transport-level PING frame

### Extension Hooks
- `auth_callback` (default `undefined`): `{Mod, Fun}` or `fun/3` invoked
  on both sides after the QUIC handshake but before the dist_util
  handshake. Returning `{error, _}` closes the connection without ever
  starting the dist controller. See `quic_dist_auth` and the
  Configuration Reference in `docs/QUIC_DIST.md`.
- `register_with_epmd` (default `false`): when `true`, the listener
  registers its port via the configured `epmd_module` so external
  tooling (e.g. `epmd -names`) can resolve the node.

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
