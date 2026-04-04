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
- [x] Active connection migration (`quic:migrate/1`)
- [x] Preferred address handling (RFC 9000 Section 9.6)

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

### Congestion Control (NewReno)
- [x] Slow start
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

## API

### Connection
- `quic:connect/3,4` - Connect to server
- `quic:close/1,2` - Close connection
- `quic:peername/1` - Get peer address
- `quic:sockname/1` - Get local address
- `quic:peercert/1` - Get peer certificate
- `quic:migrate/1` - Trigger connection migration

### Datagrams (RFC 9221)
- `quic:send_datagram/2` - Send unreliable datagram
- `quic:datagram_max_size/1` - Get max datagram size (0 if unsupported)

### Streams
- `quic:open_stream/1` - Open bidirectional stream
- `quic:open_unidirectional_stream/1` - Open unidirectional stream
- `quic:send/3,4` - Send data on stream
- `quic:close_stream/2,3` - Close stream
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
