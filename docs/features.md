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

## API

### Connection
- `quic:connect/3,4` - Connect to server
- `quic:close/1,2` - Close connection
- `quic:peername/1` - Get peer address
- `quic:sockname/1` - Get local address
- `quic:peercert/1` - Get peer certificate
- `quic:migrate/1` - Trigger connection migration

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

### Options
- `idle_timeout` - Connection idle timeout in milliseconds (0 to disable)
- `max_data` - Connection-level flow control limit
- `max_stream_data` - Stream-level flow control limit
- `alpn` - ALPN protocols list
- `verify` - Certificate verification mode
- `preferred_ipv4` - Server preferred IPv4 address
- `preferred_ipv6` - Server preferred IPv6 address
- `pool_size` - Number of listener processes for server pools (default: 1)
- `connection_handler` - Callback for handling new connections

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
