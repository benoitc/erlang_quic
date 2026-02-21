# Changelog

All notable changes to this project will be documented in this file.

## [0.10.0] - 2026-02-21

### Added
- RFC 9312 QUIC-LB Connection ID encoding support for load balancer routing
- New `quic_lb` module with three encoding algorithms:
  - Plaintext: server_id visible in CID (no encryption)
  - Stream Cipher: AES-128-CTR encryption of server_id
  - Block Cipher: 4-round Feistel network for <16 bytes, AES-CTR for 16 bytes,
    truncated cipher for >16 bytes
- `#lb_config{}` record for LB configuration (algorithm, server_id, key, nonce_len)
- `#cid_config{}` record for CID generation configuration
- `lb_config` option in `quic_listener` to enable LB-aware CID generation
- Variable DCID length support in short header packet parsing
- LB-aware CID generation in `quic_connection` for NEW_CONNECTION_ID frames
- E2E test suite `quic_lb_e2e_SUITE` with 21 integration tests
- `quic:server_spec/3` to get a child spec for embedding QUIC servers in custom
  supervision trees
- Stream reassembly test suite `quic_stream_reassembly_SUITE` for ordered delivery
  verification

### Changed
- `quic:set_owner/2` is now asynchronous (cast instead of call)

### Fixed
- `quic:get_server_port/1` now returns the actual OS-assigned port when server
  was started with port 0 (ephemeral port), instead of returning 0
- `quic:get_server_connections/1` now correctly returns connection PIDs; was
  returning empty list due to `get_listeners/1` returning supervisor pids
  instead of actual listener processes
- Removed redundant `link/1` call in listener (connection already linked via
  `gen_statem:start_link`)
- Unhandled calls in connection state machine now return `{error, {invalid_state, State}}`
  instead of silently timing out
- Server-side connection termination no longer closes shared listener socket:
  previously when a server connection terminated, it would close the UDP socket
  shared with the listener, breaking all subsequent connections
- Cancel delayed ACK timer in connection terminate to prevent timer messages
  to dead processes
- Session ticket table now has TTL (7 days) and size limit (10,000 entries) to
  prevent unbounded memory growth
- Listener now properly cleans up ETS tables on terminate (standalone mode only,
  pool mode tables are managed by the pool manager)
- Draining state now uses calculated `3 * PTO` timeout per RFC 9000 Section 10.2
  instead of hardcoded 3 seconds
- Pre-connection pending data queue now has size limit (1000 entries) to prevent
  memory exhaustion from slow handshakes
- Buffer contiguity calculation now has iteration limit to prevent stack overflow
  with highly fragmented receive buffers
- Stream data is now properly reassembled before delivery: previously data was
  delivered immediately as received, causing corruption when packets arrived out
  of order during large file transfers. Data is still streamed incrementally as
  contiguous chunks become available
- Server connections no longer modify listener's socket active state: server-side
  connections were calling `inet:setopts(Socket, [{active, once}])` on the shared
  listener socket, overriding the listener's `{active, N}` configuration and
  causing the socket to go passive after receiving packets

## [0.9.0] - 2026-02-20

### Added
- Multi-pool server support with ranch-style named server pools
- `quic:start_server/3` to start named server with connection pooling
- `quic:stop_server/1` to stop named server
- `quic:get_server_info/1` to get server information (pid, port, opts, started_at)
- `quic:get_server_port/1` to get server listening port
- `quic:get_server_connections/1` to get server connection PIDs
- `quic:which_servers/0` to list all running servers
- Application supervision structure (`quic_app`, `quic_sup`, `quic_server_sup`)
- ETS-based server registry (`quic_server_registry`) with process monitoring
- `pool_size` option for listener process pooling with SO_REUSEPORT
- FreeBSD CI testing workflow
- Expanded Linux CI matrix (Ubuntu 22.04/24.04, OTP 26-28)

### Changed
- `quic.app.src` now includes `{mod, {quic_app, []}}` for OTP application behaviour
- Listener supervisor registers with server registry on init for restart recovery

## [0.8.0] - 2026-02-20

### Added
- Stream prioritization (RFC 9218): urgency-based scheduling with 8 priority
  levels (0-7) and incremental delivery flag
- `quic:set_stream_priority/4` and `quic:get_stream_priority/2` API
- Bucket-based priority queue for O(1) stream scheduling
- Preferred address handling (RFC 9000 Section 9.6): server can advertise a
  preferred address during handshake, client validates via PATH_CHALLENGE and
  automatically migrates to validated preferred address
- `preferred_ipv4` and `preferred_ipv6` listener options for server configuration
- `#preferred_address{}` record for IPv4/IPv6 addresses, CID, and reset token
- `quic_tls:encode_preferred_address/1` and `quic_tls:decode_preferred_address/1`
- Idle timeout enforcement (RFC 9000 Section 10.1): when `idle_timeout` option
  is set, internal timer automatically closes connection after timeout with no
  activity (set to 0 to disable)
- Persistent congestion detection (RFC 9002 Section 7.6): detects prolonged packet
  loss spanning > PTO * 3 and resets cwnd to minimum window
- Frame coalescing: ACK frames are coalesced with small pending stream data
  (< 500 bytes) for more efficient packet utilization

## [0.7.1] - 2026-02-20

### Fixed
- Packet number reconstruction per RFC 9000 Appendix A: truncated packet numbers
  are now properly reconstructed using the largest received PN, fixing decryption
  failures for large responses (>255 packets with 1-byte PN encoding)

## [0.7.0] - 2026-02-20

### Added
- Docker interop runner integration (client and server images)
- Session resumption interop test (`resumption`)
- 0-RTT early data interop test (`zerortt`)
- Connection migration interop test (`connectionmigration`)
- `quic:migrate/1` API for triggering active path migration
- All 10 QUIC Interop Runner test cases now pass:
  - handshake, transfer, retry, keyupdate, chacha20, multiconnect, v2,
    resumption, zerortt, connectionmigration

### Fixed
- Connection-level flow control: now properly tracks `data_received` and sends
  MAX_DATA frames when 50% of connection window is consumed (RFC 9000 Section 4.1)
- Large downloads: interop client now writes to disk incrementally (streaming)
  instead of accumulating in memory
- Server DCID initialization: server now correctly sets DCID from client's
  Initial packet SCID field, fixing short header packet alignment
- Key update HP key preservation: header protection keys are no longer rotated
  during key updates per RFC 9001 Section 6.6
- Fixed bit validation: skip padding bytes (0x00) and invalid short headers
  (fixed bit not set) in coalesced packets
- Role-based key selection in 1-RTT packet decryption

## [0.6.5] - 2026-02-19

### Added
- `quic_listener:start/2` for unlinked listener processes
- `set_owner` call handling in idle and handshaking states

### Fixed
- IPv4/IPv6 address family matching when opening client sockets
- Race condition: transfer socket ownership before sending packet
- Handle header unprotection errors gracefully in packet decryption
- Removed verbose debug logging from listener

## [0.6.4] - 2026-02-17

### Fixed
- Server now selects correct signature algorithm based on key type (EC vs RSA)

## [0.6.3] - 2026-02-17

### Fixed
- Fixed transport params parsing in ClientHello - properly unwrap {ok, Map} result

## [0.6.2] - 2026-02-17

### Fixed
- Fixed key selection for all packet types based on role (server vs client)
- Server now uses correct keys for both sending and receiving packets
- Fixed Initial, Handshake, and 1-RTT packet encryption/decryption

## [0.6.1] - 2026-02-17

### Fixed
- Server-side packet decryption now uses correct keys (client keys for Initial/Handshake packets received from clients)

## [0.6.0] - 2026-02-17

### Added
- DATAGRAM frame support (RFC 9221) for unreliable data transmission
- `quic:set_owner/2` to transfer connection ownership (like gen_tcp:controlling_process/2)
- `quic:peercert/1` to retrieve peer certificate (DER-encoded)
- `quic:send_datagram/2` to send QUIC datagrams
- Connection handler callback in `quic_listener` for custom connection handling
- ACK delay for datagram-only packets per RFC 9221 Section 5.2
- Proper ACK generation at packet level for all ack-eliciting frames

### Fixed
- Datagrams are not retransmitted on loss (RFC 9221 compliance)
- ACKs now sent for all ack-eliciting frames, not just stream data

## [0.5.1] - 2026-02-17

### Fixed
- Pad payload for header protection sampling to prevent crashes during PTO timeout

## [0.5.0] - 2026-02-17

### Added
- Retry packet handling (RFC 9000 Section 8.1)
- Stateless reset support (RFC 9000 Section 10.3)
- Connection ID limit enforcement (RFC 9000 Section 5.1.1)
- ECN support for congestion control (RFC 9002 Section 7.1)
- RFC 9000/9001 test vectors
- Interoperability test suite with quic-go server
- E2E tests in CI pipeline

### Fixed
- CI compatibility with OTP 28 (use rebar3 nightly)
- quic-go Docker build (pin to v0.48.2)

## [0.4.0] - 2025-02-17

### Changed
- Moved `doc/` to `docs/` to prevent ex_doc from overwriting documentation
- Consolidated `hash_len/1` and `cipher_to_hash/1` functions in `quic_crypto` module
- Refactored key derivation in `quic_keys` using `cipher_params/1` helper
- Improved socket cleanup on initialization failure in `quic_connection`

### Removed
- Removed `send_headers/4` API (HTTP/3 functionality, not core QUIC transport)

### Fixed
- Added bounds checking for header protection sample extraction in `quic_aead`
- Added CID length validation (max 20 bytes per RFC 9000) in `quic_packet`
- Added token length validation in `quic_packet`
- Added frame data length limits in `quic_frame` to prevent memory exhaustion
- Added ACK range limits in `quic_ack` to prevent DoS attacks
- Fixed weak random: use `crypto:strong_rand_bytes/1` for ticket age_add
- Fixed dialyzer warning in `quic_tls` by adding error handling to `decode_transport_params/1`

## [0.3.0] - 2025-02-16

### Added
- Server mode with `quic_listener` module
- 0-RTT early data support (RFC 9001 Section 4.6)
- Connection migration support (RFC 9000 Section 9)
- Key update support (RFC 9001 Section 6)

## [0.2.0] - 2025-02-15

### Added
- Stream multiplexing (bidirectional and unidirectional)
- Flow control (connection and stream level)
- Congestion control (NewReno)
- Loss detection and packet retransmission (RFC 9002)

## [0.1.0] - 2025-02-14

### Added
- Initial release
- TLS 1.3 handshake (RFC 8446)
- Basic QUIC transport (RFC 9000)
- AEAD packet protection (RFC 9001)
