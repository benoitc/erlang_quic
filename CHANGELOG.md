# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.1.0] - Unreleased

Server-side throughput work. Per-connection send batching over the
shared listener socket on Linux + socket backend coalesces outgoing
packets into sendmsg super-datagrams via UDP_SEGMENT (GSO); on macOS /
gen_udp it is functionally neutral. Several GSO correctness fixes
after CI surfaced a handshake stall. Extra observability so tests and
operators can see the batching win directly.

### Added
- Per-connection send batching on the server. Each server connection
  owns a `quic_socket` batch buffer that reuses the listener's UDP
  socket. Gated by the new `server_send_batching` option on
  `start_server/3` (default `true`); set to `false` to fall back to
  the previous direct `gen_udp:send/4` path. (#66)
- `quic_socket:info/1` — map with `backend`, `gso_supported`,
  `gso_size`, `gro_enabled`, `batching_enabled`, `max_batch_packets`,
  and the new `batch_flushes` / `packets_coalesced` counters.
- `quic_socket:send_immediate/4` — public wrapper that bypasses the
  per-connection batch for one-shot control-plane sends.
- `quic_socket:new_sender/2` — build a per-connection sender that
  inherits backend + GSO capability from the listener without owning
  the socket.
- `quic_connection:get_stats/1` now returns `batch_flushes` and
  `packets_coalesced` so tests and benchmarks can assert batching
  behaviour rather than just wiring.
- `quic_server_batching_SUITE` — behaviour-level regression: real
  256 KB server-to-client downloads assert `packets_coalesced > 1`
  when batching is on, and both counters stay at 0 when disabled.
- `docker/gso-debug/` — Erlang 28 + tcpdump + strace container that
  reproduces the GSO handshake stall against a bind-mounted tree.
  (#74)
- `bench/run_download_bench.erl` and
  `quic_throughput_bench:run_download_sink/0,1` drive server-to-client
  bulk transfers and report MB/s alongside `batch_flushes` /
  `packets_coalesced` so the batching effect is visible next to
  throughput.

### Changed
- Stream send path is iovec-native. `quic_frame:encode_iodata/1`
  returns `[Header, Data]` and threads iodata through header
  protection and `quic_aead` without copying `Data` into a fresh
  binary. AEAD specs relaxed to accept iodata.
- 1-RTT ACKs delayed to every 2nd packet or `max_ack_delay` per
  RFC 9002 §6.2. Halves receiver ACK traffic on the server and
  sender event-processing on the client. Measured on macOS gen_udp:
  10 MB upload 45 → 56 MB/s. (#69)
- `quic_loss` switched to a single `queue:queue(#sent_packet{})` for
  outstanding packets. Per-ACK work scales with the ACK window, not
  the full outstanding queue. Measured on macOS gen_udp: 10 MB
  upload 55 → 59 MB/s, 5 MB download 34 → 50 MB/s. (#72)
- `flush_gso/1` passes the batch as an iov list directly to
  `socket:sendmsg/2` with the UDP_SEGMENT cmsg, saving up to
  ~76 KB of user-space copy per flush on a 64-packet batch. (#70)
- `send_app_packet_internal/3` samples `monotonic_time` once per
  packet and reuses it for loss tracking and `last_activity`. (#71)
- Per-packet overhead on the bulk-send path reduced: single
  `#state{}` update, PTO timer reschedule skipped when within
  tolerance, `process_send_queue` and pacing timeout short-circuit
  on empty queue, stream data normalised to binary once at the
  fragmentation boundary.
- `state_to_map/1` replaces the coarse `send_batching` boolean with
  three explicit fields: `send_backend` (`direct` | `gen_udp` |
  `socket`), `send_batching_enabled`, `send_gso_supported`.

### Fixed
- Server connection crashed with `function_clause` when the listener
  was on `socket_backend => socket` because `inet:sockname/1` rejects
  `{'$socket', Ref}` handles. Branch on socket shape:
  `socket:sockname/1` for OTP socket handles, `inet:sockname/1` for
  `gen_udp` ports.
- UDP_SEGMENT `setsockopt` now uses `sizeof(int)` (32-bit native)
  instead of u16, which Linux rejected with `EINVAL`; GSO capability
  detection silently returned false and the GSO CT job was skipping.
  The cmsg path already used u16 correctly. (#67)
- GSO skipped for single-packet batches: UDP_SEGMENT with a
  sub-`gso_size` single-packet payload drops silently on
  ubuntu-24.04. `batch_count == 1` has no segmentation work; fall
  through to `flush_individual`. (#73)
- Listener no longer sets UDP_SEGMENT at socket level. A socket-wide
  UDP_SEGMENT forces segmentation on every outbound datagram,
  including short handshake packets that can't be segmented. GSO is
  now applied only via the per-message cmsg in `flush_gso`. (#73)
- GSO bypassed when a batch mixes packet sizes (padded 1200-byte
  Initial + ~400-byte Handshake). UDP_SEGMENT requires every segment
  except the last to be exactly `gso_size`, otherwise the client
  sees undecodable datagrams and stalls at
  `awaiting_encrypted_extensions`. `flush/1` checks uniformity and
  falls through to `flush_individual` when it fails. (#75)
- Listener self-send: `send_packet/6` was calling `quic_socket:send/4`
  and dropping the returned state, so version-negotiation / retry /
  stateless-reset packets were buffered then lost on the socket
  backend with `batching_enabled=true`. Switched to
  `send_immediate/4`.
- `send_queue_bytes` accounting leaked on ACK-coalesce dequeues and
  could eventually trip `?MAX_SEND_QUEUE_BYTES` on long-lived
  connections. Added `send_queue_count` as an explicit O(1)
  emptiness predicate so zero-byte FIN-only sends enqueued under
  pacing are no longer stranded.
- `examples/echo_server.erl`: `handle_connection/2` expects a DCID
  binary, not an info map; returns `{ok, HandlerPid}` so the listener
  transfers ownership; peer address fetched via `quic:peername/1`.
  (#65)
- `examples/qlog_example.erl`: added a `connection_handler` so the
  server echoes client data; waits for the client connection to
  terminate before returning so the qlog writer flushes. (#68)

## [1.0.2] - 2026-04-16

### Fixed
- h3: thread FIN through the peer uni stream-type dispatch so a
  STREAM frame carrying type-varint + payload + FIN surfaces as one
  `{stream_type_data, uni, _, _, true}` event to claimed-stream
  owners (#64)

## [1.0.1] - 2026-04-15

### Fixed
- h3: consult `stream_type_handler` on fresh peer-initiated bidi
  streams so extensions can claim them before default request
  handling (#62)
- docs: `rebar3 ex_doc` now runs clean (#63)

## [1.0.0] - 2026-04-15

First release with HTTP/3. Brings full client + server HTTP/3
(RFC 9114) with QPACK (RFC 9204), HTTP Datagrams (RFC 9297),
Server Push, Extensible Priorities, Extended CONNECT, and the
extension-stream hooks WebTransport needs. Also a critical
flow-control deadlock fix in the QUIC core, a BBR loopback
throughput fix, and the H3 server owner default change.

### HTTP/3 (`quic_h3`, new module)

#### Added
- HTTP/3 client and server (RFC 9114) with QPACK header compression
  (RFC 9204): request/response, body data, trailers, GOAWAY,
  cancellation, CLI tools (`bin/quic_h3c`, `bin/quic_h3d`)
- Server Push (RFC 9114 §4.6): `push/3`, `send_push_response/4`,
  `send_push_data/4`, `set_max_push_id/2`, `cancel_push/2`
- Extensible Priorities (RFC 9218): `priority` request option,
  PRIORITY_UPDATE frames, urgency / incremental hints
- Extended CONNECT (RFC 9220) for WebTransport-style upgrades
- HTTP Datagrams (RFC 9297): `send_datagram/3`,
  `h3_datagrams_enabled/1`, `max_datagram_size/2`, capsule framing
- Extension-stream hook: `stream_type_handler` option on
  `start_server/3` claims peer-initiated uni and bidi streams whose
  first varint matches a caller-supplied filter; claimed bytes are
  delivered as `{stream_type_data, ...}` owner messages instead of
  being parsed as HTTP/3 requests. Owner also receives
  `stream_type_open`, `stream_type_closed`, `stream_type_reset`,
  `stream_type_stop_sending` events
- Client-initiated extension streams: `quic_h3:open_bidi_stream/1,2`
  pre-claims a bidi stream with a signal-type varint (e.g.
  WebTransport's `0x41`) so inbound bytes route through the
  claimed-bidi path
- Per-connection owner override via `connection_handler` callback on
  `start_server/3` for hosting many sessions per listener
- Per-stream handler registration: `set_stream_handler/3,4`,
  `unset_stream_handler/2` to redirect body data to a worker pid
- Query API: `get_settings/1`, `get_peer_settings/1`,
  `get_quic_conn/1`
- Documentation: `docs/HTTP3.md` reference + benchmarks section
- E2E test infrastructure: `quic_h3_e2e_SUITE`, `quic_h3_h3spec_SUITE`,
  `quic_h3_owner_SUITE`; dedicated CI job
- Performance benchmark: `quic_h3_bench`

#### Changed
- Server connection owner now defaults to the listener gen_server
  (long-lived, trap_exit'ed) instead of the `start_server` caller
  pid; durable owners for datagram / stream-type events should be
  supplied via the per-connection `connection_handler` callback
- SETTINGS directionality validation tightened to RFC 9114

#### Fixed
- Server connections wedged with `connect_timeout` when the process
  that called `start_server/3` exited before a client arrived and
  either `h3_datagram_enabled` or `stream_type_handler` was set
- Discard unknown unidirectional stream payload (RFC 9114 §6.2
  unknown-stream-type rule) instead of erroring the connection
- Emit trailing empty DATA event when response carries FIN so owners
  always see `Fin = true` exactly once
- Strict PRIORITY_UPDATE frame parsing per RFC 9218
- DoS hardening on header / capsule / frame parsing
- Header / trailer / `:path` / `:status` symmetry between client and
  server validation
- GOAWAY drain enforcement: reject new requests after a GOAWAY is
  sent or received
- Server push lifecycle correctness (PUSH_PROMISE pairing, duplicate
  detection, MAX_PUSH_ID enforcement)
- Tighten RFC 9114 / 9204 compliance across multiple parsers
- `sync` option on `connect/3` resolves an E2E race where the client
  tried to send before SETTINGS exchange completed
- Improved frame error handling and header validation
- aioquic SETTINGS compatibility
- QPACK: encoder eviction guard prevents references to
  unacknowledged dynamic-table entries; rejects `Increment = 0`

### QUIC transport

#### Added
- Spin bit (RFC 9000 §17.4)
- Stateless reset support (RFC 9000 §10.3)
- Full NEW_TOKEN issuance and validation loop
- `RESET_STREAM_AT` transport parameter and frame plumbing
- `quic:set_congestion_control/2` runtime CC switch API
- `quic:get_peer_transport_params/1` introspection API

#### Changed
- BBR internal clock switched to microseconds; loopback transfers no
  longer pin to the InitialRtt fallback

#### Fixed
- Stream-level `MAX_STREAM_DATA` window stopped sliding once
  `recv_max_data` reached `fc_max_receive_window` (8 MB default).
  Past the cap, the auto-tune re-sent the same value forever and the
  sender stalled at 8 MB lifetime per stream. The window now slides
  past `recv_offset` like the connection-level window already does
- BBR loopback throughput regression: ms-precision clock collapsed
  delivery-rate intervals to 0/1 ms and clamped BDP to the 4-packet
  minimum, holding throughput at ~0.03 Mbps. Microsecond-precision
  internal clock restores expected behavior
- Send `MAX_STREAMS` as peer-initiated streams complete
  (RFC 9000 §4.6); previously peers could exhaust the stream-id space

### Distribution (`quic_dist`)

#### Added
- User-accessible streams API: `quic_dist:open_stream/1,2`, `send/3`,
  `close_stream/1`, `reset_stream/1,2`, `controlling_process/2`,
  `list_streams/0,1`, with acceptor pool and stream priorities
- Connection migration logging
- Distributed Erlang benchmarks + multi-node test scripts
- Per-iteration latency stats in throughput benchmark (min/p50/p99/max
  + timeout counts)

#### Changed
- Test runner logs each test's results as it returns rather than at
  the end, so a stalled middle test no longer hides the others

### Tests and infrastructure
- `quic_e2e_*_SUITE` and `quic_h3_e2e_SUITE` run against in-process
  servers; Docker no longer required for these jobs

## [0.11.0] - 2026-04-09

### Added
- Full QUIC connection migration support (RFC 9000 Section 9)
  - Server-side address change detection (NAT rebinding vs active migration)
  - Path validation with PATH_CHALLENGE/PATH_RESPONSE
  - CID rotation for path unlinkability
  - `disable_active_migration` transport parameter
- Application error code support for CONNECTION_CLOSE frames
- Client certificate support (`verify` server option)
- CUBIC congestion control (RFC 9438)
- BBR congestion control
- HyStart++ slow start (RFC 9406) for all CC algorithms
- UDP packet batching with GSO/GRO support
- Configurable UDP buffer sizing (recbuf/sndbuf options)
- QLOG tracing for debug visibility
- Pluggable congestion control behavior
- Stream deadlines for per-stream timeout control
- STOP_SENDING API (`quic:stop_sending/3`)
- `max_udp_payload_size` transport parameter
- Async send API and socket receive optimizations
- Throughput benchmarks (`quic_throughput_bench`, `quic_batch_bench`)
- QUIC-based Erlang distribution (`quic_dist`) for node communication over QUIC
- Distribution modules: `quic_dist`, `quic_dist_controller`, `quic_dist_sup`
- EPMD replacement module (`quic_epmd`) for QUIC-based node discovery
- Discovery backends: `quic_discovery_static` (static config), `quic_discovery_dns` (DNS SRV)
- Session ticket storage (`quic_dist_tickets`) for 0-RTT reconnection
- Stream prioritization for distribution: control stream (urgency 0), data streams (urgency 4-6)
- Backpressure mechanism for distribution congestion control
- Keep-alive PING frames for transport-level liveness (configurable via `keep_alive_interval`)
- `quic:get_stats/1` API for connection packet counts (used for liveness detection)
- `quic:send_ping/1` API for transport-level PING frames
- RTT-based flow control auto-tuning for improved throughput
- Packet pacing (RFC 9002 Section 7.7) to prevent bursts

### Changed
- ConnRef is now connection PID (simpler API)
- Improved ACK processing performance (O(n^2) to O(n) with gb_sets)
- Timer batching for reduced overhead
- Zero-copy packet processing optimizations
- Distribution liveness detection now uses QUIC packet counts instead of application ticks
- Improved congestion control with quic-go-inspired settings (larger initial cwnd)
- Flow control windows auto-tune based on RTT measurements

### Fixed
- Throughput regression in connection migration (wasteful binary allocation)
- CUBIC cwnd collapse issue
- BBR delivery rate interval causing cwnd collapse
- BBR initial pacing rate causing transfer hangs
- Pacing precision loss causing transfer stalls
- Various RFC compliance fixes for QUIC connection migration
- `net_tick_timeout` errors under heavy load by using QUIC-level activity as liveness proof
- Stream flow control `recv_max_data` using wrong limits
- Distribution controller backpressure data loss
- Congestion control protocol compliance issues
- Recovery exit when only non-ack-eliciting packets are ACKed
- Tick timeout issues in distribution controller
- Flow control blocking that caused deadlocks
- Message framing for large message transfers

### Removed
- NAT traversal support from `quic_dist` (use standard QUIC connection migration instead)

## [0.10.2] - 2026-02-21

### Fixed
- Deprecated `catch` expressions replaced with `try...catch...end`
- Undefined `dynamic()` type replaced with `term()` in type specs
- CI workflow consolidated with separate unit-tests, e2e, and interop jobs

## [0.10.1] - 2026-02-21

### Fixed
- ACK range encoding crash for out-of-order packets: when packets arrived out
  of order (e.g., 10, 5, 6), ACK ranges were not properly maintained in
  descending order or merged, causing negative Gap values that crashed
  `quic_varint:encode/1` with `badarg`

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
