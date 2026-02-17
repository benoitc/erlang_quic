# Changelog

All notable changes to this project will be documented in this file.

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
