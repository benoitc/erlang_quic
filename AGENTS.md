# Agents

Instructions for AI coding agents working on this project.

## Project Overview

Pure Erlang QUIC implementation (RFC 9000/9001) with zero external dependencies. Requires Erlang/OTP 26.0+ and rebar3.

## Required Checks

Every change must be formatted and pass all checks before committing:

```bash
rebar3 fmt                  # Auto-format (always run first)
rebar3 compile              # Must compile cleanly
rebar3 eunit                # Unit tests must pass
rebar3 lint                 # Elvis linter must pass
rebar3 dialyzer             # Type checking must pass
rebar3 xref                 # Cross-reference analysis must pass
```

## Build & Development Commands

```bash
rebar3 compile                                    # Build
rebar3 eunit                                      # Run all EUnit tests
rebar3 eunit --module=quic_varint_tests           # Run specific test module
rebar3 eunit --module=quic_varint_tests --test=encode_0_test  # Run single test
rebar3 proper                                     # Run PropEr property-based tests
rebar3 ct --suite=quic_e2e_SUITE                  # Run specific Common Test suite
rebar3 lint                                       # Elvis linter
rebar3 fmt --check                                # Check formatting (erlfmt)
rebar3 fmt                                        # Auto-format code
rebar3 dialyzer                                   # Type checking
rebar3 xref                                       # Cross-reference analysis
rebar3 ex_doc                                     # Generate docs
```

## Architecture

### Module Layers

**Public API:** `quic.erl` (main client/server API), `quic_listener.erl` (server listener)

**Connection Management:** `quic_connection.erl` (gen_statem state machine — the central module), `quic_stream.erl` (per-stream state), `quic_server_registry.erl` (multi-server registry)

**Protocol:** `quic_packet.erl` (packet encode/decode), `quic_frame.erl` (frame encode/decode), `quic_varint.erl` (RFC 9000 §16 variable-length integers)

**Crypto:** `quic_crypto.erl` (key derivation, transcript hashing), `quic_tls.erl` (TLS 1.3 messages), `quic_keys.erl` (traffic keys), `quic_aead.erl` (AEAD encryption, header protection), `quic_hkdf.erl` (HKDF expansion)

**Flow Control & Loss:** `quic_flow.erl` (connection/stream flow control), `quic_cc.erl` (NewReno congestion control), `quic_loss.erl` (loss detection/recovery), `quic_ack.erl` (ACK processing)

**Other:** `quic_ticket.erl` (session tickets/PSK), `quic_lb.erl` (QUIC-LB RFC 9312)

### Supervision Tree

`quic_app` → `quic_sup` → `quic_server_sup` → `quic_listener_sup_sup` → `quic_listener_sup` (pool). `quic_listener_manager` manages connection routing.

### Key Files

- `include/quic.hrl` — All protocol constants, frame types, and record definitions (`conn_state`, `quic_packet`, `stream_state`, `pn_space`, etc.)
- `docs/DESIGN.md` — Detailed architecture, state machine diagrams, packet processing flow
- `docs/features.md` — Feature matrix and full API reference

### Connection Model

Connections are `gen_statem` processes (`quic_connection.erl`) that progress through states: `handshaking` → `connected` → `closing` → `draining`. The owner process receives messages like `{quic, ConnRef, {connected, Info}}`, `{quic, ConnRef, {stream_data, StreamId, Data, Fin}}`.

### Test Organization

- `test/quic_*_tests.erl` — EUnit tests (unit)
- `test/prop_quic_*.erl` — PropEr property-based tests (encoding roundtrips, reliability)
- `test/quic_*_SUITE.erl` — Common Test suites (E2E against aioquic/quic-go via Docker, interop runner)
- E2E tests require Docker containers (`docker/docker-compose.yml`)

## Linting Notes

Elvis rules are configured in `rebar.config`. Notable exceptions:
- `quic_connection` is excluded from `dont_repeat_yourself`
- Several modules (`quic_ack`, `quic_connection`, `quic_frame`, etc.) are excluded from `max_function_length`
- `quic`, `quic_connection`, `quic_crypto`, `quic_stream` are excluded from `no_god_modules`
- Atom naming regex: `^[a-z](_?[a-zA-Z0-9]+)*(_SUITE)?$`

