# Agents

Instructions for AI coding agents working on erlang_quic. Read this file
before you change anything; it applies to every agent and every change.

## Project Overview

Pure Erlang QUIC implementation (RFC 9000/9001) with zero external dependencies. Requires Erlang/OTP 27 or later and rebar3.

## First principle: compliance, latest spec, safety

erlang_quic faces untrusted peers. Every change that touches how packets,
frames, transport parameters, TLS handshake messages, HTTP/3 frames or QPACK
field sections are read, parsed or written, or how a connection, stream, path
or key changes state, must pass three checks before it is called done,
committed or opened as a pull request:

1. **Compliance**: the behaviour matches the governing spec section, and a test
   shows the accept and the reject path. The test fails on main without the
   change.
2. **Latest specification**: you checked that the spec you cite is the current
   one (not obsoleted, no newer draft revision that changes the rule), and you
   read the section itself instead of quoting from memory.
3. **Safety**: the change does not open a known abuse class (amplification,
   resource exhaustion, flood, connection hijack) and every per-peer resource
   it touches stays bounded.

Use the [protocol-change-review](.agents/skills/protocol-change-review/SKILL.md)
skill to run them. When in doubt whether a change is protocol code, it is.

## Specification issues are bugs, not security issues

A report is a specification issue when the fix is to make erlang_quic do what
a spec it implements says (see [Specifications](#specifications)):

- input accepted, rejected or framed differently from the spec (packets,
  frames, transport parameters, version negotiation, TLS handshake messages,
  HTTP/3 frames and settings, QPACK, capsules, datagrams);
- a wrong error code, close or reset, or a state transition the spec does not
  allow (connection, stream, path, key update);
- loss detection, congestion control, path validation or migration that does
  not follow RFC 9002 and RFC 9000 Sections 8 and 9;
- a missing or wrong bound that the spec or an option defines (flow-control
  credit, stream and connection ID limits, the anti-amplification limit, ACK
  ranges, idle and handshake timeouts, `max_field_section_size`,
  `max_buffered_body`).

This holds even when the report calls it amplification, denial of service or
a remote crash. Treat it as a bug:

- fix it in a public pull request, with a public issue if one is needed;
- list it under **Fixed** in the CHANGELOG, in plain English, citing the spec
  section;
- do not open a GitHub Security Advisory, request a CVE, embargo the fix,
  give it a severity, or describe how to attack it;
- when it arrived as an advisory, close the advisory as not a vulnerability
  and link the pull request that fixes it.

Only a problem that is not a spec deviation goes through
[SECURITY.md](SECURITY.md): code execution; a peer accepted without the
authentication the configuration asks for (certificate chain, hostname or
client-certificate checks, PSK and session-ticket binding, Erlang
distribution node authentication); keys, secrets or one connection's data
reaching someone else; erlang_quic weakening TLS below what the
configuration allows. Peer authentication stays a security issue even where
a spec describes the check. If unsure, ask the maintainer before treating
anything as a security issue.

## Required Checks

Every change must be formatted and pass all checks before committing. This list
matches what CI gates on; see [CONTRIBUTING.md](CONTRIBUTING.md) for the rest of
the workflow.

```bash
rebar3 fmt                  # Auto-format (always run first)
rebar3 compile              # Must compile cleanly
rebar3 eunit                # Unit tests, including the docs drift check
rebar3 proper               # Property tests must pass
rebar3 fmt --check          # CI fails on unformatted code
rebar3 lint                 # Elvis linter must pass
rebar3 dialyzer             # Type checking must pass
rebar3 xref                 # Cross-reference analysis must pass
rebar3 ex_doc               # Docs must build
```

## Pull Requests

Work on one issue goes in one pull request. Give each change a reviewer has to
look at its own commit, with its tests, rather than opening a pull request per
change. Docs and CHANGELOG entries go in the same pull request.

- Every bug fix and feature has a test. Show it failing on main.
- Never relax a limit or a check to make a peer pass; exclude the legitimate
  case precisely.
- Descriptions state what was wrong, the fix in a few lines, and breaking
  changes. Reference issues with `Fixes #N`. No test plan, no file-by-file
  walkthrough.
- No `Co-Authored-By`, "Generated with" or similar trailers, in commits or
  pull requests.
- CHANGELOG: plain English, what was wrong and what it means for the user,
  the spec section when there is one. No implementation details, no attack
  narratives.
- Follow "Write for the person who reads it" in
  [CONTRIBUTING.md](CONTRIBUTING.md#write-for-the-person-who-reads-it): plain
  English, no inflated or pseudo-technical wording, and a person has read the
  change before it is opened.

## Specifications

The specs erlang_quic implements, at the version the code follows. Where a
newer one exists it is listed under [Pending updates](#pending-updates).
Last checked: 2026-11-08; the TLS table 2026-11-12.

### QUIC

| Spec | Scope in erlang_quic | Code |
|---|---|---|
| RFC 9000 QUIC transport | packets, frames, streams, flow control, connection IDs, migration, path validation, stateless reset, anti-amplification | `quic_connection`, `quic_packet`, `quic_frame`, `quic_listener` |
| RFC 9001 QUIC-TLS | packet protection, header protection, key update, AEAD limits | `quic_crypto`, `quic_aead`, `quic_keys` |
| RFC 9002 loss detection and congestion control | ACK handling, PTO, NewReno | `quic_loss`, `quic_ack`, `quic_cc_newreno` |
| RFC 8999 version-independent properties (updated by RFC 9368) | long and short header invariants, Version Negotiation | `quic_packet` |
| RFC 9368 compatible version negotiation, RFC 9369 QUIC v2 | `version_information`, v2 packets and keys | `quic_connection`, `quic_crypto` |
| RFC 9221 DATAGRAM | DATAGRAM frames, `max_datagram_frame_size` | `quic_connection` |
| RFC 8899 DPLPMTUD | PMTU probing | `quic_pmtu` |
| RFC 9438 CUBIC, RFC 9406 HyStart++ | congestion control | `quic_cc_cubic`, `quic_cc_newreno` |
| draft-ietf-ccwg-bbr (revision not recorded) BBRv3 | congestion control | `quic_cc_bbr` |
| draft-ietf-quic-reliable-stream-reset-07 | RESET_STREAM_AT, `reset_stream_at` transport parameter | `quic_connection` |
| draft-ietf-quic-load-balancers (revision not recorded) QUIC-LB | routable connection IDs | `quic_lb` |
| RFC 8305 Happy Eyeballs v2 | client address racing | `quic_happy` |

### TLS

| Spec | Scope |
|---|---|
| RFC 9846 TLS 1.3 | handshake, PSK and session tickets, 0-RTT, HelloRetryRequest |
| RFC 5869 HKDF | key schedule |
| RFC 6066 TLS extensions | SNI |
| RFC 7301 ALPN | protocol negotiation |
| RFC 9525 service identity | hostname checks on the server certificate |

### HTTP/3

| Spec | Scope | Code |
|---|---|---|
| RFC 9114 HTTP/3 | frames, streams, SETTINGS, GOAWAY, push | `quic_h3_connection`, `quic_h3_frame` |
| RFC 9204 QPACK | field compression, encoder and decoder streams | `quic_qpack` |
| RFC 9110 HTTP semantics | fields, status, Content-Length, trailers | `quic_h3_connection` |
| RFC 9297 HTTP datagrams and capsules | `h3_datagram_enabled`, capsules | `quic_h3_connection`, `quic_h3_capsule` |
| RFC 9218 extensible priorities | PRIORITY_UPDATE, `priority` field | `quic_h3_connection` |
| RFC 9220 extended CONNECT over HTTP/3 | `enable_connect_protocol`, `:protocol` | `quic_h3_connection` |
| draft-ietf-webtrans-http3-17 | the primitives WebTransport needs: SETTINGS_WT_ENABLED, WT_STREAM, claimed streams | `quic_h3_connection` |

Code comments call QUIC-LB "RFC 9312", which is the QUIC manageability
document; it is draft-ietf-quic-load-balancers. Erlang distribution over QUIC
(`quic_dist`) follows the OTP distribution protocol, which is documented in
the OTP sources rather than an RFC.

### Keeping the specifications current

A spec changes under the code when an RFC is obsoleted or updated, or a
draft gets a new revision. Check the list:

- before every release;
- when you change a module listed in it, for the specs that module follows;
- when a peer implementation or erlang-webtransport moves to a newer
  revision, since interop breaks first.

Check an RFC with
`curl -sL https://www.rfc-editor.org/rfc/rfcNNNN.json` (`obsoleted_by`,
`updated_by`) and its errata on https://www.rfc-editor.org/errata/rfcNNNN.
Check a draft's latest revision on
`https://datatracker.ietf.org/doc/draft-.../`. Then set "Last checked"
above.

When a newer version exists, it is its own piece of work, not a side change:

1. Add it under [Pending updates](#pending-updates) with what is known to
   differ.
2. Diff the sections the code relies on, old version against new, and list
   every change: codepoints (frame types, transport parameter and setting
   ids, error codes), MUST and SHOULD changes, removed features.
3. Decide per change: follow it now, or keep the old behaviour and say why
   (for example, peers still on the old draft codepoint; keep both, as
   `wt_enabled` and `wt_enabled_draft15` do for WebTransport).
4. Make the change in one pull request, one commit per item, each with a
   test, run through the [protocol-change-review](.agents/skills/protocol-change-review/SKILL.md)
   checks, and run the Interop Runner against peers on both revisions where
   they exist.
5. Update the citations in the code it touches, the row in the tables above
   and the "Last checked" date, and remove it from Pending updates. Add a
   CHANGELOG entry when behaviour or a codepoint changes, saying which
   version is now followed.

A new RFC number that only renumbers the same text still updates the
citations and the table, with no CHANGELOG entry.

### Pending updates

Known newer versions, checked 2026-11-08. Each needs the diff in step 2
before any code changes.

| Spec | Code follows | Latest | To check |
|---|---|---|---|
| Reliable stream reset | draft-ietf-quic-reliable-stream-reset-07 | -11 | frame type (`16#24`) and transport parameter id, Reliable Size and Final Size rules |
| QUIC-LB | revision not recorded | draft-ietf-quic-load-balancers-22 | CID formats, config rotation bits, encryption modes in `quic_lb`; fix the "RFC 9312" citation |
| BBR | revision not recorded | draft-ietf-ccwg-bbr-07 | state machine and gains in `quic_cc_bbr`; record the revision followed |

## Skills

Task guides for agents live in `.agents/skills/<name>/SKILL.md`; read the one
that matches the task before starting. `.claude/skills` links to the same
directories, so there is one copy.

- [protocol-change-review](.agents/skills/protocol-change-review/SKILL.md):
  the three checks above (compliance, latest spec, safety) for a change, a
  commit or a pull request.
- [rfc-compliance](.agents/skills/rfc-compliance/SKILL.md): check a change or
  pull request against RFC 9000, 9001, 9002 and the related specs.

## Build & Development Commands

```bash
rebar3 compile                                    # Build
rebar3 eunit                                      # Run all EUnit tests
rebar3 eunit --module=quic_varint_tests           # Run specific test module
rebar3 eunit --module=quic_varint_tests --test=encode_0_test  # Run single test
rebar3 proper                                     # Run PropEr property-based tests
rebar3 ct --suite=quic_e2e_SUITE                  # Run specific Common Test suite
docker/run-ct.sh quic_bulk_run_send_SUITE         # Run a Linux-only suite from macOS
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

**Connection Management:** `quic_connection.erl` (gen_statem state machine — the central module), `quic_stream.erl` (standalone per-stream state helper; the connection keeps its own `#stream_state{}` inline), `quic_server_registry.erl` (multi-server registry)

**Protocol:** `quic_packet.erl` (packet encode/decode), `quic_frame.erl` (frame encode/decode), `quic_varint.erl` (RFC 9000 §16 variable-length integers)

**Crypto:** `quic_crypto.erl` (key derivation, transcript hashing), `quic_tls.erl` (TLS 1.3 messages), `quic_keys.erl` (traffic keys), `quic_aead.erl` (AEAD encryption, header protection), `quic_hkdf.erl` (HKDF expansion)

**Flow Control & Loss:** `quic_flow.erl` (standalone connection-level accounting helper; the flow control that runs is inline in `quic_connection.erl`), `quic_cc.erl` (congestion control behaviour and dispatch; NewReno, CUBIC and BBR live in `quic_cc_newreno.erl`, `quic_cc_cubic.erl`, `quic_cc_bbr.erl`), `quic_loss.erl` (loss detection/recovery), `quic_ack.erl` (ACK processing)

**Other:** `quic_ticket.erl` (session tickets/PSK), `quic_lb.erl` (QUIC-LB RFC 9312)

### Supervision Tree

`quic_app` → `quic_sup` → `quic_server_sup` → `quic_listener_sup` → `quic_listener_sup_sup` → `quic_listener` (worker pool). `quic_listener_sup` is `rest_for_one` over `quic_listener_manager` (connection routing) then the pool supervisor. `quic_sup` also starts `quic_server_registry`, `quic_token_cache`, `quic_conn_sup`, `quic_happy_sup` and `quic_dist_sup`.

### Key Files

- `include/quic.hrl` — All protocol constants, frame types, and record definitions (`conn_state`, `quic_packet`, `stream_state`, `pn_space`, etc.)
- `docs/DESIGN.md` — Detailed architecture, state machine diagrams, packet processing flow
- `docs/features.md` — Feature matrix and full API reference

### Connection Model

Connections are `gen_statem` processes (`quic_connection.erl`) that progress through states: `idle` → `handshaking` → `connected` → `draining` → `closed`. The owner process receives messages like `{quic, ConnRef, {connected, Info}}`, `{quic, ConnRef, {stream_data, StreamId, Data, Fin}}`.

### Test Organization

- `test/quic_*_tests.erl` — EUnit tests (unit)
- `test/prop_quic_*.erl` — PropEr property-based tests (encoding roundtrips, reliability)
- `test/quic_*_SUITE.erl` — Common Test suites (E2E against aioquic/quic-go via Docker, interop runner)
- `quic_connection`, `quic_listener` and `quic_socket` compile with `export_all` under TEST, so unit tests call internals directly. Do not add `-ifdef(TEST)` exports; put `#state{}` builders and accessors in `test/quic_connection_test_support.erl`
- E2E tests require Docker containers (`docker/docker-compose.yml`)
- macOS defers loopback UDP by up to hundreds of milliseconds, so a test that runs there asserts what the sender did, not how fast the peer received it (see [CONTRIBUTING.md](CONTRIBUTING.md))

## Linting Notes

Elvis rules are configured in `elvis.config`, the only lint configuration.
`rebar3 lint` reads that file and ignores any `{elvis, ...}` entry in
`rebar.config` while it exists, so an exemption added to `rebar.config` has
no effect. Notable exceptions:
- `quic_connection` is excluded from `dont_repeat_yourself`
- Several modules (`quic_ack`, `quic_connection`, `quic_frame`, etc.) are excluded from `max_function_length`
- `quic`, `quic_connection`, `quic_crypto`, `quic_stream` and others are excluded from `no_god_modules`
- Atom naming regex: `^[a-z](_?[a-zA-Z0-9]+)*(_SUITE)?$`
