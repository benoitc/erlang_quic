# Module Map

Where the code lives and what to read first. The source is 66 modules and about 46,000 lines, and roughly a quarter of it is one module, so reading in file order does not work. Read this when you are new to the tree, or when you know what you want to change but not where it lives. [docs/DESIGN.md](DESIGN.md) covers how the protocol works; this page covers where it is.

## Read these seven first

In this order, they give you the whole path of a connection without opening the big module:

1. `src/quic.erl` (976 lines) is the public API and the owner-message protocol. Its module header lists every message an owner receives.
2. `src/quic_listener.erl` (1,411) accepts connections. Its header is the clearest writing in the tree on connection ownership and the handover race.
3. `src/quic_packet.erl` (405) and `src/quic_frame.erl` (443) are the wire format, with the header diagrams in the packet module.
4. `src/quic_varint.erl` (112) is the encoding everything else is built from.
5. `src/quic_crypto.erl` (671) is the key schedule, and `src/quic_aead.erl` packet protection.
6. `src/quic_cc.erl` (401) is the congestion control behaviour, with `quic_loss` and `quic_ack` beside it.
7. `src/quic_connection.erl` (12,676) is the state machine everything above meets in. Read it by section banner, not top to bottom.

## Layers

| Layer | Modules |
|-------|---------|
| Public API | `quic`, `quic_listener` |
| Connection | `quic_connection`, `quic_connection_state.hrl`, `quic_pqueue` (the send queue's urgency buckets, RFC 9218), `quic_reassembly` (out-of-order buffers), `quic_interval` (disjoint interval lists, used for reclaimed stream ids) |
| Protocol | `quic_packet`, `quic_frame`, `quic_varint` |
| Crypto | `quic_crypto`, `quic_tls`, `quic_tls_negotiation` (cipher, ALPN and group choices), `quic_keys`, `quic_aead`, `quic_aead_ctx`, `quic_hkdf`, `quic_crypto_nif`, `quic_cert`, `quic_keylog` |
| Recovery | `quic_cc` with `quic_cc_newreno`, `quic_cc_cubic`, `quic_cc_bbr`; `quic_loss`, `quic_ack` (the connection's ACK range and frame path, plus an `#ack_state{}` accumulator only tests drive) |
| Transport services | `quic_socket`, `quic_pmtu`, `quic_lb`, `quic_happy`, `quic_ticket`, `quic_token_cache`, `quic_address_token`, `quic_qlog` |
| Supervision | `quic_app`, `quic_sup`, `quic_server_sup`, `quic_server_registry`, `quic_conn_sup`, `quic_happy_sup`, `quic_listener_sup`, `quic_listener_sup_sup`, `quic_listener_manager` |
| HTTP/3 | `src/h3/`: `quic_h3`, `quic_h3_connection`, `quic_h3_frame`, `quic_h3_capsule`, plus the client and server escripts |
| QPACK | `src/qpack/`: `quic_qpack`, `quic_qpack_huffman`, `quic_qpack_prefix` |
| Distribution | `src/dist/`: `quic_dist`, `quic_dist_controller`, `quic_dist_dispatch`, `quic_dist_auth`, `quic_dist_tickets`, `quic_epmd`, `quic_discovery*` |
| Interop | `src/interop/`: the runner client and server escripts |

## What depends on what

Most called, so most expensive to change:

| Module | Lines | Called by | Calls |
|--------|------:|----------:|------:|
| `quic` | 976 | 8 | 6 |
| `quic_varint` | 112 | 8 | 0 |
| `quic_crypto` | 671 | 6 | 1 |
| `quic_listener` | 1,411 | 5 | 8 |
| `quic_connection` | 12,676 | 5 | 21 |
| `quic_cc` | 401 | 4 | 1 |
| `quic_h3` | 836 | 4 | 2 |

`quic_connection` calling 21 other modules and being called by 5 is the shape to keep in mind: it is the hub, and almost any protocol change lands in it.

## Modules no grep will lead you to

Seventeen modules have no caller anywhere in `src`. None is dead, and each is reached a different way:

| Module | How it is reached |
|--------|-------------------|
| `quic_cc_newreno`, `quic_cc_cubic`, `quic_cc_bbr` | `quic_cc` maps the `cc_algorithm` option to one of these modules internally and calls it through the `quic_cc` behaviour |
| `quic_log` | Passed as a logger `report_cb` fun |
| `quic_epmd` | Named in a VM argument, `-epmd_module quic_epmd` |
| `quic_h3_client`, `quic_h3_server`, `quic_interop_client`, `quic_interop_server` | escript entry points, built per rebar3 profile |
| `quic_app`, `quic_dist_sup`, `quic_dist_tickets`, `quic_listener_sup_sup` | Started by a supervisor as a child spec, by name |
| `quic_discovery_static`, `quic_discovery_dns` | Selected by dist configuration |
| `quic_flow`, `quic_stream` | Standalone helpers. The connection implements its own flow control and stream state inline |
| `quic_h3_capsule` | A primitive for extension libraries, used by `erlang_masque` |

## Reading quic_connection

The file carries section banners, and the module header lists them in order.
The ones worth knowing:

- API and gen_statem callbacks, then the five state functions: `idle`, `handshaking`, `connected`, `draining`, `closed`.
- TLS handshake, then PSK validation and the session ticket store, then the handshake's server flight. Its second half, the TLS message driver, sits inside the packet-processing region because that is where CRYPTO frames arrive.
- Packet send layer: frames and payloads become packets, at all three levels.
- Packet processing, the largest region, covering decrypt, parse and the batched receive path.
- Stream processing and reassembly; socket I/O; ACK emission and decimation; delivery to the owner.
- Send path, then the send queue and its urgency priority queue.
- Timers: retransmission, PTO, idle, keep-alive, pacing.
- Key update, migration, PMTU.

The two hot paths have their own walkthroughs: [SEND_PATH.md](SEND_PATH.md) and
[RECV_PATH.md](RECV_PATH.md).

`#state{}` lives in `src/quic_connection_state.hrl` and has 194 fields. When you change one, grep for the field name rather than reading the function you are in: most fields are touched in several regions.

## Where tests live

`test/` is flat: `quic_*_tests.erl` for EUnit, `prop_quic_*.erl` for properties, `quic_*_SUITE.erl` for Common Test. A subsystem's tests are named after it, so `quic_loss_time_threshold_tests.erl` is the place to learn loss detection by example.
