# HTTP/3 Compliance Matrix

Map each RFC 9114 and RFC 9204 MUST / SHOULD check this implementation
cares about to the test that covers it. Use this as the first stop
when adding features or reviewing PRs that touch `src/h3/` or
`src/qpack/` — an entry without a test is a gap, and a test without an
entry is noise.

**Status legend**

- `✓` covered by an in-tree test
- `⬜` gap: no test drives this path yet
- `n/a` feature not implemented in this codebase (out of scope)

All tests live under `test/`; module names in the table are bare
(drop the `.erl`).

## RFC 9114 — HTTP/3

### §4 Expressing HTTP Semantics

| Section | Requirement | Test |
|---|---|---|
| §4.1 | DATA before HEADERS on request stream → stream error | `quic_h3_compliance_tests:data_before_headers_returns_stream_reset_test` ✓ |
| §4.1 | DATA after complete → stream error | `quic_h3_compliance_tests:frame_after_complete_returns_reset_test` ✓ |
| §4.1.2 | Content-Length vs received body: overflow → `H3_MESSAGE_ERROR` | `quic_h3_compliance_tests:content_length_overflow_returns_reset_test` ✓ |
| §4.1.2 | Content-Length vs received body: underflow → `H3_MESSAGE_ERROR` | `quic_h3_compliance_tests:content_length_underflow_returns_reset_test` ✓ |
| §4.1.2 | Trailers duplicate Content-Length mismatch → reject | `quic_h3_compliance_tests:duplicate_content_length_mismatch_rejected_test` ✓ |
| RFC 9110 §8.6 | `content-length` value negative → reject | `quic_h3_compliance_tests:content_length_negative_rejected_test` ✓ |
| RFC 9110 §8.6 | `content-length` value non-numeric → reject | `quic_h3_compliance_tests:content_length_non_numeric_rejected_test` ✓ |
| §4.2 | Forbidden request field (`connection`, `keep-alive`, `upgrade`, `transfer-encoding`, `te` ≠ trailers) | `quic_h3_compliance_tests:connection_header_rejected_test`, `te_non_trailers_rejected_test` ✓ |
| §4.2 | Field name uppercase → reject | `quic_h3_compliance_tests:uppercase_header_name_rejected_test` ✓ |
| §4.2 | Invalid field value (CTL) → reject | `quic_h3_compliance_tests:invalid_field_value_ctl_rejected_test` ✓ |
| §4.2.2 | Field section size bounded by peer / local setting | `quic_h3_compliance_tests:outbound_field_section_size_limit_test`, `inbound_field_section_uses_local_setting_test` ✓ |
| §4.3 | Pseudo-header after regular header → `H3_MESSAGE_ERROR` | `quic_h3_compliance_tests:pseudo_header_after_regular_rejected_test` ✓ |
| §4.3 | Duplicate pseudo-header → reject | `quic_h3_compliance_tests:duplicate_method_pseudo_header_rejected_test`, `duplicate_path_pseudo_header_rejected_test`, `duplicate_status_pseudo_header_rejected_test` ✓ |
| §4.3.1 | Request missing `:method` → reject | `quic_h3_compliance_tests:request_missing_method_rejected_test` ✓ |
| §4.3.1 | Request with empty `:path` → reject | `quic_h3_compliance_tests:request_empty_path_rejected_test` ✓ |
| §4.3.1 / RFC 3986 §3.1 | `:scheme` MUST start with ALPHA → digit-first rejected | `quic_h3_compliance_tests:scheme_starts_with_digit_rejected_test` ✓ |
| §4.3.1 | Request missing `:scheme` / `:path` / `:authority` | `quic_h3_compliance_tests:authority_required_non_connect_test`, `neither_authority_nor_host_rejected_test` ✓ |
| §4.3.1 | Request with response pseudo-header (`:status`) → reject | `quic_h3_compliance_tests:request_with_status_pseudo_header_rejected_test` ✓ |
| §4.3.2 | Response with request pseudo-header → reject | `quic_h3_compliance_tests:response_with_request_pseudo_rejected_test` ✓ |
| §4.3.2 | Response `:status` out of 100..599 → reject | `quic_h3_compliance_tests:response_status_out_of_range_rejected_test` ✓ |
| §4.3.2 | Response missing `:status` → reject | `quic_h3_compliance_tests:response_missing_status_rejected_test` ✓ |
| §4.3.2 | Response `:status` non-numeric → reject | `quic_h3_compliance_tests:response_status_non_numeric_rejected_test` ✓ |
| §4.4 | CONNECT without peer-enabled → reject | `quic_h3_compliance_tests:extended_connect_rejected_when_disabled_test` ✓ |
| §4.4 | Plain CONNECT with `:scheme` → reject | `quic_h3_compliance_tests:plain_connect_with_scheme_rejected_test` ✓ |
| §4.4 | Plain CONNECT with `:path` → reject | `quic_h3_compliance_tests:plain_connect_with_path_rejected_test` ✓ |
| §4.4 / RFC 9220 | Extended CONNECT missing `:scheme` → reject | `quic_h3_compliance_tests:extended_connect_missing_scheme_rejected_test` ✓ |
| §4.4 / RFC 9220 | Extended CONNECT empty `:path` → reject | `quic_h3_compliance_tests:extended_connect_empty_path_rejected_test` ✓ |
| §4.6 | PUSH: MAX_PUSH_ID MUST NOT decrease | `quic_h3_compliance_tests:max_push_id_decrease_error_test` ✓ |

### §5 Connection Management

| Section | Requirement | Test |
|---|---|---|
| §5.2 | GOAWAY ID MUST NOT increase across frames | `quic_h3_compliance_tests:goaway_id_increase_error_test` ✓ |
| §5.2 | GOAWAY server-sent ID is a client-initiated bidi stream | `quic_h3_compliance_tests:goaway_client_receives_non_bidi_id_rejected_test` ✓ |
| §5.2 | GOAWAY client-sent ID is a push ID | `quic_h3_compliance_tests:goaway_server_receives_any_push_id_accepted_test` ✓ |
| §5.2 | GOAWAY blocks new requests above threshold | `quic_h3_compliance_tests:goaway_blocks_new_request_stream_test` ✓ |
| §7.2.3 | CANCEL_PUSH with push id > MAX_PUSH_ID → `H3_ID_ERROR` | `quic_h3_compliance_tests:cancel_push_above_max_push_id_is_id_error_test` ✓ |

### §6 Stream Handling

| Section | Requirement | Test |
|---|---|---|
| §6.2.1 | Only one control stream per direction → `H3_STREAM_CREATION_ERROR` | `quic_h3_compliance_tests:duplicate_control_stream_is_stream_creation_error_test` ✓ |
| §6.2.1 | Control stream closure → `H3_CLOSED_CRITICAL_STREAM` | `quic_h3_compliance_tests:critical_stream_closure_returns_error_test`, `is_critical_stream_*_test` ✓ |
| §6.2.1 | First control-stream frame MUST be SETTINGS | `quic_h3_compliance_tests:first_control_frame_not_settings_is_missing_settings_test` ✓ |
| §6.2.2 | Only one QPACK encoder stream per direction → `H3_STREAM_CREATION_ERROR` | `quic_h3_compliance_tests:duplicate_encoder_stream_is_stream_creation_error_test` ✓ |
| §6.2.3 | Only one QPACK decoder stream per direction → `H3_STREAM_CREATION_ERROR` | `quic_h3_compliance_tests:duplicate_decoder_stream_is_stream_creation_error_test` ✓ |
| §4.6 | Only server may initiate a push stream → `H3_STREAM_CREATION_ERROR` | `quic_h3_compliance_tests:push_stream_to_server_is_stream_creation_error_test` ✓ |
| §4.6 | Push stream before client sent MAX_PUSH_ID → `H3_ID_ERROR` | `quic_h3_compliance_tests:push_stream_without_max_push_id_is_id_error_test` ✓ |

### §7 HTTP Framing Layer

| Section | Requirement | Test |
|---|---|---|
| §7.1 | Oversized frame → `H3_EXCESSIVE_LOAD` | `quic_h3_compliance_tests:oversized_frame_rejected_test` ✓ |
| §7.2.1 | DATA on control stream → `H3_FRAME_UNEXPECTED` | `quic_h3_compliance_tests:data_on_control_stream_is_frame_unexpected_test` ✓ |
| §7.2.2 | HEADERS on control stream → `H3_FRAME_UNEXPECTED` | `quic_h3_compliance_tests:headers_on_control_stream_is_frame_unexpected_test` ✓ |
| §7.2.4 | Duplicate SETTINGS → `H3_FRAME_UNEXPECTED` | `quic_h3_compliance_tests:second_settings_frame_is_frame_unexpected_test` ✓ |
| §7.2.4 | Duplicate setting id inside one SETTINGS → `H3_SETTINGS_ERROR` | `quic_h3_compliance_tests:duplicate_setting_error_code_test` ✓ |
| §7.2.4 | Unknown setting identifier MUST be ignored | `quic_h3_compliance_tests:unknown_setting_id_ignored_test` ✓ |
| §7.2.4.1 | HTTP/2-only setting → `H3_SETTINGS_ERROR` | `quic_h3_compliance_tests:http2_setting_rejected_at_frame_level_test` ✓ |
| §7.2.5 | CANCEL_PUSH on request stream → `H3_FRAME_UNEXPECTED` | `quic_h3_compliance_tests:cancel_push_on_request_stream_is_frame_unexpected_test` ✓ |
| §7.2.5 | Server receiving PUSH_PROMISE → `H3_FRAME_UNEXPECTED` | `quic_h3_compliance_tests:push_promise_server_receives_error_test` ✓ |
| §7.2.7 | MAX_PUSH_ID from server → `H3_FRAME_UNEXPECTED` | `quic_h3_compliance_tests:max_push_id_from_server_error_test` ✓ |
| §7.2.8 | HTTP/2-reserved frame type (0x02/0x06/0x08/0x09) → `H3_FRAME_UNEXPECTED` | `quic_h3_frame_tests:decode_h2_reserved_frame_rejected_test_` ✓ |
| §9 | Reserved frame type (0x1f*N+0x21) accepted and ignored | `quic_h3_frame_tests:decode_reserved_frame_test`, `is_reserved_frame_type_test` ✓ |

### Error-code emission coverage

| Error code | Emitted? | Notes |
|---|---|---|
| `H3_NO_ERROR` | `n/a` — normal closure, never appears in error contexts |
| `H3_GENERAL_PROTOCOL_ERROR` | ✓ | duplicate push promise mismatch |
| `H3_INTERNAL_ERROR` | `n/a` — reserved for implementation faults |
| `H3_STREAM_CREATION_ERROR` | ✓ | duplicate unidirectional streams, wrong stream parity |
| `H3_CLOSED_CRITICAL_STREAM` | ✓ | control / encoder / decoder stream closed |
| `H3_FRAME_UNEXPECTED` | ✓ | DATA/HEADERS on control, CANCEL_PUSH on request, second SETTINGS, PUSH_PROMISE on server |
| `H3_FRAME_ERROR` | ✓ | malformed frame payloads |
| `H3_EXCESSIVE_LOAD` | ✓ | frame size > 1 MiB |
| `H3_ID_ERROR` | ✓ | GOAWAY id increase, MAX_PUSH_ID decrease |
| `H3_SETTINGS_ERROR` | ✓ | HTTP/2 setting id, duplicate setting id |
| `H3_MISSING_SETTINGS` | ✓ | first control frame not SETTINGS |
| `H3_REQUEST_REJECTED` | ✓ | handler-driven reset |
| `H3_REQUEST_CANCELLED` | ✓ | emitted by `quic_h3:cancel_stream/2` and by the server-side CANCEL_PUSH handler (`src/h3/quic_h3_connection.erl`); code value asserted in `quic_h3_tests` |
| `H3_REQUEST_INCOMPLETE` | ✓ | stream closed before FIN with a pending body |
| `H3_MESSAGE_ERROR` | ✓ | pseudo-header ordering, missing/prohibited pseudo, forbidden fields |
| `H3_CONNECT_ERROR` | `n/a` — CONNECT tunneling not shipped |
| `H3_VERSION_FALLBACK` | `n/a` — alt-protocol negotiation not shipped |

## RFC 9218 — HTTP/3 Extensible Priorities

HTTP/3 priorities are integrated end-to-end: the `priority` header and
the `PRIORITY_UPDATE` frame both land urgency / incremental on the
relevant H3 stream, and QUIC's send scheduler uses the urgency value
as a bucket index into an 8-bucket priority queue
(`src/quic_connection.erl` `pqueue_in/3` / `pqueue_out/2`).

| Section | Requirement | Test |
|---|---|---|
| §4.1 | Default urgency = 3 when no signal present | `quic_h3_compliance_tests:priority_defaults_when_no_header_test` ✓ |
| §5.1 | `priority` request header `u=N, i` parses into urgency / incremental | `quic_h3_compliance_tests:priority_header_parsed_into_stream_test` ✓ |
| §7.1 | PRIORITY_UPDATE for a request stream rewrites urgency / incremental | `quic_h3_compliance_tests:priority_update_request_stream_updates_state_test` ✓ |

## RFC 9297 — HTTP Datagrams

WebTransport (sibling repo github.com/benoitc/erlang-webtransport)
depends on these primitives.

| Section | Requirement | Test |
|---|---|---|
| §2.1 | `SETTINGS_H3_DATAGRAM` codepoint = 0x33 | `quic_h3_datagram_tests:settings_h3_datagram_constant_test` ✓ |
| §2.1 | SETTINGS carrying `h3_datagram=1` round-trips | `quic_h3_datagram_tests:settings_encode_decode_h3_datagram_test` ✓ |
| §2.1 | SETTINGS carrying `h3_datagram=0` round-trips | `quic_h3_datagram_tests:settings_decode_zero_is_disabled_test` ✓ |
| §2.1 | `SETTINGS_H3_DATAGRAM=1` without QUIC datagram support → `H3_SETTINGS_ERROR` | `quic_h3_datagram_tests:peer_h3_datagram_without_quic_datagram_is_settings_error_test` ✓ |
| §2.1 | Quarter-stream-id encoding (StreamId bsr 2) round-trips | `quic_h3_datagram_tests:qsid_roundtrip_test_`, `qsid_varint_sizes_test_` ✓ |

## RFC 9204 — QPACK

| Section | Requirement | Test |
|---|---|---|
| §3.1 | Invalid static-table index → `H3_QPACK_DECOMPRESSION_FAILED` | `quic_qpack_tests:invalid_static_index_rejected_test` ✓ |
| §4.3 | Encoder-stream Set Dynamic Table Capacity > peer max → `H3_QPACK_ENCODER_STREAM_ERROR` | `quic_qpack_tests:encoder_set_capacity_over_max_rejected_test` ✓ |
| §4.3 | `set_dynamic_capacity` API clamps to `max_allowed_capacity` | `quic_qpack_tests:set_dynamic_capacity_clamps_to_max_test` ✓ |
| §4.4 | Decoder-stream Section Acknowledgment encoding | `quic_qpack_tests:section_ack_encoding_test`, `section_ack_large_stream_id_test` ✓ |
| §4.4 | Decoder-stream Stream Cancellation encoding | `quic_qpack_tests:stream_cancel_encoding_test` ✓ |
| §4.4.3 | Decoder-stream Insert Count Increment = 0 → `H3_QPACK_DECODER_STREAM_ERROR` | `quic_qpack_tests:insert_count_increment_zero_rejected_test` ✓ |
| §5 | Huffman EOS / over-long padding → reject | `quic_qpack_tests:huffman_invalid_eos_rejected_test` ✓ |

## Out of scope / deferred

- **HTTP/3 priority (RFC 9218)**: partial parse exists; not a compliance
  target until we negotiate priorities end-to-end.
- **HTTP/3 datagrams (RFC 9297)**: SETTINGS-gated path exists; no
  datagram-specific compliance tests beyond the SETTINGS requirement
  check (`h3_datagram_enabled` → SETTINGS `H3_DATAGRAM=1`).
- **WebTransport over HTTP/3** (draft-15): out of scope for this
  matrix — validated via its own dedicated tests.
- **CONNECT**: not shipped; `H3_CONNECT_ERROR` unused.
- **Alt-protocol negotiation**: not shipped; `H3_VERSION_FALLBACK`
  unused.
