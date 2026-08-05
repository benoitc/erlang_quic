# Refactoring exploration

Findings from a read-only sweep of `src/` for: modules over 2K lines and how to
split them, duplicate code that can be shared, and dead code. This is analysis
only. Nothing here has been applied. Each item is independently shippable as one
commit.

## Summary

- Three modules exceed 2K lines: `quic_connection.erl` (11,030),
  `quic_h3_connection.erl` (4,149), `quic_dist_controller.erl` (2,069).
  `quic_tls.erl` (1,846) is borderline.
- The biggest readability wins are in H3 and the dist controller, which already
  have a clean seam (helpers return `{ok, State}`, the state callbacks wrap
  transitions). `quic_connection` is hard: most of its bulk is send-path
  orchestration that cannot leave without a larger architectural change.
- The clearest duplication is the three congestion-control modules, written by
  copy-paste (pacing, persistent-congestion, HyStart++).
- Dead code is limited: 8 unused exported functions and one stale `nowarn`
  annotation. No unused locals, unreachable clauses, or commented-out blocks.

## 1. Modules over 2K lines

All three are `gen_statem`s threading a large `#state{}` record. The extraction
strategy is the same: move cohesive helper groups into sibling function-modules
that take and return `#state{}` (or a field subset), and keep every
`{keep_state, ...}` / `{next_state, ...}` decision in the callbacks.
`quic_dist_dispatch.erl` is the existing precedent for this pattern.

### 1a. quic_connection.erl (11,030 lines)

#### Why it is this large

It is not bloat. One module implements roughly 13 RFC subsystems that elsewhere
would each be a module, and it is one `gen_statem` where nearly every function
threads `#state{}` and most paths build and send packets.

Structural metrics:

- `#state{}` record: 406 lines, 164 fields (lines 244-649).
- 722 function clauses, 83 exports, 117 state-callback clauses,
  35 `process_frame/3` clauses, 60 `send_*` clauses.
- It is 27% of all `src/` code (11K of 41K across 59 modules).

Where the lines go (grouped by real concern; the in-file section dividers are
coarse and lump several concerns):

| Concern | approx lines |
| --- | --- |
| Packet / frame decode and dispatch (`process_frame`, decrypt, per-level routing) | 2,370 |
| Send path: send queue, flow control, framing, priority queue, socket batch/flush | 2,300 |
| TLS 1.3 handshake (flight building) | 1,124 |
| Migration + path validation + address-change detection | 1,272 |
| gen_statem callbacks + state functions + common-event handling | 1,484 |
| `#state{}` record + exports + module doc | 651 |
| Stream processing | 441 |
| API 278, test helpers 252, PMTU 232, key update 191, timers 257 | 1,210 |

The two biggest chunks (packet dispatch and the send path) mutate `#state` and
build packets, so they cannot move without dragging the record and the socket
with them. That is why the safe extractions barely change the size.

#### Feasible extractions

| New module | Moves (lines) | approx lines | #state coupling | Risk |
| --- | --- | --- | --- | --- |
| `quic_stream_ids` | reclaimed-id interval algebra `interval_add/member/merge_next` + 3 wrappers (7066-7123) | 55 | 0 (pass the two `reclaimed_ranges_*` maps) | lowest |
| `quic_key_update` | RFC 9001 6 (9084-9272); operates on `#key_update_state{}` already in quic.hrl | 185 | 2 (`key_state`, `app_keys`) | low |
| `quic_frame_class` | `is_probing_frame/1`, `contains_non_probing_frame/1` (3544-3561) | 20 | 0 (pure) | lowest |
| `quic_connection_test_helpers` | all `test_*` and the `-ifdef(TEST)` export block | 252 | record access | medium (needs `#state{}` lifted to a header first) |
| `quic_pmtu_driver` (optional) | PMTU probe driving (10547-10778) | 232 | ~8 fields + a send callback | medium-high |

Enabling step for the test-helper split and others: lift the `#state{}` record
(244-649) into a private `include/quic_connection_state.hrl`.

Must stay: gen_statem callbacks, the send path, TLS handshake orchestration,
packet-processing dispatch, connection migration, retransmission, timers.

If `quic_connection` needs to be meaningfully smaller, the only real lever is
extracting a `quic_send` engine (send queue + flow control + framing + priority
queue + socket batch/flush, about 2,300 lines, the second-biggest concern). That
is the hot path and threads roughly 20 `#state` fields, so it is a deliberate
architectural project, not a quick split.

In-module cleanups found:

- `initiate_key_update` (9116-9139) and `handle_peer_key_update` (9185-9207)
  contain a verbatim copy of the next-phase key-derivation block. Fold one
  `derive_next_phase_keys/1` helper out, naturally part of the `quic_key_update`
  move.
- Line 42 `nowarn_unused_function` still lists `send_handshake_ack/1`, but it is
  called at line 6523. Drop it from the list (the function is live).
  `contains_non_probing_frame/1` in the same list is genuinely production-dead
  (only a test uses it); move it with the test split.

### 1b. quic_h3_connection.erl (4,149 lines)

Best return on effort. Push (server and client, RFC 9114 4.6) is about 1,200
lines and largely self-contained: 9 of roughly 50 `#state` fields are push-only.
Internal helpers already return plain tuples, so the seam is clean.

| New module | Moves (lines) | approx lines | Risk |
| --- | --- | --- | --- |
| `quic_h3_stream_handler` | per-stream handler registry (3423-3539) | 115 | lowest |
| `quic_h3_headers` | header validation/decode wall (2523-3060); parameterize 3 `#state` reads to drop the record dependency | 520 | low |
| `quic_h3_push` | all push RX/TX (1647-2143, 2382-2522, 3540-3823) | 1,200 | medium (do after headers) |
| `quic_h3_critical` (optional) | QPACK / critical-stream setup | 230 | low |

Net: core drops from about 4,150 to about 2,000 lines.

Must stay: the 6 state callbacks, stream classification/routing demux
(1033-1542), request RX/TX hot path and GOAWAY, connection-error and transition
control. Pick one dependency direction (push and headers depend on shared TX and
header helpers exported from the core or `quic_h3_critical`, never the reverse)
to avoid a module cycle.

In-module cleanups found:

- The QPACK-encode then instructions then HEADERS sequence is repeated verbatim
  4 times (3219, 3281, 3375, 3620). Extract `encode_header_block/3`.
- `open_critical_streams/1` (971-999) has three near-identical open-and-propagate
  arms; collapse to a fold over `[control, qpack_encoder, qpack_decoder]`.
- Test-only exports (`test_discarded_uni_streams/1`, `test_stream/2`,
  `test_push_stream/2`, plus the `-ifdef(TEST)` block) live in the production
  module; relocate per convention.

### 1c. quic_dist_controller.erl (2,069 lines)

The Input Handler already runs as its own process and is completely
`#state{}`-free, the cleanest extraction in the codebase.

| New module | Moves (lines) | approx lines | Risk |
| --- | --- | --- | --- |
| `quic_dist_input_handler` | input handler loop + delivery (1337-1502), already a standalone process | 165 | lowest |
| `quic_dist_recv` | receive/reassembly (1504-1671) | 165 | low |
| `quic_dist_send` | tick/backpressure/send-queue (1026-1335) | 310 | medium (hot path) |
| `quic_dist_user_stream` | user-stream API (1672-end) | 400 | medium-high (needs a transition to `{State, Replies}` refactor first) |

Net: controller drops from about 2,070 to about 900 lines. Like H3, the
`#state{}` record needs a shared header (`quic_dist.hrl` already holds
`#user_stream{}`).

Must stay: `init`/`terminate`/`code_change`/`callback_mode`, the three state
callbacks, and `handle_common_event/3` dispatch; stream setup (handshake
sequencing and input-handler wiring); tick-timer ownership.

In-module cleanups found:

- `do_send_tick_frame/1` duplicates its four-arm error handling between the
  control-stream clause (1069-1082) and the data-stream fallback (1086-1096).
  Collapse via a shared `handle_tick_send_result/2`.
- The three `-ifdef(TEST)` exports (line 98) all belong to the input handler and
  travel with that module.

### Before / after sizes

| Module | Now | Core after | New sibling modules (approx lines) |
| --- | ---: | ---: | --- |
| quic_connection.erl | 11,030 | ~10,300 | quic_stream_ids (55), quic_key_update (185), quic_frame_class (20), quic_connection_test_helpers (252) [+ quic_pmtu_driver 230] |
| quic_h3_connection.erl | 4,149 | ~2,000 | quic_h3_push (1,200), quic_h3_headers (520), quic_h3_stream_handler (115) [+ quic_h3_critical 230] |
| quic_dist_controller.erl | 2,069 | ~900 | quic_dist_input_handler (165), quic_dist_recv (165), quic_dist_send (310), quic_dist_user_stream (400) |

## 2. Duplicate code

The three congestion-control modules are the largest source; they were written
by copy-paste.

1. Token-bucket pacing (`pacing_allows`, `get_pacing_tokens`, `pacing_delay`,
   `send_check`, `refill_tokens_at`) is byte-identical across
   `quic_cc_newreno.erl:914-1034`, `quic_cc_cubic.erl:842-948`,
   `quic_cc_bbr.erl:567-703` (about 120 lines x3, hot path). Move to a new
   `quic_cc_pacing` operating on a `{Tokens, MaxBurst, Rate, LastUpdate}` tuple.
   Note bbr's `refill_tokens_at` divides by 1_000_000 versus 1_000 in the other
   two; reconcile the rate units.
2. `detect_persistent_congestion/3` is identical in all three and its state arg
   is unused. Move to `quic_cc` as `/2`. Lowest effort, no record coupling.
3. HyStart++ (`hystart_on_ack`, `update_hystart_rtt`, plus about 7 fields) is
   identical in newreno and cubic (about 70 lines x2 of drift-prone logic). Move
   to `quic_cc_hystart`.
4. Trivial CC accessors (`cwnd`, `ssthresh`, `bytes_in_flight`, `can_send`,
   `can_send_control`, etc.) have identical bodies, blocked only by per-algorithm
   records. Tackle alongside 1 and 3 via a shared CC sub-record.

Outside CC:

5. `get_opt/3` (map-or-proplist accessor) is duplicated in `quic_dist.erl:564`,
   `quic_dist_controller.erl:362`, `quic_discovery_dns.erl:119`,
   `quic_discovery_static.erl:168`. One shared helper. Low effort.
6. `cancel_timer(undefined)` safe-cancel is duplicated in `quic_qlog.erl:598`,
   `quic_connection.erl:8867`, `quic_pmtu.erl:703`, plus about 6 inline `case`
   variants. Move to a small `quic_util:cancel_timer/1` and fold the inline sites
   in.
7. Long-header CID/packet-type bit parsing is reimplemented inline in
   `quic_connection.erl:3819` and `quic_listener.erl:683` instead of reusing
   `quic_packet`. Export `quic_packet:peek_long_header/1`. Lower confidence: the
   sites have slightly different needs (the listener does an error-tolerant
   routing peek), so verify before merging.

Investigated and ruled out as not duplication: the QPACK prefixed-int codec
(`quic_qpack.erl`) is RFC 9204 prefixed integers, a different encoding from QUIC
varint; `quic_qpack_prefix.erl` holds RIC/Base reconstruction only.

## 3. Dead code

Verified with a clean `rebar3 compile` (zero unused-function or unused-variable
warnings), `xref exports_not_used` over src plus the compiled test beams, then
per-candidate caller checks (module-qualified calls, internal/recursive calls,
`apply`/MFA, behaviour dispatch).

### Removable exported functions (high confidence)

| File | Symbol | Note |
| --- | --- | --- |
| quic_aead.erl | `unprotect_short_packet/7` | 0 callers |
| quic_socket.erl | `open_server_send/2` | 0 callers |
| quic_socket.erl | `get_fd/1` | 0 callers (unrelated to `quic:get_fd/1`) |
| quic_lb.erl | `validate_config/1` | 0 callers |
| quic_pmtu.erl | `set_probe_timer/2` | 0 callers |
| quic_pmtu.erl | `set_raise_timer/2` | 0 callers |
| quic_connection.erl | `close_stream/3` | 0 callers; not re-exported by quic.erl |
| quic_tls.erl | `verify_finished/3` | callers use `verify_finished/4` |

### Stale annotation

`quic_connection.erl:42` lists `send_handshake_ack/1` in `nowarn_unused_function`,
but it is called at line 6523. Drop it. `contains_non_probing_frame/1` in the
same list is production-dead (only a test uses it).

### Test-only exports in production modules

Against the convention that test-only exports belong in a separate module.
Live (used by tests) but mislocated, in: `quic_connection.erl`,
`quic_h3_connection.erl`, `quic_dist_controller.erl:97`, `quic_listener.erl:61`.

### Clean

No unused local functions, no unreachable clauses, no commented-out code blocks.

Ruled out as live (not dead): all `quic_cc_*` exports (quic_cc behaviour
callbacks dispatched via `Mod:Fun`), `quic_discovery_*` callbacks, the dist/epmd
VM entry points and gen_statem state callbacks, the public API modules
(`quic.erl`, `quic_h3.erl`, `quic_dist.erl`), and several over-exported helpers
that are called internally or via a lower-arity wrapper.

## Suggested sequencing

Lowest risk to highest value:

1. Quick cleanups, no structural risk: remove the 8 dead exports; fix the stale
   `send_handshake_ack` nowarn; CC `detect_persistent_congestion` dedup (2); the
   `get_opt` and `cancel_timer` shared helpers (5, 6).
2. CC consolidation: `quic_cc_pacing` + `quic_cc_hystart` (1, 3). Biggest dup
   payoff, contained to three sibling modules.
3. H3 split: `quic_h3_stream_handler`, then `quic_h3_headers`, then
   `quic_h3_push`.
4. Dist controller split: `quic_dist_input_handler`, then `recv`, then `send`,
   then `user_stream`.
5. quic_connection: the pure `quic_stream_ids` and `quic_key_update` first (fold
   the key-derivation dedup in); lift `#state{}` to a header, then move the test
   helpers. Leave the send-path and TLS bulk alone unless a `quic_send` engine
   extraction is taken on as its own project.
