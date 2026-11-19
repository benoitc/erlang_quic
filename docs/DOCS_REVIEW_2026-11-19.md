# Documentation and maintainability review, 2026-11-19

Scope: `main` at `a827d9c` (PR #597 merged). This plan gates the release
that follows 3.1.3. It updates the review of 2026-11-17 (`c5375f6`); the
next review should update this file again instead of starting over.

## What it found, in a few lines

The reading path still works: README, GETTING_STARTED, GLOSSARY, DESIGN,
MODULE_MAP, then the area guides. The two pre-release items of the last
review are done. Since then 24 commits merged, with new public API and
several behaviour changes, and three pages did not follow them. Those are
the items marked **pre-release** below. The rest are the open items of the
last review, two new maintainability findings, and one broken script.

## Since the last review

Done:

- `docs/MODULE_MAP.md` numbers were refreshed (69 modules, about 57,000
  lines). Measured today: 69 modules, 57,379 lines, so it is still right.
  One number has moved: `quic_connection.erl` is listed at 17,825 and is
  17,911.
- `OTP-ISSUE-crypto_one_time_aead_init.md` is gone from the repository
  root.

Still open from the last review:

- Split `docs/HTTP3.md` into guide and reference. It grew from 1,379 to
  1,434 lines.
- A key lifecycle section in `docs/DESIGN.md`. The need grew: key updates
  now also have a spacing rule (#569).
- A section map at the top of `docs/QUIC_DIST.md` (788 lines).
- The first two questions for the maintainer (section 13).

Merged since `c5375f6`, by area:

- 0-RTT: discard window on the batched receive path, same ClientHello
  after a Retry, flow-control count, HelloRetryRequest as rejection.
- Streams: MAX_STREAM_DATA opens a peer stream; a stream's writes leave
  in order; an ACK rechecks only the waiting streams it names (#595).
- Keys: `key_update/1` refuses a second update within three PTOs.
- HTTP/3: malformed datagrams, CONNECT and Content-Length, pushes that
  wait for QPACK instructions, malformed pushes as stream errors, unsafe
  methods held out of 0-RTT (`early_data` request option), never-indexed
  fields (`qpack_never_indexed` option, three-element header form).
- Other: session ticket lifetime, GSO fallback, PMTU log level, interop
  client ticket handling.

## 1. Recommended structure

Unchanged. Orientation: `README.md`, `docs/GETTING_STARTED.md`,
`docs/GLOSSARY.md`. Architecture: `docs/DESIGN.md`, `docs/MODULE_MAP.md`,
`docs/RECV_PATH.md`, `docs/SEND_PATH.md`. Area guides: `CLIENT_GUIDE`,
`SERVER_GUIDE`, `HTTP3`, `QUIC_DIST`, `PSK`, `INTERNAL_NETWORKS`,
`QLOG_GUIDE`, `PERFORMANCE`, `features`, `h3_compliance`. Contributor:
`AGENTS.md`, `CONTRIBUTING.md`, `docs/DEVELOPER_GUIDE.md`. Do not add a
layer.

## 2. Main starting point

`README.md`, its document index, then `docs/GETTING_STARTED.md`. Keep it.

## 3 to 5. Per-document verdicts

Only the documents whose verdict changed or that need work are listed.
Every other document keeps the "keep" of the last review.

| Document | Verdict | Reason |
|---|---|---|
| `docs/features.md` (467) | **update, pre-release** | It is the API index, and it has no line for `qpack_never_indexed`, for the `{Name, Value, never_indexed}` header form, or for the `early_data` request option. `quic_connection:key_update/1` and its errors are not in it at all. |
| `docs/SEND_PATH.md` (80) | **update, pre-release** | It says a write "is sent now, or queued". Since #597 a write also queues behind its own stream's data. One paragraph, and a line on the waiting sets (`pending_fin_reclaim`, `pending_send_reset_at`) and when an ACK looks at them. |
| `docs/h3_compliance.md` (193) | **update, pre-release** | The table maps rules to tests. It has no rows for: blocked field sections on push streams and PUSH_PROMISE (RFC 9204 Section 2.1.2), a malformed push as a stream error (RFC 9114 Section 4.1.2), no Content-Length on a 2xx to CONNECT (RFC 9110 Section 8.6), unsafe methods out of 0-RTT (RFC 8470 Section 4), never-indexed literals (RFC 9204 Section 7.1.3). The tests exist. |
| `AGENTS.md` (284) | **update, pre-release** | "Last checked" says 2026-11-17. The list was checked again today (section 6b): nothing newer. Set the two dates. Done on this branch. |
| `docs/MODULE_MAP.md` (84) | update when convenient | `quic_connection.erl` 17,825 is now 17,911. It does not list `quic_h3_connection.erl` with its size (section 9). |
| `docs/HTTP3.md` (1,434) | split | As before. "Public API Reference" is lines 15 to 1,030. The new "Never-indexed fields" section sits inside the client API, although it applies to servers too. |
| `docs/DESIGN.md` (615) | add a section | "Key Update" is seven lines and has neither the disposal timeline nor the three-PTO spacing. |
| `docs/QUIC_DIST.md` (788) | keep, add a section map | As before. |

## 6. Concepts needing a dedicated explanation

- **Key lifecycle**, as in the last review, now with the spacing rule:
  what is held, what drops it, when the next update may start.
- **Stream send lifecycle.** Three things now decide when a stream's send
  side is done: writes leave in order, the FIN is acknowledged, and the
  stream waits until the rest of its data is. `docs/SEND_PATH.md` is the
  place; a dozen lines.

## 6b. Specification list (AGENTS.md, checked 2026-11-19)

Every RFC in the tables was read through `rfc-editor.org/rfc/rfcNNNN.json`
and every draft through the datatracker.

- No RFC is obsoleted. RFC 8999 is updated by RFC 9368, which the table
  says. RFC 6066 and RFC 7301 carry older registry updates and RFC 9846,
  which the table lists.
- Drafts are at the revisions the code follows: BBR -07, ACK frequency
  -14 (still expired, no newer revision), reliable stream reset -11,
  QUIC-LB -22, WebTransport over HTTP/3 -17.
- RFC 8470 was added to the HTTP/3 table with #594.
- No pending updates.

## 7. Navigation

No change needed beyond the MODULE_MAP numbers above.

## 8 to 10. Module size and complexity findings (measured)

- `src/quic_connection.erl`: 17,911 lines, about 1,650 clause heads, 31%
  of the tree. One responsibility, held together by section banners. No
  split recommended. The candidate boundary of the last review (key
  update and disposal) stands.
- `src/h3/quic_h3_connection.erl`: **6,175 lines, about 740 clause
  heads, 35 test-only exports.** The last review missed it when it said
  no other module exceeds 2,100 lines. It holds the client and server
  state machines, request and response processing, server push on both
  sides, extension streams, datagrams and capsules. Push alone accounts
  for about 450 lines that mention it. Primary problem: **module
  organisation**. Not for this release. The clearest future boundary is
  push (`handle_push_*`, `do_push*`, `*_push_*`), which has its own
  state fields and its own tests. Documentation first: MODULE_MAP should
  name the module's sections the way it does for `quic_connection`.
- **Test state built by position.** `test/quic_h3_push_tests.erl` and
  `test/quic_h3_compliance_tests.erl` each carry a `make_test_state/1`
  that builds the `#state{}` of `quic_h3_connection` as a tuple, field by
  field, with comments such as "blocked_streams is at position 28". Two
  copies, and every new state field must be added to both in the right
  place. Primary problem: **code complexity** in tests. Recommended: one
  builder in a support module, as `test/quic_connection_test_support.erl`
  does for the connection. Not for this release.
- `src/quic_connection.erl` compiles with two "variable 'StateName' is
  unused" warnings outside the test profile (lines near 2561 and 2595).
  They predate this cycle. Small, worth a cleanup commit.
- No other module exceeds 2,400 lines (`quic_dist_controller` 2,319,
  `quic_tls` 2,056).

## 11. Contributor workflows

Adequate, as before. One addition worth a paragraph in `CONTRIBUTING.md`:
how to run another project's tests against a local build (a `_checkouts`
link), since this cycle needed it for hackney and livery.

## 12. Diagrams

None needed. A small timeline for key disposal would help the DESIGN
section when it is written.

## 13. Questions for the maintainer

1. `docs/DEVELOPER_GUIDE.md` is the user's guide while `AGENTS.md` serves
   contributors. Rename to `USER_GUIDE.md`? (Open since the last review.)
2. Mirror the pyshark pin note of `interop/runner.Dockerfile` in
   `interop/README.md`? The runner's tshark crashed once in this cycle
   and a rerun passed. (Open since the last review.)
3. `scripts/run_docker_dist_bench.sh` prints an empty results table: its
   `sed` expressions expect each `throughput_result` on one line and the
   nodes now log it over several. Fix the script, or drop the table and
   print the raw results?
4. Should `quic_connection:key_update/1` be a documented public function
   (it is not reachable through `quic`), or stay internal and out of
   `docs/features.md`?
5. hackney and livery are locked to `quic 3.1.0`. Their tests pass
   against current `main`. Is a note for their maintainers wanted in the
   release notes about the two caller-visible changes (unsafe methods
   wait for the handshake on resumed connections; a malformed push
   reports `push_cancelled` and no longer closes the connection)?

## 14. Implementation order

1. **Pre-release, one docs-only PR:** `docs/features.md`,
   `docs/SEND_PATH.md`, `docs/h3_compliance.md`, the `AGENTS.md` dates,
   the MODULE_MAP number.
2. The key lifecycle section in `docs/DESIGN.md`.
3. The `docs/HTTP3.md` split.
4. The shared HTTP/3 test state builder, then the two unused-variable
   warnings.
5. The `docs/QUIC_DIST.md` section map.
6. The answers to section 13.

## Release gate status

The maintainer asked for the documentation to be complete before the
release. Done on this branch, with no source change:

- Item 1 of section 14: `docs/features.md`, `docs/SEND_PATH.md`,
  `docs/h3_compliance.md`, the `AGENTS.md` dates, the MODULE_MAP number.
- Item 2: the key lifecycle section in `docs/DESIGN.md`, with the 0-RTT
  notes on HelloRetryRequest and Retry.
- A "Reading quic_h3_connection" section in `docs/MODULE_MAP.md`.
- `docs/QUIC_DIST.md` said tickets live seven days; it is 24 hours.
- `quic_connection:key_update/1` is now in `docs/features.md` with its
  errors, which answers question 4 unless the maintainer wants it
  internal.

Still open after this branch: the `docs/HTTP3.md` split, the shared
HTTP/3 test state builder, the two compiler warnings, the
`docs/QUIC_DIST.md` section map, and questions 1, 2, 3 and 5.
