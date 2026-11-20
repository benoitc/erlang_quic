# Documentation and maintainability review, 2026-11-20

Scope: `main` at `911c39b` (PR #601 merged). This plan gates the release
that follows 3.2.0. It updates the review of 2026-11-19 (`a827d9c`); the
next review should update this file again instead of starting over.

## What it found, in a few lines

The reading path still works. Since 3.2.0, 14 commits merged: four
fixes that change what callers see, and no new feature. Three pages do
not follow them yet, and the API index has never listed the owner
calls whose result changed. Those are the items marked **pre-release**.
The fixes of this cycle were all races in how a connection changes
owner, and no page explains that hand-off; that is the one new concept
worth a section. `quic_h3.erl` is nine lines under the lint limit.

## Since the last review

Done:

- The two "variable 'StateName' is unused" warnings are gone (#599).
- Every item the last review marked pre-release, plus the key lifecycle
  section in `docs/DESIGN.md` and the "Reading quic_h3_connection"
  section in `docs/MODULE_MAP.md`.

Still open from the last review:

- Split `docs/HTTP3.md` into guide and reference. 1,434 lines then,
  1,449 now.
- One shared builder for the `quic_h3_connection` test state. Still two
  copies (`test/quic_h3_compliance_tests.erl`,
  `test/quic_h3_push_tests.erl`), and this cycle added tests that use
  one of them.
- A section map at the top of `docs/QUIC_DIST.md` (788 lines).
- Questions 1, 2, 3 and 5 (section 13).

Merged since 3.2.0, by area:

- HTTP/3: `push_promise` and `push_stream` events keep never-indexed
  marks (#600). `quic_h3:connect/3` returns the server's close reason
  when the server closes right after the handshake, instead of crashing
  the caller or waiting for `connect_timeout` (#601).
- Ownership: `quic:set_owner_sync/2` on a closing connection returns
  `{error, closed}` instead of `{error, {invalid_state, draining}}`.
  Happy Eyeballs ends the race with the winner's close reason. The
  server dist controller no longer swaps owner a second time (#601).
- TLS: a refused handshake sends one CONNECTION_CLOSE and stops reading
  the flight after its alert (#602).
- `AGENTS.md` lists `draft-ietf-happy-happyeyeballs-v3-05` under
  Pending updates (#601).

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
| `docs/features.md` (484) | **update, pre-release** | The API index has no line for `quic:set_owner/2` or `quic:set_owner_sync/2`, and the result of `set_owner_sync/2` changed in this release: `{error, closed}` once the connection is closing or gone, with the reason in the `{closed, Reason}` the owner already got. |
| `docs/CLIENT_GUIDE.md` (695) | **update, pre-release** | "IPv6 and Happy Eyeballs" says `connect/4` blocks "until the first attempt connects (or all fail / time out)". A winner the server closes right after the handshake now ends the race with `{error, Reason}`, the server's reason, and the other attempts are not waited for. Two sentences. |
| `docs/DEVELOPER_GUIDE.md` (433) | **update, pre-release** | The "Server with Connection Handler" example has the spawned process call `quic:set_owner(Conn, self())` in `init/1`. The listener already makes the returned pid the owner before the first packet (`quic_listener` module doc), so the call is redundant and teaches the opposite of that doc. Drop it. |
| `docs/MODULE_MAP.md` (98) | **update, pre-release** | Six sizes are stale: `quic` 1,188 → 1,190, `quic_listener` 1,712 → 1,718, `quic_frame` 443 → 549, `quic_cc` 401 → 459, `quic_connection` 17,911 → 17,922, `quic_h3_connection` 6,175 → 6,250. `quic_frame` and `quic_cc` were already stale at the last review, which missed them. "Reading quic_h3_connection" should say that `take_over/2` runs in the caller's process, not in the HTTP/3 process: it reads the caller's mailbox. |
| `AGENTS.md` (287) | **update, pre-release** | Set "Last checked" to 2026-11-20 (section 6b). |
| `docs/DESIGN.md` (653) | add a section | Connection ownership (section 6). Recommended before the release, since this release changes what a hand-off returns; it can wait. |
| `docs/HTTP3.md` (1,449) | split | As before. |
| `docs/QUIC_DIST.md` (788) | keep, add a section map | As before. |

## 6. Concepts needing a dedicated explanation

- **Connection ownership and hand-off.** The bugs of this cycle were all
  in one place: a connection changing owner while the peer closes it.
  Four code paths move ownership (`quic_h3:connect/3` through
  `quic_h3_connection:take_over/2`, the Happy Eyeballs coordinator in
  `quic_happy`, the listener's `connection_handler`, the dist client in
  `quic_dist_controller:init/1`), and each relies on the same two facts
  that no page states: a connection tells its owner `{closed, Reason}`
  before it answers any later call, so the reason is already in the old
  owner's mailbox when `set_owner_sync/2` fails; and a closing connection
  refuses a new owner with `{error, closed}`. A dozen lines in
  `docs/DESIGN.md`: who owns a connection at each stage, how ownership
  moves, what a hand-off returns when the connection has closed, and
  where each path lives. Read before changing any of the four.

## 6b. Specification list (AGENTS.md, checked 2026-11-20)

Every RFC in the tables was read through `rfc-editor.org/rfc/rfcNNNN.json`
and every draft through the datatracker.

- No RFC is obsoleted. The `updated_by` entries are those the last
  review noted: RFC 6066 (RFC 8446, 8449, 9325, 9846), RFC 7301
  (RFC 8447), RFC 8999 (RFC 9368).
- Drafts are at the revisions the code follows: BBR -07, ACK frequency
  -14 (still expired, no newer revision), reliable stream reset -11,
  QUIC-LB -22, WebTransport over HTTP/3 -17.
- One pending update, already listed: Happy Eyeballs v3
  (`draft-ietf-happy-happyeyeballs-v3-05`), which updates RFC 8305. Not
  diffed yet; its section 6.1 matches what `quic_happy` does since #601.

## 7. Navigation

No change beyond the MODULE_MAP numbers and the ownership section.

## 8 to 10. Module size and complexity findings (measured)

- `src/h3/quic_h3.erl`: 1,238 lines, **491 lines of code against the
  Elvis `max_module_length` limit of 500**. #601 crossed the limit and
  moved the hand-off helpers into `quic_h3_connection` to get back under
  it. The module is the public HTTP/3 API for both client and server;
  the next additive function will cross the limit again. Primary
  problem: **module organisation**. Options in question 2.
- **The hand-off helpers exist twice.** `forward_quic_backlog/2` and
  `close_reason/2` are in `src/quic_happy.erl` (lines 271, 282) and in
  `src/h3/quic_h3_connection.erl` (lines 417, 430). Both drain the old
  owner's mailbox, and both depend on the ordering facts of section 6.
  One copy, next to `set_owner_sync/2` in `quic_connection`, would keep
  that contract in one place. Primary problem: **module organisation**.
  Not for this release.
- `src/h3/quic_h3_connection.erl`: 6,250 lines. Unchanged finding: push
  is the clearest future boundary.
- `src/quic_connection.erl`: 17,922 lines. Unchanged finding.
- **A flaky CI test.** `quic_server_0rtt_discard_tests:
  server_discards_early_keys_after_first_1rtt` failed on the macOS NIF
  job on main twice (`163be7d`, `de01d12`) and on #600; a rerun passed
  each time. It polls for a deadline with a 5 s wait. Primary problem:
  **code complexity** in tests. Worth an issue.
- No other module exceeds 2,400 lines (`quic_dist_controller` 2,317,
  `quic_tls` 2,056).

## 11. Contributor workflows

Adequate. The `_checkouts` note for testing another project against a
local build is still worth a paragraph in `CONTRIBUTING.md`.

## 12. Diagrams

None needed. The ownership section reads best as a short list of
stages, not a diagram.

## 13. Questions for the maintainer

1. Version: patch or minor? There is no new function, but
   `quic:set_owner_sync/2` returns a different error on a closing
   connection, `{error, closed}` instead of `{error, {invalid_state,
   draining}}`. Your rule bumps the minor version only when the public
   API changed. Is a changed error term such a change (3.3.0), or a fix
   (3.2.1)?
2. `quic_h3.erl` at 491 of 500 lines of code: split the public API into
   client and server modules behind `quic_h3`, or add it to the
   `max_module_length` ignore list as `quic` already is?
3. A note for the livery and hackney maintainers in the release notes?
   Livery's `livery_mtls_SUITE` hit the `connect/3` crash on CI, and
   any code that matched `{error, {invalid_state, draining}}` from
   `set_owner_sync/2` sees `{error, closed}` now. (Replaces question 5
   of the last review, which asked the same for 3.2.0.)
4. `docs/DEVELOPER_GUIDE.md` is the user's guide while `AGENTS.md` serves
   contributors. Rename to `USER_GUIDE.md`? (Open since two reviews.)
5. Mirror the pyshark pin note of `interop/runner.Dockerfile` in
   `interop/README.md`? tshark crashed in the runner again in this cycle,
   during the #600 run, after the erlang-quic pairs had finished. (Open
   since two reviews.)
6. `scripts/run_docker_dist_bench.sh` prints an empty results table.
   Fix the script, or drop the table? (Open since the last review.)

## 14. Implementation order

1. **Pre-release, one docs-only PR:** `docs/features.md`,
   `docs/CLIENT_GUIDE.md`, `docs/DEVELOPER_GUIDE.md`, the
   `docs/MODULE_MAP.md` numbers and the `take_over/2` note, the
   `AGENTS.md` date, and this plan.
2. The connection ownership section in `docs/DESIGN.md`, in the same PR
   if you want it before the release.
3. The answers to questions 1 and 3, then the version bump and the
   CHANGELOG release section.
4. After the release: one copy of the hand-off helpers, the
   `quic_h3.erl` decision (question 2), an issue for the flaky 0-RTT
   test, the shared HTTP/3 test state builder, the `docs/HTTP3.md`
   split, the `docs/QUIC_DIST.md` section map, questions 4 to 6.

## Release gate status

The maintainer asked for the documentation to be fixed, then the
release. Done on this branch, with no source change:

- Item 1 of section 14: `docs/features.md` (the owner calls),
  `docs/CLIENT_GUIDE.md` (a refused Happy Eyeballs winner),
  `docs/DEVELOPER_GUIDE.md` (the handler example), the
  `docs/MODULE_MAP.md` numbers and the `take_over/2` note, the
  `AGENTS.md` date.
- Item 2: the "Connection Ownership" section in `docs/DESIGN.md`.

Still open after this branch: everything in item 4 of section 14, and
questions 2 and 4 to 6. Questions 1 and 3 had no answer. The release is
3.3.0, since the result of a public function changed; the "Changed"
entry of the CHANGELOG is what livery and hackney need to read.
