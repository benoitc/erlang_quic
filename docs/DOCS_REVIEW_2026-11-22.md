# Documentation and maintainability review, 2026-11-22

Scope: `main` at `06feed7` (PR #609 merged). This plan gates the release
that follows 3.3.0. It updates the review of 2026-11-20 (`911c39b`); the
next review should update this file again instead of starting over.

## What it found, in a few lines

The reading path still works. Since 3.3.0 one fix merged (#609): a
connection that changes owner while it is already delivering events now
hands them over in order, which removes the `connect_timeout` flake livery
saw. Its documentation came with it. Four small items stand before the
release:

- the `AGENTS.md` date;
- stale sizes in `docs/MODULE_MAP.md`, including a dependency table that
  the last two reviews missed;
- one sentence there about `take_over/2`;
- a redundant owner call in the `docs/GETTING_STARTED.md` server example,
  the same one the last cycle removed from `docs/DEVELOPER_GUIDE.md`.

## Since the last review

Done:

- **The hand-off helpers.** `forward_quic_backlog/2` existed twice; now
  `quic_connection` alone holds the hand-off (#609).
  - `close_reason/2` still exists twice (section 8).
- **Connection ownership.** The "Connection Ownership" section of
  `docs/DESIGN.md` now explains why forwarding events after
  `set_owner_sync/2` can reorder them, and how the hand-off keeps the
  order. `quic:set_owner_sync/2` and `docs/features.md` say not to forward
  delivered events after the call (#609).
- **The other pre-release items** of the last review are done: the owner
  calls in `docs/features.md`, the Happy Eyeballs close in
  `docs/CLIENT_GUIDE.md`, the handler example in
  `docs/DEVELOPER_GUIDE.md`, and the ownership section (#603).

Still open from the last review:

- **Split `docs/HTTP3.md`** into guide and reference. It is still 1,449
  lines.
- **One shared builder for the `quic_h3_connection` test state.** There
  are still two copies.
- **A section map at the top of `docs/QUIC_DIST.md`** (788 lines).
- **An issue for the flaky 0-RTT discard test.** It has not failed on
  `main` since 2026-11-19.
- **Questions 2, 4, 5 and 6** of section 13.

Merged since 3.3.0:

- **Ownership (#609).** A new internal `quic_connection:hand_over/3` is
  used by `quic_happy` and by `quic_h3_connection:take_over/2`.
  `set_owner_sync/2` keeps its behaviour. The dist client is unchanged,
  and a comment there says why nothing can be in flight.

## 1. Recommended structure

Unchanged:
- **Orientation:** `README.md`, `docs/GETTING_STARTED.md`,
  `docs/GLOSSARY.md`.
- **Architecture:** `docs/DESIGN.md`, `docs/MODULE_MAP.md`,
  `docs/RECV_PATH.md`, `docs/SEND_PATH.md`.
- **Area guides:** `CLIENT_GUIDE`, `SERVER_GUIDE`, `HTTP3`, `QUIC_DIST`,
  `PSK`, `INTERNAL_NETWORKS`, `QLOG_GUIDE`, `PERFORMANCE`, `features`,
  `h3_compliance`.
- **Contributor:** `AGENTS.md`, `CONTRIBUTING.md`,
  `docs/DEVELOPER_GUIDE.md`.

Do not add a layer.

## 2. Main starting point

`README.md`, its document index, then `docs/GETTING_STARTED.md`. Keep it.

## 3 to 5. Per-document verdicts

Only the documents whose verdict changed or that need work are listed.
Every other document keeps the "keep" of the last review.

| Document | Verdict | Reason |
|---|---|---|
| `AGENTS.md` (287) | **update, pre-release** | Set "Last checked" to 2026-11-22 (section 6b). |
| `docs/MODULE_MAP.md` (99) | **update, pre-release** | Three sizes in the reading list are stale: `quic` 1,190 → 1,196, `quic_connection` 17,922 → 17,991, `quic_h3_connection` 6,250 → 6,236 (also in "Reading quic_h3_connection"). The "What depends on what" table is older still, and its replacement is measured in section 7. The `take_over/2` bullet says it "reads that process's mailbox"; it should add that the connection resends what was read before anything newer (`hand_over` in `quic_connection`). |
| `docs/GETTING_STARTED.md` (238) | **update, pre-release** | The echo server's `connection_loop/1` starts with `ok = quic:set_owner(Conn, self())`. The listener already makes the pid that `handle_connection/2` returns the owner before the first packet, so the call does nothing. It teaches the pattern `quic_listener` warns against. The last cycle removed the same call from `docs/DEVELOPER_GUIDE.md` and missed this copy. Drop the line. |
| `docs/HTTP3.md` (1,449) | split | As before. |
| `docs/QUIC_DIST.md` (788) | keep, add a section map | As before. |

## 6. Concepts needing a dedicated explanation

None new. The concept the last review asked for, connection ownership and
hand-off, is in `docs/DESIGN.md` now, and #609 completed it with the
ordering rule.

## 6b. Specification list (AGENTS.md, checked 2026-11-22)

Every RFC in the tables was read through `rfc-editor.org/rfc/rfcNNNN.json`
and every draft through the datatracker.

- **RFCs:** none is obsoleted. The `updated_by` entries are unchanged:
  RFC 6066 (RFC 8446, 8449, 9325, 9846), RFC 7301 (RFC 8447), RFC 8999
  (RFC 9368).
- **Drafts:** each is at the revision the code follows:
  - BBR -07;
  - ACK frequency -14, still expired, with no newer revision;
  - reliable stream reset -11;
  - QUIC-LB -22;
  - WebTransport over HTTP/3 -17.
- **Pending update, already listed:** Happy Eyeballs v3 is still at -05
  and not diffed yet.

## 7. Navigation

The dependency table of `docs/MODULE_MAP.md` ("Most called, so most
expensive to change") dates from September 2026 (#334): `quic` 976,
`quic_connection` 12,691, `quic_h3` 836. Its call counts no longer hold
either, and two modules that are now among the most called are missing. Measured with `xref` on `main` (module
call graph, own application only):

| Module | Lines | Called by | Calls |
|--------|------:|----------:|------:|
| `quic_redact` | 258 | 11 | 0 |
| `quic_varint` | 112 | 8 | 0 |
| `quic_connection` | 17,991 | 7 | 28 |
| `quic` | 1,196 | 7 | 7 |
| `quic_crypto` | 671 | 7 | 1 |
| `quic_cert` | 495 | 6 | 0 |
| `quic_listener` | 1,718 | 5 | 12 |
| `quic_h3` | 1,238 | 4 | 3 |

- **`quic_cc` leaves the table.** It is called by one module now;
  `quic_connection` reaches the controllers through it.
- **The sentence below the table** should read "calling 28 other modules
  and being called by 7".
- **Add one line on where the numbers come from:** an `xref` module graph,
  so the next reviewer can measure again rather than copy.

## 8 to 10. Module size and complexity findings (measured)

- **`src/quic_connection.erl`: 17,991 lines** (+69).
  - #609 added the hand-off: `hand_over/3` on the caller's side, and on
    the connection side `hand_over_owner/4`, which waits in a `receive`
    inside the gen_statem callback until the old owner answers.
  - That is the one place where the connection blocks on purpose. The
    reason is in `docs/DESIGN.md` and in the function's comment.
  - Otherwise the finding is unchanged.
- **`src/h3/quic_h3.erl`: 1,238 lines**, unchanged since 3.3.0. It is
  still 491 lines of code against the Elvis limit of 500. Question 2.
- **`close_reason/2` exists twice**, in `src/quic_happy.erl` (line 265) and
  `src/h3/quic_h3_connection.erl` (line 416).
  - Both read the old owner's mailbox for the `{closed, Reason}` a
    connection sends before it refuses a hand-off.
  - With `forward_quic_backlog/2` gone, these seven lines are the only
    duplicate left. One copy next to `hand_over/3` would keep the
    hand-off contract in one module.
  - Primary problem: **module organisation**. Not for this release.
- **`src/h3/quic_h3_connection.erl`: 6,236 lines** (-14). Unchanged
  finding: push is the clearest future boundary.
- **`src/quic_happy.erl`: 339 lines** (-20). The coordinator no longer
  forwards events itself.
- **A test that takes 5 s.**
  `quic_hand_over_tests:a_stuck_old_owner_closes_the_connection_test_`
  waits out the hand-off timeout, a macro of 5,000 ms. It is the only
  test that waits for that timeout. Fine as is; noted so nobody shortens
  the timeout to speed up the suite.
- **The interop runner was unstable this cycle.**
  - `tshark` crashed once inside the runner during the #609 run, in the
    rebind-port check; this concerns question 5.
  - `handshakeloss` with an erlang-quic server and a quic-go client failed
    once: the client gave up after 27 of 50 handshakes. It then passed
    three runs on `main` and three on the branch.
  - Neither touches the code #609 changed. Worth watching, not an issue
    yet.

## 11. Contributor workflows

Adequate.
- The `_checkouts` note for testing another project against a local build
  is still worth a paragraph in `CONTRIBUTING.md`.
- That paragraph should warn that a copied `_build` keeps absolute
  symlinks into the original checkout, and CMake caches with its path.
  Clone the other project and let rebar3 build its dependencies, rather
  than copying `_build`.

## 12. Diagrams

None needed.

## 13. Questions for the maintainer

1. **Version.** The next release is 3.3.1, a patch.
   - #609 changes no public function. `hand_over/3` is `@private` in
     `quic_connection`, and `set_owner_sync/2` behaves as before.
   - The fix is visible only as `quic_h3:connect/3` no longer timing out.
   - Agree?
2. **`quic_h3.erl` at 491 of 500 lines of code.** Split the public API into
   client and server modules behind `quic_h3`, or add it to the
   `max_module_length` ignore list as `quic` already is? (Open since the
   last review.)
3. **livery.** Should its next bump to 3.3.1 close livery PR #128, the qlog
   collection that was opened to catch this flake? Or keep the traces on
   CI failure anyway?
4. **`docs/DEVELOPER_GUIDE.md`** is the user's guide, while `AGENTS.md`
   serves contributors. Rename it to `USER_GUIDE.md`? (Open since three
   reviews.)
5. **The tshark note.** Mirror the pyshark pin note of
   `interop/runner.Dockerfile` in `interop/README.md`? tshark crashed in
   the runner again this cycle. (Open since three reviews.)
6. **`scripts/run_docker_dist_bench.sh`** prints an empty results table.
   Fix the script, or drop the table? (Open since two reviews.)

## 14. Implementation order

1. **Pre-release, one docs-only PR** on this branch:
   - the `AGENTS.md` date;
   - the `docs/MODULE_MAP.md` sizes, its dependency table and the
     `take_over/2` sentence;
   - the `docs/GETTING_STARTED.md` example;
   - this plan.
2. **The release:** the answer to question 1, then the version bump and
   the CHANGELOG release section, which turns `[Unreleased]` into 3.3.1.
3. **After the release:**
   - one copy of `close_reason/2`;
   - the `quic_h3.erl` decision (question 2);
   - an issue for the flaky 0-RTT test;
   - the shared HTTP/3 test state builder;
   - the `docs/HTTP3.md` split;
   - the `docs/QUIC_DIST.md` section map;
   - the `_checkouts` paragraph;
   - questions 4 to 6.

## Release gate status

You asked for the four pre-release items first, then 3.3.1 (question 1).
Done on this branch, with no source change:

- the `AGENTS.md` date;
- the `docs/MODULE_MAP.md` sizes, the measured dependency table, and the
  `take_over/2` sentence;
- the `docs/GETTING_STARTED.md` server example.

Still open after this branch: item 3 of section 14, and questions 2 to 6.
