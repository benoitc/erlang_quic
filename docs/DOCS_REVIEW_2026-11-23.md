# Documentation and maintainability review, 2026-11-23

Scope: `main` at `b1d314d` (PR #616 merged). This plan gates the release
that follows 3.3.1. It updates the review of 2026-11-22 (`06feed7`); the
next review should update this file again instead of starting over.

## What it found, in a few lines

The reading path still works. Since 3.3.1, two PRs merged:

- **#615:** a refused or misbehaving peer is logged at debug level, not
  as a warning or an error.
- **#616:** three changes by Johan Bevemyr:
  - `stop_server/1` sends the last CONNECTION_CLOSEs;
  - an opt-in `min_bin_vheap_size` option;
  - queued writes share packets.

Each came with its documentation. Three small items stand before the
release:

1. the `AGENTS.md` date;
2. two sizes in `docs/MODULE_MAP.md`;
3. a note in `docs/SERVER_GUIDE.md`. This release changes what a server
   operator sees when a client is refused, and the guide does not say
   where that went.

## Since the last review

Done, all in #610:

- **`AGENTS.md`:** the date;
- **`docs/MODULE_MAP.md`:**
  - sizes;
  - a measured dependency table;
  - the `take_over/2` sentence;
- **`docs/GETTING_STARTED.md`:** the example.

Merged since 3.3.1:

- **Logging (#615).** 38 events a peer can cause go to debug, with their
  reason:
  - certificate and TLS refusals on both sides;
  - PSK and key share failures;
  - connections declined by `connection_handler`, `sni_callback` or
    `alpn_handler`;
  - dist auth refusals;
  - transport protocol violations.

  A late Initial packet, or a 0-RTT packet with no keys, is dropped
  without a warning (RFC 9001 Section 4.9).

  Documented in:
  - `docs/DEVELOPER_GUIDE.md` (Logger Configuration);
  - `docs/QUIC_DIST.md`;
  - the `quic_listener` module doc.
- **Listener, options and send path (#616):**
  - `stop_server/1` lets the shared sender finish;
  - `min_bin_vheap_size`, in `docs/features.md`;
  - queued writes fill their packets, in `docs/SEND_PATH.md`.

  #611, #612 and #613 were superseded by #616, which carries their
  commits as they were.

Still open from the last review: everything in its section 14 item 3, and
questions 2, 4, 5 and 6.

## 3 to 5. Per-document verdicts

Only the documents that need work are listed.

| Document | Verdict | Reason |
|---|---|---|
| `AGENTS.md` (287) | **update, pre-release** | Set "Last checked" to 2026-11-23 (section 6b). |
| `docs/MODULE_MAP.md` (102) | **update, pre-release** | `quic_connection` 17,991 → 18,063 and `quic_listener` 1,718 → 1,729, both in the reading list and in the dependency table. Then the measurement date. The call counts are unchanged (section 7). |
| `docs/SERVER_GUIDE.md` (639) | **update, pre-release** | Add "Refused peers" under Observability, after "Crash reports". The new section says four things: (1) a refused client and a client that breaks the protocol are logged at debug, with the reason; (2) a refused client is one without a certificate, one whose certificate does not verify, or one a callback declines; (3) the owner still gets the error; (4) how to turn the reports on. Before #615 an operator saw an error per refused client; the guide should say where those went. |
| `docs/HTTP3.md` (1,449) | split | As before. |
| `docs/QUIC_DIST.md` (789) | keep, add a section map | As before. |

## 6b. Specification list (AGENTS.md, checked 2026-11-23)

Every RFC in the tables was read through `rfc-editor.org/rfc/rfcNNNN.json`
and every draft through the datatracker. Nothing changed since
2026-11-22:

- **RFCs:** none is obsoleted, and the `updated_by` entries are the
  same.
- **Drafts:** each is at the revision the code follows (BBR -07, ACK
  frequency -14, reliable stream reset -11, QUIC-LB -22, WebTransport
  -17).
- **Pending update:** Happy Eyeballs v3 is still at -05 and not diffed.

## 7. Navigation

The dependency table, measured again with `xref` on `b1d314d`, has the
same callers and callees as on 2026-11-22. Only two line counts moved
(section 3).

## 8 to 10. Module size and complexity findings (measured)

- **`src/quic_connection.erl`: 18,063 lines (+72).**
  - #616 added the packing of queued writes (`fill_pending_packet/8`) and
    the `min_bin_vheap_size` flag.
  - #615 changed log levels only.
  - Unchanged finding.
- **`src/quic_listener.erl`: 1,729 lines (+11),** for the drain of the
  shared sender.
- **`src/h3/quic_h3.erl`:** unchanged, still 491 lines of code of 500.
  Question 2.
- **`close_reason/2` exists twice.** Unchanged. Not for this release.
- **`min_bin_vheap_size`** is checked in the connection's `init/1`, so a
  bad value fails the connection's start. A bad `fullsweep_after` fails
  in the caller, before the process exists. Minor, after the release.
- **A second flaky CT case.**
  `quic_credit_deadlock_SUITE:credit_reaches_the_peer_while_the_window_is_full`
  failed once, on docs-only #610. Its premise, a full window at the end of
  the outage, did not hold, and a rerun passed. Worth an issue if it
  fails again.
- **Two harness problems seen while validating #613:**
  - **`scripts/run_dist_bench.sh` fails on `main`** with
    `{credentials,no_credentials}`. It passes its settings with
    `erl -config`, which loads the quic application's settings only
    after distribution has started. No document points to it. Primary
    problem: **code complexity** in tooling. Fix it (or say how to run
    the bench) after the release.
  - **Suites that use the `socket` backend only run on Linux.** They
    time out on macOS, which `docker/run-ct.sh` documents.
    `quic_h3_failures_SUITE` now has such a case, and running the suite
    on a Mac reports it as failed. A skip on non-Linux hosts would say
    why. Minor.

## 11. Contributor workflows

Adequate. The `_checkouts` paragraph for `CONTRIBUTING.md` (last review)
still stands.

## 12. Diagrams

None needed.

## 13. Questions for the maintainer

1. **Version.** The next release is 3.3.2, a patch.
   - #616 adds one option and #615 changes log levels; neither changes a
     public function.
   - Monitoring that alerted on the refusal warnings sees them at debug
     now. The CHANGELOG says so.
   - Agree?
2. **`quic_h3.erl` at 491 of 500 lines of code.** Split it, or add it to
   the ignore list? (Open since two reviews.)
3. **livery.** Close livery PR #128 when it bumps to 3.3.2? (Open since
   the last review.)
4. **Rename `docs/DEVELOPER_GUIDE.md` to `USER_GUIDE.md`?** (Open since
   four reviews.)
5. **The tshark note in `interop/README.md`?** (Open since four reviews.)
6. **`scripts/run_docker_dist_bench.sh` prints an empty table, and
   `scripts/run_dist_bench.sh` no longer starts.** Fix both, or drop
   them? (Extended from the last review.)

## 14. Implementation order

1. **Pre-release, one docs-only PR on this branch:**
   - the `AGENTS.md` date;
   - the two `docs/MODULE_MAP.md` sizes;
   - the `docs/SERVER_GUIDE.md` note;
   - this plan.
2. **The release:** the answer to question 1, then the version bump and
   the CHANGELOG release section, which turns `[Unreleased]` into 3.3.2.
3. **After the release:**
   - everything in item 3 of the last review;
   - the `min_bin_vheap_size` validation;
   - a skip for the Linux-only case;
   - the two bench scripts;
   - questions 2 to 6.
