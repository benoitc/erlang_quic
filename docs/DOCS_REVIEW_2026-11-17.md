# Documentation and maintainability review — 2026-11-17

Scope: `main` at `c5375f6` (PR #570 merged). This plan gates the 3.1.2
release. The next review should update this file rather than start over.

## What it found, in a few lines

The documentation is in unusually good shape: there is a clear reading
path (README → GETTING_STARTED → MODULE_MAP → DESIGN), a glossary, a
module map written for people who grep, and per-area guides. The
problems are drift and two oversized pages, not missing structure.
Nothing here blocks a release except the two staleness fixes marked
**pre-release**; the rest can wait for the follow-up it names.

## 1. Recommended structure (already largely in place — keep it)

Orientation: `README.md` (what it does, requirements, quick start) →
`docs/GETTING_STARTED.md` (first connection) → `docs/GLOSSARY.md`
(vocabulary).

Architecture: `docs/DESIGN.md` (how the protocol works) →
`docs/MODULE_MAP.md` (where it lives) → `docs/RECV_PATH.md` /
`docs/SEND_PATH.md` (the two hot paths).

Area guides: `docs/CLIENT_GUIDE.md`, `docs/SERVER_GUIDE.md`,
`docs/HTTP3.md`, `docs/QUIC_DIST.md`, `docs/PSK.md`,
`docs/INTERNAL_NETWORKS.md`, `docs/QLOG_GUIDE.md`,
`docs/PERFORMANCE.md`, `docs/features.md`, `docs/h3_compliance.md`.

Contributor: `AGENTS.md`, `CONTRIBUTING.md`, `docs/DEVELOPER_GUIDE.md`.

Do not add a layer. The gaps below are fixes inside existing pages.

## 2. Main starting point

`README.md` → its own doc index (line 259 onward) → `GETTING_STARTED`.
This works. Keep it.

## 3–5. Per-document verdicts

| Document | Verdict | Reason |
|---|---|---|
| README.md (294) | keep | Right altitude, correct index. |
| GETTING_STARTED.md (238) | keep | First-connection walkthrough as promised. |
| GLOSSARY.md | keep | Referenced where the jargon bites. |
| MODULE_MAP.md (84) | **rewrite numbers — pre-release** | Measurements are stale (see 7). |
| DESIGN.md (615) | keep | Section-per-concept matches the code's banners. |
| RECV_PATH.md / SEND_PATH.md | keep | Short, point at the real functions. |
| CLIENT_GUIDE.md (695), SERVER_GUIDE.md (639) | keep | Right size for their audience. |
| HTTP3.md (1379) | **split** | Six sections, two of them (Public API Reference 960 lines, Module Internals 130) are reference material the edoc build already covers. Split into HTTP3.md (concepts + usage) and a generated-or-thin API page. |
| QUIC_DIST.md (788) | keep, add a section-banner map | Longest guide; good content, hard to navigate. |
| features.md (467) | keep | API index; updated for this series. |
| DEVELOPER_GUIDE.md (433) | keep | It is the user-facing developer guide despite the name; see 13. |
| QLOG_GUIDE.md, PERFORMANCE.md, PSK.md, INTERNAL_NETWORKS.md, h3_compliance.md | keep | Scoped, current. |
| OTP-ISSUE-crypto_one_time_aead_init.md (root, 71) | **move or delete — pre-release** | Working notes committed at the repo root; nothing links to it. Either fold its one durable fact (ChaCha HP never touches the ECB cache) into a code comment where it belongs and delete, or move under `docs/` and link it. |
| AGENTS.md / CONTRIBUTING.md / SECURITY.md | keep | Followed during this series; accurate. |

## 6. Concepts needing a dedicated explanation

One: **key lifecycle**. After PR #570 the disposal rules span Initial,
Handshake, 0-RTT and key-update generations with different triggers and
timers. DESIGN.md §"Key Update" covers the update mechanics but not the
disposal timeline. A short section in DESIGN.md (a dozen lines: what is
held, what drops it, when) would prevent the next contributor from
re-deriving it. Candidate author: whoever merges this plan.

## 7. Navigation measurements (stale numbers — pre-release fix)

Measured today: 48 top-level `src/*.erl` plus 21 in `src/h3/`,
`src/qpack/`, `src/dist/`, `src/interop/` — **69 modules, 57,015 lines
total**. `quic_connection.erl` is **17,825 lines**.

- MODULE_MAP says "68 modules and about 47,000 lines" and lists
  `quic.erl` (976 — now 1,188), `quic_listener.erl` (1,411 — now 1,712),
  `quic_connection.erl` (12,691 — now 17,825). The counts predate the
  connection-timers and key-lifecycle work. Update the numbers; the
  advice ("read by section banner, not top to bottom") stays correct.
- Nothing links from MODULE_MAP's quic_connection entry to the section
  banners list. One sentence pointing at the banners would do.

## 8–10. Module size findings (measured, not guessed)

- `src/quic_connection.erl`: 17,825 lines, ~25% of the tree. The repo
  already documents why (elvis excludes it from `dont_repeat_yourself`
  and `max_function_length`; AGENTS.md names it the central module).
  It has one coherent responsibility — the connection state machine —
  and the section banners hold it together. **No split recommended
  now.** If it grows past ~20k, the candidate boundary is the
  key-update and disposal block (roughly `select_decrypt_keys` through
  `retire_prev_keys`, ~700 lines) into `quic_key_update.erl`; the
  deferral is deliberate to keep this release review-only.
- `docs/HTTP3.md`: 1,379 lines mixing guide and API reference (see
  verdict table).
- No other module exceeds 2,100 lines, and none mixes unrelated
  responsibilities measurably.

## 11. Contributor workflows

The "If you want to..." material already exists, scattered:
CONTRIBUTING.md has the workflow, MODULE_MAP has "where tests live",
DEVELOPER_GUIDE has debugging. Adequate; do not consolidate for its
own sake.

## 12. Diagrams

DESIGN.md's ASCII packet-flow diagrams are sufficient. No additions
recommended.

## 13. Questions for the maintainer

1. `docs/DEVELOPER_GUIDE.md` is the *user's* developer guide (clients,
   servers, streams, options) while `AGENTS.md` serves contributors.
   Intentional naming? A `USER_GUIDE.md` rename would match its content.
2. Should the interop-runner image's pyshark pin note
   (`interop/runner.Dockerfile`) be mirrored in `interop/README.md`?
   One line, prevents the next person re-debugging the 0.6 crash.
3. Keep `OTP-ISSUE-crypto_one_time_aead_init.md` (move under docs/ and
   link) or fold its durable fact into code comments and delete?

## 14. Implementation order

1. **Pre-release (this series):** MODULE_MAP numbers; move or delete
   the root OTP-ISSUE file. One small PR, no code.
2. HTTP3.md split (guide vs reference) — its own PR.
3. Key-lifecycle section in DESIGN.md — its own PR.
4. QUIC_DIST.md banner map — whenever someone touches that area next.
5. The maintainer's answers to 13 become small follow-ups.

## Release gate status

Items in 1 are the only ones this review blocks the release on. The
maintainer decides; everything else can ship after 3.1.2.
