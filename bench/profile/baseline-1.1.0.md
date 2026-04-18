# Baseline: 1.1.0 + Phase 0a instrumentation

Phase 0 of the throughput optimization plan. This is the reference point every
later phase diffs against.

## Commit / code state

- Release tag: `v1.1.0`
- On top of: `perf(stats): instrument ack_sent and retransmits counters`
  (Phase 0a, PR #77, merged as `f18e356`).
- Baseline branch: `perf/phase-0b-baseline`.

## Platforms

Two host environments, both loopback, single connection, single stream.

| Host | Kernel / virt | Arch | Erlang | Notes |
|---|---|---|---|---|
| macOS (native) | Darwin 25.3.0 | arm64 | OTP 28 | `gen_udp` only; no GSO/GRO |
| Linux (docker) | orbstack-hosted VM on macOS | arm64 | OTP 28 (erlang:28 image) | `socket` + `gen_udp`; GSO path exercised |

The Linux numbers come from `quic-bench:phase-0b` built from
`docker/benchmark/Dockerfile` on this tree.

## Method

- `quic_throughput_bench:run_download_sink/1` (server → client download) for download.
- `quic_throughput_bench:run/1` with `mode => sink` for upload (client → server sink).
- Three runs per size / backend. Handshake and listener setup are outside the
  timed window in both helpers.
- Sizes: 1 MB, 5 MB, 10 MB.
- Flow-control windows set to 16–32 MB so transfers never block on
  `MAX_STREAM_DATA` / `MAX_DATA`.

Metrics, per run:

- Throughput (MB/s) computed by the bench driver.
- Server-side `get_stats/1`: `batch_flushes`, `packets_coalesced`,
  `ack_sent`, `retransmits`. Available on download runs (where the server is
  the sender and the bench snapshots server stats before/after).

Upload runs do **not** currently snapshot server stats; upload rows below show
client-side throughput only. Adding server-stat capture for the upload path is
deferred — it is not needed for the phases that follow and would expand Phase 0
scope.

## Results

### macOS — `gen_udp`

Download (server → client):

| Size | MB/s (3 runs) | avg | ack_sent (server) | retransmits |
|---|---|---|---|---|
| 1 MB  | 20.36, 42.47, 33.33 | 32.05 | 2, 2, 1 | 0, 0, 0 |
| 5 MB  | 50.47, 49.21, 48.67 | 49.45 | 3, 4, 4 | 0, 0, 0 |
| 10 MB | 31.08, 47.70, 44.23 | 41.00 | 3, 4, 3 | 0, 0, 0 |

Upload (client → server sink):

| Size | MB/s (3 runs) | avg |
|---|---|---|
| 1 MB  | 62.50, 45.45, 45.45 | 51.14 |
| 5 MB  | 60.24, 59.52, 64.10 | 61.29 |
| 10 MB | 65.36, 66.23, ~65    | ~65.5 |

### Linux (docker) — `socket` backend, batching on (GSO when available)

Download:

| Size | MB/s (3 runs) | avg | flushes | coalesced | coalesce ratio | ack_sent | retransmits |
|---|---|---|---|---|---|---|---|
| 1 MB  | 16.80, 33.81, 32.32 | 27.64 | 289 / 192 / 193    | 765 / 770 / 771       | 2.65 / 4.01 / 3.99 | 3, 2, 3 | 0, 0, 0 |
| 5 MB  | 47.72, 52.92, 41.31 | 47.32 | 1290 / 948 / 948   | 3791 / 3791 / 3789    | 2.94 / 4.00 / 4.00 | 3, 3, 3 | 0, 0, 0 |
| 10 MB | 43.99, 47.42, 41.19 | 44.20 | 1872 / 2607 / 2528 | 7561 / 7553 / 7552    | 4.04 / 2.90 / 2.99 | 3, 3, 3 | 0, 0, 0 |

Upload:

| Size | MB/s (3 runs) | avg |
|---|---|---|
| 1 MB  | 37.04, 29.41, 38.46 | 34.97 |
| 5 MB  | 52.08, 49.50, 50.00 | 50.53 |
| 10 MB | 69.93, 56.18, 61.73 | 62.61 |

### Linux (docker) — `socket` backend, batching off

Download: **all 9 runs returned `{error, connect_timeout}`**. The first
backend's runs in the same Erlang node completed cleanly; switching to the
no-batching socket backend on a fresh server within the same bench session
fails to connect. Tracked as a follow-up — not a regression from Phase 0a and
out of scope for Phase 0.

Upload:

| Size | MB/s (3 runs) | avg |
|---|---|---|
| 1 MB  | 47.62, 34.48, 37.04 | 39.71 |
| 5 MB  | 55.56, 50.00, 62.50 | 56.02 |
| 10 MB | 64.10, 66.67, 48.54 | 59.77 |

### Linux (docker) — `gen_udp`

Download:

| Size | MB/s (3 runs) | avg | ack_sent | retransmits |
|---|---|---|---|---|
| 1 MB  | 57.44, 45.10, 48.99 | 50.51 | 1, 1, 1 | 0, 0, 0 |
| 5 MB  | 54.54, 46.48, 43.26 | 48.09 | 3, 4, 3 | 0, 0, 0 |
| 10 MB | 42.59, 53.13, 45.05 | 46.93 | 3, 4, 4 | 0, 0, 0 |

Upload:

| Size | MB/s (3 runs) | avg |
|---|---|---|
| 1 MB  | 43.48, 52.63, 33.33 | 43.15 |
| 5 MB  | 51.02, 50.51, 56.82 | 52.78 |
| 10 MB | 72.46, 56.18, 60.61 | 63.08 |

## Observations

1. **GSO coalescing is working on Linux**: `batch_flushes` and
   `packets_coalesced` are non-zero on the socket+batching backend and zero
   elsewhere. Coalesce ratios cluster near 3-4 packets per flush, consistent
   with one GSO super-datagram per send-queue drain at loopback MTU.

2. **GSO does not currently beat `gen_udp` on loopback in this environment.**
   At 10 MB, `socket` + GSO averages 44.2 MB/s vs `gen_udp` 46.9 MB/s in the
   same docker/arm64 VM; upload is 62.6 vs 63.1. This is loopback inside a
   hypervisor on arm64 — CPU cost per packet dominates over what GSO
   amortizes. The performance phases that follow (especially Phase 1 send
   quantum) are aimed exactly at that CPU cost.

3. **Retransmits are zero everywhere**. Baseline is a no-loss loopback.
   Phase 5 validation will need a lossy scenario to exercise this counter.

4. **`ack_sent` on download paths is 1-4**. Makes sense: the server receives
   the client's initial request + FIN and acks those; the bulk data path is
   server-to-client so the server rarely has to ack. Upload runs do not
   snapshot server stats, so that row is blank.

5. **Small-transfer variance is high** (1 MB ranges ~17-57 MB/s). Handshake
   is excluded, but connection warm-up and pacing state dominate at 1 MB on
   loopback. Later phases should keep 5 MB and 10 MB as the primary signal.

6. **`socket` + batching-off download fails with `connect_timeout`** on
   repeated use within the same session. Tracked separately — does not block
   the plan.

## Targets for Phase 1+

Diff against these numbers, with the same matrix, after each phase:

- Primary: 5 MB and 10 MB **download**, `socket` + GSO. Any improvement here
  is pure send-loop work.
- Secondary: 10 MB **upload**, any Linux backend, for the send-path changes
  that run on the client side.
- Required: no regression in `retransmits` under loss (to be added when
  Phase 5 lands a lossy harness).
