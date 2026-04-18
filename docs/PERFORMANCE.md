# Performance

This page is about how fast the stack goes today, how we got there,
and what we would still like to do. Numbers come from loopback
benchmarks on a single connection and a single stream. They tell us
what happens in process and on a LAN. They do not replace a proper
real network measurement.

## 1.2.0 versus 1.1.0

The reference baseline lives in `bench/profile/baseline-1.1.0.md`.
Same docker VM on arm64, same OTP 28, same bench driver
(`quic_throughput_bench:run/1` with `mode => sink` for upload,
`run_download_sink/1` for download). Three runs per cell on the
baseline, ten-run medians on the new numbers for the download
column because the VM is noisy on bigger transfers.

Upload, client to server sink, MB/s:

| Size | gen_udp 1.1.0 | gen_udp 1.2.0 | Δ | socket 1.1.0 | socket 1.2.0 | Δ |
|---|---|---|---|---|---|---|
| 1 MB  | 43.15 | 83.72 | +94%  | 34.97 | 74.95 | +114% |
| 5 MB  | 52.78 | 60.88 | +15%  | 50.53 | 75.45 | +49%  |
| 10 MB | 63.08 | 69.01 | +9%   | 62.61 | 68.16 | +9%   |

Download, server to client, MB/s, n=10 medians on 1.2.0:

| Size | gen_udp 1.1.0 | gen_udp 1.2.0 | Δ | socket 1.1.0 | socket 1.2.0 | Δ |
|---|---|---|---|---|---|---|
| 1 MB  | 50.51 | 51.56 | +2%  | 27.64 | 54.45 | +97% |
| 5 MB  | 48.09 | 48.30 | +0%  | 47.32 | 60.27 | +27% |
| 10 MB | 46.93 | 40.88 | noise | 44.20 | 43.70 | ±0%  |

About the 10 MB download row: the median looks like a regression
but the minimum run is around 28 MB/s and the maximum around 56.
This is docker on arm64 doing its thing. The p90 of gen_udp is
48.71 and the p90 of socket is 49.81. Both sit at or above the
1.1.0 average. So this is variance, not a real drop.

### What moved the numbers

All of the work went into the hot path, on both the send and the
receive side. In no particular order:

* The per packet cwnd and pacing check is now fused into
  `quic_cc:send_check/3`. One BIF call and one record match, where
  the old version needed four.
* The chunked send loop used to recompute the same values on every
  chunk. The stream urgency, the max stream data per packet, and
  the stream frame header prefix now live in a per drain context.
* The qlog macros check the `?QLOG_ENABLED` flag at the call site,
  so when qlog is off nobody builds the event map.
* The receive hot path takes a single `monotonic_time` sample and
  threads it through. The three previous samples were coalesced
  into that one.
* The header protection mask uses a short inline Erlang XOR
  instead of a call into `crypto:exor/2`. For one to four bytes it
  is faster than paying the NIF round trip.
* `contains_ack_eliciting_frames/1` has a fast path for the common
  case of a single stream frame, which shows up on bulk upload
  everywhere.
* An ACK only packet now flushes the pending stream data batch
  first. This keeps the batch uniform for GSO, which means the
  flush stays on the fast `flush_gso` path instead of falling back
  to individual sends.

The full list, one commit per bullet, is in `CHANGELOG.md` under
the 1.2.0 entry.

## The socket backend is opt in, for now

Version 1.2.0 adds a `socket_backend => socket` option on
`quic:connect`. It routes the client through the OTP 27+ `socket`
NIF and uses GSO through a per message cmsg instead of a socket
level setsockopt. On download it is a clear win, from +20% to
+97% depending on the size. On small uploads it is also a win.
The problem is bulk upload above 5 MB, where the socket backend
sits between 8 and 11% behind `gen_udp` on the same machine.

The reason is structural, not a bug. The client receive handler
flushes the pending batch at the end of every `{udp, ...}` event.
Server ACKs arrive every ten client packets or so, which means
the batch never reaches its 64 packet cap. It usually leaves with
four to eight packets. On top of that, a small client ACK joining
a batch of 1200 byte stream chunks breaks
`gso_batch_uniform/2`, and the flush falls through to
`flush_individual`. `socket:sendmsg/2` through the socket NIF is
more expensive per call than `gen_udp:send/4` through the `inet`
port driver, and when GSO does not fire, that difference is what
you pay. Download is not affected because the socket backend wins
on the receive side: there is no `{active, N}` port driver
dispatch per packet, there is a dedicated receiver process, and
the amortization is large enough to dominate.

### Should you turn it on

Turn it on if:

* The client receives more than it sends. Typical HTTP/3 fetch
  and gRPC unary workloads fit here.
* You run client and server under a moderate concurrent load and
  your transfers are in the 1 to 5 MB range. The small transfer
  wins are large.

Stay on the default `gen_udp` if:

* The client sends many large uploads, say bigger than 5 MB per
  stream. Until the upload gap is closed, `gen_udp` is on par or
  slightly faster.
* You are on macOS, Windows, FreeBSD, or OTP older than 27.
  `quic_socket:open_for_send/2` detects the platform and falls
  back to `gen_udp` on these anyway, so the option does not hurt
  you, it just does not help either.

A few operational notes while we are here. Each socket backend
client spawns a dedicated receiver process, because the socket
NIF has no `{active, N}` mode. This is fine for a handful of
connections. If you run thousands of concurrent client
connections, the memory and scheduler cost is real, and we would
like to see numbers before pushing this as a default. Migration
(`quic:migrate/1`) now works on both backends. On the socket
backend it is slightly more work because the whole OTP socket and
its receiver process are rebuilt on rebind.

### When will it become the default

Not in 1.2.x. The plan is to flip the default in 1.3 or 1.4,
after three things land:

1. The upload gap shrinks. See the Future work section for the
   three candidates we have in mind.
2. `quic_dist` and the HTTP/3 client are validated on the socket
   backend. They share the connect path and neither has been
   exercised end to end yet.
3. FreeBSD is a first class backend (see below), so the auto
   detection is not just a Linux-or-else story.

The escape hatch will remain: `socket_backend => gen_udp` will
always force the port driver path.

## Future work

The work we would like to do next, grouped by the place where we
expect to find the next piece of throughput.

### Closing the socket backend upload gap

Three candidates, each a real refactor and not a one line tweak.
Some benches under realistic load before picking.

* Stop flushing the batch on every receive event while a chunked
  drain is in progress. The idea is that full 64 packet uniform
  flushes go out instead of four to eight packet partial ones.
  The difficulty is that ACKs need to go out promptly, so the
  "still draining" signal has to be tight.
* Separate the stream data batch from the control frame batch.
  Small ACKs, MAX_STREAM_DATA, MAX_DATA would never share a
  buffer with 1200 byte stream chunks, and `gso_batch_uniform/2`
  keeps firing.
* Accept the hybrid shape: keep `gen_udp` on the send side by
  default, and use the socket NIF for receive only. The send side
  is where `gen_udp` beats us.

### Coarser pacing

The original plan was to move to a release time burst token model:
one pacing decision per flush, allow a small burst, re-arm once.
The naive form, one `monotonic_time` per drain instead of per
chunk, does not work. The current `pacing_max_burst` is
`14400` bytes, which is roughly twelve packets. A 64 packet
chunked drain only flows past that cap because of the small per
chunk refills. Remove them and the drain blocks at packet twelve.
A proper release time model needs to reserve a bigger budget up
front, drain locally, and commit the unused portion at drain
exit. It spans the `quic_cc` facade, all three CC modules, and
the drain loop. Not a small PR, but well defined.

### Recovery tuning

Loss detection thresholds may be too eager on real networks with
mild reordering. Before changing the defaults we want to validate
throughput and retransmit rate under a lossy harness, not just on
loopback where everything is zero loss. Spurious loss detection
is also on the list.

### FreeBSD

There are four distinct pieces of work here.

* Extend `quic_socket:detect_capabilities/0` to probe
  `{unix, freebsd}` instead of falling straight to `gen_udp`.
  Default to no GSO and no GRO unless proven otherwise. Validate
  `pktinfo`, ECN and TOS ancillary handling, socket buffer sizing,
  and `reuseport`.
* Replace the `socket:recvfrom/4` branch with `recvmsg`, parse
  the ancillary data we actually care about, and drain multiple
  datagrams per wakeup.
* Use `socket:sendmsg` iov as the primary FreeBSD send path.
  Optimize for more packets per wakeup, not Linux style
  segmentation. Validate `reuseport` listener sharding.
* Add native FreeBSD bench runs and a native validation job if
  one is available. The goal is to clearly beat FreeBSD
  `gen_udp`, not to match Linux GSO throughput.

### Observability

* The upload bench does not currently snapshot server stats. Add
  that so we can see batching behaviour on the send path directly.
* A lossy harness (tc-netem or an in-process packet drop shim) to
  exercise the `retransmits` counter. We want this before any
  recovery tuning change.

## Out of scope

These would very likely help, but they do not fit the current
codebase or are too invasive to pursue here.

* `io_uring`, `sendmmsg`, `recvmmsg`, RSS, BPF datapath.
* API level send buffering in the msquic style.
* A large lsquic style send controller refactor.

## Where to look

* `bench/profile/baseline-1.1.0.md` for the pre 1.2.0 reference
  numbers.
* `test/quic_throughput_bench.erl` for the bench harness.
* `CHANGELOG.md` for the per release change list.
