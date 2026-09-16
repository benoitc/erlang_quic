# The Send Path

How an application write becomes bytes on a socket. Read this before changing
anything in `quic_connection`'s send regions, or when a packet count moves and
you need to know which stage produced it. Functions are named rather than
located by line, so this survives the file changing underneath it.

`docs/RECV_PATH.md` covers the other direction.

## The short version

```
quic:send_data/4
  -> quic_connection:do_send_data/4        flow control, fragmentation
     -> queue_stream_data/5                when blocked: park it, priority queue
     -> send_stream_chunk_run/8            bulk: many chunks, one bookkeeping pass
     -> send_app_packet_internal/3         one frame, maybe coalesced
        -> send_app_packet_now/3           encrypt, protect, count, hand to socket
           -> flush_socket_batch/1         GSO batch leaves the process
```

## Stage by stage

**`do_send_data/4`** is the entry point for a stream write. It checks connection
and stream flow control, and fragments data larger than one packet can carry.
Three outcomes: send now, queue because the congestion window or the peer's
window has no room, or reject when the send queue is full.

**`queue_stream_data/5`** parks a write that cannot go now. Entries live in a
bucket-per-urgency priority queue (RFC 9218, urgency 0 to 7), so insertion is
constant time and the drain order matches stream priority. `send_queue_bytes`,
`send_queue_count` and `send_queue_version` track it; the count, not the byte
total, decides emptiness, because a FIN-only entry carries no bytes.

**`process_send_queue/1`** drains after an ACK opens the window, after pacing
releases, or on a burst continuation. It works through
`process_send_queue_entry/1` under the burst budget and the congestion
controller's approval.

**`send_stream_chunk_run/8`** is the bulk path. Once the first full-size chunk
is approved, as many further chunks as congestion control, pacing and the burst
budget allow are approved up front, sealed, and handed to the socket in one
loop, with loss, congestion, packet-number and counter bookkeeping updated once
for the whole run. It rebuilds `#state{}` once per run rather than once per
packet, which is what makes bulk transfer cheap.

**`send_app_packet_internal/3`** is the single-frame entry. With coalescing on
it accumulates into `pend_payload` so several small sends share one packet;
with coalescing off it goes straight to `send_app_packet_now/3`. A payload that
would exceed the remaining budget flushes the pending packet first.

**`send_app_packet_now/3`** is where a packet is actually built: select keys by
role, assign the packet number from `pn_app`, encrypt, apply header protection,
update the congestion controller and loss tracker, bump counters, and hand the
datagram to the socket layer. It matches `app_keys = {ClientKeys, ServerKeys}`
in its head, so it cannot run before the handshake installs keys.

**`flush_pending_packet/1`** emits whatever coalescing accumulated.
**`flush_socket_batch/1`** pushes the socket layer's batch out, which is where
GSO super-datagrams leave on Linux. Anything queued but unflushed sits until
the next event on the connection, so handlers that queue must flush.

## Things that surprise people

- **Two write paths, not one.** Bulk stream data goes through
  `send_stream_chunk_run/8`; everything else (ACKs, control frames, small
  writes) goes through `send_app_packet_internal/3`. They meet at
  `send_app_packet_now/3`.
- **Coalescing is a send-side field named `coalesce`**, distinct from
  `delivery_coalescing`, which is a receive-side owner-message option.
- **The queue is not FIFO.** It is eight buckets by urgency, and a requeued
  remainder goes to the front of its bucket rather than the back, so a partly
  sent chunk is not overtaken.
- **Counters are the contract.** `quic_regression_SUITE` gates on
  `packets_sent` and `retransmits`, never on a rate. If a change here moves
  packet counts, that gate is what notices.
