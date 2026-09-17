# The Receive Path

How a datagram becomes a message in the owner's mailbox. Read this before
changing anything in `quic_connection`'s receive regions, or when deliveries
arrive in an order you did not expect. Functions are named rather than located
by line, so this survives the file changing underneath it.

`docs/SEND_PATH.md` covers the other direction.

## The short version

```
socket or listener
  -> drain_recv_msgs/2                 take queued datagrams in one pass
     -> handle_packets_batch/2         anti-amplification accounting first
        -> do_handle_packets_batch/2   decrypt and parse each packet
           -> fold_opened/2            apply parsed packets to state
           -> stream_train/2           bulk fast path, if the run qualifies
              -> apply_stream_train/6  one state update for the whole train
           -> process_frame/3          otherwise: frame by frame
              -> do_process_stream_data_buffered/5   lean stream path
              -> do_process_stream_data_slow/5       reassembly path
        -> deliver_stream_train/3      hand data to the owner
     -> finish_recv_pass/1             one ACK decision per pass
```

## Stage by stage

**Arrival.** Server connections receive `{quic_packet, ...}` or
`{quic_packets, ...}` from the listener, which demultiplexes by connection ID.
Client connections receive `{udp, ...}` or `{udp_batch, ...}` from their own
socket. `drain_recv_msgs/2` pulls further queued datagrams out of the mailbox,
up to a cap, so one pass handles a burst.

**`handle_packets_batch/2`** accounts received bytes for anti-amplification
before anything else: until the peer's address is validated, we may send at
most three times what we received, and `amp_account_recv/2` is what makes that
budget real.

**`do_handle_packets_batch/2`** decrypts and parses. A coalesced datagram can
carry several packets; each is unprotected, decrypted with the keys for its
level, and parsed into frames. Packets that fail decryption are dropped, not
fatal: they may be stateless resets, or a key update we have not switched to.

**`fold_opened/2`** applies the parsed packets. It updates the packet number
space, ACK ranges, spin bit and activity in one `#state{}` update per run.

**`stream_train/2` and `apply_stream_train/6`** are the bulk fast path. When
every packet in the run carries exactly one stream frame, for the same stream,
at contiguous offsets, with no FIN and qlog off, the whole run becomes a single
stream-state and flow-control update instead of one per packet. On bulk flows
almost all frames land here.

**`process_frame/3`** is the general path: a clause per frame type, covering
ACK processing, flow control updates, stream data, connection IDs, path
validation, close, and the rest.

**`do_process_stream_data_buffered/5`** is the lean stream path: data arriving
in order, one stream-record update and one map put. **`_slow/5`** handles
everything else, including out-of-order data, where `quic_reassembly`'s
`gb_trees` buffer holds chunks until they are contiguous.

**Delivery.** `deliver_stream_train/3` and `deliver_stream_data/4` hand data to
the owner. With `delivery_coalescing` on and a receive pass active, consecutive
chunks of one stream merge into one message, flushed at the end of the pass or
as soon as another stream delivers, so arrival order across streams is
preserved and a reset never overtakes data sent before it.

**`finish_recv_pass/1`** closes the pass: one ACK decision for the batch rather
than one per packet, under the decimation policy.

## Things that surprise people

- **The pass, not the packet, is the unit.** ACK decisions, delivery flushes
  and timer re-arms happen once per pass. A change that moves work inside the
  per-packet loop instead of the pass boundary shows up as extra ACK traffic.
- **Two stream paths.** The lean one handles in-order bulk data; the slow one
  handles reassembly, flow-control window updates and limit violations.
- **Decryption failure is normal.** Stateless resets and packets from a
  retired key phase both look like garbage until identified.
- **`delivery_coalescing` is off by default**, because merging deliveries
  breaks owners that treat each message as one application message. QUIC gives
  no such guarantee, but the option is opt-in regardless.
