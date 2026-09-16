# Glossary

Abbreviations and local vocabulary you will meet in the source. Read this alongside [docs/MODULE_MAP.md](MODULE_MAP.md) when a variable name in `quic_connection` means nothing to you.

## Protocol terms

| Term | Meaning |
|------|---------|
| PN | Packet number. Each number space (Initial, Handshake, application) counts separately |
| PN space | One of the three independent packet number spaces, each with its own ACK state and keys |
| CID | Connection ID. The routing label in a packet header |
| DCID, SCID | Destination and source connection ID, as written in an outgoing packet |
| ODCID | Original destination connection ID, the one the client first used. It keys the Initial secrets and the Retry integrity tag |
| HP | Header protection. The mask applied over the packet number and flag bits, separate from payload encryption |
| AEAD | The authenticated cipher protecting a packet payload |
| PTO | Probe timeout. The timer that fires when nothing has been acknowledged, triggering a probe |
| RTT | Round-trip time. The code keeps a smoothed value, the latest sample, and a minimum |
| cwnd | Congestion window, in bytes. `ssthresh` is the slow-start threshold, BDP the bandwidth-delay product |
| ECN | Explicit congestion notification, the codepoints a router sets to signal congestion without dropping |
| PMTU | Path MTU. The largest datagram that crosses the path without fragmentation |
| HRR | HelloRetryRequest. The server asking the client for a key share it will accept |
| 0-RTT, early data | Application data sent with the first flight, using keys from a previous session |
| PSK, epsk | Pre-shared key, and an external one supplied by configuration rather than a prior session |
| Spin bit | A bit flipped once per round trip so passive observers can measure RTT |
| GSO, GRO | Linux offloads that send or receive many datagrams in one system call |
| RIC | Required Insert Count, a QPACK field prefix value saying which dynamic table entries a header block needs |
| Quarter stream id | A stream id divided by four, how HTTP/3 datagrams name their stream |

## This codebase's vocabulary

These are our words, not the RFC's.

| Term | Meaning |
|------|---------|
| Train | A batch of datagrams arriving as one message, typically from GRO. Processing a train in one pass amortizes the per-event work. See `stream_train/2` in `quic_connection` |
| Run | A sequence of packets that share a shape and can be handled in one step: contiguous stream data on the send side, uniform sizes for GSO. See `split_uniform_runs/1` in `quic_socket` |
| Opened | A packet that has been decrypted and parsed, before its frames are applied. `fold_opened/2` folds a list of them into the state |
| Recv pass | One trip through the receive path for a batch of packets. The `recv_pass` flag defers ACK and delivery work until the pass ends, so a train produces one flush rather than one per packet |
| pqueue | The send queue: a bucket per urgency level 0 to 7, RFC 9218 priorities |
| amp_rx, amp_tx | Bytes received from and sent to an unvalidated address. The anti-amplification limit caps `amp_tx` at three times `amp_rx` |
| Reclaimed stream | A closed stream whose state has been dropped, tracked so late frames for it are not mistaken for a new stream |
| Lean path | A fast path taken when nothing unusual applies, for example a bulk stream with both flow control windows wide open |
| Shared sender | One process per listener that writes to the socket for many connections, so sends batch together |
| Sink, download sink | Benchmark harness roles: the sink receives a bulk transfer, the download sink requests one |
