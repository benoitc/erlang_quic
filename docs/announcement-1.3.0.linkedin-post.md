<!-- LinkedIn feed-post version. ~900 chars. Plain text only;
     keep paragraph breaks but no markdown. Paste verbatim. -->

erlang_quic 1.3.0 is out — the first production-ready release of a pure-Erlang QUIC and HTTP/3 stack.

It implements RFC 9000 / 9001 (QUIC), RFC 9114 (HTTP/3), RFC 9204 (QPACK), plus extensible priorities (RFC 9218) and HTTP/3 datagrams (RFC 9297). No external dependencies, runs on stock OTP 27+.

Two things make it interesting:

• A full HTTP/3 stack: server and client APIs, full pseudo-header rules, server push, QPACK with dynamic table, and a compliance matrix mapping every MUST and SHOULD to an in-tree test.

• Erlang distribution over QUIC: a -proto_dist quic mode that replaces the standard TCP dist. Encrypted by default, no head-of-line blocking between unrelated streams, connection migration across IP changes, and per-node-pair circuits for bulk transfer or RPC alongside the dist control plane.

Full write-up, architecture, and code samples in the article below.

#Erlang #QUIC #HTTP3 #BEAM #OTP
