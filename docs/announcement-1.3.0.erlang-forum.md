<!-- erlang-forum.com follow-up to the 0.11.0 / hackney 4.0.0 thread.
     Discourse renders markdown; safe to paste verbatim. -->

# erlang_quic 1.3.0 — production-ready QUIC + HTTP/3

I am pleased to announce **erlang_quic 1.3.0**, the first
production-ready release of the library. The transport layer that
0.11.0 introduced is now paired with a complete HTTP/3 stack and a
formal RFC compliance matrix.

## What is in 1.3.0 that was not in 0.11.0

### A complete HTTP/3 stack

`quic_h3` ships server and client APIs for RFC 9114 with the full
pseudo-header rule set, GOAWAY, server push, and the entire HTTP/3
error-code surface. QPACK (RFC 9204) is implemented with the static
and dynamic tables, blocked-stream tracking, and the encoder and
decoder instruction streams. The eight-bucket priority scheduler is
fed by both the `priority` request header and `PRIORITY_UPDATE`
frames (RFC 9218).

```erlang
{ok, _} = quic_h3:start_server(my_h3, 4433, #{
    cert => Cert,
    key  => Key,
    handler => fun(Conn, StreamId, <<"GET">>, Path, _Headers) ->
        quic_h3:send_response(Conn, StreamId, 200,
            [{<<"content-type">>, <<"text/plain">>}]),
        quic_h3:send_data(Conn, StreamId, <<"hello ", Path/binary>>, true)
    end
}).
```

### HTTP/3 datagrams and extended CONNECT

RFC 9297 datagrams are wired in with the quarter-stream-id
multiplexing of `quic_h3:send_datagram/3`. Extended CONNECT (RFC 9220)
is the primitive on which the companion library
[`erlang-webtransport`][wt] builds its WebTransport-over-HTTP/3
implementation.

[wt]: https://github.com/benoitc/erlang-webtransport

### Companion libraries already on the new stack

- **[hackney 4.0.0](https://github.com/benoitc/hackney/releases/tag/4.0.0)**
  routes HTTP/3 through `quic_h3` with the unchanged
  `hackney:request/5` API.
- **erlang-webtransport** uses extended CONNECT, the bidirectional
  and unidirectional stream claim hook, and the H3 datagram dispatch.

### A compliance matrix

`docs/h3_compliance.md` maps every MUST and SHOULD in RFC 9114, 9204,
9218 and 9297 to a deterministic in-tree test that drives the state
machine directly. It is the readiness gate for any future PR that
touches `src/h3/` or `src/qpack/`. The 0.11.0 thread mentioned passing
the QUIC Interop Runner cases; the matrix extends that down to the
HTTP/3 layer and replaces the unmaintained external `h3spec` runner
that erlang_quic used to drive.

### User streams ("circuits") on the dist connection

The `-proto_dist quic` mode introduced in 0.11.0 has gained a
public `quic_dist:open_user_stream/2` API. Two nodes that already
talk dist can open extra QUIC streams over the same connection for
bulk transfer, low-latency RPC, or streaming subscriptions, with
their own flow control and error code, multiplexed alongside the
standard `gen_server:call` traffic without head-of-line blocking
between them.

```erlang
%% On node1@host1 — open a user stream to node2@host2.
{ok, StreamRef} = quic_dist:open_user_stream(node2@host2, self()),
ok = quic_dist:send(StreamRef, <<"chunk-1">>),
ok = quic_dist:send(StreamRef, <<"chunk-2">>, _Fin = true),

%% Owner receives:
%%   {quic_dist_stream, StreamRef, {data, Data, Fin}}
%%   {quic_dist_stream, StreamRef, closed}
```

## Versioning note

The bump from 0.x to 1.3.0 reflects the production-ready commitment
on the public API surface (`quic`, `quic_h3`, `quic_dist`,
`quic_qpack`, `quic_lb`). Internals under `src/` may continue to
move; the exposed APIs follow semver from this release on.

## Links

- Repository: https://github.com/benoitc/erlang_quic
- Release notes: https://github.com/benoitc/erlang_quic/releases/tag/v1.3.0
- Compliance matrix: https://github.com/benoitc/erlang_quic/blob/main/docs/h3_compliance.md
- Getting started: https://github.com/benoitc/erlang_quic/blob/main/docs/GETTING_STARTED.md
- Distribution guide: https://github.com/benoitc/erlang_quic/blob/main/docs/QUIC_DIST.md
- HTTP/3 guide: https://github.com/benoitc/erlang_quic/blob/main/docs/HTTP3.md

Pull as a rebar3 dependency, or activate the QUIC distribution mode
on a cluster. Issues and pull requests welcome on the tracker.
