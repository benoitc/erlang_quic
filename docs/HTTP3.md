# HTTP/3 Documentation

This document covers the HTTP/3 implementation (RFC 9114) built on top of the QUIC transport layer.

## Overview

The HTTP/3 layer provides a high-level API for HTTP semantics over QUIC, including:

- Client connections and requests
- Server request handling
- Server push (RFC 9114 Section 4.6)
- QPACK header compression (RFC 9204)
- Graceful shutdown via GOAWAY

## Public API Reference

All functions are exported from the `quic_h3` module.

### Client API

#### connect/2, connect/3

Establish an HTTP/3 connection to a server.

```erlang
-spec connect(Host, Port) -> {ok, conn()} | {error, term()}.
-spec connect(Host, Port, Opts) -> {ok, conn()} | {error, term()}.
```

**Arguments:**
- `Host` - Hostname, IP address, or binary
- `Port` - TCP port number
- `Opts` - Connection options map

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sync` | boolean | `false` | Wait for H3 connection before returning |
| `connect_timeout` | integer | 5000 | Timeout in ms for sync connect |
| `cert` | binary | - | Client certificate (DER) |
| `key` | term | - | Client private key |
| `cacerts` | [binary()] | - | CA certificates for verification |
| `verify` | atom | - | `verify_none` or `verify_peer` |
| `settings` | map | - | HTTP/3 settings |
| `quic_opts` | map | - | Additional QUIC options |

**Example:**

```erlang
{ok, Conn} = quic_h3:connect("example.com", 443, #{sync => true}).
```

#### request/2, request/3

Send an HTTP request.

```erlang
-spec request(conn(), headers()) -> {ok, stream_id()} | {error, term()}.
-spec request(conn(), headers(), map()) -> {ok, stream_id()} | {error, term()}.
```

Opens a new request stream and sends the HEADERS frame. Returns the stream ID for tracking the response.

**Required pseudo-headers:**

| Header | Description |
|--------|-------------|
| `:method` | HTTP method (GET, POST, etc.) |
| `:scheme` | URL scheme (https) |
| `:path` | Request path |
| `:authority` | Host authority |

**Example:**

```erlang
Headers = [
    {<<":method">>, <<"GET">>},
    {<<":scheme">>, <<"https">>},
    {<<":path">>, <<"/">>},
    {<<":authority">>, <<"example.com">>}
],
{ok, StreamId} = quic_h3:request(Conn, Headers).
```

#### wait_connected/2

Block until the connection is established.

```erlang
-spec wait_connected(conn(), timeout()) -> ok | {error, timeout}.
```

Blocks until the connection is established and SETTINGS exchanged, or until the timeout expires.

### Shared API (Client and Server)

#### send_data/3, send_data/4

Send body data on a request stream.

```erlang
-spec send_data(conn(), stream_id(), binary()) -> ok | {error, term()}.
-spec send_data(conn(), stream_id(), binary(), boolean()) -> ok | {error, term()}.
```

For clients, this sends request body data. For servers, this sends response body data.
Set `Fin` to `true` to indicate the end of the body.

#### send_trailers/3

Send trailers on a request stream.

```erlang
-spec send_trailers(conn(), stream_id(), headers()) -> ok | {error, term()}.
```

Trailers are sent after the body and signal the end of the stream.

#### cancel/2, cancel/3

Cancel a stream.

```erlang
-spec cancel(conn(), stream_id()) -> ok.
-spec cancel(conn(), stream_id(), error_code()) -> ok.
```

Cancels the stream with `H3_REQUEST_CANCELLED` (default) or a specific error code.

#### goaway/1

Initiate graceful shutdown.

```erlang
-spec goaway(conn()) -> ok.
```

Sends a GOAWAY frame to the peer. No new requests will be accepted, but existing streams will complete.

#### close/1

Close the connection.

```erlang
-spec close(conn()) -> ok.
```

Immediately closes the HTTP/3 connection and underlying QUIC connection.

#### set_stream_handler/3, set_stream_handler/4

Register a handler to receive stream body data.

```erlang
-spec set_stream_handler(conn(), stream_id(), pid()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
-spec set_stream_handler(conn(), stream_id(), pid(), map()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
```

By default, body data messages are sent to the connection owner. For server handlers that need to receive body data (e.g., POST bodies), call this function to redirect data to the handler process.

The handler will receive messages of the form:
`{quic_h3, Conn, {data, StreamId, Data, Fin}}`

If data arrived before registration, it is returned as a list of `{Data, Fin}` tuples.

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `drain_buffer` | boolean | `true` | Return buffered data instead of sending as messages |

**Example:**

```erlang
handle_request(Conn, StreamId, <<"POST">>, _Path, _Headers) ->
    case quic_h3:set_stream_handler(Conn, StreamId, self()) of
        ok ->
            receive_body(Conn, StreamId, <<>>);
        {ok, BufferedChunks} ->
            Body = process_chunks(BufferedChunks),
            receive_body(Conn, StreamId, Body)
    end.
```

#### unset_stream_handler/2

Unregister a stream handler.

```erlang
-spec unset_stream_handler(conn(), stream_id()) -> ok.
```

Future data will be sent to the connection owner.

#### get_settings/1

Get local HTTP/3 settings.

```erlang
-spec get_settings(conn()) -> map().
```

#### get_peer_settings/1

Get peer HTTP/3 settings.

```erlang
-spec get_peer_settings(conn()) -> map() | undefined.
```

Returns `undefined` if SETTINGS has not been received yet.

### Server API

#### start_server/3

Start an HTTP/3 server.

```erlang
-spec start_server(Name, Port, Opts) -> {ok, pid()} | {error, term()}.
```

**Arguments:**
- `Name` - Server name (atom)
- `Port` - Listen port
- `Opts` - Server options map

**Options:**

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `cert` | binary | Yes | DER-encoded certificate |
| `key` | term | Yes | Private key |
| `handler` | fun/5 or module | No | Request handler |
| `settings` | map | No | HTTP/3 settings |
| `quic_opts` | map | No | Additional QUIC options |

The handler can be:
- A function: `fun(Conn, StreamId, Method, Path, Headers) -> ok`
- A module implementing `handle_request/5`

**Example:**

```erlang
{ok, _} = quic_h3:start_server(my_server, 4433, #{
    cert => CertDer,
    key => KeyTerm,
    handler => fun(Conn, StreamId, <<"GET">>, Path, _) ->
        Body = <<"Hello from ", Path/binary>>,
        quic_h3:send_response(Conn, StreamId, 200, []),
        quic_h3:send_data(Conn, StreamId, Body, true)
    end
}).
```

#### stop_server/1

Stop an HTTP/3 server.

```erlang
-spec stop_server(atom()) -> ok | {error, term()}.
```

#### send_response/4

Send an HTTP response (server only).

```erlang
-spec send_response(conn(), stream_id(), status(), headers()) -> ok | {error, term()}.
```

Sends the response status and headers. The body should be sent separately using `send_data/4`.

### Server Push API (RFC 9114 Section 4.6)

#### push/3

Initiate a server push (server only).

```erlang
-spec push(conn(), stream_id(), headers()) -> {ok, push_id()} | {error, term()}.
```

Sends a PUSH_PROMISE on the request stream and allocates a push ID.
Returns the push ID for subsequent `send_push_response`/`send_push_data` calls.

The Headers should contain the pseudo-headers for the pushed request:
`:method`, `:scheme`, `:authority`, and `:path`.

**Example:**

```erlang
{ok, PushId} = quic_h3:push(Conn, StreamId, [
    {<<":method">>, <<"GET">>},
    {<<":scheme">>, <<"https">>},
    {<<":authority">>, <<"example.com">>},
    {<<":path">>, <<"/style.css">>}
]).
```

#### send_push_response/4

Send response headers on a push stream (server only).

```erlang
-spec send_push_response(conn(), push_id(), status(), headers()) -> ok | {error, term()}.
```

After `push/3` returns a push ID, use this to send the response headers.

#### send_push_data/4

Send data on a push stream (server only).

```erlang
-spec send_push_data(conn(), push_id(), binary(), boolean()) -> ok | {error, term()}.
```

Set `Fin` to `true` to indicate this is the last data.

### Client Push API

#### set_max_push_id/2

Set the maximum push ID (client only).

```erlang
-spec set_max_push_id(conn(), push_id()) -> ok | {error, term()}.
```

This enables server push up to the specified push ID. Call this after connecting to allow the server to push resources. The MaxPushId cannot be decreased once set.

**Example:**

```erlang
%% Enable push with up to 10 promised resources (push IDs 0-9)
ok = quic_h3:set_max_push_id(Conn, 9).
```

#### cancel_push/2

Cancel a push (client only).

```erlang
-spec cancel_push(conn(), push_id()) -> ok.
```

Sends CANCEL_PUSH to tell the server we don't want this push. Can be called after receiving a `push_promise` notification.

### Extension Streams (stream_type_handler)

HTTP/3 layers extensions on top of unidirectional streams by assigning
them new type codepoints — WebTransport's `WT_STREAM` (varint `0x54`) is
the canonical example. By default, RFC 9114 §6.2.3 says the server MUST
ignore unknown types: the bytes are discarded and the stream is left
alone. Set `stream_type_handler` to take them over instead.

The handler is a function the connection calls whenever it sees a new
uni stream with a type it doesn't recognise:

```erlang
stream_type_handler => fun((uni, StreamId, VarintType) -> claim | ignore)
```

Return `claim` to take ownership of the stream, or `ignore` to fall back
to the default discard. The option can be passed to either
`quic_h3:connect/3` or `quic_h3:start_server/3`.

```erlang
Claim = fun
    (uni, _StreamId, 16#54) -> claim;   %% WebTransport WT_STREAM
    (_, _, _)               -> ignore
end,
{ok, _} = quic_h3:start_server(my_server, 4433, #{
    cert => Cert, key => Key,
    handler => fun my_http_handler/5,
    stream_type_handler => Claim
}).
```

Once a stream is claimed, the connection owner receives these events:

| Event | Description |
|-------|-------------|
| `{stream_type_open, uni, StreamId, VarintType}` | Claim accepted; no payload yet |
| `{stream_type_data, uni, StreamId, Data, Fin}` | Raw bytes received on the claimed stream |
| `{stream_type_closed, uni, StreamId}` | Peer closed the stream |

To send on a claimed stream, retrieve the QUIC connection with
`quic_h3:get_quic_conn/1` and call `quic:send_data/4` directly; H3 does
not frame or encode the payload.

Bidirectional streams go through the same claim hook. The handler is
consulted on the first varint of every peer-initiated bidi stream,
before HTTP/3 request parsing kicks in. WebTransport's
`WT_BIDI_SIGNAL` (varint `0x41`) is the canonical use:

```erlang
Claim = fun
    (uni,  _StreamId, 16#54) -> claim;   %% WT_STREAM
    (bidi, _StreamId, 16#41) -> claim;   %% WT_BIDI_SIGNAL
    (_, _, _)                -> ignore
end,
```

On claim, the owner sees bidi versions of the same events:

| Event | Description |
|-------|-------------|
| `{stream_type_open, bidi, StreamId, VarintType}` | Claim accepted; no payload yet |
| `{stream_type_data, bidi, StreamId, Data, Fin}` | Raw bytes on the claimed stream |
| `{stream_type_closed, bidi, StreamId}` | Peer closed the stream |
| `{stream_type_reset, bidi, StreamId, ErrorCode}` | Peer reset the stream with a non-zero code |
| `{stream_type_stop_sending, bidi, StreamId, ErrorCode}` | Peer sent STOP_SENDING |

On `ignore`, the bidi stream falls back to the HTTP/3 request path
exactly as if the hook had never fired — every buffered byte
(including the varint that was peeked) is replayed through the
request parser, so legitimate `HEADERS`-starting peers are
unaffected.

The same claimed-stream reset/stop_sending events fire on uni
streams too.

### Per-connection owner

By default every H3 connection spawned by `start_server/3` delivers
extension-stream events (claimed streams, H3 datagrams) to the single
process that called `start_server/3`. Extension libraries that host
many concurrent sessions on one listener can pick a dedicated owner
pid per H3 connection via the `connection_handler` option:

```erlang
{ok, _} = quic_h3:start_server(my_server, 4433, #{
    cert => Cert, key => Key,
    stream_type_handler => Claim,
    h3_datagram_enabled => true,
    connection_handler => fun(_QuicConnPid) ->
        #{owner => spawn(fun my_router:loop/0)}
    end
}).
```

The returned map's `owner`, `handler`, `stream_type_handler`,
`h3_datagram_enabled`, and `settings` keys replace the listener
defaults for that single connection; absent keys inherit.

#### `connection_handler` vs `set_stream_handler/3`

These solve different problems and compose rather than overlap.

- `set_stream_handler/3,4` reroutes the body `{data, StreamId, Data,
  Fin}` events of an *already-classified HTTP/3 request stream* to a
  chosen pid, returning any bytes buffered before registration. It
  only works on streams already present in the connection's request
  map; extension-claimed streams (WT uni `0x54`, WT bidi `0x41`)
  aren't request streams and can't be registered this way. Other
  events on the same request stream (`{request, ...}`,
  `{trailers, ...}`, `{stream_reset, ...}`) still reach the
  connection owner.
- `connection_handler` picks the *connection's* owner pid at
  construction, before any stream exists. Every connection-level
  event — `{connected, ...}`, `{request, ...}`,
  `{stream_type_*, ...}`, `{datagram, StreamId, ...}` — is routed to
  it. Use this to spawn one router process per H3 connection when
  hosting many concurrent extension sessions on a single listener.

A WebTransport or CONNECT-UDP server uses `connection_handler` to
create a per-connection router and then simply consumes
`{stream_type_*, ...}` or `{datagram, ...}` events directly.
`set_stream_handler` isn't involved unless the same connection is
also serving plain HTTP/3 requests whose bodies benefit from
streaming to a different process.

### HTTP Datagrams (RFC 9297)

Enable with `h3_datagram_enabled => true` on either
`quic_h3:connect/3` or `quic_h3:start_server/3`. The H3 layer then
advertises `SETTINGS_H3_DATAGRAM = 1`, and — unless you explicitly set
`max_datagram_frame_size` in your QUIC options — automatically opens
RFC 9221 datagram support with a 65535-byte cap. Both sides must
negotiate for the extension to go live; check with
`quic_h3:h3_datagrams_enabled/1`.

Each datagram is bound to a request stream via a quarter-stream-id
varint prefix; that encoding is applied automatically. Callers just
supply the stream id and payload:

```erlang
{ok, _} = quic_h3:start_server(my_server, 4433, #{
    cert => Cert, key => Key,
    handler => fun my_http_handler/5,
    h3_datagram_enabled => true
}).

%% Inside a handler, once you have a StreamId for the request:
ok = quic_h3:send_datagram(Conn, StreamId, <<"ping">>).
```

The owner process receives one event per inbound datagram:

| Event | Description |
|-------|-------------|
| `{datagram, StreamId, Payload}` | H3 datagram delivered on the given request stream |

Datagrams for unknown stream ids are dropped silently per RFC 9297 §5.
`quic_h3:max_datagram_size/2` reports the largest payload that fits
under the peer's cap minus the quarter-stream-id prefix. Everything
else — loss, congestion drops, PMTU clamping — surfaces as the
RFC 9221 error atoms from the QUIC layer (`datagram_too_large`,
`datagram_too_large_for_path`, `congestion_limited`, etc.).

This is the layer a CONNECT-UDP (RFC 9298) library builds on: once
HTTP Datagrams are live on an extended CONNECT stream, the library
adds its Context ID prefix and forwards UDP payloads through
`send_datagram/3`.

### Capsule Protocol (RFC 9297 §3.2)

RFC 9297 also defines a reliable framing for the request stream body
itself — capsules. A capsule is `Type(varint) | Length(varint) | Value`
and is the channel CONNECT-UDP uses for session-level signalling
distinct from unreliable datagrams.

`quic_h3_capsule` is a primitive codec; it does not own the request
stream body. Buffer bytes as they arrive and feed them to `decode/1`
until the result is no longer `{more, _}`:

```erlang
Encoded = quic_h3_capsule:encode(16#00, <<"payload">>),
{ok, {Type, Value, Rest}} = quic_h3_capsule:decode(iolist_to_binary(Encoded)).
```

Registered capsule type constants are in `include/quic_h3.hrl`:
`?H3_CAPSULE_DATAGRAM` (`0x00`) and `?H3_CAPSULE_LEGACY_DATAGRAM`
(`0xff37a0`). Unknown types are returned as their varint value so
extensions can claim their own codepoints.

### Building extension libraries

The primitives above are designed to support both WebTransport and
CONNECT-UDP (RFC 9298) as separate libraries. Here's which hook
each one relies on:

| Hook | WebTransport | CONNECT-UDP |
|------|--------------|-------------|
| Extended CONNECT (`enable_connect_protocol`) | `:protocol = webtransport` | `:protocol = connect-udp` |
| H3 datagrams (`h3_datagram_enabled`) | WT datagrams keyed by the CONNECT stream | UDP payloads keyed by the CONNECT stream + Context ID |
| Capsule codec (`quic_h3_capsule`) | `CLOSE_WEBTRANSPORT_SESSION`, `DRAIN_WEBTRANSPORT_SESSION` | RFC 9298 §3.5 DATAGRAM capsules |
| Bidi 0x41 claim (`stream_type_handler`) | `WT_BIDI_SIGNAL` on new peer-initiated bidi streams | not used — one extended-CONNECT bidi stream per session is all |
| Uni 0x54 claim (`stream_type_handler`) | `WT_STREAM` on new peer-initiated uni streams | not used |
| Per-connection owner (`connection_handler`) | Dedicated session manager per H3 connection | Dedicated session manager per H3 connection |
| Reset / STOP_SENDING (`stream_type_reset`, `stream_type_stop_sending`) | Propagates to WT stream FSM | Only fires on claimed streams, so unused by CONNECT-UDP |

A CONNECT-UDP server looks like:

```erlang
{ok, _} = quic_h3:start_server(udp_proxy, 443, #{
    cert => C, key => K,
    settings => #{enable_connect_protocol => 1},
    h3_datagram_enabled => true,
    connection_handler => fun(_) ->
        #{owner => spawn(fun udp_proxy_conn:loop/0)}
    end,
    handler => fun handle_connect_udp_request/5
}).
```

The per-connection owner process receives
`{quic_h3, Conn, {datagram, StreamId, Payload}}` and demultiplexes by
`StreamId` (= CONNECT request stream id). It decodes RFC 9298's
Context ID prefix out of `Payload`, then forwards the UDP bytes. Body
capsules on the same stream go through `quic_h3_capsule:decode/1`.
No `stream_type_handler` involvement at all.

A WebTransport server adds a `stream_type_handler` that claims uni
(`0x54`) and bidi (`0x41`) streams, mapping session-id bytes to its
own router. Same `connection_handler` + `h3_datagram_enabled`
pattern; the two extensions coexist on the same listener if needed.

### Messages to Owner

The connection owner process receives messages in the form `{quic_h3, Conn, Event}`.

#### Connection Events

| Event | Description |
|-------|-------------|
| `connected` | H3 connection established, SETTINGS exchanged |
| `goaway_sent` | GOAWAY sent, no new streams accepted |
| `{goaway, StreamId}` | GOAWAY received from peer |
| `{closed, Reason}` | Connection closed |

#### Request/Response Events

| Event | Description |
|-------|-------------|
| `{request, StreamId, Method, Path, Headers}` | Request received (server) |
| `{response, StreamId, Status, Headers}` | Response headers received (client) |
| `{data, StreamId, Data, Fin}` | Body data received |
| `{trailers, StreamId, Trailers}` | Trailers received |

#### Push Events

| Event | Description |
|-------|-------------|
| `{push_promise, PushId, RequestStreamId, Headers}` | Push promise received (client) |
| `{push_response, PushId, Status, Headers}` | Push response headers (client) |
| `{push_data, PushId, Data, Fin}` | Push response data (client) |
| `{push_complete, PushId}` | Push stream completed (client) |
| `{push_cancelled, PushId}` | Push was cancelled (client) |

#### Extension Stream Events

Emitted only when a `stream_type_handler` has claimed the stream — see
[Extension Streams](#extension-streams-stream_type_handler) above.

| Event | Description |
|-------|-------------|
| `{stream_type_open, uni, StreamId, VarintType}` | Extension claimed a new uni stream |
| `{stream_type_data, uni, StreamId, Data, Fin}` | Raw bytes on a claimed stream |
| `{stream_type_closed, uni, StreamId}` | Peer closed a claimed stream |

#### HTTP Datagram Events (RFC 9297)

Emitted only when `h3_datagram_enabled => true` was negotiated by both
sides — see [HTTP Datagrams (RFC 9297)](#http-datagrams-rfc-9297) above.

| Event | Description |
|-------|-------------|
| `{datagram, StreamId, Payload}` | H3 datagram delivered on the given request stream |

#### Error Events

| Event | Description |
|-------|-------------|
| `{stream_reset, StreamId, ErrorCode}` | Stream was reset |
| `{error, Reason}` | Connection error |

## Module Internals

### quic_h3_connection.erl

Core gen_statem implementing the HTTP/3 connection state machine.

**State Machine:**

```
              ┌────────────────┐
              │  awaiting_quic │
              └───────┬────────┘
                      │ QUIC connected
                      ▼
              ┌────────────────┐
              │  h3_connecting │
              └───────┬────────┘
                      │ SETTINGS exchanged
                      ▼
              ┌────────────────┐
      ┌───────│   connected    │───────┐
      │       └────────────────┘       │
      │ goaway sent              goaway received
      ▼                                ▼
┌─────────────┐                ┌───────────────┐
│ goaway_sent │                │goaway_received│
└──────┬──────┘                └───────┬───────┘
       │                               │
       └───────────┬───────────────────┘
                   ▼
              ┌─────────┐
              │ closing │
              └─────────┘
```

**Critical Streams:**

The connection manages three critical unidirectional streams:

| Stream | Purpose |
|--------|---------|
| Control | SETTINGS, GOAWAY, MAX_PUSH_ID frames |
| QPACK Encoder | Dynamic table update instructions |
| QPACK Decoder | Header acknowledgments |

**State Record Fields:**

| Field | Description |
|-------|-------------|
| `quic_conn` | Underlying QUIC connection pid |
| `role` | `client` or `server` |
| `owner` | Owner process pid |
| `local_settings` | Our HTTP/3 settings |
| `peer_settings` | Peer's HTTP/3 settings |
| `streams` | Map of active request streams |
| `push_streams` | Map of active push streams (server) |
| `blocked_streams` | Streams waiting for QPACK instructions |

### quic_h3_frame.erl

Frame encoding and decoding (RFC 9114 Section 7.2).

**Exports:**

| Function | Description |
|----------|-------------|
| `encode/1` | Encode any frame type |
| `encode_data/1` | Encode DATA frame |
| `encode_headers/1` | Encode HEADERS frame |
| `encode_settings/1` | Encode SETTINGS frame |
| `encode_goaway/1` | Encode GOAWAY frame |
| `encode_push_promise/2` | Encode PUSH_PROMISE frame |
| `encode_max_push_id/1` | Encode MAX_PUSH_ID frame |
| `encode_cancel_push/1` | Encode CANCEL_PUSH frame |
| `decode/1` | Decode single frame |
| `decode_all/1` | Decode all frames from buffer |
| `decode_stream_type/1` | Decode unidirectional stream type |
| `default_settings/0` | Get default HTTP/3 settings |

**Frame Types:**

| Type | Code | Description |
|------|------|-------------|
| DATA | 0x00 | Body data |
| HEADERS | 0x01 | QPACK-encoded headers |
| CANCEL_PUSH | 0x03 | Cancel a push |
| SETTINGS | 0x04 | Connection settings |
| PUSH_PROMISE | 0x05 | Push promise |
| GOAWAY | 0x07 | Graceful shutdown |
| MAX_PUSH_ID | 0x0D | Maximum push ID |

### quic_h3.hrl

Constants and record definitions.

**Key Records:**

```erlang
-record(h3_stream, {
    id :: non_neg_integer(),
    type :: request | push,
    state :: idle | open | half_closed_local | half_closed_remote | closed,
    method :: binary() | undefined,
    path :: binary() | undefined,
    headers = [] :: [{binary(), binary()}],
    trailers = [] :: [{binary(), binary()}],
    status :: non_neg_integer() | undefined,
    frame_state :: expecting_headers | expecting_data | expecting_trailers | complete
}).
```

**Settings Constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| `H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY` | 0x01 | QPACK dynamic table size |
| `H3_SETTINGS_MAX_FIELD_SECTION_SIZE` | 0x06 | Max header block size |
| `H3_SETTINGS_QPACK_BLOCKED_STREAMS` | 0x07 | Max blocked streams |
| `H3_SETTINGS_ENABLE_CONNECT_PROTOCOL` | 0x08 | Enable CONNECT protocol |

**Error Codes:**

| Constant | Value | Description |
|----------|-------|-------------|
| `H3_QPACK_DECOMPRESSION_FAILED` | 0x200 | QPACK decompression error |
| `H3_QPACK_ENCODER_STREAM_ERROR` | 0x201 | Encoder stream error |
| `H3_QPACK_DECODER_STREAM_ERROR` | 0x202 | Decoder stream error |

## Testing Guide

### Unit Tests (EUnit)

```bash
# Run all tests
rebar3 eunit

# Run specific test modules
rebar3 eunit --module=quic_h3_tests              # API tests
rebar3 eunit --module=quic_h3_frame_tests        # Frame encode/decode tests
rebar3 eunit --module=quic_h3_compliance_tests   # RFC 9114 compliance tests
rebar3 eunit --module=quic_h3_push_tests         # Server push tests
```

### Property Tests (PropEr)

```bash
# Run all property tests
rebar3 proper

# Run H3 frame property tests
rebar3 proper --module=quic_h3_frame_prop_tests
```

### E2E Tests (Common Test)

E2E tests require Docker containers for interoperability testing.

**Start Docker services:**

```bash
# Start H3 server for client tests
docker compose -f docker/docker-compose.yml up h3-server -d

# Start push-enabled server
docker compose -f docker/docker-compose.yml up h3-push-server -d
```

**Run tests:**

```bash
# Client E2E tests against aioquic server
H3_SERVER_HOST=127.0.0.1 H3_SERVER_PORT=4435 rebar3 ct --suite=quic_h3_e2e_SUITE

# Server tests with aioquic clients
rebar3 ct --suite=quic_h3_server_SUITE

# h3spec conformance tests
rebar3 ct --suite=quic_h3_h3spec_SUITE
```

**Docker Services:**

| Service | Port | Purpose |
|---------|------|---------|
| h3-server | 4435/udp | HTTP/3 server for client tests |
| h3-push-server | 4436/udp | HTTP/3 server with push support |
| aioquic-h3-client | - | Client tool for server tests |

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `H3_SERVER_HOST` | 127.0.0.1 | H3 test server host |
| `H3_SERVER_PORT` | 4435 | H3 test server port |
| `H3_PUSH_ENABLED` | - | Set to `1` for push server |

### Certificates

Generate test certificates before running E2E tests:

```bash
./certs/generate_certs.sh
```

This creates:
- `certs/cert.pem` - Server certificate
- `certs/priv.key` - Server private key

## Usage Examples

### Simple Client

```erlang
%% Connect and make a request
{ok, Conn} = quic_h3:connect("example.com", 443, #{sync => true}),

Headers = [
    {<<":method">>, <<"GET">>},
    {<<":scheme">>, <<"https">>},
    {<<":path">>, <<"/">>},
    {<<":authority">>, <<"example.com">>}
],
{ok, StreamId} = quic_h3:request(Conn, Headers),

%% Receive response
receive
    {quic_h3, Conn, {response, StreamId, Status, RespHeaders}} ->
        io:format("Status: ~p~nHeaders: ~p~n", [Status, RespHeaders])
end,

%% Receive body
receive
    {quic_h3, Conn, {data, StreamId, Body, true}} ->
        io:format("Body: ~s~n", [Body])
end,

quic_h3:close(Conn).
```

### POST Request with Body

```erlang
{ok, Conn} = quic_h3:connect("example.com", 443, #{sync => true}),

Headers = [
    {<<":method">>, <<"POST">>},
    {<<":scheme">>, <<"https">>},
    {<<":path">>, <<"/api/data">>},
    {<<":authority">>, <<"example.com">>},
    {<<"content-type">>, <<"application/json">>}
],
{ok, StreamId} = quic_h3:request(Conn, Headers),

%% Send body
quic_h3:send_data(Conn, StreamId, <<"{\"key\":\"value\"}">>, true),

%% Handle response...
```

### Simple Server

```erlang
Handler = fun(Conn, StreamId, Method, Path, Headers) ->
    case {Method, Path} of
        {<<"GET">>, <<"/">>} ->
            quic_h3:send_response(Conn, StreamId, 200, [
                {<<"content-type">>, <<"text/plain">>}
            ]),
            quic_h3:send_data(Conn, StreamId, <<"Hello, HTTP/3!">>, true);
        _ ->
            quic_h3:send_response(Conn, StreamId, 404, []),
            quic_h3:send_data(Conn, StreamId, <<"Not Found">>, true)
    end
end,

{ok, _} = quic_h3:start_server(my_server, 4433, #{
    cert => CertDer,
    key => KeyTerm,
    handler => Handler
}).
```

### Server Push

```erlang
Handler = fun(Conn, StreamId, <<"GET">>, <<"/page.html">>, _Headers) ->
    %% Push associated resources
    {ok, CssPushId} = quic_h3:push(Conn, StreamId, [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/style.css">>}
    ]),

    %% Send push response
    ok = quic_h3:send_push_response(Conn, CssPushId, 200, [
        {<<"content-type">>, <<"text/css">>}
    ]),
    ok = quic_h3:send_push_data(Conn, CssPushId, CssContent, true),

    %% Send main response
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"text/html">>}
    ]),
    quic_h3:send_data(Conn, StreamId, HtmlContent, true)
end.
```

### Client Receiving Push

```erlang
{ok, Conn} = quic_h3:connect("example.com", 443, #{sync => true}),

%% Enable server push
ok = quic_h3:set_max_push_id(Conn, 10),

%% Make request
{ok, _StreamId} = quic_h3:request(Conn, Headers),

%% Handle events
loop(Conn) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, Headers}} ->
            io:format("Response ~p: ~p~n", [StreamId, Status]),
            loop(Conn);
        {quic_h3, Conn, {push_promise, PushId, _ReqStreamId, Headers}} ->
            io:format("Push promised: ~p -> ~p~n", [PushId, Headers]),
            loop(Conn);
        {quic_h3, Conn, {push_response, PushId, Status, _Headers}} ->
            io:format("Push ~p response: ~p~n", [PushId, Status]),
            loop(Conn);
        {quic_h3, Conn, {push_data, PushId, Data, true}} ->
            io:format("Push ~p complete: ~p bytes~n", [PushId, byte_size(Data)]),
            loop(Conn);
        {quic_h3, Conn, {closed, _}} ->
            done
    end.
```

## Benchmarks

`test/quic_h3_bench.erl` exercises five sub-benchmarks against an
in-process server. Run via:

```bash
rebar3 as test shell
1> quic_h3_bench:run().
```

Latest run on Erlang/OTP 28, Apple M-series, loopback (single-core
loopback path; numbers are not network-representative and meant for
relative comparison across changes):

| Benchmark         | Result                                        |
|-------------------|-----------------------------------------------|
| connection_setup  | 100 iterations, p50 2.5 ms, p99 3.0 ms        |
| latency           | 1000/1000 GETs, p50 149 µs, p99 266 µs        |
| throughput        | 5 MiB POST + 5 MiB echo in 219 ms (45.7 MB/s) |
| concurrent        | 50/50 streams in 6 ms (8333 streams/s)        |
| qpack             | small encode 0.9 µs, large 33.8 µs, decode 36.9 µs |

Individual benchmarks can be invoked directly:

```erlang
quic_h3_bench:latency(1000).         % N requests on one connection
quic_h3_bench:throughput(5242880).   % POST + echo of N bytes
quic_h3_bench:concurrent(100).       % N in-flight streams
quic_h3_bench:connection_setup(100). % N fresh connections
quic_h3_bench:qpack_bench().         % header (de)compression micro-bench
```
