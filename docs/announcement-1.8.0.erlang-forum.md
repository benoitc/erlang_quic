# erlang_quic 1.8.0

We have not posted here since 1.3.0, so here is a short update. Five minor releases later, the work went mostly into two directions: talking to real servers on the internet, and security.

## Security

In 1.4.4 we fixed a serious client bug: the client did not authenticate the server. `verify` was a no-op, so any certificate was accepted (CVE-2026-49457, reported by benmmurphy). The client now verifies the CertificateVerify signature, validates the chain against the trust store (OS store by default), and checks the hostname. `verify` is on by default for clients. The same release brought the result of a full security review: anti-amplification limit, Retry tokens with constant-time compare, PSK binder verification, single-use 0-RTT, AEAD usage-limit key update, connection and CRYPTO buffer caps, stricter HTTP/3 and QPACK decoding.

Servers can now do mutual TLS. With `verify => true` the client chain is validated, and `require_client_cert => true` rejects a client that sends no certificate.

## Interop with the real web

Many small fixes, each of them blocking a real server: QPACK prefix encoding now matches RFC 9204 so nghttp3 accepts our headers, the TLS flight is segmented so Chromium stops dropping it, cross-signed chains and expired cross-signed roots validate, wildcard SANs match, Version Negotiation and Retry follow the RFC, and `max_udp_payload_size` advertises what we can receive instead of 1500.

Concretely, you can now fetch `www.google.com` or `cloudflare.com` over HTTP/3 with the client.

## Transport

0-RTT works on both sides now, client and server, with `quic:early_data_accepted/1` to check what happened. IPv6 is supported for listeners and clients, with Happy Eyeballs (RFC 8305) racing on dual-stack hostnames. Stateless reset (RFC 9000 §10.3): a restarted server tells the peer the connection is gone instead of letting it wait for the idle timer.

On the TLS side: external PSK (RFC 8446 §4.2.11), so two nodes can authenticate with a shared secret and no certificates, HelloRetryRequest with `x25519` / `secp256r1` / `secp384r1`, and per-handshake signature selection including Ed25519.

## HTTP/3

`quic_h3:respond/5` sends status, headers and body in one call. A listener can pick its certificate per hostname with `sni_callback`, so one port serves several domains:

```erlang
{ok, _} = quic_h3:start_server(my_h3, 4433, #{
    sni_callback =>
        fun(<<"a.example.com">>) -> {ok, #{cert => CertA, key => KeyA}};
           (_)                   -> {ok, #{cert => CertB, key => KeyB}}
        end,
    handler =>
        fun(Conn, StreamId, <<"GET">>, Path, _Headers) ->
            quic_h3:respond(Conn, StreamId, 200,
                            [{<<"content-type">>, <<"text/plain">>}],
                            <<"hello ", Path/binary>>)
        end
}).
```

Responses coalesce the HEADERS frame with the first DATA frame, so small responses go out in one packet. Received bodies are no longer accumulated in the stream record.

## Distribution

Dist traffic is now spread over 16 streams, hashed by `{From, To}`, so a large message does not block the others while ordering per sender/receiver pair is preserved. `auth_callback` runs your own check between the QUIC handshake and the dist handshake, and closes the connection before the dist controller starts if it returns `{error, _}`. `priv/bin/quic_call.sh` is the `erl_call` equivalent for a `-proto_dist quic` cluster. The keep-alive is paced on `net_ticktime`, so a busy node is not declared down.

## Upgrading

One thing to check in 1.8.0: a handshake failure now reaches the owner as `{quic, Conn, {error, Reason}}`, tagged with the connection handle like every other event. If you matched `{quic, ConnRef, {error, _}}` before, match the handle instead. In return, `quic_h3:connect/3` gives you the real reason, for example `{error, {certificate_invalid, _}}` instead of a timeout.

Thanks to sstrollo, ycastorium, benmmurphy and maslowalex for the patches and the reports.

## Links

- Repository: https://github.com/benoitc/erlang_quic
- Release notes: https://github.com/benoitc/erlang_quic/releases/tag/1.8.0
- Changelog: https://github.com/benoitc/erlang_quic/blob/main/CHANGELOG.md
- Getting started: https://github.com/benoitc/erlang_quic/blob/main/docs/GETTING_STARTED.md
- HTTP/3 guide: https://github.com/benoitc/erlang_quic/blob/main/docs/HTTP3.md
- Distribution guide: https://github.com/benoitc/erlang_quic/blob/main/docs/QUIC_DIST.md

Issues and pull requests welcome.
