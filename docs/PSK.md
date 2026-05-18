# TLS 1.3 External PSK

This guide covers TLS 1.3 external pre-shared key (PSK) support for
QUIC connections, defined by [RFC 8446 §4.2.11][rfc8446-4-2-11].
External PSKs let two endpoints authenticate each other without
X.509 certificates by sharing a secret out of band.

This is **not** [RFC 9258][rfc9258] (the PSK Importer). The secret
you pass is consumed as raw IKM by the TLS key schedule; no
derivation is layered on top. If you need importer-style derivation
to bind a PSK to a target protocol/KDF, do it before handing the
secret to this library.

[rfc8446-4-2-11]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11
[rfc9258]: https://www.rfc-editor.org/rfc/rfc9258

## When to use it

[RFC 9257 §5.1][rfc9257-5-1] describes the typical use cases:

- Closed deployments where the operator controls both endpoints and
  PKI would just add ceremony (cluster nodes, service-mesh peers).
- Device-to-device authentication with pre-provisioned secrets.
- Environments without a certificate authority (lab gear, embedded
  devices, internal control planes).

[rfc9257-5-1]: https://www.rfc-editor.org/rfc/rfc9257#section-5.1

## Secret requirements

The PSK is consumed unchanged by HKDF, so you choose the entropy.

- Minimum 128 bits of entropy. Longer is fine.
- No truncation, no derivation. What you pass is what HKDF gets.
- Generate with `crypto:strong_rand_bytes/1` or your KMS.
- Keep secrets in a vault or KMS. This library does not store them.

## API

### Client

```erlang
{ok, Conn} = quic:connect(Host, Port, #{
    verify => false,
    alpn => [<<"echo">>],
    external_psk => {<<"client-id">>, <<"32-byte-shared-secret-...">>}
}, self()).
```

Two forms are accepted:

- `{Identity, Secret}`: defaults to mode `[psk_dhe_ke]`
  (forward-secret).
- `{Identity, Secret, Modes}`: explicit non-empty list of
  `psk_dhe_ke | psk_ke`. First match wins on the server.

`external_psk` and `session_ticket` are mutually exclusive. Passing
both yields `{error, {bad_opts, psk_conflict}}`.

### Server

```erlang
{ok, _} = quic:start_server(my_server, 4433, #{
    alpn => [<<"echo">>],
    %% Either or both:
    psks => #{<<"client-id">> => <<"32-byte-shared-secret-...">>},
    psk_callback => fun
        (<<"client-id">>) -> {ok, <<"32-byte-shared-secret-...">>};
        (_) -> not_found
    end
}).
```

Lookup order is `psk_callback` first, then `psks` map. Either or
both may be configured. They may coexist with `cert`/`key`. Without
PSK config and without `cert`/`key`, `start_server/3` returns
`{error, no_auth_method}`.

A callback that raises is treated as `not_found` and logged at
warning level. It will not crash the handshake.

## Modes

- **`psk_dhe_ke`** (default): PSK authentication with (EC)DHE.
  Forward-secret. Use this unless you have a specific reason not
  to.
- **`psk_ke`**: PSK only, no DHE. No forward secrecy. Use only on
  endpoints that cannot do DHE or when forward secrecy is
  explicitly out of scope.

## Downgrade protection

When a client supplies `external_psk`, it requires the server to
select that PSK. If the server's ServerHello does not echo the
expected `selected_psk_identity`, the client aborts with
`{error, psk_not_selected}` rather than completing a cert-based
handshake. This prevents silent fallback to an unauthenticated
cert path when `verify => false` is in effect.

## Mixed cert + PSK servers

A server configured with both certs and PSK selects per-handshake:

- Client offers a known PSK identity, binder verifies, compatible
  mode → server selects PSK.
- Client offers an unknown identity OR no compatible mode → server
  falls through to the cert path.
- Client offers a known identity but the binder fails to verify →
  fatal `decrypt_error` alert. The server does **not** fall
  through to cert in this case (silent downgrade prevention).

## v1 limitations

- No 0-RTT / `early_data` on external PSK. A client offering
  `external_psk` with `early_data` will have the `early_data`
  extension ignored by the server.
- `NewSessionTicket` is not emitted on PSK-authenticated
  handshakes. External PSK clients already hold a long-lived
  credential.

Both items are tracked as follow-ups in `docs/features.md`.

## Distribution

Erlang distribution over QUIC (`quic_dist`) supports PSK
authentication for certificate-less clustering. See
[QUIC_DIST.md](QUIC_DIST.md#psk-only-authentication).
