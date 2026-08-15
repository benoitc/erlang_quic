# Running on a Trusted Internal Network

This guide covers what you can and cannot turn off when every client
and server sits on the same internal subnet. The short answer is that
TLS stays on, but the PKI around it does not have to: you can skip
certificate validation, or drop certificates entirely and authenticate
with a shared secret. Read this when you are deploying inside a VPC,
a service mesh, or a lab network and do not want to run a CA.

## You cannot disable TLS

There is no option for it, in this library or in QUIC. Packet
protection is part of the transport, not a layer stacked on top of it
([RFC 9001 §3][rfc9001-3]):

- Every packet is AEAD-sealed and header-protected. Application data
  travels under 1-RTT keys derived from the TLS 1.3 handshake.
- Transport parameters are carried inside the TLS handshake, so
  connection setup has no cert-free path.

Initial packets are the one nuance: they are protected with keys
derived from the client's Destination Connection ID, which any
observer can compute. That protects against off-path injection, not
disclosure. Everything after the handshake keys are installed is
confidential.

A listener with neither certificates nor a PSK is refused up front:

```erlang
1> quic:start_server(my_server, 4433, #{alpn => [<<"echo">>]}).
{error,no_auth_method}
```

[rfc9001-3]: https://www.rfc-editor.org/rfc/rfc9001#section-3

## Skip certificate validation

Use this when you already have a certificate on the server (a
self-signed one is fine) and just do not want to distribute a CA to
clients. Clients validate by default, so this is opt-in.
`verify_none`, `none` and `false` all mean the same thing.

```erlang
{ok, Conn} = quic:connect(Host, Port, #{
    verify => verify_none,
    alpn => [<<"echo">>]
}, self()).
```

The server still needs a `cert` + `key` pair:

```erlang
{ok, _} = quic:start_server(my_server, 4433, #{
    cert => CertDer,
    key => KeyTerm,
    alpn => [<<"echo">>]
}).
```

Notes:

- Traffic is encrypted exactly as it would be with a validated chain.
- The client does not check who it is talking to. Anyone who can get
  packets to the client can present any certificate. Only do this
  where you trust the path.

## Drop certificates entirely

Use an external PSK ([RFC 8446 §4.2.11][rfc8446-4-2-11]) when you
control both ends and want no X.509 at all. Both sides share a secret
out of band, and both sides are authenticated by it.

Server:

```erlang
{ok, _} = quic:start_server(my_server, 4433, #{
    alpn => [<<"echo">>],
    psks => #{<<"node-a">> => Secret}
}).
```

Client:

```erlang
{ok, Conn} = quic:connect(Host, Port, #{
    verify => verify_none,
    alpn => [<<"echo">>],
    external_psk => {<<"node-a">>, Secret}
}, self()).
```

Notes:

- The secret is consumed as raw IKM by the TLS key schedule. Give it
  at least 128 bits of entropy, from `crypto:strong_rand_bytes/1` or
  your KMS.
- The default mode `psk_dhe_ke` keeps forward secrecy. `psk_ke` skips
  the (EC)DHE and drops it.
- `verify => verify_none` on the client does not weaken this. The
  client requires the server to select the offered PSK and aborts if
  it does not, so there is no silent fallback to an unverified cert.
- For per-identity lookup instead of a static map, use `psk_callback`.

Full guide: [PSK.md](PSK.md).

[rfc8446-4-2-11]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11

## Erlang distribution

The same rules apply. Distribution over QUIC runs the same handshake,
so it cannot run in cleartext either, and it accepts the same two ways
to shed PKI. A node configured with neither certificates nor a PSK
fails to start its listener with `{error, {credentials, no_credentials}}`.

`verify_none` is already the dist default. For a cert-free cluster,
give every node the same secret:

```erlang
%% sys.config
[
    {quic, [
        {dist, [
            {psks, #{<<"cluster">> => <<"32-byte-shared-secret-...">>}},
            {external_psk, {<<"cluster">>, <<"32-byte-shared-secret-...">>}},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, [
                {'node1@host1', {"192.168.1.1", 4433}},
                {'node2@host2', {"192.168.1.2", 4433}}
            ]}
        ]}
    ]}
].
```

`cert_file` / `key_file` may be omitted entirely. Per-peer identities
go through `quic_dist:set_connect_options/2`. See
[QUIC_DIST.md](QUIC_DIST.md#psk-only-authentication).

## Cost

The handshake negotiates `TLS_AES_128_GCM_SHA256`, which is the only
suite offered, so there is no cipher choice to tune. AES-GCM runs on
the AES-NI / ARM crypto extensions through OpenSSL on any current
server CPU. If throughput is the reason you wanted to drop TLS, see
[PERFORMANCE.md](PERFORMANCE.md): the cost that shows up in profiles
is packet handling and syscalls, not the AEAD.

## Verifying it

`test/quic_trusted_network_SUITE.erl` runs both configurations above
through a recording UDP relay and asserts the echoed payload appears
in no datagram in either direction:

```
rebar3 ct --suite=quic_trusted_network_SUITE
```

Cert-free distribution is covered by
`test/quic_dist_psk_SUITE.erl`.
