# QUIC Interop Runner

erlang_quic can be run in the [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner),
which tests QUIC implementations against each other over a simulated
network: handshakes, transfers, retry, resumption, 0-RTT, HTTP/3, QUIC v2,
key updates, and in the extended cases loss, corruption, ECN, IPv6,
rebinding and migration.

## The endpoint image

`interop/Dockerfile` builds one image for both roles, on the runner's
`martenseemann/quic-network-simulator-endpoint`. `run_endpoint.sh` starts
the interop client (`src/interop/quic_interop_client.erl`) or server
(`src/interop/quic_interop_server.erl`) depending on `ROLE`.

```bash
docker build -t erlang-quic-interop -f interop/Dockerfile .
```

A released image is published as `ghcr.io/benoitc/erlang_quic-interop`
by the `Interop image` workflow.

## Running the runner

```bash
make interop                                    # erlang_quic against itself, core cases
make interop INTEROP="-c quic-go,ngtcp2 -t extended"
interop/run.sh -s picoquic -c erlang-quic -t zerortt,resumption
```

`make interop` builds the image first; `interop/run.sh` uses the one
already built.

`-s` and `-c` take comma-separated names from the runner's
`implementations_quic.json`; `-t` takes test names, `core` or
`extended`; `-i` picks another image. The runner is cloned under
`_build/interop` at a pinned revision and runs in its own container, so
the host needs only Docker. Results go to `_build/interop/results/<time>`:
`result.json` and, per cell, the endpoints' logs, the simulator's pcaps
and the TLS key logs.

A failing cell is easiest to read from the pcap with the key log:

```bash
tshark -r sim/trace_node_left.pcap -o tls.keylog_file:server/keys.log -Y quic
```

The runner's own checks are in its `testcases_quic.py`; a red cell is
often a requirement there rather than in the RFC, such as a
PATH_CHALLENGE in the first packet on a new path.

## Listing on interop.seemann.io

[interop.seemann.io](https://interop.seemann.io) runs every listed
implementation against every other one daily. Joining takes a PR to the
runner adding `implementations.json`'s entry to its
`implementations_quic.json`, once the image is published.
