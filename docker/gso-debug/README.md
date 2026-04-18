# GSO handshake-stall reproduction

Opt-in local tooling to reproduce `quic_server_batching_SUITE:server_download_uses_gso_on_linux/1` — the CT case that times out on Linux with `socket_backend => socket` (see PR #73 and the tracking notes in the plan). macOS can't reproduce it because the test guard skips on non-Linux; this container pins a real Linux kernel via Docker Desktop's VM and captures traffic alongside the run.

## Usage

One-shot run with packet capture (artifacts land under `docker/gso-debug/out/`):

```
docker compose -f docker/gso-debug/docker-compose.yml build
docker compose -f docker/gso-debug/docker-compose.yml run --rm gso-debug \
    bash docker/gso-debug/run-debug.sh
```

After the run, inspect:

- `docker/gso-debug/out/gso.pcap` — UDP traffic on `any` interface. `tcpdump -r ... -n -v` on the host.
- `docker/gso-debug/out/ct-logs/` — CT suite log tree; open `ct-logs/index.html` or grep the per-case `suite.log`.

Interactive iteration (edit source on host, re-run without rebuild — rebar3 recompiles in place on the bind mount):

```
docker compose -f docker/gso-debug/docker-compose.yml run --rm gso-debug bash
# inside:
QUIC_ENABLE_GSO_TEST=1 rebar3 ct --suite=quic_server_batching_SUITE
```

The container has `tcpdump`, `strace`, `iproute2`, and `netcat` available for ad-hoc probing.
