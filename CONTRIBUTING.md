# Contributing

This page is for people changing erlang_quic itself. For using the library, start with [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md). For finding your way around the source, read [docs/MODULE_MAP.md](docs/MODULE_MAP.md), and keep [docs/GLOSSARY.md](docs/GLOSSARY.md) open for the abbreviations.

## Set up

You need Erlang/OTP 26 or later and rebar3. Nothing else is required to build: the library has no dependencies.

```bash
git clone --recursive https://github.com/benoitc/erlang_quic.git
cd erlang_quic
rebar3 compile
```

If you already cloned without `--recursive`, run `git submodule update --init`. The `test/qifs` submodule carries the QPACK interop corpus, and `quic_qpack_interop_SUITE` skips itself without it, so a missing submodule looks like a passing test rather than a failure.

Generate the test certificates once. Every Common Test suite that opens a connection needs them:

```bash
./certs/generate_certs.sh
```

## Before you commit

Run what CI runs. These are the checks that gate a pull request:

```bash
rebar3 fmt          # format first, then check the rest
rebar3 compile
rebar3 eunit        # includes quic_docs_drift_tests, see "Documentation" below
rebar3 proper
rebar3 fmt --check
rebar3 lint
rebar3 xref
rebar3 dialyzer
rebar3 ex_doc
```

`make test-static` runs the four static checks in one go. `make test-local` runs the unit, property and Common Test suites that need no Docker. `make test-all` adds the Docker suites.

## Tests

- `test/quic_*_tests.erl` are EUnit tests, run by `rebar3 eunit`.
- `test/prop_quic_*.erl` are PropEr properties, run by `rebar3 proper`.
- `test/quic_*_SUITE.erl` are Common Test suites, run one at a time with `rebar3 ct --suite=quic_e2e_SUITE`.

Most end-to-end suites run in process against `test/quic_test_echo_server.erl`, so they need no containers. The suites that talk to other implementations do:

```bash
docker compose -f docker/docker-compose.yml up -d --wait
make test-docker
```

That brings up aioquic on 4433, quic-go on 4434, and HTTP/3 servers on 4435 and 4436. `test/quic_test_peer.erl` probes them with a Version Negotiation packet, so a suite skips only when a peer is genuinely down.

To reach `quic_connection` internals from a test, note that `quic_connection`, `quic_listener` and `quic_socket` compile with `export_all` under TEST. Do not add `-ifdef(TEST)` exports. State builders and accessors belong in `test/quic_connection_test_support.erl`.

A test must fail for one reason. A denial test that also passes when the call crashes, or a test that asserts a value it computed itself, is worse than no test because it reads as coverage.

## What CI enforces

Twenty check runs per pull request:

| Job | What it proves |
|-----|----------------|
| Unit Tests (OTP 26, 27, 28, 29) | `rebar3 eunit` and `rebar3 proper` across five OTP and Ubuntu combinations, and that the crypto NIF is not built by default |
| macOS, FreeBSD | The NIF builds and loads there, and the suite passes with it on and off |
| E2E Tests | `quic_e2e_SUITE`, `quic_trusted_network_SUITE`, and the post-quantum suites on OTP 28.1 |
| Server Batching + Linux GSO | `quic_server_batching_SUITE` with GSO enabled, pinned to a kernel that supports it |
| Crypto NIF, Crypto NIF Fuzz (ASan) | The fused crypto paths, fuzzed under AddressSanitizer for all three ciphers |
| Performance Regression | `quic_regression_SUITE`, which gates on packet and retransmit counters, never on a rate |
| Distribution Tests | Real nodes speaking Erlang distribution over QUIC |
| HTTP/3 E2E Tests, Interop Tests | HTTP/3 end to end, and the compliance, reassembly and 0-RTT suites against the Docker peers |
| Dialyzer, XRef, erlfmt, Elvis lint, Docs | Static analysis, formatting, linting, and `rebar3 ex_doc` |

## Documentation

`rebar3 eunit` includes `test/quic_docs_drift_tests.erl`, which fails when the documentation stops matching the code. It checks that every option named in a docs table is read somewhere in `src`, that every `module:function/arity` mentioned is exported, that every suite named in a command exists, and that the version in `src/quic.app.src` agrees with the Makefile, SECURITY.md and the install snippets.

So when you rename an option or remove a function, the docs fail with the code. Fix them in the same change.

Write guides in the task-oriented style the existing ones use: say what the thing is, when you need it, then show the steps with short notes between code blocks.

## Pull requests

Branch from `main` using the prefix that fits: `fix/`, `feat/`, `perf/`, `refactor/`, `docs/`, `test/` or `chore/`.

Write the commit subject in the imperative, describing what the code now does rather than what it used to do. Keep the body to short bullets. Do not add generated-by or co-authored-by trailers.

Say what the change is for and how it works. Skip the test inventory: CI reports that. If the change touches the public API, show it in a short code block.

Sync a branch that has fallen behind by merging `main` into it, not by rebasing.

## Releases

Version lives in `src/quic.app.src` and the drift test keeps the other copies honest. A release is a pull request that bumps it and adds the CHANGELOG entry, then an annotated tag on the merge commit with no `v` prefix, then a GitHub release carrying that CHANGELOG section.
