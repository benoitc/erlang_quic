# Contributing

This page is for people changing erlang_quic itself. For using the library, start with [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md). For finding your way around the source, read [docs/MODULE_MAP.md](docs/MODULE_MAP.md), and keep [docs/GLOSSARY.md](docs/GLOSSARY.md) open for the abbreviations.

## Write for the person who reads it

Every issue, pull request and comment is read by a person. Make it easy for
them.

- Read what you send before you send it. You are responsible for every line,
  whether you wrote it or a tool did.
- Use plain English and short sentences. Say what happens, what you
  expected, and how to reproduce it. Explain any term a reader may not know.
- Don't inflate it. No buzzwords, no severity scores, CVSS or CWE labels, no
  "critical" for a bug, no long generated write-ups. If it takes a page to
  explain, cut it down until it doesn't.
- A bug report gives: the erlang_quic and OTP versions, client or server,
  the options you set, the peer implementation, a minimal reproduction, what
  you got and what you expected. A packet capture with a key log
  (`SSLKEYLOGFILE`) helps most.
- A pull request says what was wrong and why it matters, the fix in a few
  lines, and any breaking change. Link the issue. Don't walk through the diff
  file by file; the reviewer reads the code.
- A fix comes with a test that fails without it.

AI tools are fine to use. Before you open anything, you must have read the
change, run the tests, and be able to answer questions about it yourself.

Maintainers read every issue and pull request before acting on it. We close
without further review:

- text we cannot understand after one request to clarify;
- descriptions that don't match the code or the reproduction;
- reports that cannot be reproduced;
- submissions opened by an automated agent that no person has read.

## Security issues and specification bugs

erlang_quic implements QUIC, TLS 1.3 for QUIC, HTTP/3, QPACK and the
extensions listed in [AGENTS.md](https://github.com/benoitc/erlang_quic/blob/main/AGENTS.md#specifications).

When the fix is to make erlang_quic do what one of these specifications says,
it is a bug, not a security issue. That includes reports described as
amplification, denial of service or a remote crash, when they come from:

- input accepted, rejected or framed differently from the specification;
- a wrong error code, close, reset or state transition;
- loss detection, congestion control, path validation or migration that
  does not follow the specification;
- a missing bound that the specification or an option defines.

Report these as a normal bug, in public. Cite the specification section. The
fix goes in a public pull request and in the CHANGELOG under Fixed. We don't
publish advisories or request CVEs for them, and advisories filed for them
are closed with a link to the fix.

Only problems that are not a specification deviation go through
[SECURITY.md](https://github.com/benoitc/erlang_quic/blob/main/SECURITY.md): code execution, a peer accepted without the
authentication the configuration asks for (certificates, hostnames, client
certificates, PSK and session tickets, distribution node authentication),
keys, secrets or one connection's data reaching someone else, or erlang_quic
weakening TLS below what the configuration allows.

## Keeping the specifications current

The specifications erlang_quic follows, and the version of each, are listed in
[AGENTS.md](https://github.com/benoitc/erlang_quic/blob/main/AGENTS.md#specifications),
with the newer versions not yet followed under Pending updates. The list is
checked before every release and when a module it names changes.

Moving to a new RFC or draft revision is its own pull request: first the
list of what changed in the sections the code uses, then one commit per
change with its test, then the Interop Runner against peers on both
revisions. The steps are in
[Keeping the specifications current](https://github.com/benoitc/erlang_quic/blob/main/AGENTS.md#keeping-the-specifications-current).
If you notice a spec has a newer version, open an issue naming it; that is
enough to get it on the list.

## Set up

You need Erlang/OTP 27 or later and rebar3. Nothing else is required to build: the library has no dependencies.

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
- Suites that exercise the OTP `socket` backend need GRO and per-message GSO,
  so they only run on Linux. From macOS or FreeBSD run them in a container
  instead: `docker/run-ct.sh quic_bulk_run_send_SUITE`. CI runs them natively.

Most end-to-end suites run in process against `test/quic_test_echo_server.erl`, so they need no containers. The suites that talk to other implementations do:

```bash
docker compose -f docker/docker-compose.yml up -d --wait
make test-docker
```

That brings up aioquic on 4433, quic-go on 4434, and HTTP/3 servers on 4435 and 4436. `test/quic_test_peer.erl` probes them with a Version Negotiation packet, so a suite skips only when a peer is genuinely down.

To reach `quic_connection` internals from a test, note that `quic_connection`, `quic_listener` and `quic_socket` compile with `export_all` under TEST. Do not add `-ifdef(TEST)` exports. State builders and accessors belong in `test/quic_connection_test_support.erl`.

macOS defers loopback UDP. On an otherwise idle pair of sockets, plain `gen_udp` had 10 of 120 datagrams arrive 106 to 600 ms after the send, while the same probe in the Linux container arrives within a millisecond every time. Inside a connection this reads as loss: the peer's socket counter stays flat, a probe goes out, and a retransmission repairs it.

So a test that has to pass on macOS must not assert how quickly a peer receives something. Assert what the sender did instead: `test/quic_api_frame_send_tests.erl` counts the datagrams a call writes to the socket, and `test/quic_socket_reuseaddr_tests.erl` reads socket options back. Where a test does have to wait for delivery, give it seconds, not hundreds of milliseconds.

To reproduce a race that only shows up under load, give the container one CPU:

```bash
docker run --rm --network host --privileged --cpus=1 \
  -v "$PWD":/app -v /app/_build -w /app quic-ct quic_dist_simultaneous_connect_SUITE
```

Handshake steps that normally finish in a millisecond then take tens of them, and orderings the scheduler usually hides become common. The QUIC distribution simultaneous-connect race failed about a third of these runs and never failed otherwise.

A test must fail for one reason. A denial test that also passes when the call crashes, or a test that asserts a value it computed itself, is worse than no test because it reads as coverage.

## What CI enforces

Twenty check runs per pull request:

| Job | What it proves |
|-----|----------------|
| Unit Tests (OTP 27, 28, 29) | `rebar3 eunit` and `rebar3 proper` across four OTP and Ubuntu combinations, and that the crypto NIF is not built by default |
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

A change to protocol code passes the three checks in [AGENTS.md](https://github.com/benoitc/erlang_quic/blob/main/AGENTS.md#first-principle-compliance-latest-spec-safety) before it is opened: compliance with the spec section, the spec being the current one, and safety against a hostile peer.

Say what the change is for and how it works. Skip the test inventory: CI reports that. If the change touches the public API, show it in a short code block.

Sync a branch that has fallen behind by merging `main` into it, not by rebasing.

## Releases

Version lives in `src/quic.app.src` and the drift test keeps the other copies honest. A release is a pull request that bumps it and adds the CHANGELOG entry, then an annotated tag on the merge commit with no `v` prefix, then a GitHub release carrying that CHANGELOG section.

Before opening the release pull request, check the specification list as described in [Keeping the specifications current](#keeping-the-specifications-current), and add any newer version found to Pending updates.
