---
name: protocol-change-review
description: Run the three required checks (compliance, latest specification, safety) on an erlang_quic change, commit or pull request that touches QUIC packets or frames, transport parameters, TLS, loss detection or congestion control, streams, flow control, connection IDs, migration, HTTP/3, QPACK, datagrams, WebTransport primitives or QUIC distribution. Use before committing, before opening or merging a PR, when reviewing a contributor PR, and when asked whether code follows a spec.
---

# Protocol change review

erlang_quic talks to untrusted peers. A change is done when it matches the
spec, the spec is the current one, and a hostile peer cannot use it. Run the
three checks below on each commit; a PR with several commits gets one verdict
per commit. The spec list is in [AGENTS.md](../../../AGENTS.md#specifications).

## 1. Compliance

Follow the [rfc-compliance](../rfc-compliance/SKILL.md) skill: fetch the spec
text, check every quoted sentence and the section around it, the requirement
level, the error code and the action, and every path that reaches the code
(long and short headers, each packet number space, client and server,
coalesced datagrams, each connection state).

Then check the test:

- It fails on main and passes with the change. Use a worktree at the merge
  base, not `git stash`:

```bash
git worktree add ../erlang_quic_base origin/main
cp test/quic_x_tests.erl ../erlang_quic_base/test/
cd ../erlang_quic_base && rebar3 eunit --module=quic_x_tests
```

- It asserts the outcome the spec names (the close code, the frame sent, the
  discard) and cannot also pass on a crash or a missing result.

Suites to run (commands in [CONTRIBUTING.md](../../../CONTRIBUTING.md)):
`rebar3 eunit`, `rebar3 proper`, every Common Test suite in the Linux
container (`docker/run-ct.sh`), the Docker interop suites (`make test-docker`
with the peers up), the QUIC Interop Runner against erlang-quic and quic-go
(`make interop-image`, then `interop/run.sh` with the cases the change
touches plus handshake, transfer and http3), and for distribution changes the
`quic_dist` suites and `docker/dist/scripts/run_test.sh`.

## 2. Latest specification

1. Name the governing document and confirm it is current on
   https://datatracker.ietf.org/doc/rfcNNNN/ ("Obsoleted by", "Updated by"),
   or `https://www.rfc-editor.org/rfc/rfcNNNN.json`. Known replacements:
   RFC 8446 to RFC 9846, RFC 6125 to RFC 9525; RFC 9368 updates RFC 8999.
2. For a draft, check the latest revision on
   `https://datatracker.ietf.org/doc/draft-.../` and read the section in that
   revision: setting ids, frame types and error codes are what drifts between
   revisions.
3. Check for errata on https://www.rfc-editor.org/errata/rfcNNNN.
4. Write the version and the date checked in the PR description.
5. If the latest text disagrees with the code, fix it in the change or say in
   the PR that it is out of scope, and add it under "Pending updates" in
   AGENTS.md. Moving to a new version follows "Keeping the specifications
   current" there.

## 3. Safety

Walk the classes that apply and state which you checked.

- **Amplification**: the three-times limit before an address is validated
  (RFC 9000 §8.1), on the first path and on every new path; Retry and
  Version Negotiation sent only as the spec allows.
- **Connection hijack and spoofing**: stateless reset tokens, path
  validation before migration, connection ID retirement, a packet from a new
  address moving the path only when it is the newest non-probing one.
- **Resource exhaustion**: every per-connection and per-stream buffer, the
  CRYPTO buffer, out-of-order stream data, ACK ranges kept, connection IDs
  held, streams opened, datagram queues, HTTP/3 frame and field section sizes
  (checked while decoding, in linear time), QPACK dynamic table and blocked
  streams, unconsumed body bytes. A peer must not grow any of them without a
  bound set by the spec or an option.
- **Floods**: stream open and reset floods, PING and empty-frame floods,
  NEW_CONNECTION_ID / RETIRE_CONNECTION_ID churn, key updates faster than the
  spec allows, HTTP/3 frame floods on the control stream.
- **Crypto**: the AEAD integrity and confidentiality limits (RFC 9001 §6.6),
  key update order, header protection sample bounds, no secret in logs or
  error terms.
- **Authentication**: certificate chain and hostname checks, client
  certificates when the listener asks for them, PSK and session tickets bound
  to the listener that issued them, distribution node authentication.

Never weaken a limit to let a legitimate peer pass; exclude that case
precisely. A regression test for an attack drives it over a real connection
or through the decoder and asserts the bound or the close.

A finding from this check is a bug when its fix is to follow the spec, even
if it is an amplification, exhaustion or crash vector: public PR, CHANGELOG
under Fixed with the spec section, no advisory, no CVE, no attack
description. Authentication and key handling stay security issues. See
"Specification issues are bugs, not security issues" in AGENTS.md.

## Report

One block per commit, in the PR description or the hand-off:

```
<sha> <subject>
  spec: RFC 9000 §19.15 MUST, quote verified | not found | paraphrased
  latest: RFC 9000 current (checked 2026-11-08)
  verdict: compliant | partial (<missing>) | wrong (<why>) | not a spec item
  test: fails before, passes after | does not discriminate | missing
  interop: Interop Runner cases run, result
  safety: <classes checked>, <bounds>, no new unbounded state
```

Then list what needs the maintainer's decision: a SHOULD left out, a
deliberate deviation, a spec update that is out of scope.
