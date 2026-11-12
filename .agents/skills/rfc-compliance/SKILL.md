---
name: rfc-compliance
description: Check a change, commit or pull request in erlang_quic against the RFCs it claims to follow (RFC 9000, 9001, 9002, 9221, 9287, 9368, 9369, 9846, 8899, drafts). Use when reviewing a PR, before merging a protocol fix, or when asked whether code complies with the spec.
---

# RFC compliance check

Use this to decide whether a change does what the spec says, no more and no less.
It applies to one commit at a time; a PR with several commits gets one verdict per commit.

## 1. Get the spec text

Never quote the RFC from memory. Fetch the plain text once and grep it:

```bash
mkdir -p "$SCRATCH/rfc" && cd "$SCRATCH/rfc"
for r in 9000 9001 9002 9221 9287 9368 9369 9846 8899; do
  [ -f rfc$r.txt ] || curl -sfL https://www.rfc-editor.org/rfc/rfc$r.txt -o rfc$r.txt
done
grep -n "MUST discard any subsequent Retry" rfc9000.txt
```

Drafts (reset_stream_at, multipath, QUIC-LB) come from datatracker.ietf.org; name the draft version you checked.

## 2. Check the claim

For each commit:

1. Find every RFC sentence the commit message or PR body quotes. Confirm it is verbatim and in the section cited.
2. Read the whole section around it, not only the sentence: exceptions, "unless", and the
   matching rule for the other role (client/server, sender/receiver) are usually a paragraph away.
3. Note the requirement level: MUST / MUST NOT is a fix; SHOULD needs a reason not to;
   MAY is a choice, so the change must say why it is worth it.
4. Check the error code and the action (discard, ignore, close with TRANSPORT_PARAMETER_ERROR,
   PROTOCOL_VIOLATION, FRAME_ENCODING_ERROR, ...) match the text exactly.
5. Check the code does what the text says on every path that reaches it: long and short
   headers, every packet number space, client and server, coalesced and batched datagrams,
   `idle`/`handshaking`/`connected`/`draining`.
6. Check it does not go further than the spec: a new MUST-close where the RFC says "MAY"
   or "SHOULD" breaks interop with peers that are allowed to do it.

## 3. Check the test

- The test fails on main without the fix and passes with it. Run it both ways.
- It asserts the outcome the spec names (the close code, the discard, the frame sent),
  and cannot also pass on a crash or a missing result.

## 4. Report

One line per commit:

```
<sha> <subject>
  spec: RFC 9000 §17.2.5.2 MUST, quote verified | quote not found | paraphrased
  verdict: compliant | partial (<what is missing>) | wrong (<why>) | not a spec item (<what it is>)
  test: fails before, passes after | does not discriminate | missing
```

Then list anything that needs the maintainer's decision (a SHOULD left out, a deliberate deviation).
