<!-- Twitter / X and Bluesky drafts for the 1.3.0 announcement.

     Twitter (free tier): 280 chars per post; URLs count as 23 chars.
     Bluesky: 300 chars per post; URLs count their actual length.

     Each block below is one post, ready to paste. Char counts noted
     as (Bluesky / Twitter), with URLs counted at their literal length
     for Bluesky and at 23 for Twitter.
-->

## Single post — Bluesky (300 char limit)

```
erlang_quic 1.3.0 is out.

First production-ready release of the pure-Erlang QUIC + HTTP/3 stack.

- RFC 9000 / 9001 (QUIC) + RFC 9114 / 9204 (HTTP/3, QPACK)
- Priorities, datagrams, extended CONNECT
- -proto_dist quic for Erlang clusters
- Zero C deps, OTP 27+

https://github.com/benoitc/erlang_quic
```

(~298 chars; URL counts at literal length on Bluesky.)

## Single post — Twitter (280 char limit, URLs count as 23)

```
erlang_quic 1.3.0 is out.

First production-ready release. Pure-Erlang QUIC + HTTP/3, zero C deps.

- RFC 9000 / 9001 + 9114 / 9204
- Priorities, datagrams, CONNECT
- -proto_dist quic for clusters
- OTP 27+

https://github.com/benoitc/erlang_quic
```

(~231 chars after URL shortening.)

---

## Four-post thread (more depth, same content as the article)

### 1/4

```
erlang_quic 1.3.0 is out, and it is the first production-ready release.

Pure-Erlang QUIC + HTTP/3, zero external dependencies, OTP 27+.

🧵 (1/4)
```

### 2/4 — protocol surface

```
What you get:

- RFC 9000 / 9001: header protection, three PN spaces, NewReno / Cubic / BBR, migration with NAT rebinding, datagrams (9221).
- RFC 9114 / 9204: full HTTP/3 server + client, QPACK with the dynamic table.
- Priorities (9218), HTTP datagrams (9297), extended CONNECT (9220).

(2/4)
```

### 3/4 — distribution and companion libs

```
-proto_dist quic ships Erlang distribution over QUIC.

Encrypted node links. No HoL blocking between unrelated streams. Migration on IP change. Per-node-pair user circuits over the same connection.

erlang-webtransport and hackney 4.0.0 already build on it.

(3/4)
```

### 4/4 — links

```
Conformance matrix maps every RFC 9114 / 9204 / 9218 / 9297 MUST and SHOULD to an in-tree state-machine test.

- Repo: https://github.com/benoitc/erlang_quic
- Notes: https://github.com/benoitc/erlang_quic/releases/tag/v1.3.0
- Matrix: https://github.com/benoitc/erlang_quic/blob/main/docs/h3_compliance.md

(4/4)
```

---

## Hashtags / mentions

Use sparingly; one or two on the first post is enough.

- #Erlang
- #QUIC
- #HTTP3
- #BEAM
- #OTP
- (Bluesky-specific) #erlang #quic via the hashtag system

@-mentions on Bluesky require the full handle (e.g. `@benoitc.bsky.social`); on Twitter the short handle works.

---

## Image attachment

Both platforms render the SVG-converted PNG fine.

Path: `docs/images/quic_dist_circuits.png` (1600 × 1013 px).

Attach to the **first post** in either format. Bluesky compresses to
WebP automatically. Twitter resizes to 1200 px wide; the diagram has
been redesigned with large text so it stays legible.
