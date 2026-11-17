# OTP issue: crypto_one_time_aead_init/4 context caches survive key discard

This file records the investigation behind the context-disposal fix
(commit 1 of the key-lifecycle series). Keep it out of the release
notes; it is working notes, not documentation.

## The defect

`quic_aead_ctx:discard/1` erased only the process-dictionary entries
the NIF path creates: `{qc_enc, Cipher, KeyId}`, `{qc_dec, Cipher,
KeyId}`, `{qc_hp, HpCipher, KeyId}`, and pruned `qc_ctx_live`.

The default (no-NIF) path caches cipher contexts in two other
process-dictionary locations:

- `{aead_ctx, Cipher, Enc}` — a map of `KeyId => Ctx`, at most two
  entries per cipher and direction (`quic_aead:aead_ctx/3`);
- `{hp_ctx, EcbCipher}` — the same shape for header-protection ECB
  contexts (`quic_aead:ecb_ctx/2`).

Neither was touched by a discard, so the key schedules of every
discarded Initial, Handshake and key-update generation stayed live in
the connection process for the life of the cache.

Two aggravating details:

1. The `{aead_ctx, Cipher, Enc}` maps are keyed by cipher. Initial
   keys are always AES-128-GCM (RFC 9001 Section 5.2), so a
   connection negotiating AES-256-GCM or ChaCha20-Poly1305 never
   overwrites the Initial contexts through the two-entry eviction -
   they survive the whole connection.
2. The OTP two-entry policy clears the whole map to admit a third
   key (`map_size(Cache) >= 2 -> #{}`), so a forged packet using a
   third-generation key legitimately churns the cache. Tests must
   therefore assert retirement functionally (a late old-phase packet
   still decrypts, or no longer does), never byte-for-byte cache
   equality.

## The fix

`quic_aead:forget_ctx/4` (AEAD + HP) and `quic_aead:forget_aead_ctx/2`
(AEAD only, for key updates whose HP key the live generation shares)
remove the discarded keys' entries from the maps and erase a map once
it is empty. The cache shapes stay in `quic_aead`, the module that
owns them; `quic_aead_ctx:discard/1` and `discard_aead/1` call them.

## Test-path notes

- Forcing the fallback: `erlang:put(qc_nif, false)` in the calling
  process covers direct calls; a connection process caches its own
  flag, so E2E assertions read the connection's dictionary instead.
- The AEAD maps are populated only when
  `crypto:crypto_one_time_aead_init/4` exists (OTP 28+); the ECB map
  exists on OTP 27 too. Cipher tests therefore gate AEAD-map
  assertions on the API check and always assert the HP map.
- Header protection for ChaCha20-Poly1305 does not go through the ECB
  cache at all: `quic_aead:compute_hp_mask/3` calls `crypto_one_time`
  directly for it (RFC 9001 Section 5.4.4), and
  `quic_aead_ctx:hp_block/3` without the NIF crashes on a ChaCha
  cipher argument (`ecb_ctx` passes an empty IV to `crypto_init`).
  Production never reaches that path; tests route ChaCha HP through
  `compute_hp_mask/3` the way the packet path does.

## Pre-existing, unrelated

`quic_open_run_tests:open_run_empty_payload_test_` fails on this
machine with the NIF built (fused decode of an empty-payload packet
returns garbage frames that vary between runs); it passes without the
NIF and passes in a fresh worktree without one. Not touched by this
series; worth its own investigation against the NIF's empty-payload
handling on OTP 29.
