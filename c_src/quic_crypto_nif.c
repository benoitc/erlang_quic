/*
 * Batch/context AEAD NIF for erlang_quic.
 *
 * QUIC encrypts every ~1300-byte packet as its own AEAD unit. OTP's
 * crypto:crypto_one_time_aead/7 re-runs the key schedule on every
 * call, which dominates per-packet crypto cost on bulk transfers.
 * This NIF keeps an EVP_CIPHER_CTX per key as a NIF resource: the key
 * schedule runs once at context creation and each packet only resets
 * the nonce.
 *
 * Contexts are NOT thread-safe; a context must only be used from the
 * process that created it (one connection process in erlang_quic),
 * whose NIF calls are sequential.
 *
 * The pure-Erlang code path remains the fallback when this NIF is not
 * built or fails to load; see quic_aead_ctx.erl.
 */

#include <erl_nif.h>
#include <openssl/evp.h>
#include <string.h>

#define TAG_LEN 16
#define NONCE_LEN 12

typedef struct {
    EVP_CIPHER_CTX *ctx;
    int enc; /* 1 = seal, 0 = open */
} qc_ctx;

static ErlNifResourceType *qc_ctx_type;

static ERL_NIF_TERM am_ok;
static ERL_NIF_TERM am_error;
static ERL_NIF_TERM am_true;
static ERL_NIF_TERM am_false;
static ERL_NIF_TERM am_not_loaded;
static ERL_NIF_TERM am_badarg;

static void
qc_ctx_dtor(ErlNifEnv *env, void *obj)
{
    qc_ctx *c = (qc_ctx *)obj;
    (void)env;
    if (c->ctx != NULL) {
        EVP_CIPHER_CTX_free(c->ctx);
        c->ctx = NULL;
    }
}

static const EVP_CIPHER *
cipher_from_atom(ErlNifEnv *env, ERL_NIF_TERM atom)
{
    char name[32];
    if (enif_get_atom(env, atom, name, sizeof(name), ERL_NIF_LATIN1) == 0)
        return NULL;
    if (strcmp(name, "aes_128_gcm") == 0)
        return EVP_aes_128_gcm();
    if (strcmp(name, "aes_256_gcm") == 0)
        return EVP_aes_256_gcm();
    if (strcmp(name, "chacha20_poly1305") == 0)
        return EVP_chacha20_poly1305();
    if (strcmp(name, "aes_128_ecb") == 0)
        return EVP_aes_128_ecb();
    if (strcmp(name, "aes_256_ecb") == 0)
        return EVP_aes_256_ecb();
    return NULL;
}

/* new_aead_ctx(Cipher, Key, Enc) -> {ok, Ctx} | {error, Reason} */
static ERL_NIF_TERM
new_aead_ctx(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    const EVP_CIPHER *cipher;
    ErlNifBinary key;
    qc_ctx *c;
    ERL_NIF_TERM res;
    int enc;

    (void)argc;
    cipher = cipher_from_atom(env, argv[0]);
    if (cipher == NULL || enif_inspect_binary(env, argv[1], &key) == 0)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (enif_is_identical(argv[2], am_true))
        enc = 1;
    else if (enif_is_identical(argv[2], am_false))
        enc = 0;
    else
        return enif_make_tuple2(env, am_error, am_badarg);

    c = enif_alloc_resource(qc_ctx_type, sizeof(qc_ctx));
    c->ctx = EVP_CIPHER_CTX_new();
    c->enc = enc;
    if (c->ctx == NULL)
        goto fail;
    /* Set cipher + key once; nonce comes per packet. */
    if (EVP_CipherInit_ex(c->ctx, cipher, NULL, NULL, NULL, enc) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL) != 1)
        goto fail;
    if ((size_t)EVP_CIPHER_CTX_key_length(c->ctx) != key.size)
        goto fail;
    if (EVP_CipherInit_ex(c->ctx, NULL, NULL, key.data, NULL, enc) != 1)
        goto fail;

    res = enif_make_resource(env, c);
    enif_release_resource(c);
    return enif_make_tuple2(env, am_ok, res);

fail:
    enif_release_resource(c);
    return enif_make_tuple2(env, am_error, am_badarg);
}

/* new_hp_ctx(Cipher, Key) -> {ok, Ctx} | {error, Reason}
 * ECB context for AES header-protection mask generation. */
static ERL_NIF_TERM
new_hp_ctx(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    const EVP_CIPHER *cipher;
    ErlNifBinary key;
    qc_ctx *c;
    ERL_NIF_TERM res;

    (void)argc;
    cipher = cipher_from_atom(env, argv[0]);
    if (cipher == NULL || enif_inspect_binary(env, argv[1], &key) == 0)
        return enif_make_tuple2(env, am_error, am_badarg);

    c = enif_alloc_resource(qc_ctx_type, sizeof(qc_ctx));
    c->ctx = EVP_CIPHER_CTX_new();
    c->enc = 1;
    if (c->ctx == NULL)
        goto fail;
    if (EVP_EncryptInit_ex(c->ctx, cipher, NULL, NULL, NULL) != 1)
        goto fail;
    if ((size_t)EVP_CIPHER_CTX_key_length(c->ctx) != key.size)
        goto fail;
    if (EVP_EncryptInit_ex(c->ctx, NULL, NULL, key.data, NULL) != 1)
        goto fail;
    EVP_CIPHER_CTX_set_padding(c->ctx, 0);

    res = enif_make_resource(env, c);
    enif_release_resource(c);
    return enif_make_tuple2(env, am_ok, res);

fail:
    enif_release_resource(c);
    return enif_make_tuple2(env, am_error, am_badarg);
}

/* seal(Ctx, Nonce, AAD, Plain) -> CipherWithTag :: binary() | {error, _} */
static ERL_NIF_TERM
seal(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    qc_ctx *c;
    ErlNifBinary nonce, aad, plain;
    ERL_NIF_TERM out_term;
    unsigned char *out;
    int len = 0, len2 = 0;

    (void)argc;
    if (enif_get_resource(env, argv[0], qc_ctx_type, (void **)&c) == 0 || c->enc != 1 ||
        enif_inspect_binary(env, argv[1], &nonce) == 0 || nonce.size != NONCE_LEN ||
        enif_inspect_iolist_as_binary(env, argv[2], &aad) == 0 ||
        enif_inspect_iolist_as_binary(env, argv[3], &plain) == 0)
        return enif_make_tuple2(env, am_error, am_badarg);

    out = enif_make_new_binary(env, plain.size + TAG_LEN, &out_term);

    if (EVP_EncryptInit_ex(c->ctx, NULL, NULL, NULL, nonce.data) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (aad.size > 0 && EVP_EncryptUpdate(c->ctx, NULL, &len, aad.data, (int)aad.size) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (plain.size > 0 &&
        EVP_EncryptUpdate(c->ctx, out, &len, plain.data, (int)plain.size) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (EVP_EncryptFinal_ex(c->ctx, out + len, &len2) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, out + plain.size) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);

    return out_term;
}

/* open(Ctx, Nonce, AAD, CipherText, Tag) -> Plain :: binary() | error */
static ERL_NIF_TERM
open_(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    qc_ctx *c;
    ErlNifBinary nonce, aad, ct, tag;
    ERL_NIF_TERM out_term;
    unsigned char *out;
    int len = 0, len2 = 0;

    (void)argc;
    if (enif_get_resource(env, argv[0], qc_ctx_type, (void **)&c) == 0 || c->enc != 0 ||
        enif_inspect_binary(env, argv[1], &nonce) == 0 || nonce.size != NONCE_LEN ||
        enif_inspect_iolist_as_binary(env, argv[2], &aad) == 0 ||
        enif_inspect_iolist_as_binary(env, argv[3], &ct) == 0 ||
        enif_inspect_binary(env, argv[4], &tag) == 0 || tag.size != TAG_LEN)
        return enif_make_tuple2(env, am_error, am_badarg);

    out = enif_make_new_binary(env, ct.size, &out_term);

    if (EVP_DecryptInit_ex(c->ctx, NULL, NULL, NULL, nonce.data) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (aad.size > 0 && EVP_DecryptUpdate(c->ctx, NULL, &len, aad.data, (int)aad.size) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (ct.size > 0 && EVP_DecryptUpdate(c->ctx, out, &len, ct.data, (int)ct.size) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag.data) != 1)
        return enif_make_tuple2(env, am_error, am_badarg);
    if (EVP_DecryptFinal_ex(c->ctx, out + len, &len2) != 1)
        return am_error; /* authentication failure */

    return out_term;
}

/* hp_block(Ctx, Sample16) -> Block16 :: binary() | {error, _}
 * One ECB block for AES header protection. */
static ERL_NIF_TERM
hp_block(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    qc_ctx *c;
    ErlNifBinary sample;
    ERL_NIF_TERM out_term;
    unsigned char *out;
    int len = 0;

    (void)argc;
    if (enif_get_resource(env, argv[0], qc_ctx_type, (void **)&c) == 0 ||
        enif_inspect_binary(env, argv[1], &sample) == 0 || sample.size != 16)
        return enif_make_tuple2(env, am_error, am_badarg);

    out = enif_make_new_binary(env, 16, &out_term);
    if (EVP_EncryptUpdate(c->ctx, out, &len, sample.data, 16) != 1 || len != 16)
        return enif_make_tuple2(env, am_error, am_badarg);
    return out_term;
}

/* protect_run(AeadCtx, HpCtx, IV12, PN0, FirstByteBase, DCID, Payloads)
 *   -> [WirePacket] | {error, badarg}
 *
 * Seals a run of short-header packets with consecutive packet numbers
 * in one call. For I = 0..K-1 with PN = PN0 + I:
 *   PNLen   = 1..4 (smallest big-endian encoding of PN)
 *   header  = (FirstByteBase | (PNLen-1)) ++ DCID ++ PN[PNLen]
 *   nonce   = IV with PN xored into the low 64 bits
 *   body    = AEAD_seal(aead, nonce, header, Payload) ++ tag
 *   mask    = ECB(hp, body[4-PNLen .. +16])
 *   header protection: first byte ^= mask[0] & 0x1f (short header),
 *   PN bytes ^= mask[1..PNLen]
 * FirstByteBase must have the PN-length bits (0-1) clear. AES only -
 * the HP context is an ECB context; ChaCha callers use the per-packet
 * path.
 */
#define MAX_RUN 256

static ERL_NIF_TERM
protect_run(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    qc_ctx *aead, *hp;
    ErlNifBinary iv, dcid, plain;
    ErlNifUInt64 pn0;
    unsigned int fbase;
    ERL_NIF_TERM list, head, tail;
    ERL_NIF_TERM packets[MAX_RUN];
    unsigned k = 0, i;

    (void)argc;
    if (enif_get_resource(env, argv[0], qc_ctx_type, (void **)&aead) == 0 || aead->enc != 1 ||
        enif_get_resource(env, argv[1], qc_ctx_type, (void **)&hp) == 0 ||
        enif_inspect_binary(env, argv[2], &iv) == 0 || iv.size != NONCE_LEN ||
        enif_get_uint64(env, argv[3], &pn0) == 0 || enif_get_uint(env, argv[4], &fbase) == 0 ||
        fbase > 255 || enif_inspect_iolist_as_binary(env, argv[5], &dcid) == 0 ||
        dcid.size > 20)
        return enif_make_tuple2(env, am_error, am_badarg);

    list = argv[6];
    while (enif_get_list_cell(env, list, &head, &tail)) {
        ErlNifUInt64 pn = pn0 + k;
        unsigned char header[1 + 20 + 4];
        unsigned char nonce[NONCE_LEN];
        unsigned char mask[16], sample_off;
        unsigned pnlen, hlen;
        unsigned char *out, *body;
        ERL_NIF_TERM pkt;
        int len = 0, len2 = 0, mlen = 0;

        if (k >= MAX_RUN || enif_inspect_iolist_as_binary(env, head, &plain) == 0 ||
            plain.size < 4)
            return enif_make_tuple2(env, am_error, am_badarg);

        pnlen = (pn < 0x100) ? 1 : (pn < 0x10000) ? 2 : (pn < 0x1000000) ? 3 : 4;
        header[0] = (unsigned char)(fbase | (pnlen - 1));
        memcpy(header + 1, dcid.data, dcid.size);
        for (i = 0; i < pnlen; i++)
            header[1 + dcid.size + i] = (unsigned char)(pn >> (8 * (pnlen - 1 - i)));
        hlen = 1 + (unsigned)dcid.size + pnlen;

        memcpy(nonce, iv.data, NONCE_LEN);
        for (i = 0; i < 8; i++)
            nonce[NONCE_LEN - 1 - i] ^= (unsigned char)(pn >> (8 * i));

        out = enif_make_new_binary(env, hlen + plain.size + TAG_LEN, &pkt);
        memcpy(out, header, hlen);
        body = out + hlen;

        if (EVP_EncryptInit_ex(aead->ctx, NULL, NULL, NULL, nonce) != 1 ||
            EVP_EncryptUpdate(aead->ctx, NULL, &len, header, (int)hlen) != 1 ||
            EVP_EncryptUpdate(aead->ctx, body, &len, plain.data, (int)plain.size) != 1 ||
            EVP_EncryptFinal_ex(aead->ctx, body + len, &len2) != 1 ||
            EVP_CIPHER_CTX_ctrl(aead->ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN,
                                body + plain.size) != 1)
            return enif_make_tuple2(env, am_error, am_badarg);

        sample_off = (unsigned char)(4 - pnlen);
        if (EVP_EncryptUpdate(hp->ctx, mask, &mlen, body + sample_off, 16) != 1 || mlen != 16)
            return enif_make_tuple2(env, am_error, am_badarg);
        out[0] ^= mask[0] & 0x1f;
        for (i = 0; i < pnlen; i++)
            out[1 + dcid.size + i] ^= mask[1 + i];

        packets[k++] = pkt;
        list = tail;
    }
    if (!enif_is_empty_list(env, list))
        return enif_make_tuple2(env, am_error, am_badarg);

    return enif_make_list_from_array(env, packets, k);
}

static ERL_NIF_TERM
is_loaded(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    return enif_make_atom(env, "true");
}

static int
load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info)
{
    (void)priv;
    (void)info;
    qc_ctx_type = enif_open_resource_type(
        env, NULL, "quic_crypto_ctx", qc_ctx_dtor, ERL_NIF_RT_CREATE, NULL);
    if (qc_ctx_type == NULL)
        return -1;
    am_ok = enif_make_atom(env, "ok");
    am_error = enif_make_atom(env, "error");
    am_true = enif_make_atom(env, "true");
    am_false = enif_make_atom(env, "false");
    am_not_loaded = enif_make_atom(env, "not_loaded");
    am_badarg = enif_make_atom(env, "badarg");
    return 0;
}

static ErlNifFunc nif_funcs[] = {
    {"is_loaded", 0, is_loaded, 0},
    {"new_aead_ctx", 3, new_aead_ctx, 0},
    {"new_hp_ctx", 2, new_hp_ctx, 0},
    {"seal", 4, seal, 0},
    {"open", 5, open_, 0},
    {"hp_block", 2, hp_block, 0},
    {"protect_run", 7, protect_run, 0},
};

ERL_NIF_INIT(quic_crypto_nif, nif_funcs, load, NULL, NULL, NULL)
