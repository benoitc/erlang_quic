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
};

ERL_NIF_INIT(quic_crypto_nif, nif_funcs, load, NULL, NULL, NULL)
