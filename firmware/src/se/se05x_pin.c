/*
 * Cardea Key — PINs inside the NXP SE05x (issue #3, part B), for the se05x backend.
 *
 * Per PIN slot and generation the chip holds:
 *   A  an ECKey Authentication Object: the NIST P-256 public key of a private key derived from the
 *      PIN (and a per-device secret), with the slot's maximum of failed attempts. Policy: written
 *      and deleted only from its own session; NOT readable (a readable public key would let anyone
 *      test PINs offline).
 *   K  an HMAC-SHA256 key. Policy: SIGN only for A; DELETE for the default session (deleting it
 *      only destroys data, which is what a reset does).
 * Verifying a PIN = opening an ECKey session with A (AN12543 3.6.3.3): the RP2350 signs a template
 * with the PIN key, the chip checks the signature and counts the attempt; it never returns anything
 * computed from the PIN key, so there is nothing to test PINs against offline. Inside the session
 * the chip computes the slot secret, HMAC(K, "cardea/pin-kek" || slot): the same formula as the
 * "model" backend, so a slot migrated from the model keeps its secret (its K is loaded into the
 * chip) and nothing wrapped with it needs to change.
 *
 * Changing the PIN rewrites A's public key from A's session: same K, same secret. Setting a PIN
 * without the current one (first time, unblock, reset) creates a new generation (new A and K, new
 * secret): callers wrap again with the returned secret. The old K is deleted; an old A can only be
 * deleted from its own session, so one left behind (blocked, or PIN unknown) stays in the chip and
 * the generation skips its identifier.
 *
 * The session's commands travel SCP03-wrapped with the session keys, inside the Platform SCP03
 * channel (se_se05x.c). Host side ported from NXP Plug & Trust (fsl_sss_se05x_eckey.c,
 * se05x_tlv.c; BSD-3-Clause). Without a link: while no PIN has moved into the chip they stay in the
 * model's test store; once one has, PIN operations fail until the link is back.
 *
 * Pending on the real chip: creating Authentication Objects under Platform SCP03, reading the
 * ECKey session key 0x7FFF0201 without attestation, and creating the NIST P-256 curve object
 * first (the simulator pre-provisions it).
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS   /* ECP key pair fields, as the rest of pico-keys */
#include <stdio.h>
#include <string.h>

#include "cardea_se.h"
#include "se05x_internal.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

#include "picokeys.h"
#include "file.h"
#include "flash.h"
#include "random.h"

/* model's test PIN store (se_model.c with CARDEA_SE_MODEL_AS_PIN_STORE): fallback without a link,
 * and source of the migration */
bool cardea_se_model_pin_present(cardea_se_pin_slot_t slot);
int cardea_se_model_pin_set(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                            uint8_t secret[32]);
int cardea_se_model_pin_verify(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t secret[32],
                               uint8_t *remaining);
int cardea_se_model_pin_change(cardea_se_pin_slot_t slot, const uint8_t *old_pin, size_t old_len,
                               const uint8_t *new_pin, size_t new_len, uint8_t secret[32], uint8_t *remaining);
int cardea_se_model_pin_reset(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                              uint8_t secret[32]);
int cardea_se_model_pin_retries(cardea_se_pin_slot_t slot);
int cardea_se_model_pin_erase(cardea_se_pin_slot_t slot);
int cardea_se_model_export(cardea_se_pin_slot_t slot, uint8_t *max_retries, uint8_t key[32]);

/* ---- object identifiers: 'C' 'A' (authenticator) / 'C' 'K' (key), slot, generation */
#define ID_A(slot, gen) (0x43410000u | ((uint32_t)(slot) << 8) | (gen))
#define ID_K(slot, gen) (0x434B0000u | ((uint32_t)(slot) << 8) | (gen))
#define ECKEY_SESSION_ID 0x7FFF0201u   /* kSE05x_AppletResID_KP_ECKEY_USER */

#define POLICY_SIGN   0x10000000u
#define POLICY_WRITE  0x00100000u
#define POLICY_DELETE 0x00040000u

#define TAG_1 0x41
#define TAG_2 0x42
#define TAG_3 0x43
#define TAG_4 0x44
#define TAG_SESSION_ID 0x10
#define TAG_POLICY 0x11
#define TAG_MAX_ATTEMPTS 0x12

#define SW_OK 0x9000
#define SW_CONDITIONS 0x6985

static const uint8_t applet_aid[16] = { 0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
                                        0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 };

/* ---- current generation per slot, in flash (dynamic file in the range keyv2_glue.c protects from
 * the OpenPGP TERMINATE). Byte = generation + 1, 0 = slot not in the chip. Not secret: going back
 * only points at old or blocked objects. */
#define GEN_FID 0xEE08

static int gen_get(cardea_se_pin_slot_t slot) {
    file_t *f = file_search(GEN_FID);
    if (!f || !file_has_data(f) || file_get_size(f) != CARDEA_SE_PIN_SLOTS) {
        return -1;
    }
    uint8_t v = file_get_data(f)[slot];
    return v ? v - 1 : -1;
}

static int gen_put(cardea_se_pin_slot_t slot, int gen) {
    uint8_t v[CARDEA_SE_PIN_SLOTS] = { 0 };
    file_t *f = file_search(GEN_FID);
    if (f && file_has_data(f) && file_get_size(f) == CARDEA_SE_PIN_SLOTS) {
        memcpy(v, file_get_data(f), sizeof(v));
    }
    v[slot] = gen < 0 ? 0 : (uint8_t)(gen + 1);
    f = file_new(GEN_FID);
    if (!f || file_put_data(f, CONST_BYTE_ARRAY(v, sizeof(v))) != PICOKEYS_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    flash_commit();
    return CARDEA_SE_PIN_OK;
}

/* ---- small TLV writer (1-byte tags, lengths up to 0xFFFF) */
static void tlv_put(uint8_t *buf, size_t *i, uint8_t tag, const uint8_t *v, size_t len) {
    buf[(*i)++] = tag;
    if (len < 0x80) {
        buf[(*i)++] = (uint8_t)len;
    }
    else if (len < 0x100) {
        buf[(*i)++] = 0x81;
        buf[(*i)++] = (uint8_t)len;
    }
    else {
        buf[(*i)++] = 0x82;
        buf[(*i)++] = (uint8_t)(len >> 8);
        buf[(*i)++] = (uint8_t)len;
    }
    memcpy(buf + *i, v, len);
    *i += len;
}

static void tlv_put_u32(uint8_t *buf, size_t *i, uint8_t tag, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    tlv_put(buf, i, tag, b, 4);
}

/* First TLV with this 1-byte tag in rsp (lengths 1 byte or 0x81/0x82). */
static const uint8_t *tlv_find(const uint8_t *rsp, size_t len, uint8_t tag, size_t *vlen) {
    size_t i = 0;
    while (i + 2 <= len) {
        uint8_t t = rsp[i++];
        size_t l = rsp[i++];
        if (l == 0x81 && i < len) {
            l = rsp[i++];
        }
        else if (l == 0x82 && i + 1 < len) {
            l = ((size_t)rsp[i] << 8) | rsp[i + 1];
            i += 2;
        }
        if (i + l > len) {
            return NULL;
        }
        if (t == tag) {
            *vlen = l;
            return rsp + i;
        }
        i += l;
    }
    return NULL;
}

/* ---- the PIN key: d = (HMAC-SHA256(device key, slot || PIN) mod (n - 1)) + 1, on NIST P-256.
 * The device key comes from the root key (MKEK until #4), so the same PIN gives a different key on
 * every device. */
static int pin_keypair(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, mbedtls_ecp_keypair *kp,
                       uint8_t pub[65]) {
    uint8_t dev[32], seed[32], s = (uint8_t)slot;
    mbedtls_mpi n1, x;
    size_t olen = 0;
    int r = cardea_se_root_kdf((const uint8_t *)"cardea/pin-ec", 13, (const uint8_t *)"v1", 2, dev, sizeof(dev));
    if (r != 0) {
        memset(dev, 0, sizeof(dev));   /* no root key: same derivation, without the per-device part */
    }
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    r = mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (r == 0) r = mbedtls_md_hmac_starts(&md, dev, sizeof(dev));
    if (r == 0) r = mbedtls_md_hmac_update(&md, &s, 1);
    if (r == 0) r = mbedtls_md_hmac_update(&md, pin, pin_len);
    if (r == 0) r = mbedtls_md_hmac_finish(&md, seed);
    mbedtls_md_free(&md);
    mbedtls_platform_zeroize(dev, sizeof(dev));

    mbedtls_mpi_init(&n1);
    mbedtls_mpi_init(&x);
    if (r == 0) r = mbedtls_ecp_group_load(&kp->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (r == 0) r = mbedtls_mpi_read_binary(&x, seed, sizeof(seed));
    if (r == 0) r = mbedtls_mpi_sub_int(&n1, &kp->grp.N, 1);
    if (r == 0) r = mbedtls_mpi_mod_mpi(&kp->d, &x, &n1);
    if (r == 0) r = mbedtls_mpi_add_int(&kp->d, &kp->d, 1);
    if (r == 0) r = mbedtls_ecp_mul(&kp->grp, &kp->Q, &kp->d, &kp->grp.G, random_fill_iterator, NULL);
    if (r == 0) r = mbedtls_ecp_point_write_binary(&kp->grp, &kp->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65);
    mbedtls_mpi_free(&n1);
    mbedtls_mpi_free(&x);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return (r == 0 && olen == 65) ? 0 : -1;
}

/* ---- default-session commands (through Platform SCP03) */
static uint16_t cmd(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len, bool le,
                    uint8_t *rsp, size_t *rsp_len) {
    const uint8_t hdr[4] = { cla, ins, p1, p2 };
    return se05x_apdu(hdr, data, len, le, rsp, rsp_len);
}

static bool object_exists(uint32_t id) {
    uint8_t d[8], rsp[8];
    size_t i = 0, rl = sizeof(rsp), vl = 0;
    tlv_put_u32(d, &i, TAG_1, id);
    if (cmd(0x80, 0x04, 0x00, 0x27, d, i, true, rsp, &rl) != SW_OK) {   /* CheckObjectExists */
        return false;
    }
    const uint8_t *v = tlv_find(rsp, rl, TAG_1, &vl);
    return v && vl == 1 && v[0] == 0x01;
}

static uint16_t delete_object(uint32_t id) {
    uint8_t d[8];
    size_t i = 0;
    tlv_put_u32(d, &i, TAG_1, id);
    return cmd(0x80, 0x04, 0x00, 0x28, d, i, false, NULL, NULL);       /* DeleteSecureObject */
}

/* Failed attempts and maximum of an Authentication Object (ReadObjectAttributes). */
static int auth_counters(uint32_t id, uint16_t *attempts, uint16_t *max) {
    uint8_t d[8], rsp[128];
    size_t i = 0, rl = sizeof(rsp), vl = 0;
    tlv_put_u32(d, &i, TAG_1, id);
    if (cmd(0x80, 0x02, 0x00, 0x3B, d, i, true, rsp, &rl) != SW_OK) {
        return -1;
    }
    const uint8_t *a = tlv_find(rsp, rl, TAG_3, &vl);
    if (!a) {
        a = tlv_find(rsp, rl, TAG_2, &vl);
    }
    /* id (4), type (1), auth indicator (1, SET = 2), attempts (2), owner (4), maximum (2), ... */
    if (!a || vl < 14 || a[5] != 0x02) {
        return -1;
    }
    *attempts = (uint16_t)((a[6] << 8) | a[7]);
    *max = (uint16_t)((a[12] << 8) | a[13]);
    return 0;
}

static int se_eckey_pub(uint8_t pub[65]) {
    static uint8_t cached[65];
    static bool have;
    if (!have) {
        uint8_t d[8], rsp[160];
        size_t i = 0, rl = sizeof(rsp), vl = 0;
        tlv_put_u32(d, &i, TAG_1, ECKEY_SESSION_ID);
        if (cmd(0x80, 0x02, 0x00, 0x00, d, i, true, rsp, &rl) != SW_OK) {   /* ReadObject */
            return -1;
        }
        const uint8_t *v = tlv_find(rsp, rl, TAG_1, &vl);
        if (!v || vl != 65 || v[0] != 0x04) {
            return -1;
        }
        memcpy(cached, v, 65);
        have = true;
    }
    memcpy(pub, cached, 65);
    return 0;
}

/* ---- ECKey applet session */
typedef struct {
    uint8_t sid[8];
    se05x_scp_t scp;
} eck_t;

/* ProcessSessionCmd: the inner command (header, Lc, data) goes in TLV[TAG_1]. */
static uint16_t process(const eck_t *s, const uint8_t *inner, size_t inner_len, uint8_t *rsp, size_t *rsp_len) {
    static uint8_t d[600];
    size_t i = 0;
    if (inner_len + 16 > sizeof(d)) {
        return 0;
    }
    tlv_put(d, &i, TAG_SESSION_ID, s->sid, 8);
    tlv_put(d, &i, TAG_1, inner, inner_len);
    return cmd(0x80, 0x05, 0x00, 0x00, d, i, true, rsp, rsp_len);
}

/* Opens a session with A. Returns SW_OK, SW_CONDITIONS (wrong PIN or blocked) or 0 (error). */
static uint16_t eck_open(eck_t *s, uint32_t auth_id, mbedtls_ecp_keypair *pin_key) {
    uint8_t d[300], rsp[64], se_pub[65], eph_pub[65], hash[32], sig[MBEDTLS_ECDSA_MAX_LEN], shared[32], master[32];
    size_t i = 0, rl = sizeof(rsp), vl = 0, olen = 0, slen = 0;
    uint16_t sw = 0;
    mbedtls_ecp_keypair eph;
    mbedtls_ecp_point se_q;
    mbedtls_mpi z;
    memset(s, 0, sizeof(*s));
    mbedtls_ecp_keypair_init(&eph);
    mbedtls_ecp_point_init(&se_q);
    mbedtls_mpi_init(&z);

    if (se_eckey_pub(se_pub) != 0) {
        goto out;
    }
    /* CreateSession */
    tlv_put_u32(d, &i, TAG_1, auth_id);
    sw = cmd(0x80, 0x04, 0x00, 0x1B, d, i, true, rsp, &rl);
    const uint8_t *sid = sw == SW_OK ? tlv_find(rsp, rl, TAG_1, &vl) : NULL;
    if (!sid || vl != 8) {
        sw = sw == SW_OK ? 0 : sw;
        goto out;
    }
    memcpy(s->sid, sid, 8);

    /* ephemeral key pair and the signed part: A6 {AID, SCP params, key type, key length}, 7F49 {pub, curve} */
    if (mbedtls_ecp_group_load(&eph.grp, MBEDTLS_ECP_DP_SECP256R1) ||
        mbedtls_ecp_gen_keypair(&eph.grp, &eph.d, &eph.Q, random_fill_iterator, NULL) ||
        mbedtls_ecp_point_write_binary(&eph.grp, &eph.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, eph_pub, 65) || olen != 65) {
        sw = 0;
        goto out;
    }
    uint8_t *p = d + 5;                     /* room for the inner header and Lc */
    size_t n = 0;
    p[n++] = 0xA6;
    p[n++] = 2 + 16 + 2 + 3 + 2 + 1 + 2 + 1;
    p[n++] = 0x4F; p[n++] = 16; memcpy(p + n, applet_aid, 16); n += 16;
    p[n++] = 0x90; p[n++] = 3; p[n++] = 0xAB; p[n++] = 0x01; p[n++] = 0x33;   /* SCP03, level 0x33 */
    p[n++] = 0x80; p[n++] = 1; p[n++] = 0x88;                                  /* AES */
    p[n++] = 0x81; p[n++] = 1; p[n++] = 0x10;                                  /* 16 bytes */
    p[n++] = 0x7F; p[n++] = 0x49; p[n++] = 2 + 65 + 3;
    p[n++] = 0xB0; p[n++] = 65; memcpy(p + n, eph_pub, 65); n += 65;
    p[n++] = 0xF0; p[n++] = 1; p[n++] = 0x03;                                  /* NIST P-256 */
    size_t signed_len = n;
    if (mbedtls_sha256(p, signed_len, hash, 0) ||
        mbedtls_ecdsa_write_signature(pin_key, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), &slen,
                                      random_fill_iterator, NULL)) {
        sw = 0;
        goto out;
    }
    p[n++] = 0x5F; p[n++] = 0x37; p[n++] = (uint8_t)slen;
    memcpy(p + n, sig, slen);
    n += slen;
    /* inner ECKeySessionInternalAuthenticate, not wrapped (the session has no keys yet) */
    d[0] = 0x84; d[1] = 0x88; d[2] = 0x00; d[3] = 0x00; d[4] = (uint8_t)n;
    rl = sizeof(rsp);
    sw = process(s, d, 5 + n, rsp, &rl);
    if (sw != SW_OK) {
        goto out;                           /* 0x6985: wrong PIN key (counted) or blocked */
    }
    size_t rnd_len = 0, rec_len = 0;
    const uint8_t *rnd = tlv_find(rsp, rl, 0x85, &rnd_len);
    const uint8_t *receipt = tlv_find(rsp, rl, 0x86, &rec_len);
    if (!rnd || rnd_len != 16 || !receipt || rec_len != 16) {
        sw = 0;
        goto out;
    }
    /* shared secret = ECDH(ephemeral, SE key); master = SHA-256(00000001 || shared || rnd || 01 33 88 10)[0:16] */
    if (mbedtls_ecp_point_read_binary(&eph.grp, &se_q, se_pub, 65) ||
        mbedtls_ecdh_compute_shared(&eph.grp, &z, &se_q, &eph.d, random_fill_iterator, NULL) ||
        mbedtls_mpi_write_binary(&z, shared, sizeof(shared))) {
        sw = 0;
        goto out;
    }
    {
        mbedtls_sha256_context h;
        const uint8_t ctr[4] = { 0, 0, 0, 1 }, params[4] = { 0x01, 0x33, 0x88, 0x10 };
        mbedtls_sha256_init(&h);
        int r = mbedtls_sha256_starts(&h, 0);
        if (r == 0) r = mbedtls_sha256_update(&h, ctr, 4);
        if (r == 0) r = mbedtls_sha256_update(&h, shared, 32);
        if (r == 0) r = mbedtls_sha256_update(&h, rnd, 16);
        if (r == 0) r = mbedtls_sha256_update(&h, params, 4);
        if (r == 0) r = mbedtls_sha256_finish(&h, master);
        mbedtls_sha256_free(&h);
        uint8_t check[16];
        if (r || se05x_kdf(master, 0x04, 0x0080, NULL, 0, s->scp.s_enc) ||
            se05x_kdf(master, 0x06, 0x0080, NULL, 0, s->scp.s_mac) ||
            se05x_kdf(master, 0x07, 0x0080, NULL, 0, s->scp.s_rmac) ||
            se05x_kdf(master, 0x08, 0x0080, NULL, 0, s->scp.mcv) ||
            se05x_cmac(s->scp.s_rmac, p, signed_len, NULL, 0, NULL, 0, check) ||
            mbedtls_ct_memcmp(check, receipt, 16) != 0) {
            printf("SE: ECKey session receipt wrong\n");
            sw = 0;
            goto out;
        }
    }
    s->scp.counter[15] = 1;
    s->scp.on = true;
    sw = SW_OK;
out:
    mbedtls_ecp_keypair_free(&eph);
    mbedtls_ecp_point_free(&se_q);
    mbedtls_mpi_free(&z);
    mbedtls_platform_zeroize(shared, sizeof(shared));
    mbedtls_platform_zeroize(master, sizeof(master));
    if (sw != SW_OK) {
        mbedtls_platform_zeroize(&s->scp, sizeof(s->scp));
    }
    return sw;
}

/* One command inside the session: wrapped with the session keys (no Le inside), answer unwrapped.
 * Returns the SW (0 = error); rsp gets the plain data. */
static uint16_t eck_call(eck_t *s, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len,
                         bool le, uint8_t *rsp, size_t *rsp_len) {
    static uint8_t inner[400], out[400];
    const uint8_t hdr[4] = { cla, ins, p1, p2 };
    size_t il = sizeof(inner), ol = sizeof(out);
    if (!s->scp.on || se05x_scp_wrap(&s->scp, hdr, data, len, le, false, inner, &il) != 0) {
        return 0;
    }
    uint16_t sw = process(s, inner, il, out, &ol);
    if (sw == 0) {
        return 0;
    }
    if (sw != SW_OK) {
        uint8_t swb[2] = { (uint8_t)(sw >> 8), (uint8_t)sw };
        size_t two = 2;
        se05x_scp_unwrap(&s->scp, swb, &two);   /* errors come plain but advance the counter */
        return sw;
    }
    if (ol + 2 > sizeof(out)) {
        return 0;
    }
    out[ol] = 0x90;
    out[ol + 1] = 0x00;
    ol += 2;
    sw = se05x_scp_unwrap(&s->scp, out, &ol);
    if (sw == SW_OK && rsp && rsp_len) {
        if (ol - 2 > *rsp_len) {
            return 0;
        }
        memcpy(rsp, out, ol - 2);
        *rsp_len = ol - 2;
    }
    return sw;
}

static void eck_close(eck_t *s) {
    if (s->scp.on) {
        eck_call(s, 0x80, 0x04, 0x00, 0x1C, NULL, 0, false, NULL, NULL);   /* CloseSession */
    }
    mbedtls_platform_zeroize(s, sizeof(*s));
}

/* The slot secret, HMAC(K, "cardea/pin-kek" || slot), computed by the chip inside A's session. */
static int eck_secret(eck_t *s, cardea_se_pin_slot_t slot, uint32_t k_id, uint8_t secret[32]) {
    uint8_t d[40], rsp[48], label[15];
    size_t i = 0, rl = sizeof(rsp), vl = 0;
    memcpy(label, "cardea/pin-kek", 14);
    label[14] = (uint8_t)slot;
    tlv_put_u32(d, &i, TAG_1, k_id);
    tlv_put(d, &i, TAG_2, (const uint8_t[]){ 0x19 }, 1);   /* kSE05x_MACAlgo_HMAC_SHA256 */
    tlv_put(d, &i, TAG_3, label, sizeof(label));
    if (eck_call(s, 0x80, 0x03, 0x0D, 0x45, d, i, true, rsp, &rl) != SW_OK) {   /* MACOneShot */
        return -1;
    }
    const uint8_t *mac = tlv_find(rsp, rl, TAG_1, &vl);
    if (!mac || vl != 32) {
        return -1;
    }
    memcpy(secret, mac, 32);
    mbedtls_platform_zeroize(rsp, sizeof(rsp));
    return 0;
}

/* WriteECKey for A: creation (policy, maximum) or, from A's session, a new public key. */
static uint16_t write_auth(eck_t *s, uint32_t a_id, const uint8_t pub[65], uint8_t max_retries, bool create) {
    uint8_t d[120];
    size_t i = 0;
    if (create) {
        uint8_t pol[9] = { 8 };
        pol[1] = (uint8_t)(a_id >> 24); pol[2] = (uint8_t)(a_id >> 16); pol[3] = (uint8_t)(a_id >> 8); pol[4] = (uint8_t)a_id;
        uint32_t ar = POLICY_WRITE | POLICY_DELETE;   /* for itself only; no READ */
        pol[5] = (uint8_t)(ar >> 24); pol[6] = (uint8_t)(ar >> 16); pol[7] = (uint8_t)(ar >> 8); pol[8] = (uint8_t)ar;
        tlv_put(d, &i, TAG_POLICY, pol, sizeof(pol));
        tlv_put(d, &i, TAG_MAX_ATTEMPTS, (const uint8_t[]){ 0x00, max_retries }, 2);
    }
    tlv_put_u32(d, &i, TAG_1, a_id);
    tlv_put(d, &i, TAG_2, (const uint8_t[]){ 0x03 }, 1);  /* NIST P-256 */
    tlv_put(d, &i, TAG_4, pub, 65);
    /* INS_WRITE | INS_AUTH_OBJECT, P1_EC | P1_PUBLIC */
    return create ? cmd(0x80, 0x41, 0x21, 0x00, d, i, false, NULL, NULL)
                  : eck_call(s, 0x80, 0x41, 0x21, 0x00, d, i, false, NULL, NULL);
}

static uint16_t write_k(uint32_t k_id, uint32_t a_id, const uint8_t key[32]) {
    uint8_t d[80], pol[18];
    size_t i = 0;
    pol[0] = 8;
    pol[1] = (uint8_t)(a_id >> 24); pol[2] = (uint8_t)(a_id >> 16); pol[3] = (uint8_t)(a_id >> 8); pol[4] = (uint8_t)a_id;
    pol[5] = (uint8_t)(POLICY_SIGN >> 24); pol[6] = (uint8_t)(POLICY_SIGN >> 16); pol[7] = (uint8_t)(POLICY_SIGN >> 8); pol[8] = (uint8_t)POLICY_SIGN;
    pol[9] = 8;
    memset(pol + 10, 0, 4);                               /* default session */
    pol[14] = (uint8_t)(POLICY_DELETE >> 24); pol[15] = (uint8_t)(POLICY_DELETE >> 16); pol[16] = (uint8_t)(POLICY_DELETE >> 8); pol[17] = (uint8_t)POLICY_DELETE;
    tlv_put(d, &i, TAG_POLICY, pol, sizeof(pol));
    tlv_put_u32(d, &i, TAG_1, k_id);
    tlv_put(d, &i, TAG_3, key, 32);
    return cmd(0x80, 0x01, 0x05, 0x00, d, i, false, NULL, NULL);   /* WriteSymmKey, HMAC */
}

/*
 * New generation for the slot: A with the PIN key, K with this key (random, or the model's when
 * migrating), and the secret computed by the chip. The previous generation's K is deleted.
 */
static int provision(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                     const uint8_t *k_value, uint8_t secret[32]) {
    uint8_t pub[65], key[32];
    mbedtls_ecp_keypair kp;
    eck_t s;
    int old = gen_get(slot), gen = -1, ret = CARDEA_SE_PIN_ERROR;
    mbedtls_ecp_keypair_init(&kp);
    for (int g = 1; g <= 256; g++) {           /* next free identifier (left-behind A's are skipped) */
        int cand = ((old < 0 ? 0 : old) + g) & 0xFF;
        if (!object_exists(ID_A(slot, cand))) {
            gen = cand;
            break;
        }
    }
    if (gen < 0 || pin_keypair(slot, pin, pin_len, &kp, pub) != 0) {
        goto out;
    }
    if (k_value) {
        memcpy(key, k_value, 32);
    }
    else {
        random_fill_buffer(BYTE_ARRAY(key, sizeof(key)));
    }
    if (object_exists(ID_K(slot, gen))) {
        delete_object(ID_K(slot, gen));
    }
    if (write_auth(NULL, ID_A(slot, gen), pub, max_retries, true) != SW_OK) {
        printf("SE: creating the PIN authenticator failed\n");
        goto out;
    }
    if (write_k(ID_K(slot, gen), ID_A(slot, gen), key) != SW_OK || eck_open(&s, ID_A(slot, gen), &kp) != SW_OK) {
        goto out;
    }
    int r = eck_secret(&s, slot, ID_K(slot, gen), secret);
    eck_close(&s);
    if (r != 0 || gen_put(slot, gen) != CARDEA_SE_PIN_OK) {
        goto out;
    }
    if (old >= 0 && old != gen) {
        delete_object(ID_K(slot, old));     /* its A can only go from its own session: stays behind */
    }
    ret = CARDEA_SE_PIN_OK;
out:
    mbedtls_ecp_keypair_free(&kp);
    mbedtls_platform_zeroize(key, sizeof(key));
    return ret;
}

/* Remaining attempts of the slot's A, or < 0. */
static int remaining_of(cardea_se_pin_slot_t slot, int gen) {
    uint16_t attempts = 0, max = 0;
    if (auth_counters(ID_A(slot, gen), &attempts, &max) != 0) {
        return CARDEA_SE_PIN_ERROR;
    }
    return attempts >= max ? 0 : max - attempts;
}

/* Opens A's session with this PIN. CARDEA_SE_PIN_OK, _WRONG / _BLOCKED (with *remaining), _ERROR. */
static int open_with_pin(eck_t *s, cardea_se_pin_slot_t slot, int gen, const uint8_t *pin, size_t pin_len,
                         uint8_t *remaining) {
    uint8_t pub[65];
    mbedtls_ecp_keypair kp;
    int left = remaining_of(slot, gen), ret = CARDEA_SE_PIN_ERROR;
    if (left < 0) {
        return CARDEA_SE_PIN_ERROR;
    }
    if (left == 0) {
        if (remaining) *remaining = 0;
        return CARDEA_SE_PIN_BLOCKED;
    }
    mbedtls_ecp_keypair_init(&kp);
    if (pin_keypair(slot, pin, pin_len, &kp, pub) == 0) {
        uint16_t sw = eck_open(s, ID_A(slot, gen), &kp);
        if (sw == SW_OK) {
            ret = CARDEA_SE_PIN_OK;
            if (remaining) *remaining = (uint8_t)remaining_of(slot, gen);
        }
        else if (sw == SW_CONDITIONS) {
            left = remaining_of(slot, gen);
            if (remaining) *remaining = left < 0 ? 0 : (uint8_t)left;
            ret = CARDEA_SE_PIN_WRONG;
        }
    }
    mbedtls_ecp_keypair_free(&kp);
    return ret;
}

#ifdef CARDEA_SE_FALLBACK
/* Some PIN already lives in the chip: then, without a link, PIN operations fail instead of falling
 * back to the model's store (a PIN set there would no longer match the chip). */
static bool chip_in_use(void) {
    for (int i = 0; i < CARDEA_SE_PIN_SLOTS; i++) {
        if (gen_get((cardea_se_pin_slot_t)i) >= 0) {
            return true;
        }
    }
    return false;
}
#endif

/* No link: an error. Only with CARDEA_SE_FALLBACK (bench), the model's store while no PIN has moved
 * into the chip. */
#ifdef CARDEA_SE_FALLBACK
#define NO_LINK_OR(model_call) \
    do { \
        if (!se05x_ready()) { \
            if (chip_in_use()) { \
                return CARDEA_SE_PIN_ERROR; \
            } \
            return model_call; \
        } \
    } while (0)
#else
#define NO_LINK_OR(model_call) \
    do { \
        if (!se05x_ready()) { \
            return CARDEA_SE_PIN_ERROR; \
        } \
    } while (0)
#endif

static bool valid(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len) {
    return (unsigned)slot < CARDEA_SE_PIN_SLOTS && pin && pin_len > 0 && pin_len <= CARDEA_SE_PIN_MAX_LEN;
}

/* ---- the interface */
bool cardea_se_pin_managed(void) {
    return true;
}

bool cardea_se_pin_present(cardea_se_pin_slot_t slot) {
    if (!se05x_ready()) {
        return (unsigned)slot < CARDEA_SE_PIN_SLOTS && (gen_get(slot) >= 0 || cardea_se_model_pin_present(slot));
    }
    return (unsigned)slot < CARDEA_SE_PIN_SLOTS && (gen_get(slot) >= 0 || cardea_se_model_pin_present(slot));
}

int cardea_se_pin_set(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                      uint8_t secret[32]) {
    NO_LINK_OR(cardea_se_model_pin_set(slot, pin, pin_len, max_retries, secret));
    if (!valid(slot, pin, pin_len) || max_retries == 0 || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    int r = provision(slot, pin, pin_len, max_retries, NULL, secret);
    if (r == CARDEA_SE_PIN_OK) {
        cardea_se_model_pin_erase(slot);
    }
    return r;
}

/* A slot still in the model's store moves into the chip on its first correct PIN, keeping its K (so
 * its secret). */
static int migrate_from_model(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t secret[32],
                              uint8_t *remaining) {
    uint8_t max = 0, key[32];
    int r = cardea_se_model_pin_verify(slot, pin, pin_len, secret, remaining);
    if (r != CARDEA_SE_PIN_OK) {
        return r;
    }
    if (cardea_se_model_export(slot, &max, key) != CARDEA_SE_PIN_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    uint8_t chip_secret[32];
    r = provision(slot, pin, pin_len, max, key, chip_secret);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (r == CARDEA_SE_PIN_OK && mbedtls_ct_memcmp(chip_secret, secret, 32) != 0) {
        /* must not happen; undo, so the slot keeps working from the model's store */
        printf("SE: migrated PIN slot gives another secret; staying in the model store\n");
        int gen = gen_get(slot);
        if (gen >= 0) {
            delete_object(ID_K(slot, gen));
        }
        gen_put(slot, -1);
        r = CARDEA_SE_PIN_ERROR;
    }
    mbedtls_platform_zeroize(chip_secret, sizeof(chip_secret));
    if (r == CARDEA_SE_PIN_OK) {
        printf("SE: PIN slot %d moved into the chip\n", (int)slot);
        cardea_se_model_pin_erase(slot);
        if (remaining) *remaining = max;
    }
    return r;
}

int cardea_se_pin_verify(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t secret[32],
                         uint8_t *remaining) {
    NO_LINK_OR(cardea_se_model_pin_verify(slot, pin, pin_len, secret, remaining));
    if (!valid(slot, pin, pin_len) || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    int gen = gen_get(slot);
    if (gen < 0) {
        return cardea_se_model_pin_present(slot) ? migrate_from_model(slot, pin, pin_len, secret, remaining)
                                                 : CARDEA_SE_PIN_ERROR;
    }
    eck_t s;
    int r = open_with_pin(&s, slot, gen, pin, pin_len, remaining);
    if (r == CARDEA_SE_PIN_OK) {
        if (eck_secret(&s, slot, ID_K(slot, gen), secret) != 0) {
            r = CARDEA_SE_PIN_ERROR;
        }
        eck_close(&s);
    }
    return r;
}

int cardea_se_pin_change(cardea_se_pin_slot_t slot, const uint8_t *old_pin, size_t old_len, const uint8_t *new_pin,
                         size_t new_len, uint8_t secret[32], uint8_t *remaining) {
    NO_LINK_OR(cardea_se_model_pin_change(slot, old_pin, old_len, new_pin, new_len, secret, remaining));
    if (!valid(slot, old_pin, old_len) || !valid(slot, new_pin, new_len) || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    int gen = gen_get(slot);
    if (gen < 0) {
        /* still in the model: move it in with the old PIN, then change it in the chip */
        int r = migrate_from_model(slot, old_pin, old_len, secret, remaining);
        if (r != CARDEA_SE_PIN_OK) {
            return r;
        }
        gen = gen_get(slot);
    }
    eck_t s;
    int r = open_with_pin(&s, slot, gen, old_pin, old_len, remaining);
    if (r != CARDEA_SE_PIN_OK) {
        return r;
    }
    uint8_t pub[65];
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    if (pin_keypair(slot, new_pin, new_len, &kp, pub) != 0 || write_auth(&s, ID_A(slot, gen), pub, 0, false) != SW_OK ||
        eck_secret(&s, slot, ID_K(slot, gen), secret) != 0) {
        r = CARDEA_SE_PIN_ERROR;
    }
    mbedtls_ecp_keypair_free(&kp);
    eck_close(&s);
    return r;
}

int cardea_se_pin_reset(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                        uint8_t secret[32]) {
    NO_LINK_OR(cardea_se_model_pin_reset(slot, pin, pin_len, max_retries, secret));
    /* Without the current PIN A cannot be rewritten: new generation, new secret (the callers wrap
     * again with it). */
    return cardea_se_pin_set(slot, pin, pin_len, max_retries, secret);
}

int cardea_se_pin_retries(cardea_se_pin_slot_t slot) {
    NO_LINK_OR(cardea_se_model_pin_retries(slot));
    if ((unsigned)slot >= CARDEA_SE_PIN_SLOTS) {
        return CARDEA_SE_PIN_ERROR;
    }
    int gen = gen_get(slot);
    if (gen < 0) {
        return cardea_se_model_pin_retries(slot);
    }
    return remaining_of(slot, gen);
}

int cardea_se_pin_erase(cardea_se_pin_slot_t slot) {
    if ((unsigned)slot >= CARDEA_SE_PIN_SLOTS) {
        return CARDEA_SE_PIN_ERROR;
    }
    if (!se05x_ready()) {
#ifdef CARDEA_SE_FALLBACK
        if (gen_get(slot) >= 0) {
            return CARDEA_SE_PIN_ERROR;   /* its K is in the chip: cannot erase it now */
        }
        return cardea_se_model_pin_erase(slot);
#else
        return CARDEA_SE_PIN_ERROR;
#endif
    }
    cardea_se_model_pin_erase(slot);
    int gen = gen_get(slot);
    if (gen >= 0) {
        uint16_t sw = delete_object(ID_K(slot, gen));   /* the data it opened is gone; A stays behind */
        if (sw != SW_OK && object_exists(ID_K(slot, gen))) {
            return CARDEA_SE_PIN_ERROR;
        }
    }
    return gen_put(slot, -1);
}
