/*
 * Cardea Key — "se05x" backend of the secure-element interface: NXP SE05x (SE051C2) over I2C.
 *
 * Issue #12: open the T=1-over-I2C link, select the applet and read its version, using NXP Plug &
 * Trust without its SSS layer (only smCom/T1oI2C and the Se05x_API_* APDU layer).
 * Issue #5: every APDU after the handshake goes through Platform SCP03 (GlobalPlatform SCP03,
 * security level 0x33: command and response encrypted and MACed), implemented here with mbedTLS.
 * It follows NXP's host code (sss/src/se05x/fsl_sss_se05x_scp03.c and
 * hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c, BSD-3-Clause) for applets >= 4.3: the command
 * counter starts at 1 after EXTERNAL AUTHENTICATE and advances after every response.
 * Issue #4: the root key lives in the chip (HKDF inside it); see root_setup().
 * PINs (#3 part B): se05x_pin.c, with ECKey applet sessions on top of this channel.
 *
 * Without an SE on the bus, init fails cleanly and the key keeps working on the soft backend.
 */
#include <stdio.h>
#include <string.h>

#include "cardea_se.h"
#include "se05x_internal.h"

#include "sm_types.h"
#include "sm_api.h"
#include "se05x_tlv.h"
#include "se05x_APDU.h"
#include "smCom.h"

#include "pico/time.h"

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

/* soft backend, compiled with CARDEA_SE_SOFT_AS_FALLBACK (see se_soft.c) */
int cardea_se_soft_init(void);
bool cardea_se_soft_root_available(void);
int cardea_se_soft_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len);
void cardea_se_soft_random(uint8_t *out, size_t len);
bool cardea_se_bus_present(void);   /* nxp/pico_se05x_platform.c */

/*
 * Platform SCP03 static keys. Default: the SE051C2 factory keys that NXP publishes in Plug & Trust
 * (sss/ex/inc/ex_sss_tp_scp03_keys.h, SSS_PFSCP_ENABLE_SE051C2), key version 0x0B. Being public,
 * they authenticate and encrypt the link but do not keep out someone who has the bus: that needs
 * the chip's keys replaced by device-unique ones (a persistent change to the chip, not done in test
 * mode). A build can pass its own with CARDEA_SE_SCP03_ENC / _MAC / _KVN.
 */
#ifndef CARDEA_SE_SCP03_ENC
#define CARDEA_SE_SCP03_ENC { 0x88, 0xDB, 0xCD, 0x65, 0x82, 0x0D, 0x2A, 0xA0, 0x6F, 0xFA, 0xB9, 0x2A, 0xA8, 0xE7, 0x93, 0x64 }
#endif
#ifndef CARDEA_SE_SCP03_MAC
#define CARDEA_SE_SCP03_MAC { 0xA8, 0x64, 0x4E, 0x2A, 0x04, 0xD9, 0xE9, 0xC8, 0xC0, 0xEA, 0x60, 0x86, 0x68, 0x29, 0x99, 0xE5 }
#endif
#ifndef CARDEA_SE_SCP03_KVN
#define CARDEA_SE_SCP03_KVN 0x0B
#endif
static const uint8_t scp_static_enc[16] = CARDEA_SE_SCP03_ENC;
static const uint8_t scp_static_mac[16] = CARDEA_SE_SCP03_MAC;

static se05x_scp_t scp;   /* Platform SCP03 */

static struct {
    bool up;                 /* T=1 link open and applet selected */
    void *conn_ctx;
    Se05xSession_t session;
    uint8_t version[7];      /* applet version: major, minor, patch, then config/secure box bytes */
    size_t version_len;
} se;

/* ---- plain (unencrypted) APDU transport; the same logic as the SSS layer's sss_se05x_TXn and
 * sss_se05x_channel_txnRaw, without the rest of SSS. SCP03 replaces this in #5. */
static smStatus_t raw_txn(void *conn_ctx, struct _sss_se05x_tunnel_context *pChannelCtx, SE_AuthType_t currAuth,
                          const tlvHeader_t *hdr, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen,
                          uint8_t hasle) {
    static uint8_t txBuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t i = 0;
    (void)pChannelCtx;
    (void)currAuth;
    if (cmdBufLen > sizeof(txBuf) - sizeof(*hdr) - 5) {
        return SM_NOT_OK;
    }
    memcpy(&txBuf[i], hdr, sizeof(*hdr));
    i += sizeof(*hdr);
    if (cmdBufLen > 0) {
        if (cmdBufLen < 0xFF && !hasle) {
            txBuf[i++] = (uint8_t)cmdBufLen;
        }
        else {
            txBuf[i++] = 0x00;
            txBuf[i++] = 0xFFu & (cmdBufLen >> 8);
            txBuf[i++] = 0xFFu & cmdBufLen;
        }
        memcpy(&txBuf[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }
    else {
        txBuf[i++] = 0x00;
    }
    if (hasle) {
        txBuf[i++] = 0x00;
        txBuf[i++] = 0x00;
    }
    U32 rx = (U32)*rspLen;
    U32 status = smCom_TransceiveRaw(conn_ctx, txBuf, (U16)i, rsp, &rx);
    *rspLen = rx;
    return status == SMCOM_OK ? SM_OK : SM_NOT_OK;
}

/* ---- SCP03 primitives (AES-128) */
int se05x_cmac(const uint8_t key[16], const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
               const uint8_t *c, size_t c_len, uint8_t out[16]) {
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    int r = mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
    if (r == 0) r = mbedtls_cipher_cmac_starts(&ctx, key, 128);
    if (r == 0 && a_len) r = mbedtls_cipher_cmac_update(&ctx, a, a_len);
    if (r == 0 && b_len) r = mbedtls_cipher_cmac_update(&ctx, b, b_len);
    if (r == 0 && c_len) r = mbedtls_cipher_cmac_update(&ctx, c, c_len);
    if (r == 0) r = mbedtls_cipher_cmac_finish(&ctx, out);
    mbedtls_cipher_free(&ctx);
    return r;
}

static int aes_cbc(const uint8_t key[16], bool encrypt, const uint8_t iv_in[16], const uint8_t *in, uint8_t *out,
                   size_t len) {
    mbedtls_aes_context ctx;
    uint8_t iv[16];
    memcpy(iv, iv_in, sizeof(iv));
    mbedtls_aes_init(&ctx);
    int r = encrypt ? mbedtls_aes_setkey_enc(&ctx, key, 128) : mbedtls_aes_setkey_dec(&ctx, key, 128);
    if (r == 0) r = mbedtls_aes_crypt_cbc(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, iv, in, out);
    mbedtls_aes_free(&ctx);
    return r;
}

int se05x_kdf(const uint8_t key[16], uint8_t constant, uint16_t l_bits, const uint8_t *context, size_t context_len,
              uint8_t out[16]) {
    uint8_t dd[16];
    memset(dd, 0, 11);
    dd[11] = constant;
    dd[12] = 0x00;
    dd[13] = (uint8_t)(l_bits >> 8);
    dd[14] = (uint8_t)l_bits;
    dd[15] = 0x01;
    return se05x_cmac(key, dd, sizeof(dd), context, context_len, NULL, 0, out);
}

static int scp_kdf(const uint8_t key[16], uint8_t constant, uint16_t l_bits, const uint8_t context[16], uint8_t out[16]) {
    return se05x_kdf(key, constant, l_bits, context, 16, out);
}

static void scp_counter_inc(se05x_scp_t *st) {
    for (int i = 15; i > 0; i--) {
        if (++st->counter[i] != 0) {
            break;
        }
    }
}

static void scp_close(void) {
    mbedtls_platform_zeroize(&scp, sizeof(scp));
}

/* INITIALIZE UPDATE + EXTERNAL AUTHENTICATE, plain, right after the applet SELECT. 0 = channel up. */
static int scp_open(void) {
    uint8_t apdu[32], rsp[64], ctx[16], tmp[16];
    U32 rsp_len = sizeof(rsp);
    scp_close();

    apdu[0] = 0x80; apdu[1] = 0x50; apdu[2] = CARDEA_SE_SCP03_KVN; apdu[3] = 0x00; apdu[4] = 8;
    cardea_se_soft_random(ctx, 8);                       /* host challenge */
    memcpy(apdu + 5, ctx, 8);
    apdu[13] = 0x00;
    if (smCom_TransceiveRaw(se.conn_ctx, apdu, 14, rsp, &rsp_len) != SMCOM_OK) {
        return -1;
    }
    /* key diversification data (10) | key info (3) | card challenge (8) | card cryptogram (8) [| sequence (3)] | SW */
    if ((rsp_len != 31 && rsp_len != 34) || rsp[rsp_len - 2] != 0x90 || rsp[rsp_len - 1] != 0x00) {
        printf("SE: SCP03 INITIALIZE UPDATE refused (%u bytes, SW %02x%02x)\n", (unsigned)rsp_len,
               rsp_len >= 2 ? rsp[rsp_len - 2] : 0, rsp_len >= 2 ? rsp[rsp_len - 1] : 0);
        return -2;
    }
    memcpy(ctx + 8, rsp + 13, 8);                        /* context = host challenge || card challenge */
    if (scp_kdf(scp_static_enc, 0x04, 0x0080, ctx, scp.s_enc) || scp_kdf(scp_static_mac, 0x06, 0x0080, ctx, scp.s_mac) ||
        scp_kdf(scp_static_mac, 0x07, 0x0080, ctx, scp.s_rmac) || scp_kdf(scp.s_mac, 0x00, 0x0040, ctx, tmp)) {
        scp_close();
        return -3;
    }
    if (mbedtls_ct_memcmp(tmp, rsp + 21, 8) != 0) {
        printf("SE: SCP03 card cryptogram wrong (other keys?)\n");
        scp_close();
        return -4;
    }
    /* EXTERNAL AUTHENTICATE, security level 0x33; its MAC chains from 16 zero bytes */
    apdu[0] = 0x84; apdu[1] = 0x82; apdu[2] = 0x33; apdu[3] = 0x00; apdu[4] = 16;
    if (scp_kdf(scp.s_mac, 0x01, 0x0040, ctx, tmp)) {
        scp_close();
        return -3;
    }
    memcpy(apdu + 5, tmp, 8);                            /* host cryptogram */
    memset(scp.mcv, 0, sizeof(scp.mcv));
    if (se05x_cmac(scp.s_mac, scp.mcv, 16, apdu, 13, NULL, 0, scp.mcv)) {
        scp_close();
        return -3;
    }
    memcpy(apdu + 13, scp.mcv, 8);
    rsp_len = sizeof(rsp);
    if (smCom_TransceiveRaw(se.conn_ctx, apdu, 21, rsp, &rsp_len) != SMCOM_OK || rsp_len != 2 || rsp[0] != 0x90 || rsp[1] != 0x00) {
        printf("SE: SCP03 EXTERNAL AUTHENTICATE refused\n");
        scp_close();
        return -5;
    }
    memset(scp.counter, 0, sizeof(scp.counter));
    scp.counter[15] = 1;
    scp.on = true;
    return 0;
}

/* Wraps a command: data padded and encrypted (C-DEC), CLA | 0x04, Lc covering the MAC, C-MAC. */
int se05x_scp_wrap(se05x_scp_t *st, const uint8_t hdr[4], const uint8_t *cmd, size_t cmd_len, bool has_le,
                   bool append_le, uint8_t *out, size_t *out_len) {
    size_t enc_len = cmd_len ? (cmd_len / 16 + 1) * 16 : 0;
    size_t lc = enc_len + 8;
    size_t lcw = (lc < 0xFF && !has_le) ? 1 : 3;
    size_t i = 0;
    if (4 + lcw + lc + 2 > *out_len) {
        return -1;
    }
    memcpy(out, hdr, 4);
    out[0] |= 0x04;
    i = 4;
    if (lcw == 1) {
        out[i++] = (uint8_t)lc;
    }
    else {
        out[i++] = 0x00;
        out[i++] = (uint8_t)(lc >> 8);
        out[i++] = (uint8_t)lc;
    }
    if (cmd_len) {
        uint8_t icv[16], zero[16] = { 0 };
        memmove(out + i, cmd, cmd_len);
        out[i + cmd_len] = 0x80;
        memset(out + i + cmd_len + 1, 0, enc_len - cmd_len - 1);
        if (aes_cbc(st->s_enc, true, zero, st->counter, icv, 16) ||   /* ICV = E(S-ENC, counter) */
            aes_cbc(st->s_enc, true, icv, out + i, out + i, enc_len)) {
            return -1;
        }
        i += enc_len;
    }
    if (se05x_cmac(st->s_mac, st->mcv, 16, out, i, NULL, 0, st->mcv)) {
        return -1;
    }
    memcpy(out + i, st->mcv, 8);
    i += 8;
    if (append_le && has_le) {
        out[i++] = 0x00;
        out[i++] = 0x00;
    }
    *out_len = i;
    return 0;
}

/* Checks the R-MAC and decrypts the response in place (data || SW). Returns the SW, or 0. Error
 * responses come plain; every response advances the counter (applets >= 4.3, and ECKey sessions). */
uint16_t se05x_scp_unwrap(se05x_scp_t *st, uint8_t *rsp, size_t *rsp_len) {
    if (*rsp_len < 2) {
        return 0;
    }
    uint16_t sw = (uint16_t)((rsp[*rsp_len - 2] << 8) | rsp[*rsp_len - 1]);
    if (sw != 0x9000) {
        scp_counter_inc(st);
        return sw;
    }
    if (*rsp_len < 10) {
        return 0;
    }
    size_t data_len = *rsp_len - 10;
    uint8_t mac[16];
    if (se05x_cmac(st->s_rmac, st->mcv, 16, rsp, data_len, rsp + *rsp_len - 2, 2, mac) ||
        mbedtls_ct_memcmp(mac, rsp + data_len, 8) != 0) {
        printf("SE: SCP03 R-MAC wrong\n");
        return 0;
    }
    if (data_len) {
        uint8_t icv[16], block[16], zero[16] = { 0 };
        memcpy(block, st->counter, 16);
        block[0] = 0x80;                                    /* response ICV: counter with MSB 0x80 */
        if (data_len % 16 || aes_cbc(st->s_enc, true, zero, block, icv, 16) ||
            aes_cbc(st->s_enc, false, icv, rsp, rsp, data_len)) {
            return 0;
        }
        size_t n = data_len;
        while (n > 0 && rsp[n - 1] == 0x00 && n > data_len - 16) {
            n--;
        }
        if (n == 0 || rsp[n - 1] != 0x80) {
            printf("SE: SCP03 response padding wrong\n");
            return 0;
        }
        data_len = n - 1;
    }
    rsp[data_len] = 0x90;
    rsp[data_len + 1] = 0x00;
    *rsp_len = data_len + 2;
    scp_counter_inc(st);
    return 0x9000;
}

static smStatus_t session_txn(struct Se05xSession *s, const tlvHeader_t *hdr, uint8_t *cmdBuf, size_t cmdBufLen,
                              uint8_t *rsp, size_t *rspLen, uint8_t hasle) {
    static uint8_t txBuf[SE05X_MAX_BUF_SIZE_CMD];
    if (scp.on) {
        size_t txLen = sizeof(txBuf);
        if (se05x_scp_wrap(&scp, hdr->hdr, cmdBuf, cmdBufLen, hasle, true, txBuf, &txLen) != 0) {
            return SM_NOT_OK;
        }
        U32 rx = (U32)*rspLen;
        if (smCom_TransceiveRaw(s->conn_ctx, txBuf, (U16)txLen, rsp, &rx) != SMCOM_OK) {
            return SM_NOT_OK;
        }
        *rspLen = rx;
        uint16_t sw = se05x_scp_unwrap(&scp, rsp, rspLen);
        return sw ? (smStatus_t)sw : SM_NOT_OK;
    }
    tlvHeader_t outHdr = { 0 };
    size_t txBufLen = sizeof(txBuf);
    smStatus_t ret = s->fp_Transform(s, hdr, cmdBuf, cmdBufLen, &outHdr, txBuf, &txBufLen, hasle);
    if (ret != SM_OK) {
        return ret;
    }
    ret = s->fp_RawTXn(s->conn_ctx, s->pChannelCtx, s->authType, &outHdr, txBuf, txBufLen, rsp, rspLen, hasle);
    /* fp_DeCrypt always runs (it keeps the command counter for Platform SCP in step) */
    smStatus_t dec = s->fp_DeCrypt(s, cmdBufLen, rsp, rspLen, hasle);
    return ret != SM_OK ? ret : dec;
}

/* Link state: SM_I2CConnect succeeded (SM_Close before trying again), and when we last tried. */
static bool link_open;
static uint32_t last_attempt_ms;
#define RECONNECT_INTERVAL_MS 2000

/* T=1 open + ATR + SELECT, Platform SCP03, GetVersion. 0 = up. Also used to reconnect after a
 * failure (SE not answering at boot, transport error, broken channel). */
static int se_connect(void) {
    se.up = false;
    scp_close();
    if (link_open) {
        SM_Close(se.conn_ctx, 0);
        link_open = false;
    }
    last_attempt_ms = to_ms_since_boot(get_absolute_time());

    if (!cardea_se_bus_present()) {
        printf("SE: nothing at I2C 0x48; running on the soft backend\n");
        return -1;
    }
    SmCommState_t comm = { 0 };
    U8 atr[64];
    U16 atr_len = sizeof(atr);
    U16 sw = SM_I2CConnect(&se.conn_ctx, &comm, atr, &atr_len, NULL);   /* T=1 open + ATR + SELECT */
    if (sw != SW_OK) {
        printf("SE: no SE05x on I2C (0x%04x); running on the soft backend\n", sw);
        return -1;
    }
    link_open = true;

    se.session.conn_ctx = se.conn_ctx;
    se.session.authType = kSSS_AuthType_None;
    se.session.fp_TXn = session_txn;
    se.session.fp_RawTXn = raw_txn;
    se.session.fp_Transform = se05x_Transform;
    se.session.fp_DeCrypt = se05x_DeCrypt;

    int r = scp_open();
    if (r != 0) {
        printf("SE: no SCP03 channel (%d); running on the soft backend\n", r);
        return -3;
    }

    se.version_len = sizeof(se.version);
    smStatus_t st = Se05x_API_GetVersion(&se.session, se.version, &se.version_len);
    if (st != SM_OK || se.version_len < 3) {
        printf("SE: GetVersion failed (0x%04x)\n", st);
        return -2;
    }
    se.up = true;
    printf("SE: SE05x applet %u.%u.%u over SCP03, ATR %u bytes\n", se.version[0], se.version[1], se.version[2], atr_len);
    return 0;
}


void cardea_se_info(cardea_se_info_t *info) {
    if (!info) {
        return;
    }
    info->backend = "se05x";
    info->hardware = se.up;   /* up implies the SCP03 channel is open */
    info->root_available = cardea_se_root_available();
}

/*
 * Root key in the SE (#4): an HMAC-SHA256 key object whose policy only allows key derivation (no
 * read, no write, no delete), used by HKDFExtractAndExpand inside the chip. On first contact the
 * current MKEK is loaded into it, and the chip has to give exactly the bytes the soft backend
 * gives: the derived kbase does not change, so no data needs migrating.
 *
 * derive_kbase() always asks for the same derivation (salt = serial hash, info = "DEVICE/ROOT"), so
 * the chip computes it once at boot, before core 1 starts, and the result is kept in RAM: no chip
 * access later from core 0 racing a PIN session on core 1. Without the chip at boot, the soft
 * backend (the MKEK, same bytes) answers for that boot.
 *
 * Test mode: the MKEK also stays in flash (erasing it would be irreversible: losing the chip would
 * lose the data), so this protects nothing yet; it exercises the path for when we leave test mode.
 */
#define ROOT_ID 0x43520000u              /* 'C' 'R': device root */
#define POLICY_ALLOW_KDF 0x00800000u
extern const uint8_t *otp_key_1;         /* pico-keys-sdk/src/otp/otp.c: the MKEK */
extern uint8_t pico_serial_hash[32];     /* pico-keys-sdk/src/serial.c */

static struct {
    bool chip;                           /* the root lives in the chip and matched the soft backend */
    bool kbase_ok;                       /* kbase below computed by the chip at boot */
    uint8_t kbase[32];
} root;

static void put_tlv(uint8_t *b, size_t *i, uint8_t tag, const uint8_t *v, size_t n) {
    b[(*i)++] = tag;
    b[(*i)++] = (uint8_t)n;
    memcpy(b + *i, v, n);
    *i += n;
}

static void put_id(uint8_t *b, size_t *i, uint8_t tag, uint32_t id) {
    const uint8_t v[4] = { (uint8_t)(id >> 24), (uint8_t)(id >> 16), (uint8_t)(id >> 8), (uint8_t)id };
    put_tlv(b, i, tag, v, 4);
}

/* HKDFExtractAndExpand(SHA-256) with the root object as IKM; out_len <= 64. */
static int chip_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len, uint8_t *out,
                         size_t out_len) {
    uint8_t d[160], rsp[80];
    size_t i = 0, rl = sizeof(rsp);
    if (salt_len > 64 || info_len > 64 || out_len == 0 || out_len > 64) {
        return -1;
    }
    put_id(d, &i, 0x41, ROOT_ID);
    put_tlv(d, &i, 0x42, (const uint8_t[]){ 0x04 }, 1);            /* SHA-256 */
    if (salt_len) put_tlv(d, &i, 0x43, salt, salt_len);
    if (info_len) put_tlv(d, &i, 0x44, info, info_len);
    put_tlv(d, &i, 0x45, (const uint8_t[]){ 0x00, (uint8_t)out_len }, 2);
    const uint8_t hdr[4] = { 0x80, 0x03, 0x00, 0x2D };             /* INS_CRYPTO, P2_HKDF */
    if (se05x_apdu(hdr, d, i, true, rsp, &rl) != 0x9000 || rl != 2 + out_len || rsp[0] != 0x41 || rsp[1] != out_len) {
        return -1;
    }
    memcpy(out, rsp + 2, out_len);
    mbedtls_platform_zeroize(rsp, sizeof(rsp));
    return 0;
}

static bool chip_object_exists(uint32_t id) {
    uint8_t d[8], rsp[8];
    size_t i = 0, rl = sizeof(rsp);
    put_id(d, &i, 0x41, id);
    const uint8_t hdr[4] = { 0x80, 0x04, 0x00, 0x27 };             /* CheckObjectExists */
    return se05x_apdu(hdr, d, i, true, rsp, &rl) == 0x9000 && rl == 3 && rsp[0] == 0x41 && rsp[2] == 0x01;
}

/* Called once the link is up (boot, before core 1 runs). */
static void root_setup(void) {
    uint8_t a[32], b[32];
    static const uint8_t check_salt[] = "cardea/root-check", check_info[] = "v1";
    root.chip = false;
    if (!cardea_se_soft_root_available()) {
        return;                          /* no MKEK: the kbase comes from the serial alone, as before */
    }
    if (!chip_object_exists(ROOT_ID)) {
        uint8_t d[64];
        size_t i = 0;
        const uint8_t pol[9] = { 8, 0, 0, 0, 0, (uint8_t)(POLICY_ALLOW_KDF >> 24), (uint8_t)(POLICY_ALLOW_KDF >> 16),
                                 (uint8_t)(POLICY_ALLOW_KDF >> 8), (uint8_t)POLICY_ALLOW_KDF };
        put_tlv(d, &i, 0x11, pol, sizeof(pol));                      /* TAG_POLICY: KDF only */
        put_id(d, &i, 0x41, ROOT_ID);
        put_tlv(d, &i, 0x43, otp_key_1, 32);                         /* TAG_3: the MKEK */
        const uint8_t hdr[4] = { 0x80, 0x01, 0x05, 0x00 };         /* WriteSymmKey, HMAC */
        uint16_t sw = se05x_apdu(hdr, d, i, false, NULL, NULL);
        mbedtls_platform_zeroize(d, sizeof(d));
        if (sw != 0x9000) {
            printf("SE: loading the root key failed (%04x); the MKEK stays the root\n", sw);
            return;
        }
        printf("SE: root key loaded into the chip\n");
    }
    if (chip_root_kdf(check_salt, sizeof(check_salt) - 1, check_info, sizeof(check_info) - 1, a, 32) != 0 ||
        cardea_se_soft_root_kdf(check_salt, sizeof(check_salt) - 1, check_info, sizeof(check_info) - 1, b, 32) != 0 ||
        mbedtls_ct_memcmp(a, b, 32) != 0) {
        printf("SE: the chip root does not match the MKEK; using the MKEK\n");
    }
    else {
        root.chip = true;
        root.kbase_ok = chip_root_kdf(pico_serial_hash, 32, (const uint8_t *)"DEVICE/ROOT", 12, root.kbase, 32) == 0;
        printf("SE: root key in the chip (kbase %s)\n", root.kbase_ok ? "derived by the chip" : "NOT derived");
    }
    mbedtls_platform_zeroize(a, sizeof(a));
    mbedtls_platform_zeroize(b, sizeof(b));
}

/*
 * SE FAULT. By default (CARDEA_SE_FALLBACK off, as the real key) a key whose SE does not come up
 * at boot, or whose root key is not in it, does not run at all: no application answers (only the
 * rescue applet), the LED shows the fault pattern and the USB product name ends in "SE FAULT"
 * (pico-keys-sdk patch 0026). Nothing is erased: the MKEK and the rest stay in flash. It lasts
 * until the next power-up. With CARDEA_SE_FALLBACK on (bench only), the key runs without the SE
 * as before: root from the MKEK, PINs in the model's test store while none is in the chip.
 */
#ifdef CARDEA_SE_FALLBACK
#define SE_FALLBACK 1
#else
#define SE_FALLBACK 0
#endif
#define BOOT_ATTEMPTS 3                 /* an SE (or the lab bridge) that is slow to wake up */
#define BOOT_RETRY_MS 500

static bool se_fault;

bool cardea_se_fault(void) {
    return se_fault;
}

int cardea_se_init(void) {
    cardea_se_soft_init();
    memset(&se, 0, sizeof(se));
    int r = -1;
    for (int t = 0; t < (SE_FALLBACK ? 1 : BOOT_ATTEMPTS); t++) {
        if (t) {
            sleep_ms(BOOT_RETRY_MS);
        }
        r = se_connect();
        if (r == 0) {
            break;
        }
    }
    if (r == 0) {
        root_setup();
    }
    if (!SE_FALLBACK && (r != 0 || (cardea_se_soft_root_available() && !(root.chip && root.kbase_ok)))) {
        se_fault = true;
        printf("SE FAULT: %s; the key will not run (build with CARDEA_SE_FALLBACK=ON to run without the SE)\n",
               r != 0 ? "no secure element" : "root key not in the secure element");
        return r != 0 ? r : -4;
    }
    return r;
}

bool cardea_se_root_available(void) {
    /* In SE FAULT there is a root (the chip's), just not reachable: derive_kbase must not fall
     * back to the serial-only derivation. */
    return se_fault || root.chip || cardea_se_soft_root_available();
}

int cardea_se_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    if (se_fault) {
        return -1;                       /* never a derivation without the chip */
    }
    if (root.kbase_ok && salt_len == 32 && memcmp(salt, pico_serial_hash, 32) == 0 && info_len == 12 &&
        memcmp(info, "DEVICE/ROOT", 12) == 0 && out_len == 32) {
        memcpy(out, root.kbase, 32);
        return 0;
    }
    return cardea_se_soft_root_kdf(salt, salt_len, info, info_len, out, out_len);
}

void cardea_se_random(uint8_t *out, size_t len) {
    cardea_se_soft_random(out, len);
}

/* ---- internal API for se05x_pin.c */
/* Up, or reconnected now: an SE that did not answer at boot, or a link that failed, is tried again
 * when needed, at most every RECONNECT_INTERVAL_MS. */
bool se05x_ready(void) {
    if (se.up && scp.on) {
        return true;
    }
    if (to_ms_since_boot(get_absolute_time()) - last_attempt_ms < RECONNECT_INTERVAL_MS) {
        return false;
    }
    printf("SE: reconnecting\n");
    if (se_connect() != 0) {
        return false;
    }
    if (!root.chip) {
        root_setup();   /* the SE was not there at boot (this runs on core 1, in a PIN operation) */
    }
    return true;
}

uint16_t se05x_apdu(const uint8_t hdr[4], const uint8_t *data, size_t len, bool has_le, uint8_t *rsp,
                    size_t *rsp_len) {
    static uint8_t cmd[SE05X_MAX_BUF_SIZE_CMD];
    static uint8_t buf[SE05X_MAX_BUF_SIZE_RSP];
    if (!se05x_ready() || len > sizeof(cmd)) {
        return 0;
    }
    tlvHeader_t h;
    memcpy(h.hdr, hdr, 4);
    if (len) {
        memcpy(cmd, data, len);
    }
    size_t n = sizeof(buf);
    smStatus_t st = session_txn(&se.session, &h, cmd, len, buf, &n, has_le ? 1 : 0);
    if (st == SM_NOT_OK || n < 2) {
        se.up = false;   /* transport or channel failed: reconnect on the next use */
        return 0;
    }
    uint16_t sw = (uint16_t)((buf[n - 2] << 8) | buf[n - 1]);
    if (sw == 0x6982) {
        se.up = false;   /* security status: the SE dropped the secure channel; reconnect */
    }
    if (rsp && rsp_len) {
        size_t data_len = n - 2;
        if (data_len > *rsp_len) {
            return 0;
        }
        memcpy(rsp, buf, data_len);
        *rsp_len = data_len;
    }
    return sw;
}
