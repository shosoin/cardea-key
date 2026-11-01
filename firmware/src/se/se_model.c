/*
 * Cardea Key — backend "model" of the secure-element interface. TEST ONLY.
 *
 * It imitates in flash what the SE051 will do with the PINs (issue #3): per slot, a retry counter
 * that counts every attempt before comparing, a hard block at the maximum, and a 32-byte secret
 * per slot that only a correct PIN releases. With it the whole PIN path of the apps (verify,
 * change, unblock, migration from the v0.1.0 files, reset) can be tested on the board without the
 * chip, and it is the reference the se05x backend has to behave like.
 *
 * It protects NOTHING: the record (verifier, counter and the key the secret comes from) is in
 * flash, so whoever dumps the flash can try PINs offline and rewrite the counter. The root key is
 * the MKEK, as in the soft backend.
 *
 * Record per slot, dynamic file CARDEA_MODEL_FID_BASE + slot (66 bytes):
 *   [0] max retries  [1] failed attempts  [2..33] verifier  [34..65] slot key K
 *   verifier = HMAC-SHA256(K, "cardea-model/verifier" || pin)
 *   secret   = HMAC-SHA256(K, "cardea/pin-kek" || slot)       (the se05x will do this HMAC inside the chip)
 */
#include <string.h>

/* In the se05x build this file only provides the PIN store (renamed cardea_se_model_*), until the
 * PINs move into the chip (#3 part B): the bench board keeps the same PINs with either firmware. */
#ifdef CARDEA_SE_MODEL_AS_PIN_STORE
#define cardea_se_pin_managed  cardea_se_model_pin_managed
#define cardea_se_pin_present  cardea_se_model_pin_present
#define cardea_se_pin_set      cardea_se_model_pin_set
#define cardea_se_pin_verify   cardea_se_model_pin_verify
#define cardea_se_pin_change   cardea_se_model_pin_change
#define cardea_se_pin_reset    cardea_se_model_pin_reset
#define cardea_se_pin_retries  cardea_se_model_pin_retries
#define cardea_se_pin_erase    cardea_se_model_pin_erase
#endif

#include "cardea_se.h"

#include "mbedtls/md.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

/* soft backend, compiled with CARDEA_SE_SOFT_AS_FALLBACK (see se_soft.c) */
int cardea_se_soft_init(void);
bool cardea_se_soft_root_available(void);
int cardea_se_soft_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len);
void cardea_se_soft_random(uint8_t *out, size_t len);

#define REC_MAX     0
#define REC_FAILS   1
#define REC_VERIF   2
#define REC_KEY     34
#define REC_LEN     66

/* ---- storage: one dynamic file per slot. The host test (firmware/tests/test_se_model.c)
 * provides its own in RAM. */
bool cardea_model_load(cardea_se_pin_slot_t slot, uint8_t rec[REC_LEN]);
int cardea_model_save(cardea_se_pin_slot_t slot, const uint8_t rec[REC_LEN]);
int cardea_model_delete(cardea_se_pin_slot_t slot);

#ifndef CARDEA_MODEL_HOST_TEST
#include "picokeys.h"
#include "file.h"
#include "flash.h"

/* 0xEE00-0xEE0F: outside every range that the FIDO reset, the OpenPGP TERMINATE and the PIV reset
 * delete (keyv2_glue.c lists it as foreign to OpenPGP). Each app erases its own slots. */
#define CARDEA_MODEL_FID_BASE 0xEE00
#define COMMIT_TIMEOUT_MS 500

bool cardea_model_load(cardea_se_pin_slot_t slot, uint8_t rec[REC_LEN]) {
    file_t *f = file_search(CARDEA_MODEL_FID_BASE + slot);
    if (!f || !file_has_data(f) || file_get_size(f) != REC_LEN) {
        return false;
    }
    memcpy(rec, file_get_data(f), REC_LEN);
    return true;
}

int cardea_model_save(cardea_se_pin_slot_t slot, const uint8_t rec[REC_LEN]) {
    file_t *f = file_new(CARDEA_MODEL_FID_BASE + slot);
    if (!f || file_put_data(f, CONST_BYTE_ARRAY(rec, REC_LEN)) != PICOKEYS_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    /* Like the chip: the counter is on persistent storage before the answer goes out. */
    if (!flash_commit_sync(COMMIT_TIMEOUT_MS) || !file_has_data(f) || memcmp(file_get_data(f), rec, REC_LEN) != 0) {
        return CARDEA_SE_PIN_ERROR;
    }
    return CARDEA_SE_PIN_OK;
}

int cardea_model_delete(cardea_se_pin_slot_t slot) {
    file_t *f = file_search(CARDEA_MODEL_FID_BASE + slot);
    if (!f) {
        return CARDEA_SE_PIN_OK;
    }
    if (file_delete_no_commit(f) != PICOKEYS_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    flash_commit();
    return CARDEA_SE_PIN_OK;
}
#endif

static int hmac(const uint8_t key[32], const char *label, const uint8_t *data, size_t data_len, uint8_t out[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int r = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (r == 0) r = mbedtls_md_hmac_starts(&ctx, key, 32);
    if (r == 0) r = mbedtls_md_hmac_update(&ctx, (const uint8_t *)label, strlen(label));
    if (r == 0 && data_len) r = mbedtls_md_hmac_update(&ctx, data, data_len);
    if (r == 0) r = mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
    return r == 0 ? CARDEA_SE_PIN_OK : CARDEA_SE_PIN_ERROR;
}

static int slot_secret(cardea_se_pin_slot_t slot, const uint8_t rec[REC_LEN], uint8_t secret[32]) {
    uint8_t s = (uint8_t)slot;
    return hmac(rec + REC_KEY, "cardea/pin-kek", &s, 1, secret);
}

static bool valid(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len) {
    return (unsigned)slot < CARDEA_SE_PIN_SLOTS && pin && pin_len > 0 && pin_len <= CARDEA_SE_PIN_MAX_LEN;
}

#ifndef CARDEA_SE_MODEL_AS_PIN_STORE
int cardea_se_init(void) {
    return cardea_se_soft_init();
}

void cardea_se_info(cardea_se_info_t *info) {
    if (!info) {
        return;
    }
    info->backend = "model";
    info->hardware = false;
    info->root_available = cardea_se_soft_root_available();
}

bool cardea_se_root_available(void) {
    return cardea_se_soft_root_available();
}

bool cardea_se_fault(void) {
    return false;
}

int cardea_se_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    return cardea_se_soft_root_kdf(salt, salt_len, info, info_len, out, out_len);
}

void cardea_se_random(uint8_t *out, size_t len) {
    cardea_se_soft_random(out, len);
}
#endif

bool cardea_se_pin_managed(void) {
    return true;
}

bool cardea_se_pin_present(cardea_se_pin_slot_t slot) {
    uint8_t rec[REC_LEN];
    bool ok = (unsigned)slot < CARDEA_SE_PIN_SLOTS && cardea_model_load(slot, rec);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return ok;
}

int cardea_se_pin_set(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                      uint8_t secret[32]) {
    if (!valid(slot, pin, pin_len) || max_retries == 0 || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    uint8_t rec[REC_LEN];
    rec[REC_MAX] = max_retries;
    rec[REC_FAILS] = 0;
    cardea_se_soft_random(rec + REC_KEY, 32);
    int r = hmac(rec + REC_KEY, "cardea-model/verifier", pin, pin_len, rec + REC_VERIF);
    if (r == CARDEA_SE_PIN_OK) r = cardea_model_save(slot, rec);
    if (r == CARDEA_SE_PIN_OK) r = slot_secret(slot, rec, secret);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return r;
}

/* Spends one attempt and compares. On success the counter is back to 0 and rec is up to date. */
static int check(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t rec[REC_LEN],
                 uint8_t *remaining) {
    if (!cardea_model_load(slot, rec)) {
        return CARDEA_SE_PIN_ERROR;
    }
    if (rec[REC_FAILS] >= rec[REC_MAX]) {
        if (remaining) *remaining = 0;
        return CARDEA_SE_PIN_BLOCKED;
    }
    rec[REC_FAILS]++;
    if (cardea_model_save(slot, rec) != CARDEA_SE_PIN_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    uint8_t v[32];
    if (hmac(rec + REC_KEY, "cardea-model/verifier", pin, pin_len, v) != CARDEA_SE_PIN_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    int diff = mbedtls_ct_memcmp(v, rec + REC_VERIF, 32);
    mbedtls_platform_zeroize(v, sizeof(v));
    if (diff != 0) {
        if (remaining) *remaining = (uint8_t)(rec[REC_MAX] - rec[REC_FAILS]);
        return CARDEA_SE_PIN_WRONG;
    }
    rec[REC_FAILS] = 0;
    if (cardea_model_save(slot, rec) != CARDEA_SE_PIN_OK) {
        return CARDEA_SE_PIN_ERROR;
    }
    if (remaining) *remaining = rec[REC_MAX];
    return CARDEA_SE_PIN_OK;
}

int cardea_se_pin_verify(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t secret[32],
                         uint8_t *remaining) {
    if (!valid(slot, pin, pin_len) || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    uint8_t rec[REC_LEN];
    int r = check(slot, pin, pin_len, rec, remaining);
    if (r == CARDEA_SE_PIN_OK) {
        r = slot_secret(slot, rec, secret);
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return r;
}

int cardea_se_pin_change(cardea_se_pin_slot_t slot, const uint8_t *old_pin, size_t old_len, const uint8_t *new_pin,
                         size_t new_len, uint8_t secret[32], uint8_t *remaining) {
    if (!valid(slot, old_pin, old_len) || !valid(slot, new_pin, new_len) || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    uint8_t rec[REC_LEN];
    int r = check(slot, old_pin, old_len, rec, remaining);
    if (r == CARDEA_SE_PIN_OK) {
        /* same K, so the same secret: what is wrapped with it stays valid */
        r = hmac(rec + REC_KEY, "cardea-model/verifier", new_pin, new_len, rec + REC_VERIF);
        if (r == CARDEA_SE_PIN_OK) r = cardea_model_save(slot, rec);
        if (r == CARDEA_SE_PIN_OK) r = slot_secret(slot, rec, secret);
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return r;
}

int cardea_se_pin_reset(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                        uint8_t secret[32]) {
    if (!valid(slot, pin, pin_len) || max_retries == 0 || !secret) {
        return CARDEA_SE_PIN_ERROR;
    }
    uint8_t rec[REC_LEN];
    if (!cardea_model_load(slot, rec)) {
        return CARDEA_SE_PIN_ERROR;
    }
    /* same K, so the same secret; new PIN, new maximum, counter full */
    rec[REC_MAX] = max_retries;
    rec[REC_FAILS] = 0;
    int r = hmac(rec + REC_KEY, "cardea-model/verifier", pin, pin_len, rec + REC_VERIF);
    if (r == CARDEA_SE_PIN_OK) r = cardea_model_save(slot, rec);
    if (r == CARDEA_SE_PIN_OK) r = slot_secret(slot, rec, secret);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return r;
}

int cardea_se_pin_retries(cardea_se_pin_slot_t slot) {
    uint8_t rec[REC_LEN];
    if ((unsigned)slot >= CARDEA_SE_PIN_SLOTS || !cardea_model_load(slot, rec)) {
        return CARDEA_SE_PIN_ERROR;
    }
    int left = rec[REC_FAILS] >= rec[REC_MAX] ? 0 : rec[REC_MAX] - rec[REC_FAILS];
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return left;
}

#ifdef CARDEA_SE_MODEL_AS_PIN_STORE
int cardea_se_model_export(cardea_se_pin_slot_t slot, uint8_t *max_retries, uint8_t key[32]);
/* Migration to the chip (se05x_pin.c): the slot key K and the maximum of a record, so the chip can
 * compute the same secret. 0 = there is a record. */
int cardea_se_model_export(cardea_se_pin_slot_t slot, uint8_t *max_retries, uint8_t key[32]) {
    uint8_t rec[REC_LEN];
    if ((unsigned)slot >= CARDEA_SE_PIN_SLOTS || !cardea_model_load(slot, rec)) {
        return CARDEA_SE_PIN_ERROR;
    }
    *max_retries = rec[REC_MAX];
    memcpy(key, rec + REC_KEY, 32);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return CARDEA_SE_PIN_OK;
}
#endif

int cardea_se_pin_erase(cardea_se_pin_slot_t slot) {
    if ((unsigned)slot >= CARDEA_SE_PIN_SLOTS) {
        return CARDEA_SE_PIN_ERROR;
    }
    return cardea_model_delete(slot);
}
