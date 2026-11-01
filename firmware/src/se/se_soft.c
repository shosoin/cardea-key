/*
 * Cardea Key — backend "soft" de la interfaz del secure element.
 *
 * Sin chip: la clave raíz es otp_key_1, que otp_init() carga de la OTP (HARDEN_HARDWARE=ON) o de
 * la flash (EF_MKEK, parche 0004). Las derivaciones son las mismas que hacía derive_kbase() en la
 * v0.1.0, byte a byte, así que no hay migración de datos. Ofrece la misma seguridad que la v0.1.0:
 * quien vuelque la flash obtiene la MKEK.
 */
/* In the se05x build this file is the fallback for what the chip does not do yet: same code,
 * renamed, called by se_se05x.c. */
#ifdef CARDEA_SE_SOFT_AS_FALLBACK
#define cardea_se_init            cardea_se_soft_init
#define cardea_se_info            cardea_se_soft_info
#define cardea_se_root_available  cardea_se_soft_root_available
#define cardea_se_root_kdf        cardea_se_soft_root_kdf
#define cardea_se_random          cardea_se_soft_random
#endif

#include "cardea_se.h"


#include "byte_array.h"
#include "random.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

extern const uint8_t *otp_key_1;   /* pico-keys-sdk/src/otp/otp.c */

#define CARDEA_SE_ROOT_LEN 32

int cardea_se_init(void) {
    return 0;
}

bool cardea_se_root_available(void) {
    return otp_key_1 != NULL;
}

void cardea_se_info(cardea_se_info_t *info) {
    if (!info) {
        return;
    }
    info->backend = "soft";
    info->hardware = false;
    info->root_available = cardea_se_root_available();
}

int cardea_se_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    if (!otp_key_1 || !out) {
        return -1;
    }
    return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, salt_len,
                        otp_key_1, CARDEA_SE_ROOT_LEN, info, info_len, out, out_len);
}

void cardea_se_random(uint8_t *out, size_t len) {
    random_fill_buffer(BYTE_ARRAY(out, len));
}

#ifndef CARDEA_SE_SOFT_AS_FALLBACK
/* Sin chip no hay fallo de chip. */
bool cardea_se_fault(void) {
    return false;
}

/* PIN: en el backend soft siguen en los ficheros de cada app, exactamente como en la v0.1.0. */
bool cardea_se_pin_managed(void) {
    return false;
}

bool cardea_se_pin_present(cardea_se_pin_slot_t slot) {
    (void)slot;
    return false;
}

int cardea_se_pin_set(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                      uint8_t secret[32]) {
    (void)slot; (void)pin; (void)pin_len; (void)max_retries; (void)secret;
    return CARDEA_SE_PIN_NOT_MANAGED;
}

int cardea_se_pin_verify(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t secret[32],
                         uint8_t *remaining) {
    (void)slot; (void)pin; (void)pin_len; (void)secret; (void)remaining;
    return CARDEA_SE_PIN_NOT_MANAGED;
}

int cardea_se_pin_change(cardea_se_pin_slot_t slot, const uint8_t *old_pin, size_t old_len, const uint8_t *new_pin,
                         size_t new_len, uint8_t secret[32], uint8_t *remaining) {
    (void)slot; (void)old_pin; (void)old_len; (void)new_pin; (void)new_len; (void)secret; (void)remaining;
    return CARDEA_SE_PIN_NOT_MANAGED;
}

int cardea_se_pin_reset(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                        uint8_t secret[32]) {
    (void)slot; (void)pin; (void)pin_len; (void)max_retries; (void)secret;
    return CARDEA_SE_PIN_NOT_MANAGED;
}

int cardea_se_pin_retries(cardea_se_pin_slot_t slot) {
    (void)slot;
    return CARDEA_SE_PIN_NOT_MANAGED;
}

int cardea_se_pin_erase(cardea_se_pin_slot_t slot) {
    (void)slot;
    return CARDEA_SE_PIN_NOT_MANAGED;
}
#endif
