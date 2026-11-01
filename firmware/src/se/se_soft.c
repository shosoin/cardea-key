/*
 * Cardea Key — backend "soft" de la interfaz del secure element.
 *
 * Sin chip: la clave raíz es otp_key_1, que otp_init() carga de la OTP (HARDEN_HARDWARE=ON) o de
 * la flash (EF_MKEK, parche 0004). Las derivaciones son las mismas que hacía derive_kbase() en la
 * v0.1.0, byte a byte, así que no hay migración de datos. Ofrece la misma seguridad que la v0.1.0:
 * quien vuelque la flash obtiene la MKEK.
 */
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
