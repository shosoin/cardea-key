/*
 * Cardea Key — prueba en el PC del backend "soft" del secure element.
 *
 * Comprueba que, para muchas MKEK y números de serie aleatorios, la kbase que se obtiene a través
 * de la interfaz (cardea_se_root_kdf, como la usa derive_kbase con PICOKEYS_SE_HOOKS) es idéntica
 * byte a byte a la fórmula de la v0.1.0. Es la condición para que una llave con datos de la
 * v0.1.0 siga funcionando sin migración. Se compila y ejecuta con scripts/test-host.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cardea_se.h"
#include "byte_array.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

const uint8_t *otp_key_1 = NULL;                   /* la define pico-keys-sdk/src/otp/otp.c */
int random_fill_buffer(byte_array_t b) {           /* la define pico-keys-sdk/src/rng/random.c */
    for (size_t i = 0; i < b.len; i++) b.data[i] = (uint8_t)rand();
    return 0;
}

/* derive_kbase() de la v0.1.0 (pico-keys-sdk a2f0a51, crypto_utils.c), copiada tal cual. */
static void v010_derive_kbase(const uint8_t *mkek, const uint8_t serial_hash[32], uint8_t kbase[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const uint8_t nootp_salt[] = "NO-OTP";
    if (mkek) {
        mbedtls_hkdf(md, serial_hash, 32, mkek, 32, (const uint8_t *)"DEVICE/ROOT", 12, kbase, 32);
    }
    else {
        mbedtls_hkdf(md, nootp_salt, sizeof(nootp_salt) - 1, serial_hash, 32, (const uint8_t *)"DEVICE/ROOT", 12, kbase, 32);
    }
}

/* derive_kbase() con PICOKEYS_SE_HOOKS (parche 0022), misma lógica de ramas. */
static void hooked_derive_kbase(const uint8_t serial_hash[32], uint8_t kbase[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const uint8_t nootp_salt[] = "NO-OTP";
    if (cardea_se_root_available() &&
        cardea_se_root_kdf(serial_hash, 32, (const uint8_t *)"DEVICE/ROOT", 12, kbase, 32) == 0) {
        return;
    }
    if (cardea_se_root_available()) { memset(kbase, 0, 32); return; }
    mbedtls_hkdf(md, nootp_salt, sizeof(nootp_salt) - 1, serial_hash, 32, (const uint8_t *)"DEVICE/ROOT", 12, kbase, 32);
}

int main(void) {
    int fails = 0, n = 0;
    uint8_t mkek[32], serial_hash[32], a[32], b[32];
    srand(20261101);
    for (int round = 0; round < 1000; round++) {
        random_fill_buffer(BYTE_ARRAY(mkek, 32));
        random_fill_buffer(BYTE_ARRAY(serial_hash, 32));
        otp_key_1 = (round % 10 == 0) ? NULL : mkek;   /* también el caso sin MKEK */
        v010_derive_kbase(otp_key_1, serial_hash, a);
        hooked_derive_kbase(serial_hash, b);
        n++;
        if (memcmp(a, b, 32) != 0) { fails++; if (fails < 5) printf("DIFERENTE en la ronda %d\n", round); }
    }
    /* Vector fijo, para detectar cualquier cambio futuro de la fórmula. */
    for (int i = 0; i < 32; i++) { mkek[i] = (uint8_t)i; serial_hash[i] = (uint8_t)(0xA0 + i); }
    otp_key_1 = mkek;
    hooked_derive_kbase(serial_hash, b);
    v010_derive_kbase(mkek, serial_hash, a);
    static const uint8_t expected[32] = {
        0x3b, 0xfe, 0x36, 0x1c, 0x6b, 0x0a, 0x8f, 0x20, 0x23, 0xeb, 0x33, 0x89, 0x1a, 0x92, 0x74, 0xe6,
        0x31, 0x12, 0x2c, 0x65, 0x1f, 0x9b, 0x88, 0x54, 0x93, 0x33, 0xaf, 0xf5, 0x93, 0x8e, 0x93, 0xcc };
    if (memcmp(b, expected, 32) != 0) { fails++; printf("vector fijo: DIFERENTE\n"); }
    else printf("vector fijo: OK\n");
    cardea_se_info_t info;
    cardea_se_info(&info);
    printf("backend=%s hardware=%d raiz=%d\n", info.backend, info.hardware, info.root_available);
    printf("%d casos, %d diferencias -> %s\n", n, fails, (fails == 0 && memcmp(a, b, 32) == 0) ? "OK" : "FALLO");
    return fails == 0 && memcmp(a, b, 32) == 0 ? 0 : 1;
}
