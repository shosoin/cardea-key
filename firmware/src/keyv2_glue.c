/*
 * key-v2 — pegamento del firmware unificado (pico-fido + pico-openpgp sobre un solo SDK).
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Affero General Public License as published by the Free Software Foundation, version 3
 * (la misma licencia que pico-fido, pico-openpgp y pico-keys-sdk, de los que deriva).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "picokeys.h"
#include "file.h"
#include "phy.h"

/*
 * Identidad que ve el applet de rescate y las herramientas de Pico Keys.
 * PICO_PRODUCT: 2 = "Pico FIDO" (lo que esperan las herramientas para la parte FIDO).
 * La versión es la de key-v2, no la de ninguna de las dos apps.
 */
uint8_t PICO_PRODUCT = 2;
uint8_t PICO_VERSION_MAJOR = KEYV2_VERSION_MAJOR;
uint8_t PICO_VERSION_MINOR = KEYV2_VERSION_MINOR;

/* FIDs estáticos de la tabla de pico-fido (generado al configurar). */
static const uint16_t fido_static_fids[] = {
#include "fido_static_fids.inc"
};

/*
 * ¿Este FID NO pertenece a OpenPGP/PIV? Lo usa el TERMINATE de OpenPGP para no borrar
 * ficheros ajenos (en upstream borra todo lo que no reconoce como suyo).
 */
bool keyv2_fid_is_foreign_to_openpgp(uint16_t fid);
bool keyv2_fid_is_foreign_to_openpgp(uint16_t fid) {
    for (size_t i = 0; i < sizeof(fido_static_fids) / sizeof(fido_static_fids[0]); i++) {
        if (fid == fido_static_fids[i]) {
            return true;
        }
    }
    /* Comunes del SDK y de la app Management */
    if (fid == EF_META || fid == EF_PHY || fid == EF_MKEK || fid == 0x1122 /* EF_DEV_CONF */) {
        return true;
    }
    uint8_t prefix = (uint8_t)(fid >> 8);
    /* Contenedores dinámicos de FIDO: OATH 0xB0-0xB5, OTP 0xB6-0xB9, OATH/OTP 0xBA-0xBB,
       credenciales 0xCF, residentes 0xD0-0xDC y 0xE0-0xE3. Vault del SDK 0xC4-0xC9: compartido. */
    return (prefix >= 0xb0 && prefix <= 0xbb) || (prefix >= 0xc4 && prefix <= 0xc9) || prefix == 0xcf ||
           (prefix >= 0xd0 && prefix <= 0xdc) || (prefix >= 0xe0 && prefix <= 0xe3);
}
