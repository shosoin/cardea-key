/*
 * Cardea Key — interfaz del secure element (SE).
 *
 * Todo lo que en la fase 1 debe vivir dentro del SE pasa por aquí: derivaciones desde la clave
 * raíz (sin exportarla) y, a partir de la issue #3, los PIN con su contador de intentos.
 *
 * Backends (se elige uno al compilar, opción CMake CARDEA_SE):
 *   soft   — por defecto. La clave raíz es la MKEK de la flash (EF_MKEK) o la de la OTP, como en
 *            la v0.1.0, y las derivaciones dan exactamente los mismos bytes: una llave con datos
 *            de la v0.1.0 sigue funcionando sin migración. Misma seguridad que la v0.1.0.
 *   se05x  — NXP SE051 por I2C (pendiente: issues #4, #5 y #6).
 *
 * El SDK solo llama a esta interfaz si se compila con PICOKEYS_SE_HOOKS (parche 0022); sin esa
 * definición, pico-fido y pico-openpgp por separado se comportan como siempre.
 */
#ifndef CARDEA_SE_H
#define CARDEA_SE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *backend;   /* "soft", "se05x" */
    bool hardware;         /* true si las claves viven en un chip aparte */
    bool root_available;   /* hay clave raíz (MKEK); si no, kbase se deriva solo del serie */
} cardea_se_info_t;

/* Arranque del backend. Se llama una vez, después de cargar la MKEK (otp_init). 0 = OK. */
int cardea_se_init(void);

void cardea_se_info(cardea_se_info_t *info);

/* ¿Hay clave raíz? Sin ella, el llamante usa la derivación de reserva de siempre. */
bool cardea_se_root_available(void);

/*
 * HKDF-SHA256 con la clave raíz como material de entrada:
 *   out = HKDF(salt, IKM = clave raíz, info), de out_len bytes.
 * La clave raíz no sale del backend. 0 = OK; distinto de 0 si no hay raíz o falla.
 */
int cardea_se_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);

/* Bytes aleatorios del backend (en soft, el generador de la placa). */
void cardea_se_random(uint8_t *out, size_t len);

/*
 * PIN (issue #3). Un PIN por hueco; cada hueco con su propio contador de intentos, que en el
 * backend se05x aplica el chip. Una verificación correcta entrega un secreto de 32 bytes propio
 * de ese PIN, que sustituirá a pin_derive_session() para desbloquear la clave de dispositivo de
 * FIDO y la DEK de OpenPGP/PIV. Se declara aquí para fijar la forma de la interfaz; se implementa
 * y se conecta en la #3, junto con las pruebas que la ejercitan.
 */
typedef enum {
    CARDEA_SE_PIN_FIDO = 0,
    CARDEA_SE_PIN_PW1,
    CARDEA_SE_PIN_PW3,
    CARDEA_SE_PIN_RC,
    CARDEA_SE_PIN_PIV,
    CARDEA_SE_PIN_PUK,
} cardea_se_pin_slot_t;

#endif /* CARDEA_SE_H */
