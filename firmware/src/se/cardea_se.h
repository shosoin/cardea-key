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
 *   model  — solo para pruebas: imita en la flash lo que hará el chip con los PIN (contador,
 *            bloqueo, secreto por hueco), para probar en la placa la ruta de PIN de la #3 sin
 *            chip. NO protege nada: quien vuelque la flash lo tiene todo.
 *   se05x  — NXP SE051 por I2C (en curso: issues #3, #4, #5 y #6).
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

/*
 * SE FAULT: el backend necesita el chip y al arrancar no estaba (o la clave raíz no está en él), y
 * se ha compilado sin CARDEA_SE_FALLBACK. Entonces la llave no funciona: el SDK no deja correr
 * ninguna aplicación (solo el applet de rescate), el LED muestra el patrón de fallo y el nombre USB
 * acaba en "SE FAULT" (parche 0026). No se borra nada de la flash. Dura hasta el siguiente arranque.
 * soft y model: siempre false.
 */
bool cardea_se_fault(void);

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
 * PIN (issue #3). Un PIN por hueco, cada uno con su propio contador de intentos. Si el backend
 * guarda los PIN (cardea_se_pin_managed()), el verificador y el contador viven en él (en el
 * se05x, dentro del chip) y una verificación correcta entrega un secreto de 32 bytes propio del
 * hueco, que sustituye a pin_derive_session() para envolver la clave de dispositivo de FIDO y la
 * DEK de OpenPGP/PIV. Si no (backend soft), todo sigue en los ficheros de cada app como en la
 * v0.1.0 y estas funciones devuelven CARDEA_SE_PIN_NOT_MANAGED.
 *
 * El "pin" es lo que cada app compara hoy: en FIDO, LEFT(SHA-256(PIN), 16); en OpenPGP/PIV, los
 * bytes del PIN tal como llegan en el APDU.
 */
typedef enum {
    CARDEA_SE_PIN_FIDO = 0,
    CARDEA_SE_PIN_PW1,
    CARDEA_SE_PIN_PW3,
    CARDEA_SE_PIN_RC,
    CARDEA_SE_PIN_PIV,
    CARDEA_SE_PIN_PUK,
    CARDEA_SE_PIN_SLOTS
} cardea_se_pin_slot_t;

#define CARDEA_SE_PIN_OK            0    /* acierto; secret relleno */
#define CARDEA_SE_PIN_WRONG         1    /* fallo; *remaining = intentos que quedan (0 = bloqueado) */
#define CARDEA_SE_PIN_BLOCKED       2    /* ya estaba bloqueado: no se ha comprobado nada */
#define CARDEA_SE_PIN_ERROR         (-1) /* el backend ha fallado o el hueco no existe */
#define CARDEA_SE_PIN_NOT_MANAGED   (-2) /* este backend no guarda PIN: usar los ficheros de la app */

#define CARDEA_SE_PIN_MAX_LEN       127  /* OpenPGP admite PIN de hasta 127 bytes */

/* ¿Guarda este backend los PIN? (soft: no; model y se05x: sí) */
bool cardea_se_pin_managed(void);

/* ¿Existe el hueco? (dado de alta con cardea_se_pin_set y no borrado) */
bool cardea_se_pin_present(cardea_se_pin_slot_t slot);

/*
 * Crea (o vuelve a crear) el hueco con este PIN y este máximo de intentos (1-255), con el contador
 * a cero y un secreto NUEVO, que se devuelve. Es lo que se usa al poner el PIN por primera vez, al
 * desbloquear (código de reinicio, PUK), al cambiar el máximo y al migrar. Lo envuelto con el
 * secreto anterior deja de poder abrirse: el llamante tiene que volver a envolverlo.
 */
int cardea_se_pin_set(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                      uint8_t secret[32]);

/*
 * Comprueba el PIN. Cada intento cuenta antes de comparar; un acierto pone el contador a cero.
 * Devuelve CARDEA_SE_PIN_OK (y el secreto), _WRONG (con los intentos que quedan), _BLOCKED o un
 * error.
 */
int cardea_se_pin_verify(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t secret[32],
                         uint8_t *remaining);

/*
 * Cambia el PIN conociendo el actual (cuenta como un intento de verificación). El secreto NO
 * cambia: lo envuelto con él sigue valiendo. Mismos resultados que cardea_se_pin_verify.
 */
int cardea_se_pin_change(cardea_se_pin_slot_t slot, const uint8_t *old_pin, size_t old_len, const uint8_t *new_pin,
                         size_t new_len, uint8_t secret[32], uint8_t *remaining);

/*
 * Pone un PIN nuevo sin conocer el actual (desbloqueo con el código de reinicio, PW3 o PUK; cambio
 * de máximo de intentos) con el contador lleno y este máximo. El backend model conserva el secreto;
 * el se05x no puede (sin el PIN actual no puede reescribir el autenticador) y crea uno nuevo. Quien
 * llama tiene que volver a envolver con el secreto devuelto, y ya ha comprobado la autorización
 * (PW3, RC, PUK...). Para un cambio con el PIN actual, mejor cardea_se_pin_change.
 */
int cardea_se_pin_reset(cardea_se_pin_slot_t slot, const uint8_t *pin, size_t pin_len, uint8_t max_retries,
                        uint8_t secret[32]);

/* Intentos que quedan (>= 0), o un error (< 0). */
int cardea_se_pin_retries(cardea_se_pin_slot_t slot);

/* Borra el hueco y su secreto (reset de la app). Borrar uno que no existe no es error. */
int cardea_se_pin_erase(cardea_se_pin_slot_t slot);

#endif /* CARDEA_SE_H */
