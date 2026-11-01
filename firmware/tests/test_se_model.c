/*
 * Cardea Key — prueba en el PC del backend "model" (PIN con contador, issue #3).
 *
 * Comprueba la semántica que luego tiene que cumplir el se05x: cada intento cuenta antes de
 * comparar, un acierto pone el contador a cero, al llegar al máximo se bloquea y ya no se compara
 * nada, cambiar el PIN conserva el secreto, volver a crear el hueco da un secreto nuevo, el
 * secreto depende del hueco y borrar deja el hueco vacío. Se ejecuta con scripts/test-host.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cardea_se.h"
#include "byte_array.h"

/* Lo que el backend model toma del soft y del SDK */
int cardea_se_soft_init(void) { return 0; }
bool cardea_se_soft_root_available(void) { return false; }
int cardea_se_soft_root_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len) {
    (void)salt; (void)salt_len; (void)info; (void)info_len; (void)out; (void)out_len;
    return -1;
}
void cardea_se_soft_random(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)rand();
}

/* Almacén en RAM, con contador de escrituras para comprobar que el intento se guarda antes. */
static uint8_t store[CARDEA_SE_PIN_SLOTS][66];
static bool used[CARDEA_SE_PIN_SLOTS];
static int saves;
bool cardea_model_load(cardea_se_pin_slot_t slot, uint8_t rec[66]);
int cardea_model_save(cardea_se_pin_slot_t slot, const uint8_t rec[66]);
int cardea_model_delete(cardea_se_pin_slot_t slot);
bool cardea_model_load(cardea_se_pin_slot_t slot, uint8_t rec[66]) {
    if (!used[slot]) return false;
    memcpy(rec, store[slot], 66);
    return true;
}
int cardea_model_save(cardea_se_pin_slot_t slot, const uint8_t rec[66]) {
    memcpy(store[slot], rec, 66);
    used[slot] = true;
    saves++;
    return 0;
}
int cardea_model_delete(cardea_se_pin_slot_t slot) {
    used[slot] = false;
    return 0;
}

static int failures;
#define CHECK(c) do { if (!(c)) { printf("FALLO línea %d: %s\n", __LINE__, #c); failures++; } } while (0)

int main(void) {
    const uint8_t pin[] = "123456", bad[] = "654321", newpin[] = "87654321";
    uint8_t s1[32], s2[32], s3[32], rem = 0xAA;
    const cardea_se_pin_slot_t F = CARDEA_SE_PIN_FIDO;

    CHECK(cardea_se_pin_managed());
    CHECK(!cardea_se_pin_present(F));
    CHECK(cardea_se_pin_verify(F, pin, 6, s1, &rem) == CARDEA_SE_PIN_ERROR);   /* sin dar de alta */
    CHECK(cardea_se_pin_set(F, pin, 6, 0, s1) == CARDEA_SE_PIN_ERROR);         /* máximo 0 */

    CHECK(cardea_se_pin_set(F, pin, 6, 3, s1) == CARDEA_SE_PIN_OK);
    CHECK(cardea_se_pin_present(F));
    CHECK(cardea_se_pin_retries(F) == 3);

    /* acierto: mismo secreto, contador lleno */
    CHECK(cardea_se_pin_verify(F, pin, 6, s2, &rem) == CARDEA_SE_PIN_OK && rem == 3);
    CHECK(memcmp(s1, s2, 32) == 0);

    /* fallo: cuenta, y se guarda antes de comparar */
    saves = 0;
    CHECK(cardea_se_pin_verify(F, bad, 6, s2, &rem) == CARDEA_SE_PIN_WRONG && rem == 2);
    CHECK(saves == 1);
    CHECK(cardea_se_pin_retries(F) == 2);
    /* un acierto pone el contador a cero */
    CHECK(cardea_se_pin_verify(F, pin, 6, s2, &rem) == CARDEA_SE_PIN_OK && rem == 3);
    CHECK(cardea_se_pin_retries(F) == 3);

    /* longitud distinta = PIN distinto */
    CHECK(cardea_se_pin_verify(F, pin, 5, s2, &rem) == CARDEA_SE_PIN_WRONG && rem == 2);

    /* bloqueo al máximo; después ni el PIN bueno sirve ni se escribe nada */
    CHECK(cardea_se_pin_verify(F, bad, 6, s2, &rem) == CARDEA_SE_PIN_WRONG && rem == 1);
    CHECK(cardea_se_pin_verify(F, bad, 6, s2, &rem) == CARDEA_SE_PIN_WRONG && rem == 0);
    CHECK(cardea_se_pin_retries(F) == 0);
    saves = 0;
    CHECK(cardea_se_pin_verify(F, pin, 6, s2, &rem) == CARDEA_SE_PIN_BLOCKED && rem == 0);
    CHECK(cardea_se_pin_change(F, pin, 6, newpin, 8, s2, &rem) == CARDEA_SE_PIN_BLOCKED);
    CHECK(saves == 0);

    /* desbloquear = volver a crear: secreto nuevo */
    CHECK(cardea_se_pin_set(F, pin, 6, 8, s2) == CARDEA_SE_PIN_OK);
    CHECK(memcmp(s1, s2, 32) != 0);
    CHECK(cardea_se_pin_retries(F) == 8);

    /* cambiar el PIN conserva el secreto; el viejo deja de valer */
    CHECK(cardea_se_pin_change(F, bad, 6, newpin, 8, s3, &rem) == CARDEA_SE_PIN_WRONG && rem == 7);
    CHECK(cardea_se_pin_change(F, pin, 6, newpin, 8, s3, &rem) == CARDEA_SE_PIN_OK);
    CHECK(memcmp(s2, s3, 32) == 0);
    CHECK(cardea_se_pin_verify(F, newpin, 8, s3, &rem) == CARDEA_SE_PIN_OK && memcmp(s2, s3, 32) == 0);
    CHECK(cardea_se_pin_verify(F, pin, 6, s3, &rem) == CARDEA_SE_PIN_WRONG);

    /* reset (desbloqueo): PIN nuevo, contador lleno, nuevo máximo, MISMO secreto */
    CHECK(cardea_se_pin_verify(F, pin, 6, s3, &rem) == CARDEA_SE_PIN_WRONG && rem == 6);
    CHECK(cardea_se_pin_reset(F, pin, 6, 5, s3) == CARDEA_SE_PIN_OK);
    CHECK(memcmp(s2, s3, 32) == 0);
    CHECK(cardea_se_pin_retries(F) == 5);
    CHECK(cardea_se_pin_verify(F, newpin, 8, s3, &rem) == CARDEA_SE_PIN_WRONG && rem == 4);
    CHECK(cardea_se_pin_verify(F, pin, 6, s3, &rem) == CARDEA_SE_PIN_OK && rem == 5 && memcmp(s2, s3, 32) == 0);
    CHECK(cardea_se_pin_reset(CARDEA_SE_PIN_PUK, pin, 6, 3, s3) == CARDEA_SE_PIN_ERROR);   /* hueco sin alta */
    /* un PIN de 127 bytes vale */
    uint8_t pin127[127];
    memset(pin127, 'x', sizeof(pin127));
    CHECK(cardea_se_pin_reset(F, pin127, sizeof(pin127), 8, s3) == CARDEA_SE_PIN_OK);
    CHECK(cardea_se_pin_verify(F, pin127, sizeof(pin127), s3, &rem) == CARDEA_SE_PIN_OK && memcmp(s2, s3, 32) == 0);
    CHECK(cardea_se_pin_retries(F) == 8);

    /* mismo PIN en otro hueco: secreto distinto e independiente */
    CHECK(cardea_se_pin_set(CARDEA_SE_PIN_PW1, newpin, 8, 3, s3) == CARDEA_SE_PIN_OK);
    CHECK(memcmp(s2, s3, 32) != 0);
    CHECK(cardea_se_pin_retries(CARDEA_SE_PIN_PW1) == 3);
    CHECK(cardea_se_pin_retries(F) == 8);

    /* borrar */
    CHECK(cardea_se_pin_erase(F) == CARDEA_SE_PIN_OK);
    CHECK(!cardea_se_pin_present(F));
    CHECK(cardea_se_pin_retries(F) < 0);
    CHECK(cardea_se_pin_erase(F) == CARDEA_SE_PIN_OK);
    CHECK(cardea_se_pin_present(CARDEA_SE_PIN_PW1));

    /* parámetros fuera de rango */
    CHECK(cardea_se_pin_verify(CARDEA_SE_PIN_SLOTS, pin, 6, s1, &rem) == CARDEA_SE_PIN_ERROR);
    CHECK(cardea_se_pin_verify(CARDEA_SE_PIN_PW1, pin, 0, s1, &rem) == CARDEA_SE_PIN_ERROR);
    uint8_t longpin[CARDEA_SE_PIN_MAX_LEN + 1] = { 0 };
    CHECK(cardea_se_pin_set(CARDEA_SE_PIN_PW1, longpin, sizeof(longpin), 3, s1) == CARDEA_SE_PIN_ERROR);

    if (failures) {
        printf("backend model: %d fallo(s)\n", failures);
        return 1;
    }
    printf("backend model: OK (contador, bloqueo, cambio, re-alta, reset, huecos, borrado)\n");
    return 0;
}
