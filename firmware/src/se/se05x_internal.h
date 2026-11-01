/*
 * Cardea Key — internal API of the se05x backend, shared by se_se05x.c (link, Platform SCP03) and
 * se05x_pin.c (PINs in the chip, ECKey sessions). Not part of the secure-element interface.
 */
#ifndef CARDEA_SE05X_INTERNAL_H
#define CARDEA_SE05X_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One SCP03 channel: the Platform SCP03 of the link, or the channel of an ECKey applet session. */
typedef struct {
    bool on;
    uint8_t s_enc[16], s_mac[16], s_rmac[16];   /* session keys */
    uint8_t mcv[16];                            /* MAC chaining value */
    uint8_t counter[16];                        /* command counter, big endian */
} se05x_scp_t;

/* Link up: T=1 open, applet selected, Platform SCP03 established. */
bool se05x_ready(void);

/*
 * One command in the default session, through Platform SCP03: hdr (CLA INS P1 P2), data, and an
 * extended Le if has_le. rsp gets the response data without the SW. Returns the SW (0x9000 = OK),
 * or 0 if the transport or the channel failed.
 */
uint16_t se05x_apdu(const uint8_t hdr[4], const uint8_t *data, size_t len, bool has_le, uint8_t *rsp,
                    size_t *rsp_len);

/* SCP03 primitives (AES-128) */
int se05x_cmac(const uint8_t key[16], const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
               const uint8_t *c, size_t c_len, uint8_t out[16]);
/* SP 800-108 KDF of SCP03: label 11 x 00 || constant, 00, L, i = 1, context (0 or 16 bytes) */
int se05x_kdf(const uint8_t key[16], uint8_t constant, uint16_t l_bits, const uint8_t *context, size_t context_len,
              uint8_t out[16]);
/* Wraps a command (C-DEC, CLA | 0x04, Lc covering the MAC, C-MAC); append_le adds an extended Le. */
int se05x_scp_wrap(se05x_scp_t *st, const uint8_t hdr[4], const uint8_t *cmd, size_t cmd_len, bool has_le,
                   bool append_le, uint8_t *out, size_t *out_len);
/* Checks the R-MAC and decrypts a response in place (data || SW). Returns the SW, or 0 if it does not verify. */
uint16_t se05x_scp_unwrap(se05x_scp_t *st, uint8_t *rsp, size_t *rsp_len);

#endif
