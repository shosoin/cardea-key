/*
 * Cardea Key — RP2350 (Pico 2) platform layer for NXP Plug & Trust (T=1 over I2C).
 *
 * Replaces the Linux files of the middleware (platform/linux/i2c_a7.c, platform/generic/sm_timer.c,
 * platform/rsp/se05x_reset.c):
 *   - I2C: i2c0 on GP4 (SDA) / GP5 (SCL), 100 kHz by default. NXP's T=1 layer polls the SE and
 *     retries on NACK, so a NACK or a timeout is reported as such, never as success.
 *   - Timers: pico_time sleeps.
 *   - Reset: optional EN (power enable) and RST pins of the SE board; -1 = not wired (e.g. the
 *     se05x-lab-bridge, which needs neither).
 */
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "hardware/gpio.h"

#include "i2c_a7.h"
#include "sm_timer.h"
#include "ax_reset.h"
#include "se05x_reset_apis.h"

#ifndef CARDEA_SE_I2C_SDA
#define CARDEA_SE_I2C_SDA 4
#endif
#ifndef CARDEA_SE_I2C_SCL
#define CARDEA_SE_I2C_SCL 5
#endif
#ifndef CARDEA_SE_I2C_HZ
#define CARDEA_SE_I2C_HZ (100 * 1000)
#endif
#ifndef CARDEA_SE_EN_PIN
#define CARDEA_SE_EN_PIN (-1)
#endif
#ifndef CARDEA_SE_RST_PIN
#define CARDEA_SE_RST_PIN (-1)
#endif
/* Per-transfer timeout. The SE answers "not ready" with a NACK; a stretched clock beyond this is
 * treated as a failed transfer, which the T=1 layer retries. */
#define CARDEA_SE_I2C_TIMEOUT_US 50000

#define SE_I2C i2c0
static bool i2c_ready;

/* Standard bus recovery: nine SCL pulses with SDA released, then a STOP. Frees a target that was
 * left holding SDA low by an interrupted transfer. */
static void bus_recover(void) {
    gpio_init(CARDEA_SE_I2C_SDA);
    gpio_init(CARDEA_SE_I2C_SCL);
    gpio_pull_up(CARDEA_SE_I2C_SDA);
    gpio_pull_up(CARDEA_SE_I2C_SCL);
    gpio_set_dir(CARDEA_SE_I2C_SDA, GPIO_IN);
    for (int i = 0; i < 9; i++) {
        gpio_set_dir(CARDEA_SE_I2C_SCL, GPIO_OUT);
        gpio_put(CARDEA_SE_I2C_SCL, 0);
        sleep_us(10);
        gpio_set_dir(CARDEA_SE_I2C_SCL, GPIO_IN);
        sleep_us(10);
    }
    gpio_set_dir(CARDEA_SE_I2C_SDA, GPIO_OUT);
    gpio_put(CARDEA_SE_I2C_SDA, 0);
    sleep_us(10);
    gpio_set_dir(CARDEA_SE_I2C_SDA, GPIO_IN);
    sleep_us(10);
}

static void bus_start(void) {
    i2c_init(SE_I2C, CARDEA_SE_I2C_HZ);
    gpio_set_function(CARDEA_SE_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(CARDEA_SE_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(CARDEA_SE_I2C_SDA);
    gpio_pull_up(CARDEA_SE_I2C_SCL);
}

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName) {
    (void)pDevName;
    if (!i2c_ready) {
        bus_recover();
        bus_start();
        i2c_ready = true;
    }
    if (conn_ctx) {
        *conn_ctx = NULL;   /* single bus: no per-connection state */
    }
    return I2C_OK;
}

void axI2CTerm(void *conn_ctx, int mode) {
    (void)conn_ctx;
    (void)mode;
    if (i2c_ready) {
        i2c_deinit(SE_I2C);
        i2c_ready = false;
    }
}

static i2c_error_t result(int r, int expected) {
    if (r == expected) {
        return I2C_OK;
    }
    if (r == PICO_ERROR_TIMEOUT) {
        /* A wedged transfer can leave the RP2 block stuck: recover before the next retry. */
        i2c_deinit(SE_I2C);
        bus_recover();
        bus_start();
        return I2C_FAILED;
    }
    return I2C_NACK_ON_ADDRESS;   /* PICO_ERROR_GENERIC: address or data not acknowledged */
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pTx, unsigned short txLen) {
    (void)conn_ctx;
    if (bus != I2C_BUS_0 || pTx == NULL) {
        return I2C_FAILED;
    }
    int r = i2c_write_timeout_us(SE_I2C, addr >> 1, pTx, txLen, false, CARDEA_SE_I2C_TIMEOUT_US);
    return result(r, txLen);
}

i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pRx, unsigned short rxLen) {
    (void)conn_ctx;
    if (bus != I2C_BUS_0 || pRx == NULL) {
        return I2C_FAILED;
    }
    int r = i2c_read_timeout_us(SE_I2C, addr >> 1, pRx, rxLen, false, CARDEA_SE_I2C_TIMEOUT_US);
    return result(r, rxLen);
}

i2c_error_t axI2CWriteByte(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pTx) {
    return axI2CWrite(conn_ctx, bus, addr, pTx, 1);
}

i2c_error_t axI2CWriteRead(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pTx,
                           unsigned short txLen, unsigned char *pRx, unsigned short *pRxLen) {
    i2c_error_t e = axI2CWrite(conn_ctx, bus, addr, pTx, txLen);
    if (e != I2C_OK || pRxLen == NULL) {
        return e;
    }
    return axI2CRead(conn_ctx, bus, addr, pRx, *pRxLen);
}

/* ---- timers (platform/generic/sm_timer.c) */
uint32_t sm_initSleep(void) {
    return 0;
}

void sm_sleep(uint32_t msec) {
    sleep_ms(msec);
}

void sm_usleep(uint32_t microsec) {
    sleep_us(microsec);
}

/* ---- reset (platform/rsp/se05x_reset.c) */
void axReset_HostConfigure(void) {
    if (CARDEA_SE_EN_PIN >= 0) {
        gpio_init(CARDEA_SE_EN_PIN);
        gpio_set_dir(CARDEA_SE_EN_PIN, GPIO_OUT);
    }
    if (CARDEA_SE_RST_PIN >= 0) {
        gpio_init(CARDEA_SE_RST_PIN);
        gpio_set_dir(CARDEA_SE_RST_PIN, GPIO_OUT);
        gpio_put(CARDEA_SE_RST_PIN, 1);
    }
}

void axReset_HostUnconfigure(void) {
}

void axReset_PowerUp(int reset_logic) {
    (void)reset_logic;
    if (CARDEA_SE_EN_PIN >= 0) {
        gpio_put(CARDEA_SE_EN_PIN, 1);
        sleep_ms(10);   /* SE power-up time */
    }
}

void axReset_PowerDown(int reset_logic) {
    (void)reset_logic;
    if (CARDEA_SE_EN_PIN >= 0) {
        gpio_put(CARDEA_SE_EN_PIN, 0);
    }
}

void axReset_ResetPulseDUT(int reset_logic) {
    (void)reset_logic;
    if (CARDEA_SE_RST_PIN >= 0) {
        gpio_put(CARDEA_SE_RST_PIN, 0);
        sleep_ms(2);
        gpio_put(CARDEA_SE_RST_PIN, 1);
        sleep_ms(10);
    }
}

void se05x_ic_reset(uint32_t applet_version) {
    (void)applet_version;
    axReset_HostConfigure();
    axReset_PowerUp(0);
    axReset_ResetPulseDUT(0);
}

/* Quick presence check before the T=1 open: does anything acknowledge address 0x48? Without it,
 * a missing SE would make NXP's stack poll for tens of seconds during boot. */
bool cardea_se_bus_present(void) {
    axI2CInit(NULL, NULL);
    uint8_t b;
    int r = i2c_read_timeout_us(SE_I2C, 0x90 >> 1, &b, 1, false, 20000);
    return r == 1;
}
