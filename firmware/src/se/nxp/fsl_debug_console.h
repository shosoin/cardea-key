/* Cardea Key: minimal stand-in for NXP's MCUXpresso debug console, which Plug & Trust includes
 * when built with AX_EMBEDDED. Output goes to the pico-sdk stdio (UART0 on GP0). */
#ifndef CARDEA_FSL_DEBUG_CONSOLE_H
#define CARDEA_FSL_DEBUG_CONSOLE_H
#include <stdio.h>
#define PRINTF printf
#define SCANF scanf
#define PUTCHAR putchar
#define GETCHAR getchar
#endif
