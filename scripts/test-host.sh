#!/usr/bin/env bash
# Cardea Key — pruebas en el PC (sin placa). Compila con el mbedTLS de third_party/ (hay que haber
# pasado scripts/fetch-sources.sh) y las ejecuta. Hoy: equivalencia del backend "soft" del secure
# element con la derivación de la v0.1.0 (firmware/tests/test_se_soft.c).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
M="$ROOT/third_party/pico-keys-sdk/third-party/mbedtls"
SDK="$ROOT/third_party/pico-keys-sdk/src"
OUT="$(mktemp -d)"
trap 'rm -r "$OUT"' EXIT
# Las fuentes propias con avisos; mbedTLS sin ellos (es código de terceros).
gcc -O1 -Wall -Wextra -c -o "$OUT/se_soft.o" -I"$ROOT/firmware/src/se" -I"$SDK" -I"$SDK/rng" -I"$M/include" "$ROOT/firmware/src/se/se_soft.c"
gcc -O1 -Wall -Wextra -c -o "$OUT/test.o" -I"$ROOT/firmware/src/se" -I"$SDK" -I"$M/include" "$ROOT/firmware/tests/test_se_soft.c"
gcc -O1 -w -o "$OUT/test_se_soft" "$OUT/se_soft.o" "$OUT/test.o" \
  -I"$M/include" -I"$M/library" \
  "$M"/library/*.c
"$OUT/test_se_soft"
