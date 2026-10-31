#!/usr/bin/env bash
# Cardea Key — reinicia la llave en modo BOOTSEL (para grabar firmware) sin desenchufarla.
#
# Usa el applet de rescate de Pico Keys (AID A0583FC19B7E4F21, INS 0x1F, P1=1) por PC/SC.
# Por seguridad la llave EXIGE pulsar su botón: hay ~30 s desde que se lanza la orden.
# Tras el reinicio aparece la unidad "RP2350" (o "RPI-RP2") para copiar el .uf2, o se usa picotool.
#
# Requisitos: pcscd en marcha y que vea la llave (con un VID/PID de pruebas, ver
# scripts/libccid-reader.py), y opensc-tool (paquete opensc).
#
# Uso: scripts/cardea-bootsel.sh [--normal]   (--normal: reinicio normal, sin botón)
#      CARDEA_READER="texto" para elegir el lector por nombre (por defecto "Cardea").
set -euo pipefail

match="${CARDEA_READER:-${KEYV2_READER:-Cardea}}"
p1="01"
if [[ "${1:-}" == "--normal" ]]; then p1="00"; fi

if ! command -v opensc-tool >/dev/null; then
    echo "Falta opensc-tool (sudo apt install opensc)." >&2; exit 1
fi

reader=$(opensc-tool -l 2>/dev/null | awk -v m="$match" 'index($0, m) && $1 ~ /^[0-9]+$/ {print $1; exit}')
if [[ -z "$reader" ]]; then
    cat >&2 <<EOF
No encuentro la llave entre los lectores PC/SC (buscando "$match").
- ¿Está enchufada? ¿pcscd la ve? (opensc-tool -l)
- Con un VID/PID que libccid no conoce, añádelo con: sudo scripts/libccid-reader.py
Alternativa manual: desenchufa la llave y vuelve a enchufarla con el botón pulsado.
EOF
    exit 1
fi

if [[ "$p1" == "01" ]]; then
    echo ">>> Pulsa el botón de la llave para confirmar el reinicio en BOOTSEL (tienes ~30 s)..."
    if [[ -x "$(dirname "$0")/notify-user.sh" ]]; then
        "$(dirname "$0")/notify-user.sh" "Cardea Key: BOOTSEL" "Pulsa el botón de la llave para reiniciarla en modo BOOTSEL." || true
    fi
fi

out=$(opensc-tool -r "$reader" -s "00 A4 04 00 08 A0 58 3F C1 9B 7E 4F 21" -s "80 1F $p1 00" 2>&1 || true)
if grep -q "Card removed\|SW1=0x90, SW2=0x00):\?$" <<<"$(tail -2 <<<"$out")"; then
    echo "OK: la llave se está reiniciando$([[ $p1 == 01 ]] && echo ' en modo BOOTSEL')."
elif grep -q "SW1=0x69, SW2=0x85" <<<"$out"; then
    echo "No se pulsó el botón a tiempo (6985). Vuelve a intentarlo." >&2; exit 2
else
    echo "Respuesta inesperada:" >&2; tail -3 <<<"$out" >&2; exit 3
fi
