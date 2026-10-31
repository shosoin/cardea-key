#!/usr/bin/env python3
"""Cardea Key — prueba de presencia de usuario (botón) por CTAPHID, sin PIN.

Manda authenticatorSelection (CTAP2 0x0B), que solo pide pulsar el botón, y muestra cuánto
tarda y qué responde. Respuesta esperada:
  00  -> botón pulsado (CTAP2_OK)
  2f  -> nadie pulsó en el tiempo de espera (CTAP2_ERR_USER_ACTION_TIMEOUT)
  27  -> cancelado / denegado (CTAP2_ERR_OPERATION_DENIED)
Uso: scripts/test-button.py [--vid 0x1209 --pid 0x0001]
"""
import argparse
import os
import subprocess
import time

from fido2.hid import CtapHidDevice, CTAPHID

ap = argparse.ArgumentParser()
ap.add_argument("--vid", type=lambda x: int(x, 0), default=0x1209)
ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x0001)
a = ap.parse_args()

dev = next(d for d in CtapHidDevice.list_devices() if d.descriptor.vid == a.vid and d.descriptor.pid == a.pid)
print(">>> Esperando botón (la llave espera hasta 30 s)...", flush=True)
t0 = time.time()
seen = []
NOTIFY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notify-user.sh")


def on_keepalive(status):
    if int(status) == 2 and 2 not in seen and os.path.exists(NOTIFY):  # UPNEEDED: avisar una vez
        subprocess.run([NOTIFY, "Cardea Key: pulsa el botón", "La llave espera el botón (LED encendido fijo)."], check=False)
    seen.append(int(status))


try:
    r = dev.call(CTAPHID.CBOR, b"\x0b", on_keepalive=on_keepalive)
    code = r[0] if r else None
    meaning = {0x00: "OK (pulsado)", 0x2F: "TIMEOUT (nadie pulsó)", 0x27: "DENEGADO"}.get(code, "?")
    print(f"respuesta: {r.hex()} = {meaning} tras {time.time() - t0:.1f} s")
except Exception as e:  # noqa: BLE001
    print(f"excepción: {e!r} tras {time.time() - t0:.1f} s")
print("keepalives recibidos:", sorted(set(seen)), "(1=procesando, 2=esperando botón)")
