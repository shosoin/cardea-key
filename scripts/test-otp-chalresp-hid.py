#!/usr/bin/env python3
"""Cardea Key — challenge-response HMAC-SHA1 de un slot OTP por el teclado HID, como ykman, pero
con cualquier VID/PID (ykman solo usa el HID con el VID de Yubico). Para probar el parche 0016
(toque en modo asíncrono): manda la trama, sondea el estado (GET_REPORT) y lee la respuesta.

  test-otp-chalresp-hid.py --slot 2 --challenge 6b65792d7632 [--key HEX]

Con un slot "con toque" el estado lleva 0x20 mientras espera; al pulsar llega la respuesta, y si
nadie pulsa vence (15 s en Cardea). Con --key comprueba el HMAC-SHA1 (slot en modo HMAC_LT64,
el de ykman por defecto). Necesita root o permisos sobre /dev/hidraw*.
"""
import argparse
import fcntl
import hashlib
import hmac
import os
import time
from importlib.machinery import SourceFileLoader

here = os.path.dirname(os.path.abspath(__file__))
ohf = SourceFileLoader("ohf", os.path.join(here, "otp-hid-frame.py")).load_module()

SLOT_CMD = {1: 0x30, 2: 0x38}   # HMAC-SHA1 challenge-response por slot

ap = argparse.ArgumentParser()
ap.add_argument("--slot", type=int, choices=(1, 2), default=2)
ap.add_argument("--challenge", default="6b65792d7632")
ap.add_argument("--key")
ap.add_argument("--vid", type=lambda x: int(x, 0), default=0x1209)
ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x0001)
ap.add_argument("--timeout", type=float, default=25)
a = ap.parse_args()

chal = bytes.fromhex(a.challenge)
assert chal and chal[-1] != 0, "el último byte del challenge no puede ser 00 (relleno LT64)"
dev = ohf.find_keyboard({(a.vid, a.pid)})
if not dev:
    raise SystemExit("No encuentro la interfaz de teclado de la llave")
fd = os.open(dev, os.O_RDWR)


def get():
    buf = bytearray(9)
    fcntl.ioctl(fd, ohf.hidiocgfeature(len(buf)), buf)
    return bytes(buf[1:])


# Restos de un intercambio anterior (respuesta sin leer o marca de fin): se vacían antes de mandar.
for _ in range(16):
    r = get()
    if not r[7] & 0x40:
        break
else:
    raise SystemExit("la llave sigue dando datos de respuesta; ¿otra orden en curso?")

payload = chal.ljust(64, b"\x00")
frame = payload + bytes([SLOT_CMD[a.slot]]) + ohf.crc16(payload).to_bytes(2, "little") + b"\x00\x00\x00"
for seq in range(10):
    fcntl.ioctl(fd, ohf.hidiocsfeature(9), bytes([0]) + frame[seq * 7:(seq + 1) * 7] + bytes([0x80 | seq]))
    time.sleep(0.01)
t0 = time.time()
print(f"challenge {chal.hex()} al slot {a.slot} por {dev}; esperando...", flush=True)
waiting = False
data = b""
while time.time() - t0 < a.timeout:
    r = get()
    flags = r[7]
    if flags & 0x40:                      # respuesta: 7 bytes por informe
        data += r[:7]
        while True:                        # hasta la marca de fin (0x40 sin datos) o el estado normal
            r = get()
            if not r[7] & 0x40 or (r[7] == 0x40 and len(data) >= 22):
                break
            data += r[:7]
        break
    if flags & 0x20 and not waiting:
        waiting = True
        print(f"  estado 0x{flags:02x}: esperando toque ({time.time() - t0:.1f} s)", flush=True)
        notify = os.path.join(here, "notify-user.sh")
        if os.path.exists(notify) and not os.environ.get("NO_NOTIFY"):
            os.system(f'"{notify}" "Cardea Key: pulsa el botón" "Challenge-response OTP esperando toque" >/dev/null 2>&1 &')
    if waiting and not flags & 0x20 and not flags & 0x40 and not flags & 0x80:
        print(f"  la espera terminó sin respuesta (estado 0x{flags:02x}) tras {time.time() - t0:.1f} s")
        break
    time.sleep(0.1)
os.close(fd)
t = time.time() - t0
if not data:
    print(f"SIN RESPUESTA tras {t:.1f} s (vencido, denegado o cancelado)")
    raise SystemExit(1)
resp = data[:20]
print(f"respuesta tras {t:.1f} s: {resp.hex()}  (hubo espera de toque: {waiting})")
if a.key:
    exp = hmac.new(bytes.fromhex(a.key), chal, hashlib.sha1).digest()
    print("HMAC-SHA1 " + ("CORRECTO" if resp == exp else f"DISTINTO (esperado {exp.hex()})"))
