#!/usr/bin/env python3
"""Cardea Key — prueba del fallo de pico-fido#311: lecturas de estado del teclado OTP (GET_REPORT)
mientras una orden CTAP espera el botón.

Manda authenticatorSelection (CTAP2 0x0B) por la interfaz FIDO y, mientras la llave espera el
botón, lee el estado OTP por la interfaz de teclado (GET_REPORT de característica) cada 0,2 s,
como hace el PC de vez en cuando. NO pulses el botón: hay que dejar que venza (30 s).

  2f -> correcto: TIMEOUT llega como TIMEOUT aunque hubo GET_REPORT en medio
  00 -> FALLO: la respuesta CTAP se perdió (el callback HID reapuntó el buffer de respuesta)

También muestra el último byte de los informes leídos: 0x80 = la llave contestó desde la caché de
estado "ocupada" (arreglo de upstream f6c197a).
Uso (root o permisos sobre /dev/hidraw*): test-otp-getreport-race.py [--vid 0x1209 --pid 0x0001]
(por defecto 2E8A:10FE, el de pico-fido original; Cardea Key es 1209:0001)
"""
import argparse
import collections
import fcntl
import os
import threading
import time

from fido2.hid import CtapHidDevice, CTAPHID

from importlib.machinery import SourceFileLoader

here = os.path.dirname(os.path.abspath(__file__))
ohf = SourceFileLoader("ohf", os.path.join(here, "otp-hid-frame.py")).load_module()

ap = argparse.ArgumentParser()
ap.add_argument("--vid", type=lambda x: int(x, 0), default=0x2E8A)
ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x10FE)
ap.add_argument("--period", type=float, default=0.2)
a = ap.parse_args()

dev = next(d for d in CtapHidDevice.list_devices() if d.descriptor.vid == a.vid and d.descriptor.pid == a.pid)
kbd = ohf.find_keyboard({(a.vid, a.pid)})
if not kbd:
    raise SystemExit("No encuentro la interfaz de teclado de la llave")
print(f"FIDO: {dev.descriptor.path}  teclado: {kbd}")

stop = threading.Event()
reads = collections.Counter()
errors = []
samples = []


def poll():
    fd = os.open(kbd, os.O_RDWR)
    try:
        while not stop.is_set():
            buf = bytearray(9)
            try:
                fcntl.ioctl(fd, ohf.hidiocgfeature(len(buf)), buf)
                reads[buf[8]] += 1
                if len(samples) < 3:
                    samples.append(bytes(buf[1:]).hex())
            except OSError as e:
                errors.append(repr(e))
            time.sleep(a.period)
    finally:
        os.close(fd)


print(">>> NO pulses el botón. Esperando a que venza (unos 30 s)...", flush=True)
seen = set()
t = threading.Thread(target=poll, daemon=True)
t0 = time.time()
t.start()
try:
    r = dev.call(CTAPHID.CBOR, b"\x0b", on_keepalive=lambda s: seen.add(int(s)))
    code = r[0] if r else None
    meaning = {0x00: "OK  <-- FALLO (respuesta perdida)", 0x2F: "TIMEOUT (correcto)", 0x27: "DENEGADO"}.get(code, "?")
    print(f"respuesta: {r.hex()} = {meaning} tras {time.time() - t0:.1f} s")
except Exception as e:  # noqa: BLE001
    print(f"excepción: {e!r} tras {time.time() - t0:.1f} s")
stop.set()
t.join()
print("keepalives:", sorted(seen), "(1=procesando, 2=esperando botón)")
print(f"GET_REPORT durante la espera: {sum(reads.values())} (último byte: "
      + ", ".join(f"0x{k:02x}×{v}" for k, v in sorted(reads.items())) + ")")
print("primeros informes:", samples)
if errors:
    print(f"errores de lectura: {len(errors)}, p. ej. {errors[0]}")
