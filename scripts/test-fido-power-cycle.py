#!/usr/bin/env python3
"""Cardea Key — prueba del bloqueo de FIDO2 tras 3 PIN fallidos seguidos (hasta reiniciar), sin botón.

  test-fido-power-cycle.py [--pin 123456] [--no-reboot]

CTAP 2.1: tras 3 PIN incorrectos seguidos, la llave no debe evaluar más PIN hasta un apagado y
encendido (CTAP2_ERR_PIN_AUTH_BLOCKED). En pico-fido original, un CTAPHID_INIT (lo manda cualquier
cliente al abrir la llave) borraba ese bloqueo y el PIN correcto volvía a entrar (aviso
GHSA-r8qh-fj4q-7xjp). La prueba:
  1. tres PIN malos: el tercero da PIN_AUTH_BLOCKED; quedan 5 intentos;
  2. nuevo CTAPHID_INIT y el PIN BUENO: debe dar PIN_AUTH_BLOCKED, sin gastar intento;
  3. reinicio real de la llave (applet de rescate, sin botón) y el PIN bueno: entra, 8 intentos.
Gasta 3 de los 8 intentos y los repone al final. Solo para placas de pruebas.
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin
from fido2.hid import CtapHidDevice


def open_pin():
    """A fresh CtapHidDevice: opening it sends CTAPHID_INIT."""
    for _ in range(20):
        dev = next((d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209), None)
        if dev:
            return ClientPin(Ctap2(dev))
        time.sleep(0.5)
    sys.exit("no encuentro el HID FIDO de la llave")


def token_result(cp, pin):
    try:
        cp.get_pin_token(pin)
        return "OK"
    except CtapError as e:
        return e.code.name


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pin", default="123456")
    ap.add_argument("--no-reboot", action="store_true", help="no reiniciar al final (hacerlo a mano)")
    a = ap.parse_args()
    bad = a.pin + "0"

    cp = open_pin()
    n, pc = cp.get_pin_retries()
    if n != 8 or pc:
        sys.exit(f"FALLO: quiero empezar con 8 intentos y sin bloqueo (hay {n}, bloqueo {pc})")

    results = [token_result(cp, bad) for _ in range(3)]
    n, pc = cp.get_pin_retries()
    print(f"[1] tres PIN malos: {results}; intentos {n}, bloqueo por arranque {bool(pc)}")
    if results != ["PIN_INVALID", "PIN_INVALID", "PIN_AUTH_BLOCKED"] or n != 5:
        sys.exit("FALLO: el tercer fallo debía bloquear hasta reiniciar")

    cp = open_pin()                                   # CTAPHID_INIT
    r = token_result(cp, a.pin)
    n, pc = cp.get_pin_retries()
    print(f"[2] tras CTAPHID_INIT, PIN BUENO: {r}; intentos {n}")
    blocked = r == "PIN_AUTH_BLOCKED" and n == 5
    if r == "OK":
        print("    -> FALLO DE SEGURIDAD: CTAPHID_INIT ha quitado el bloqueo (comportamiento de upstream)")

    if a.no_reboot:
        print("Reinicia la llave a mano y comprueba que el PIN bueno entra con 8 intentos.")
    elif r != "OK":
        here = Path(__file__).resolve().parent
        subprocess.run([str(here / "cardea-bootsel.sh"), "--normal"], check=False, capture_output=True)
        time.sleep(4)
        cp = open_pin()
        r3 = token_result(cp, a.pin)
        n, pc = cp.get_pin_retries()
        print(f"[3] tras reiniciar, PIN bueno: {r3}; intentos {n}")
        if r3 != "OK" or n != 8:
            sys.exit("FALLO: tras reiniciar el PIN bueno debía entrar")
    if not blocked:
        sys.exit("FALLO: el bloqueo por arranque no aguanta un CTAPHID_INIT")
    print("OK: el bloqueo por arranque solo se quita reiniciando")


if __name__ == "__main__":
    main()
