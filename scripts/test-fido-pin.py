#!/usr/bin/env python3
"""Cardea Key — prueba del PIN de FIDO2 (issue #3) en la placa, sin botón.

  test-fido-pin.py [--pin 123456]

Recorre la ruta de PIN y deja la llave como estaba (mismo PIN, contador lleno):
  1. intentos que quedan (tiene que haber PIN puesto y el contador lleno, 8);
  2. token con el PIN bueno y lista de credenciales residentes (prueba que la clave de dispositivo
     se abre; con el backend "model", el primer acierto es además la migración);
  3. un PIN malo: CTAP2_ERR_PIN_INVALID y queda uno menos;
  4. el bueno: el contador vuelve a 8;
  5. cambio de PIN a otro y vuelta, comprobando que el viejo deja de valer y que las credenciales
     siguen abriéndose con el nuevo.
No llega a los 3 fallos seguidos (pediría desenchufar) ni bloquea nada.

Solo para placas de pruebas. Necesita python-fido2 y acceso al HID de la llave (VID 0x1209).
"""
import argparse
import sys

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.hid import CtapHidDevice

OTHER_PIN = "24681357"


def device():
    dev = next((d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209), None)
    if not dev:
        sys.exit("no encuentro el HID FIDO de la llave")
    return Ctap2(dev)


def retries(cp):
    n, power_cycle = cp.get_pin_retries()
    return n, bool(power_cycle)


def rps_with(ctap, cp, pin):
    token = cp.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap, cp.protocol, token)
    n = cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    return [rp[CredentialManagement.RESULT.RP]["id"] for rp in cm.enumerate_rps()] if n else []


def expect_error(fn, code, what):
    try:
        fn()
    except CtapError as e:
        if e.code != code:
            sys.exit(f"FALLO {what}: esperaba {code.name}, llega {e.code.name}")
        return
    sys.exit(f"FALLO {what}: esperaba {code.name} y ha funcionado")


def step(n, text):
    print(f"[{n}] {text}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pin", default="123456")
    pin = ap.parse_args().pin

    ctap = device()
    if not ctap.info.options.get("clientPin"):
        sys.exit("la llave no tiene PIN de FIDO2 puesto")
    cp = ClientPin(ctap)

    n, pc = retries(cp)
    step(1, f"intentos: {n}{' (pide desenchufar)' if pc else ''}")
    if pc or n != 8:
        sys.exit("FALLO: quiero empezar con el contador lleno (8) y sin bloqueo por arranque")

    rps = rps_with(ctap, cp, pin)
    step(2, f"PIN bueno: token OK, credenciales residentes {rps}")

    expect_error(lambda: cp.get_pin_token(pin + "9"), CtapError.ERR.PIN_INVALID, "PIN malo")
    n, _ = retries(cp)
    step(3, f"PIN malo: PIN_INVALID, intentos {n}")
    if n != 7:
        sys.exit("FALLO: el fallo no ha contado")

    cp.get_pin_token(pin)
    n, _ = retries(cp)
    step(4, f"PIN bueno: intentos {n}")
    if n != 8:
        sys.exit("FALLO: un acierto no repone el contador")

    cp.change_pin(pin, OTHER_PIN)
    try:
        expect_error(lambda: cp.get_pin_token(pin), CtapError.ERR.PIN_INVALID, "PIN viejo tras el cambio")
        rps2 = rps_with(ctap, cp, OTHER_PIN)
        n, _ = retries(cp)
        step(5, f"cambio de PIN: el viejo no vale, con el nuevo credenciales {rps2}, intentos {n}")
        if rps2 != rps or n != 8:
            sys.exit("FALLO tras el cambio de PIN")
    except BaseException:
        # dejar la llave con su PIN aunque la prueba falle a mitad
        try:
            cp.change_pin(OTHER_PIN, pin)
            print(f"    (PIN devuelto a {pin} tras el fallo)")
        except Exception as e:  # noqa: BLE001
            print(f"    OJO: no he podido devolver el PIN a {pin} ({e}); el PIN actual es {OTHER_PIN}")
        raise
    cp.change_pin(OTHER_PIN, pin)
    rps3 = rps_with(ctap, cp, pin)
    n, _ = retries(cp)
    print(f"    vuelta al PIN original: credenciales {rps3}, intentos {n}")
    if rps3 != rps or n != 8:
        sys.exit("FALLO al volver al PIN original")
    print("OK: ruta de PIN de FIDO2 correcta")


if __name__ == "__main__":
    main()
