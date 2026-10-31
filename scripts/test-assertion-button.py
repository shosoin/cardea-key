#!/usr/bin/env python3
"""Cardea Key — prueba del parche 0020: getAssertion (firmar con una passkey) debe esperar el botón.

Firma dos veces con una passkey residente ya existente (por defecto la de rp key-v2.test):
  1. pulsando el botón  -> debe firmar, con UP=1, después de esperar la pulsación;
  2. SIN pulsar         -> debe denegarse (OPERATION_DENIED) al acabar el tiempo de espera.
Antes del parche, la firma salía en 0,3 s con UP=1 sin tocar la llave.

Uso: test-assertion-button.py --pin-file N [--rp key-v2.test]
"""
import argparse
import os
import sys
import time
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice


def assertion(ctap, pin, rp):
    protocol = PinProtocolV2()
    token = ClientPin(ctap, protocol).get_pin_token(pin, permissions=ClientPin.PERMISSION.GET_ASSERTION,
                                                    permissions_rpid=rp)
    cdh = os.urandom(32)
    t0 = time.time()
    try:
        ga = ctap.get_assertion(rp, cdh, pin_uv_param=protocol.authenticate(token, cdh),
                                pin_uv_protocol=protocol.VERSION)
        return time.time() - t0, ga.auth_data.flags, None
    except CtapError as e:
        return time.time() - t0, None, e.code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin-file", required=True)
    ap.add_argument("--rp", default="key-v2.test")
    a = ap.parse_args()
    pin = Path(a.pin_file).read_text().strip()
    devs = [d for d in CtapHidDevice.list_devices() if (d.descriptor.vid, d.descriptor.pid) == (0x1209, 0x0001)]
    if len(devs) != 1:
        sys.exit(f"Esperaba una llave y encuentro {len(devs)}")
    ctap = Ctap2(devs[0])

    print("1. PULSA el botón cuando el LED se quede fijo...", flush=True)
    t, flags, err = assertion(ctap, pin, a.rp)
    if err is not None or not flags & 1:
        sys.exit(f"   FALLO: err={err} flags={flags}")
    print(f"   OK  firmó tras {t:.1f} s con UP=1")
    if t < 1.0:
        sys.exit("   FALLO: demasiado rápido, no esperó al botón")

    print("2. Ahora NO pulses: debe denegarse al acabar la espera...", flush=True)
    t, flags, err = assertion(ctap, pin, a.rp)
    if err == CtapError.ERR.OPERATION_DENIED:
        print(f"   OK  denegada tras {t:.1f} s sin pulsación (0x{err:02x})")
    else:
        sys.exit(f"   FALLO: err={err} flags={flags} en {t:.1f} s")
    print("\nTODO CORRECTO")


if __name__ == "__main__":
    main()
