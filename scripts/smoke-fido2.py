#!/usr/bin/env python3
"""Cardea Key — prueba de humo FIDO2 sin prompts (python-fido2 >= 1.1).

Qué hace, contra la primera llave FIDO conectada (o la de --vid/--pid):
  1. Muestra la info CTAP2 (versiones, opciones, reintentos de PIN).
  2. Si la llave no tiene PIN, fija el PIN de PRUEBAS indicado (por defecto 123456).
  3. Registra una credencial residente para el RP "key-v2.test"  -> pulsar el botón.
  4. Hace una autenticación con ella y verifica la firma           -> pulsar el botón.
  5. Lista las credenciales residentes con credMgmt.

Solo para placas de pruebas: el PIN va en la línea de órdenes.
Uso: scripts/smoke-fido2.py [--pin 123456] [--vid 0x2e8a --pid 0x10fe]
"""
import argparse
import os
import subprocess
import sys

from fido2.client import Fido2Client, UserInteraction
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.hid import CtapHidDevice
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_ID = "key-v2.test"
ORIGIN = "https://" + RP_ID


class Interaction(UserInteraction):
    def __init__(self, pin):
        self.pin = pin

    def prompt_up(self):
        # python-fido2 llama a esto cuando la llave avisa (keepalive UPNEEDED) de que espera el botón
        print(">>> PULSA EL BOTÓN de la llave (LED encendido fijo)", flush=True)
        notify = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notify-user.sh")
        if os.path.exists(notify):
            subprocess.run([notify, "Cardea Key: pulsa el botón", "La llave espera el botón (LED encendido fijo).\nPúlsalo una vez."], check=False)

    def request_pin(self, permissions, rp_id):
        return self.pin

    def request_uv(self, permissions, rp_id):
        return True


def pick_device(vid, pid):
    for dev in CtapHidDevice.list_devices():
        d = dev.descriptor
        if (vid is None or d.vid == vid) and (pid is None or d.pid == pid):
            return dev
    sys.exit("No hay ninguna llave FIDO conectada (o no coincide VID/PID)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", default="123456")
    ap.add_argument("--vid", type=lambda x: int(x, 0))
    ap.add_argument("--pid", type=lambda x: int(x, 0))
    a = ap.parse_args()

    dev = pick_device(a.vid, a.pid)
    print(f"Llave: {dev.descriptor.path} {dev.descriptor.vid:04x}:{dev.descriptor.pid:04x} "
          f"{dev.descriptor.product_name!r}")
    ctap = Ctap2(dev)
    info = ctap.info
    print("versions:", info.versions)
    print("options :", info.options)
    client_pin = ClientPin(ctap)

    # 1-2. PIN
    if not info.options.get("clientPin"):
        print(f"Sin PIN: fijando PIN de pruebas ({len(a.pin)} dígitos)")
        client_pin.set_pin(a.pin)
        ctap = Ctap2(dev)
        client_pin = ClientPin(ctap)
    print("PIN retries:", client_pin.get_pin_retries()[0])

    client = Fido2Client(dev, ORIGIN, user_interaction=Interaction(a.pin))

    # 3. Registro
    print("\n[registro] credencial residente para", RP_ID)
    create = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id=RP_ID, name="Cardea Key prueba"),
        user=PublicKeyCredentialUserEntity(id=os.urandom(16), name="prueba", display_name="Prueba"),
        challenge=os.urandom(32),
        pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    reg = client.make_credential(create)
    auth_data = reg.attestation_object.auth_data
    cred = auth_data.credential_data
    print("  fmt          :", reg.attestation_object.fmt)
    print("  flags UP/UV  :", auth_data.is_user_present(), auth_data.is_user_verified())
    print("  aaguid       :", cred.aaguid.hex())
    print("  credential id:", cred.credential_id.hex()[:32] + "…", f"({len(cred.credential_id)} B)")
    print("  sign count   :", auth_data.counter)

    # 4. Autenticación
    print("\n[autenticación] con la credencial recién creada")
    req = PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY,
                                                         id=cred.credential_id)],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    res = client.get_assertion(req).get_response(0)
    cred.public_key.verify(bytes(res.authenticator_data) + res.client_data.hash, res.signature)
    print("  firma ES256  : OK (verificada con la clave pública del registro)")
    print("  sign count   :", res.authenticator_data.counter)

    # 5. Credenciales residentes
    print("\n[credMgmt] credenciales residentes")
    token = client_pin.get_pin_token(a.pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap, client_pin.protocol, token)
    meta = cm.get_metadata()
    print("  guardadas / libres:", meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT],
          "/", meta[CredentialManagement.RESULT.MAX_REMAINING_COUNT])
    for rp in cm.enumerate_rps():
        rp_id = rp[CredentialManagement.RESULT.RP]["id"]
        n = len(cm.enumerate_creds(rp[CredentialManagement.RESULT.RP_ID_HASH]))
        print(f"  {rp_id}: {n} credencial(es)")
    print("\nPRUEBA FIDO2: OK")


if __name__ == "__main__":
    main()
