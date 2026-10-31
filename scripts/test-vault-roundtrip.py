#!/usr/bin/env python3
"""Cardea Key — prueba en la placa del vault (export/import) y de la restauración de la clave maestra.

Necesita una llave con firmware ENABLE_VAULT=ON, con PIN y dada de alta en el vault de
--vault-file (scripts/cardea-vault.py enroll). Pide dos toques del botón.

1. Crea una passkey de prueba (rp vault-test.cardeakey.org).               [toque 1]
2. La exporta con el vault y comprueba que la copia se descifra con la identidad del vault.
3. La borra de la llave (credential management) y comprueba que ya no está.
4. Importa la copia y comprueba que vuelve con el mismo id.
5. Restauración de la clave maestra (CTAP_VENDOR_BACKUP 0x02), parche 0019: con PIN puesto,
   sin token, con token falso y con tamaño incorrecto debe rechazarse SIN llegar al botón ni
   tocar la clave maestra.
6. Firma con la passkey restaurada y verifica la firma con la clave pública original.  [toque 2]
7. Borra la passkey de prueba.

Uso: test-vault-roundtrip.py --vault-file F --passphrase-file P --pin-file N
"""
import argparse
import hashlib
import importlib.util
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("cardea_vault", Path(__file__).with_name("cardea-vault.py"))
cv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cv)

from fido2 import cbor  # noqa: E402
from fido2.ctap import CtapError  # noqa: E402
from fido2.ctap2 import CredentialManagement  # noqa: E402
from fido2.ctap2.pin import ClientPin  # noqa: E402
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity  # noqa: E402

RP = "vault-test.cardeakey.org"
CTAP_VENDOR_BACKUP = 0x01
P = ClientPin.PERMISSION


def step(msg):
    print(f"\n== {msg}", flush=True)


def ok(msg):
    print(f"   OK  {msg}", flush=True)


def fail(msg):
    print(f"   FALLO  {msg}", flush=True)
    sys.exit(1)


def backup_call(device, params, auth=None, protocol_version=2):
    arguments = {1: 0x02, 2: params}
    if auth is not None:
        arguments[3] = protocol_version
        arguments[4] = auth
    try:
        # En los comandos de fabricante el estado CTAP va en el primer byte de la respuesta.
        response = device.call(cv.CTAP_VENDOR_CBOR, bytes([CTAP_VENDOR_BACKUP]) + cbor.encode(arguments))
        return response[0]
    except CtapError as e:
        return e.code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault-file", required=True)
    ap.add_argument("--passphrase-file", required=True)
    ap.add_argument("--pin-file", required=True)
    a = ap.parse_args()
    _, kvault, _ = cv.vault_open(a.vault_file, cv.read_secret(a.passphrase_file, ""))
    pin = cv.read_secret(a.pin_file, "")
    device = cv.open_device()
    st = cv.device_status(device)
    if st.get(1) != cv.vault_id(kvault):
        fail("la llave no está dada de alta en este vault")
    ok(f"llave {device.descriptor.serial_number} en el vault {cv.vault_id(kvault).hex()[:16]}…")

    step("1. Crear passkey de prueba (PULSA EL BOTÓN cuando el LED se quede fijo)")
    ctap, protocol, token = cv.pin_session(device, pin, P.MAKE_CREDENTIAL)
    client_data_hash = os.urandom(32)
    user = PublicKeyCredentialUserEntity(id=os.urandom(16), name="vault-test", display_name="Vault test")
    mc = ctap.make_credential(client_data_hash, PublicKeyCredentialRpEntity(id=RP, name="Cardea vault test"), user,
                              [{"type": "public-key", "alg": -7}], options={"rk": True},
                              pin_uv_param=protocol.authenticate(token, client_data_hash),
                              pin_uv_protocol=protocol.VERSION)
    cred = mc.auth_data.credential_data
    cred_id, public_key = cred.credential_id, cred.public_key
    ok(f"passkey creada, id {cred_id.hex()[:24]}…")

    step("2. Exportar con el vault")
    ctap, protocol, token = cv.pin_session(device, pin, P.AUTHENTICATOR_CFG | P.CREDENTIAL_MGMT)
    code, r = cv.vendor_call(device, cv.VAULT_EXPORT, {1: cred_id}, (protocol, token))
    if code != 0:
        fail(f"exportación rechazada 0x{code:02x}")
    blob = r[1]
    inner = cv.blob_decrypt(kvault, blob)
    # Campo 2: id interno de la credencial; campo 6: el id que ve el servicio (requested_id).
    if inner.get(4) != RP or cred_id not in (inner.get(2), inner.get(6)):
        fail(f"la copia descifrada no corresponde: rp={inner.get(4)} ids={inner.get(2, b'').hex()[:16]}/{inner.get(6, b'').hex()[:16]}")
    ok(f"copia de {len(blob)} B; se descifra con la identidad del vault (rp={inner.get(4)})")

    step("3. Borrar la passkey de la llave")
    cm = CredentialManagement(ctap, protocol, token)
    cm.delete_cred({"type": "public-key", "id": cred_id})
    if any(c[1] == cred_id for c in cv.resident_credentials(ctap, protocol, token)):
        fail("sigue en la llave tras borrarla")
    ok("borrada")

    step("4. Importar la copia")
    ctap, protocol, token = cv.pin_session(device, pin, P.AUTHENTICATOR_CFG | P.CREDENTIAL_MGMT)
    code, _ = cv.vendor_call(device, cv.VAULT_IMPORT, {1: blob}, (protocol, token))
    if code != 0:
        fail(f"importación rechazada 0x{code:02x}")
    if not any(c[0] == RP and c[1] == cred_id for c in cv.resident_credentials(ctap, protocol, token)):
        fail("la passkey no aparece tras importarla")
    ok("de vuelta en la llave con el mismo id")
    tampered = bytearray(blob)
    tampered[-1] ^= 1
    code, _ = cv.vendor_call(device, cv.VAULT_IMPORT, {1: bytes(tampered)}, (protocol, token))
    ok(f"copia alterada rechazada (0x{code:02x})") if code != 0 else fail("aceptó una copia alterada")

    step("5. Restaurar clave maestra sin PIN válido (parche 0019): debe rechazarse sin pedir botón")
    print("   ¡NO PULSES EL BOTÓN en este paso! Con un firmware sin el parche 0019, una pulsación"
          " aquí borraría la clave maestra.", flush=True)
    fake = os.urandom(60)
    code = backup_call(device, {1: fake})
    ok(f"sin token: 0x{code:02x} PUAT_REQUIRED") if code == CtapError.ERR.PUAT_REQUIRED else fail(f"sin token: 0x{code:02x}")
    code = backup_call(device, {1: fake}, auth=os.urandom(32))
    ok(f"token falso: 0x{code:02x} PIN_AUTH_INVALID") if code == CtapError.ERR.PIN_AUTH_INVALID else fail(f"token falso: 0x{code:02x}")
    code = backup_call(device, {1: os.urandom(10)})
    ok(f"tamaño incorrecto: 0x{code:02x} INVALID_PARAMETER") if code == CtapError.ERR.INVALID_PARAMETER else fail(f"tamaño: 0x{code:02x}")

    step("6. Firmar con la passkey restaurada (PULSA EL BOTÓN)")
    ctap, protocol, token = cv.pin_session(device, pin, P.GET_ASSERTION)
    client_data_hash = os.urandom(32)
    ga = ctap.get_assertion(RP, client_data_hash, allow_list=[{"type": "public-key", "id": cred_id}],
                            pin_uv_param=protocol.authenticate(token, client_data_hash),
                            pin_uv_protocol=protocol.VERSION)
    public_key.verify(ga.auth_data + client_data_hash, ga.signature)
    ok("firma válida con la clave pública original: la clave maestra sigue intacta y la copia funciona")

    step("7. Limpieza")
    ctap, protocol, token = cv.pin_session(device, pin, P.CREDENTIAL_MGMT)
    CredentialManagement(ctap, protocol, token).delete_cred({"type": "public-key", "id": cred_id})
    ok("passkey de prueba borrada")
    print("\nTODO CORRECTO")


if __name__ == "__main__":
    main()
