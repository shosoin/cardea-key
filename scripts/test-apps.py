#!/usr/bin/env python3
"""Cardea Key — datos de prueba y foto del estado de todas las apps (para el test de reset cruzado).

  test-apps.py populate   crea datos en OATH, PIV y OpenPGP (sin botón)
  test-apps.py check      muestra qué hay en cada app (FIDO2 incluido) y prueba una firma OpenPGP

Solo para placas de pruebas: PINs por defecto / de pruebas (FIDO 123456, OpenPGP 123456/12345678,
PIV 123456 con clave de gestión por defecto). Necesita pcscd viendo la llave, ykman, pyscard,
python-fido2 y cryptography. Usa el lector cuyo nombre contiene "Cardea".
"""
import hashlib
import subprocess
import sys

from smartcard.System import readers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

FIDO_PIN = "123456"
OATH_NAME = "keyv2-test"
OATH_SECRET = "JBSWY3DPEHPK3PXP"          # secreto TOTP de ejemplo (RFC 4226 "Hello!")
PIV_SLOT = "9a"
P256_OID = bytes.fromhex("2A8648CE3D030107")


def reader_name():
    for r in readers():
        if "Cardea" in str(r):
            return str(r)
    sys.exit("No veo la llave en PC/SC")


def ykman(*args, check=True):
    cmd = ["ykman", "--reader", "Cardea", *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout.strip()


# ------------------------------------------------------------------------------------- OpenPGP
class Card:
    def __init__(self):
        self.c = next(r for r in readers() if "Cardea" in str(r)).createConnection()
        self.c.connect()

    def apdu(self, hexstr, data=b"", le=None, ok=(0x9000,)):
        cmd = list(bytes.fromhex(hexstr))
        if data:
            cmd += [len(data)] + list(data)
        if le is not None:
            cmd += [le]
        resp, sw1, sw2 = self.c.transmit(cmd)
        while sw1 == 0x61:  # GET RESPONSE
            more, sw1, sw2 = self.c.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            resp += more
        sw = (sw1 << 8) | sw2
        if sw not in ok:
            raise RuntimeError(f"APDU {hexstr} -> SW {sw:04X}")
        return bytes(resp), sw


def pgp_select(card):
    card.apdu("00A40400", bytes.fromhex("D27600012401"))


def find_tlv(buf, tag):
    """Busca un TLV (tags de 1 o 2 bytes) en profundidad; devuelve el valor."""
    i = 0
    while i < len(buf):
        t = buf[i]; i += 1
        if t & 0x1F == 0x1F:
            t = (t << 8) | buf[i]; i += 1
        ln = buf[i]; i += 1
        if ln == 0x81:
            ln = buf[i]; i += 1
        elif ln == 0x82:
            ln = (buf[i] << 8) | buf[i + 1]; i += 2
        val = buf[i:i + ln]
        if t == tag:
            return val
        if t in (0x7F49, 0x65, 0x6E, 0x73):
            sub = find_tlv(val, tag)
            if sub is not None:
                return sub
        i += ln
    return None


def pgp_populate(card):
    pgp_select(card)
    card.apdu("00200083", b"12345678")                     # VERIFY PW3 (admin)
    card.apdu("00DA00C1", b"\x13" + P256_OID)              # firma: ECDSA P-256
    resp, _ = card.apdu("00478000", b"\xB6\x00", le=0)     # GENERATE clave de firma
    point = find_tlv(resp, 0x86)
    print(f"  OpenPGP: clave de firma P-256 generada en la tarjeta ({len(point)} B de clave pública)")


def pgp_check(card):
    pgp_select(card)
    resp, sw = card.apdu("00478100", b"\xB6\x00", le=0, ok=(0x9000, 0x6A88, 0x6B00, 0x6A80))
    point = find_tlv(resp, 0x86) if sw == 0x9000 else None
    if not point:
        return "sin clave de firma"
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    card.apdu("00200081", b"123456")                       # VERIFY PW1 (firma)
    msg = b"Cardea Key reset cruzado"
    digest = hashlib.sha256(msg).digest()
    sig, _ = card.apdu("002A9E9A", digest, le=0)           # PSO: COMPUTE DIGITAL SIGNATURE
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
    fpr = hashlib.sha256(point).hexdigest()[:16]
    return f"clave de firma P-256 (huella pub {fpr}…), firma verificada OK"


# ------------------------------------------------------------------------------------- FIDO2
def fido_check():
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
    dev = next((d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209), None)
    if not dev:
        return "no encuentro el HID FIDO"
    ctap = Ctap2(dev)
    if not ctap.info.options.get("clientPin"):
        return "sin PIN (sin credenciales residentes protegidas)"
    cp = ClientPin(ctap)
    token = cp.get_pin_token(FIDO_PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap, cp.protocol, token)
    n = cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    rps = [rp[CredentialManagement.RESULT.RP]["id"] for rp in cm.enumerate_rps()] if n else []
    return f"PIN puesto, {n} credencial(es) residente(s) {rps}"


# ------------------------------------------------------------------------------------- main
def populate():
    print("[populate]")
    ykman("oath", "accounts", "add", "-f", OATH_NAME, OATH_SECRET)
    print(f"  OATH: cuenta TOTP '{OATH_NAME}' añadida")
    ykman("piv", "keys", "generate", "-a", "ECCP256", "-m", "010203040506070801020304050607080102030405060708",
          PIV_SLOT, "/tmp/keyv2-piv-9a.pub")
    ykman("piv", "certificates", "generate", "-s", "CN=keyv2-test", "-P", "123456",
          "-m", "010203040506070801020304050607080102030405060708", PIV_SLOT, "/tmp/keyv2-piv-9a.pub")
    print(f"  PIV: clave ECCP256 + certificado autofirmado en el slot {PIV_SLOT}")
    pgp_populate(Card())


def check():
    print("[check]")
    for name, fn in (("FIDO2  ", fido_check),
                     ("OATH   ", lambda: ykman("oath", "accounts", "list") or "sin cuentas"),
                     ("PIV    ", lambda: next((l.strip() for l in ykman("piv", "info").splitlines()
                                               if "Subject DN" in l), "sin certificado en 9a")),
                     ("OpenPGP", lambda: pgp_check(Card()))):
        try:
            print(f"  {name}: {fn()}")
        except Exception as e:  # noqa: BLE001
            print(f"  {name}: ERROR {e}")


if __name__ == "__main__":
    reader_name()
    {"populate": populate, "check": check}.get(sys.argv[1] if len(sys.argv) > 1 else "check", check)()
