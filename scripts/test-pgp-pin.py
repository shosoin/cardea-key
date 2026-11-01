#!/usr/bin/env python3
"""Cardea Key — prueba de los PIN de OpenPGP y PIV (issue #3) en la placa, sin botón.

  test-pgp-pin.py [openpgp|piv]

Parte de la placa de pruebas de test-apps.py (OpenPGP: PW1 123456, PW3 12345678, clave de firma
P-256; PIV: PIN 123456, PUK 12345678, clave ECCP256 con certificado en 9a) y la deja igual. En
cada paso comprueba los contadores (DO C4 en OpenPGP, VERIFY sin datos en PIV) y que las claves
siguen abriéndose (firma OpenPGP y firma PIV verificadas con la clave pública):
  OpenPGP  PW1 malo/bueno · PW3 malo/bueno · cambio de PW1 y vuelta · código de reinicio (RC) y
           desbloqueo de PW1 con él · desbloqueo de PW1 con PW3
  PIV      PIN malo/bueno · cambio de PIN y vuelta · desbloqueo con el PUK · cambio de PUK y
           vuelta · metadatos "PIN/PUK por defecto"
Nunca llega a 3 fallos seguidos. Con el backend "model", el primer acierto de cada PIN es además
su migración al secure element.

Las claves PIV van cifradas con la clave base del dispositivo, no con la DEK: el PIN de PIV
autoriza, no descifra. La firma PIV prueba esa autorización y el contador.

Solo para placas de pruebas. Necesita pcscd viendo la llave, pyscard, ykman y cryptography.
"""
import hashlib
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from smartcard.System import readers

# PW1 nuevo de 7: con 8 o más, el modo admin-less pendiente (Gnuk) sincronizaría PW3 con PW1.
PW1, PW3, NEW_PW1, RC = b"123456", b"12345678", b"2468135", b"87654321"
PIV_PIN, PIV_PUK = b"123456\xff\xff", b"12345678"
NEW_PIV_PIN, NEW_PIV_PUK = b"654321\xff\xff", b"87654321"


class Card:
    def __init__(self):
        r = next((r for r in readers() if "Cardea" in str(r)), None)
        if not r:
            sys.exit("no encuentro el lector Cardea en pcscd")
        self.c = r.createConnection()
        self.c.connect()

    def apdu(self, hexstr, data=b"", le=None):
        cmd = list(bytes.fromhex(hexstr))
        if data:
            cmd += [len(data)] + list(data)
        if le is not None:
            cmd += [le]
        resp, sw1, sw2 = self.c.transmit(cmd)
        while sw1 == 0x61:
            more, sw1, sw2 = self.c.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            resp += more
        return bytes(resp), (sw1 << 8) | sw2

    def ok(self, hexstr, data=b"", le=None, what=""):
        resp, sw = self.apdu(hexstr, data, le)
        if sw != 0x9000:
            sys.exit(f"FALLO {what or hexstr}: SW {sw:04X}")
        return resp

    def sw(self, hexstr, data, want, what):
        _, sw = self.apdu(hexstr, data)
        if sw != want:
            sys.exit(f"FALLO {what}: esperaba {want:04X}, llega {sw:04X}")


def find_tlv(buf, tag):
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
        if t in (0x7F49, 0x65, 0x6E, 0x73, 0x7C):
            sub = find_tlv(val, tag)
            if sub is not None:
                return sub
        i += ln
    return None


def step(text):
    print(f"  {text}")


# ------------------------------------------------------------------------------------- OpenPGP
def pgp_select(card):
    card.ok("00A40400", bytes.fromhex("D27600012401"), what="SELECT OpenPGP")


def pgp_counters(card):
    c4 = card.ok("00CA00C4", le=0, what="GET DATA C4")
    return c4[4], c4[5], c4[6]          # PW1, RC, PW3


def pgp_expect(card, pw1, rc, pw3, what):
    got = pgp_counters(card)
    if got != (pw1, rc, pw3):
        sys.exit(f"FALLO {what}: contadores PW1/RC/PW3 {got}, esperaba {(pw1, rc, pw3)}")


def pgp_sign(card, pub, pin, what):
    card.ok("00200081", pin, what=f"VERIFY PW1 ({what})")
    msg = f"Cardea Key #3 {what}".encode()
    sig = card.ok("002A9E9A", hashlib.sha256(msg).digest(), le=0, what=f"firma ({what})")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))


def openpgp():
    print("[OpenPGP]")
    card = Card()
    pgp_select(card)
    point = find_tlv(card.ok("00478100", b"\xB6\x00", le=0, what="clave pública de firma"), 0x86)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    pgp_expect(card, 3, 0, 3, "estado inicial (sin código de reinicio)")

    card.sw("00200081", b"654321", 0x63C2, "PW1 malo")
    pgp_expect(card, 2, 0, 3, "tras PW1 malo")
    pgp_sign(card, pub, PW1, "PW1 bueno")
    pgp_expect(card, 3, 0, 3, "tras PW1 bueno")
    step("PW1: malo cuenta (2), bueno repone (3) y firma OK")

    card.sw("00200083", b"87654321", 0x63C2, "PW3 malo")
    card.ok("00200083", PW3, what="PW3 bueno")
    pgp_expect(card, 3, 0, 3, "tras PW3")
    step("PW3: malo cuenta, bueno repone")

    card.ok("00240081", PW1 + NEW_PW1, what="cambio de PW1")
    card.sw("00200081", PW1, 0x63C2, "PW1 viejo tras el cambio")
    pgp_sign(card, pub, NEW_PW1, "PW1 nuevo")
    card.ok("00240081", NEW_PW1 + PW1, what="vuelta de PW1")
    pgp_sign(card, pub, PW1, "PW1 original")
    step("cambio de PW1: el viejo no vale, firma con el nuevo y vuelta al original")

    card.ok("00200083", PW3, what="PW3 para poner el RC")
    card.ok("00DA00D3", RC, what="PUT DATA código de reinicio")
    pgp_expect(card, 3, 3, 3, "con código de reinicio")
    card.ok("002C0081", RC + PW1, what="RESET RETRY COUNTER con el RC")
    pgp_sign(card, pub, PW1, "tras desbloqueo con RC")
    step("código de reinicio puesto y PW1 desbloqueado con él; firma OK")

    card.sw("00200081", b"654321", 0x63C2, "PW1 malo antes del desbloqueo por PW3")
    card.ok("00200083", PW3, what="PW3 para desbloquear PW1")
    card.ok("002C0281", PW1, what="RESET RETRY COUNTER con PW3")
    pgp_expect(card, 3, 3, 3, "tras desbloqueo con PW3")
    pgp_sign(card, pub, PW1, "tras desbloqueo con PW3")
    step("PW1 desbloqueado con PW3; firma OK")

    # Dejar el RC como al principio: el de fábrica se desactiva solo en el siguiente arranque.
    card.ok("00200083", PW3, what="PW3 para quitar el RC")
    card.ok("00DA00D3", b"12345678", what="RC de fábrica")
    step("RC puesto al de fábrica (se desactiva en el próximo arranque)")


# ------------------------------------------------------------------------------------- PIV
def piv_select(card):
    card.ok("00A40400", bytes.fromhex("A000000308"), what="SELECT PIV")


def piv_retries(card, ref):
    _, sw = card.apdu(f"002000{ref}")
    if sw == 0x9000:
        return "verificado"
    if sw & 0xFFF0 != 0x63C0:
        sys.exit(f"FALLO intentos PIV {ref}: SW {sw:04X}")
    return sw & 0xF


def pgp_clear_access(card):
    pgp_select(card)
    for ref in ("81", "82", "83"):
        card.ok(f"0020FF{ref}", what=f"OpenPGP: quitar acceso {ref}")


def piv_sign(card, pub, pin, what):
    pgp_clear_access(card)
    piv_select(card)
    card.ok("00200080", pin, what=f"VERIFY PIN PIV ({what})")
    msg = f"Cardea Key #3 PIV {what}".encode()
    digest = hashlib.sha256(msg).digest()
    tmpl = b"\x7C\x24\x82\x00\x81\x20" + digest
    resp, sw = card.apdu("0087119A", tmpl, le=0)
    if sw != 0x9000:
        return False, f"SW {sw:04X}"
    der = find_tlv(resp, 0x82)
    try:
        pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    return True, ""


def piv_metadata_default(card, ref):
    resp = card.ok(f"00F700{ref}", le=0, what=f"GET METADATA {ref}")
    v = find_tlv(resp, 0x05)
    return v is not None and v[0] == 1


def piv():
    print("[PIV]")
    pem = subprocess.run(["ykman", "--reader", "Cardea", "piv", "certificates", "export", "9a", "-"],
                         capture_output=True, timeout=60, check=True).stdout
    pub = x509.load_pem_x509_certificate(pem).public_key()
    card = Card()
    # Sin PW1/PW3 de OpenPGP verificados, para que PIV dependa solo de su PIN.
    pgp_clear_access(card)
    piv_select(card)
    if piv_retries(card, "80") != 3:
        sys.exit("FALLO: quiero empezar con 3 intentos de PIN PIV")
    if not (piv_metadata_default(card, "80") and piv_metadata_default(card, "81")):
        sys.exit("FALLO: PIN y PUK de PIV deberían ser los de fábrica")

    card.sw("00200080", NEW_PIV_PIN, 0x63C2, "PIN PIV malo")
    ok, err = piv_sign(card, pub, PIV_PIN, "PIN bueno")
    if not ok:
        sys.exit(f"FALLO firma PIV con el PIN bueno: {err}")
    piv_select(card)
    if piv_retries(card, "80") not in (3, "verificado"):
        sys.exit("FALLO: el acierto no repone el contador de PIV")
    step("PIN PIV: malo cuenta, bueno repone y firma OK")

    card.ok("00240080", PIV_PIN + NEW_PIV_PIN, what="cambio de PIN PIV")
    card.sw("00200080", PIV_PIN, 0x63C2, "PIN PIV viejo tras el cambio")
    ok, err = piv_sign(card, pub, NEW_PIV_PIN, "PIN nuevo")
    if not ok:
        sys.exit(f"FALLO firma PIV con el PIN nuevo: {err}")
    step("cambio de PIN PIV: el viejo no vale, firma con el nuevo OK")
    card.ok("00240080", NEW_PIV_PIN + PIV_PIN, what="vuelta del PIN PIV")
    ok, err = piv_sign(card, pub, PIV_PIN, "PIN original")
    if not ok:
        sys.exit(f"FALLO firma PIV al volver al PIN original: {err}")

    card.sw("00200080", NEW_PIV_PIN, 0x63C2, "PIN PIV malo antes del PUK")
    card.ok("002C0080", PIV_PUK + PIV_PIN, what="RESET RETRY con el PUK")
    piv_select(card)
    if piv_retries(card, "80") != 3:
        sys.exit("FALLO: el desbloqueo con PUK no repone el contador")
    ok, err = piv_sign(card, pub, PIV_PIN, "tras desbloqueo con PUK")
    if not ok:
        sys.exit(f"FALLO firma PIV tras desbloqueo con PUK: {err}")
    step("PIN PIV desbloqueado con el PUK (mismo PIN); firma OK")

    card.ok("00240081", PIV_PUK + NEW_PIV_PUK, what="cambio de PUK")
    card.sw("002C0080", PIV_PUK + PIV_PIN, 0x63C2, "PUK viejo tras el cambio")
    card.ok("00240081", NEW_PIV_PUK + PIV_PUK, what="vuelta del PUK")
    if not (piv_metadata_default(card, "80") and piv_metadata_default(card, "81")):
        sys.exit("FALLO: tras volver a los de fábrica, los metadatos no los ven como de fábrica")
    step("cambio de PUK y vuelta; metadatos: PIN y PUK de fábrica")


if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    if only in ("", "openpgp"):
        openpgp()
    if only in ("", "piv"):
        piv()
    print("OK: PIN de OpenPGP y PIV correctos")
