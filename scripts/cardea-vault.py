#!/usr/bin/env python3
"""Cardea Key — herramienta de alta del vault (copia de seguridad cifrada de passkeys).

Modelo (el del firmware, pico-keys-sdk/src/vault.c, protocolo de alta v2):
- Una IDENTIDAD DE VAULT = clave del vault (kvault, 32 bytes aleatorios) + par de claves X448.
  Es el secreto principal: con kvault se descifran todas las copias exportadas de las llaves
  dadas de alta en ese vault. Se guarda en un fichero cifrado con frase de paso (scrypt +
  AES-256-GCM); dónde se guarda ese fichero y la frase es cosa de cada cual.
- Por cada llave, la CA del vault firma un certificado que liga la clave pública X448 del vault
  con el número de serie de la llave (SAN DNS = serie USB). El firmware lo verifica contra la CA
  compilada (firmware/certs/, opción KEYV2_VAULT_CA_CERT) y comprueba que la serie es la suya.
- Alta: la llave genera un X448 efímero y un reto; la herramienta le manda kvault cifrado con
  HPKE en modo auth (RFC 9180: DHKEM(X448, HKDF-SHA512), HKDF-SHA512, AES-256-GCM), autenticado
  con la clave X448 del vault. La llave exige PIN (permiso acfg) y que se haya mantenido pulsado
  el botón 10 s dentro del primer minuto tras enchufarla.

Subcomandos:
  new     --out FICHERO [--label TEXTO]                  crea una identidad de vault
  cert    --vault-file F --ca-key K [--serial S] --out C la CA firma el certificado de una llave
                                                         (sin --serial: la de la llave conectada)
  status                                                 estado del vault en la llave (sin PIN)
  enroll  --vault-file F --cert C                        da de alta la llave conectada
  export  --out-dir D [--rp RP]                          exporta las passkeys (cifradas con el vault)
  import  FICHERO...                                     restaura copias en una llave del mismo vault
  inspect --vault-file F FICHERO...                      descifra copias sin llave (comprobación)

La clave privada de la CA solo entra con --ca-key <fichero>. Frase de paso y PIN se piden por
teclado, o con --passphrase-file / --pin-file.
Requiere: python3-cryptography, python3-fido2 (y una llave con firmware ENABLE_VAULT=ON).
"""
import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CA_CERT = ROOT / "firmware" / "certs" / "cardea-key-vault-ca.crt"

VAULT_FILE_FORMAT = "cardea-vault-1"
ENVELOPE_AAD = b"Cardea Key vault identity v1"
VAULT_ID_DOMAIN = b"PicoKeys Vault ID v1"        # firmware: picokeys_vault_hash_kvault
ENROLL_INFO = b"PicoKeys Vault enrollment v2"     # firmware: vault_enrollment_hpke_info
LABEL_MAX = 64
CERT_MAX = 1900                                   # firmware: PICOKEYS_VAULT_ENROLL_CERT_MAX

CTAP_VENDOR_CBOR = 0x41                           # CTAPHID_VENDOR_FIRST + 1
CTAP_VENDOR_VAULT = 0x05
VAULT_STATUS, VAULT_ENROLL_BEGIN, VAULT_ENROLL_FINISH = 0x01, 0x02, 0x03


# ---------------------------------------------------------------- utilidades

def raw_x448_public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def vault_id(kvault):
    return hashlib.sha256(VAULT_ID_DOMAIN + kvault).digest()


def read_secret(path, prompt, confirm=False):
    if path:
        return Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repítela: ") != value:
        sys.exit("No coinciden")
    if not value:
        sys.exit("Vacía")
    return value


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


# ---------------------------------------------------------------- fichero de identidad del vault

def scrypt_key(passphrase, salt):
    return Scrypt(salt=salt, length=32, n=2 ** 17, r=8, p=1).derive(passphrase.encode())


def vault_seal(passphrase, kvault, private_key, label):
    salt, nonce = os.urandom(16), os.urandom(12)
    plain = json.dumps({
        "kvault": base64.b64encode(kvault).decode(),
        "x448_private": base64.b64encode(private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())).decode(),
    }).encode()
    public = {
        "format": VAULT_FILE_FORMAT,
        "label": label,
        "vault_id": vault_id(kvault).hex(),
        "x448_public": base64.b64encode(raw_x448_public(private_key.public_key())).decode(),
        "kdf": {"name": "scrypt", "n": 2 ** 17, "r": 8, "p": 1,
                "salt": base64.b64encode(salt).decode()},
        "nonce": base64.b64encode(nonce).decode(),
    }
    aad = ENVELOPE_AAD + json.dumps(public, sort_keys=True).encode()
    public["ciphertext"] = base64.b64encode(
        AESGCM(scrypt_key(passphrase, salt)).encrypt(nonce, plain, aad)).decode()
    return json.dumps(public, indent=2).encode() + b"\n"


def vault_open(path, passphrase):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("format") != VAULT_FILE_FORMAT:
        sys.exit(f"{path}: no es un fichero de identidad de vault de Cardea Key")
    ciphertext = base64.b64decode(value.pop("ciphertext"))
    aad = ENVELOPE_AAD + json.dumps(value, sort_keys=True).encode()
    try:
        plain = json.loads(AESGCM(scrypt_key(passphrase, base64.b64decode(value["kdf"]["salt"]))).decrypt(
            base64.b64decode(value["nonce"]), ciphertext, aad))
    except Exception:
        sys.exit("Frase de paso incorrecta o fichero alterado")
    kvault = base64.b64decode(plain["kvault"])
    private_key = x448.X448PrivateKey.from_private_bytes(base64.b64decode(plain["x448_private"]))
    if vault_id(kvault).hex() != value["vault_id"] or \
            base64.b64encode(raw_x448_public(private_key.public_key())).decode() != value["x448_public"]:
        sys.exit(f"{path}: contenido incoherente")
    return value, kvault, private_key


def vault_public(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("format") != VAULT_FILE_FORMAT:
        sys.exit(f"{path}: no es un fichero de identidad de vault de Cardea Key")
    return value, x448.X448PublicKey.from_public_bytes(base64.b64decode(value["x448_public"]))


# ---------------------------------------------------------------- HPKE (RFC 9180), modo auth
# Suite: KEM 0x0021 DHKEM(X448, HKDF-SHA512), KDF 0x0003 HKDF-SHA512, AEAD 0x0002 AES-256-GCM.

KEM_SUITE = b"KEM" + struct.pack(">H", 0x0021)
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x0021, 0x0003, 0x0002)
MODE_AUTH = 0x02


def hkdf_extract(salt, ikm):
    h = HMAC(salt or bytes(64), hashes.SHA512())
    h.update(ikm)
    return h.finalize()


def hkdf_expand(prk, info, length):
    out, block, counter = b"", b"", 1
    while len(out) < length:
        h = HMAC(prk, hashes.SHA512())
        h.update(block + info + bytes([counter]))
        block = h.finalize()
        out += block
        counter += 1
    return out[:length]


def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def kem_shared_secret(dh, kem_context):
    eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", kem_context, 64)


def key_schedule(shared_secret, info):
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = bytes([MODE_AUTH]) + psk_id_hash + info_hash
    secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    return (labeled_expand(HPKE_SUITE, secret, b"key", context, 32),
            labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12))


def hpke_auth_seal(sender_private, recipient_public_raw, info, aad, plaintext):
    recipient = x448.X448PublicKey.from_public_bytes(recipient_public_raw)
    ephemeral = x448.X448PrivateKey.generate()
    enc = raw_x448_public(ephemeral.public_key())
    dh = ephemeral.exchange(recipient) + sender_private.exchange(recipient)
    kem_context = enc + recipient_public_raw + raw_x448_public(sender_private.public_key())
    key, nonce = key_schedule(kem_shared_secret(dh, kem_context), info)
    return enc + AESGCM(key).encrypt(nonce, plaintext, aad)


def hpke_auth_open(recipient_private, sender_public_raw, info, aad, enc, ciphertext):
    """Espejo de vault_hpke_auth_decap del firmware; solo para la autocomprobación."""
    sender = x448.X448PublicKey.from_public_bytes(sender_public_raw)
    dh = recipient_private.exchange(x448.X448PublicKey.from_public_bytes(enc)) + recipient_private.exchange(sender)
    kem_context = enc + raw_x448_public(recipient_private.public_key()) + sender_public_raw
    key, nonce = key_schedule(kem_shared_secret(dh, kem_context), info)
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def enrollment_packet(certificate_der, sender_private, device_public, challenge, kvault, label):
    label_bytes = label.encode()
    if len(label_bytes) > LABEL_MAX:
        sys.exit(f"La etiqueta pasa de {LABEL_MAX} bytes")
    plain = kvault + bytes([len(label_bytes)]) + label_bytes
    sealed = hpke_auth_seal(sender_private, device_public, ENROLL_INFO + challenge, certificate_der, plain)
    return struct.pack(">H", len(certificate_der)) + certificate_der + sealed


# ---------------------------------------------------------------- subcomandos

def cmd_new(a):
    if os.path.exists(a.out):
        sys.exit(f"{a.out} ya existe; no se sobrescribe")
    passphrase = read_secret(a.passphrase_file, "Frase de paso nueva para la identidad del vault: ",
                             confirm=not a.passphrase_file)
    kvault = os.urandom(32)
    private_key = x448.X448PrivateKey.generate()
    write_private(a.out, vault_seal(passphrase, kvault, private_key, a.label))
    print(f"Identidad de vault creada en {a.out} (0600)")
    print(f"  vault_id: {vault_id(kvault).hex()}")
    print("  Es el secreto principal: sin ella no se recuperan las copias; con ella, se descifran.")


def cmd_cert(a):
    value, vault_pub = vault_public(a.vault_file)
    if a.serial:
        serial = a.serial.strip().upper()
    else:
        device = open_device()
        serial = device.descriptor.serial_number or ""
        print(f"Serie leída de la llave conectada: {serial}")
    if not serial or any(c not in "0123456789ABCDEF" for c in serial):
        sys.exit("La serie debe ser hexadecimal (la serie USB de la llave, p. ej. 0123456789ABCDEF)")
    ca_cert = x509.load_pem_x509_certificate(Path(a.ca_cert).read_bytes())
    ca_pem = Path(a.ca_key).read_bytes()
    try:
        ca_key = serialization.load_pem_private_key(ca_pem, password=None)
    except TypeError:
        ca_key = serialization.load_pem_private_key(
            ca_pem, password=getpass.getpass("Contraseña de la clave de la CA: ").encode())
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        sys.exit("La clave de la CA no es ECDSA")
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if ca_key.public_key().public_bytes(serialization.Encoding.DER, pub) != \
            ca_cert.public_key().public_bytes(serialization.Encoding.DER, pub):
        sys.exit("La clave privada no corresponde al certificado de la CA")

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_after = min(now + datetime.timedelta(days=365 * a.years), ca_cert.not_valid_after_utc)
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cardea Key"),
                   x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Vault"),
                   x509.NameAttribute(NameOID.COMMON_NAME, f"Vault {value['vault_id'][:16]} / {serial}"),
               ]))
               .issuer_name(ca_cert.subject)
               .public_key(vault_pub)
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=True, key_cert_sign=False, crl_sign=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(serial)]), critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(vault_pub), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                              critical=False))
    cert = builder.sign(ca_key, hashes.SHA384())
    der = cert.public_bytes(serialization.Encoding.DER)
    if len(der) > CERT_MAX:
        sys.exit(f"Certificado demasiado grande ({len(der)} > {CERT_MAX} B)")
    cert.verify_directly_issued_by(ca_cert)
    if os.path.exists(a.out):
        sys.exit(f"{a.out} ya existe; no se sobrescribe")
    Path(a.out).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificado de alta para la llave {serial} en {a.out} ({len(der)} B DER, "
          f"válido hasta {not_after:%Y-%m-%d}). Es público.")


def open_device(wait=False):
    from fido2.hid import CtapHidDevice
    deadline = time.monotonic() + (120 if wait else 0)
    while True:
        devices = [d for d in CtapHidDevice.list_devices()
                   if (d.descriptor.vid, d.descriptor.pid) in ((0x1209, 0x0001), (0x2E8A, 0x10FE), (0x1050, 0x0407))]
        if len(devices) == 1 or len(devices) > 1 or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    if len(devices) != 1:
        sys.exit(f"Esperaba una llave conectada y encuentro {len(devices)}")
    return devices[0]


def vendor_call(device, subcommand, params=None, pin=None):
    from fido2 import cbor
    from fido2.ctap import CtapError
    arguments = {1: subcommand}
    raw_params = cbor.encode(params) if params is not None else b""
    if params is not None:
        arguments[2] = params
    if pin is not None:
        protocol, token = pin
        arguments[3] = protocol.VERSION
        arguments[4] = protocol.authenticate(token, b"\xff" * 32 + b"\x0d" + bytes([subcommand]) + raw_params)
    try:
        response = device.call(CTAP_VENDOR_CBOR, bytes([CTAP_VENDOR_VAULT]) + cbor.encode(arguments))
    except CtapError as error:
        return error.code, {}
    return response[0], cbor.decode(response[1:]) if len(response) > 1 else {}


def device_status(device):
    code, st = vendor_call(device, VAULT_STATUS)
    if code != 0:
        sys.exit(f"La llave no responde al vault (0x{code:02x}): ¿firmware compilado con ENABLE_VAULT=ON?")
    return st


def cmd_status(a):
    device = open_device()
    if a.pin_file or a.pin:
        # La clave del dispositivo va cifrada con el PIN: hasta que no se mete el PIN en esta
        # sesión, el firmware no puede leer la clave del vault y responde "no dada de alta".
        from fido2.ctap2.pin import ClientPin
        pin_session(device, read_secret(a.pin_file, "PIN de la llave: "), ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    st = device_status(device)
    if not st.get(1) and st.get(4) and not (a.pin_file or a.pin):
        print("Hay un alta guardada, pero sin el PIN de esta sesión la llave no puede leerla "
              "(su clave va cifrada con el PIN). Repite con --pin para comprobarla.")
    serial = device.descriptor.serial_number
    print(f"Llave {device.descriptor.product_name} serie={serial}")
    print(f"  dada de alta: {'sí, vault_id ' + st.get(1).hex() if st.get(1) else 'no'}"
          f"{' etiqueta ' + repr(st.get(5)) if st.get(5) else ''}")
    print(f"  botón de alta aceptado: {st.get(2)}  (ms desde el arranque: {st.get(3)})")
    print(f"  almacén disponible: {st.get(4)}  protocolo de alta: {st.get(6)}")


def cmd_enroll(a):
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin, PinProtocolV2

    cert = x509.load_pem_x509_certificate(Path(a.cert).read_bytes())
    der = cert.public_bytes(serialization.Encoding.DER)
    value, kvault, private_key = vault_open(
        a.vault_file, read_secret(a.passphrase_file, "Frase de paso de la identidad del vault: "))
    if cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != \
            raw_x448_public(private_key.public_key()):
        sys.exit("El certificado no es de esta identidad de vault")
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)

    pin = read_secret(a.pin_file, "PIN de la llave: ")
    # El firmware solo acepta el botón al consultarlo, y solo durante el primer minuto tras
    # enchufar: hay que preguntar mientras tanto y hacer el alta dentro de esa ventana. Si la llave
    # lleva más de un minuto encendida, se espera a que la desenchufen y la vuelvan a enchufar.
    print("Esperando: (re)enchufa la llave y mantén el botón pulsado 10 s en el primer minuto...")
    deadline, said_replug = time.monotonic() + 300, False
    while True:
        if time.monotonic() > deadline:
            sys.exit("Tiempo agotado esperando el botón de alta")
        try:
            device = open_device(wait=True)
            st = device_status(device)
        except (Exception, SystemExit) as error:
            time.sleep(0.5)
            continue
        if st.get(6) != 2:
            sys.exit(f"Protocolo de alta {st.get(6)} no soportado (se espera 2)")
        if st.get(2):
            break
        if st.get(3, 0) > 60000:
            if not said_replug:
                print(f"La llave lleva {st.get(3) // 1000} s encendida: desenchúfala y vuelve a enchufarla.")
                said_replug = True
            device.close()
            time.sleep(1)
            continue
        time.sleep(0.3)
    serial = device.descriptor.serial_number
    if serial not in sans:
        if not a.test_skip_serial_check:
            sys.exit(f"El certificado es para {sans} y la llave conectada es {serial}")
        print(f"PRUEBA: certificado para {sans} en la llave {serial}; la llave debe rechazarlo")
    print(f"Botón aceptado a los {st.get(3) / 1000:.1f} s del arranque")
    protocol = PinProtocolV2()
    token = ClientPin(Ctap2(device), protocol).get_pin_token(pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    auth = (protocol, token)

    code, begin = vendor_call(device, VAULT_ENROLL_BEGIN, pin=auth)
    if code != 0:
        sys.exit(f"Inicio de alta rechazado: 0x{code:02x} ({CtapError.ERR(code).name if code in CtapError.ERR._value2member_map_ else '?'})")
    device_public, challenge = begin.get(1, b""), begin.get(2, b"")
    if len(device_public) != 56 or len(challenge) != 32:
        sys.exit("Respuesta de inicio de alta inválida")
    packet = enrollment_packet(der, private_key, device_public, challenge, kvault, value.get("label", ""))
    code, finish = vendor_call(device, VAULT_ENROLL_FINISH, {1: packet}, auth)
    if code != 0:
        sys.exit(f"Alta rechazada por la llave: 0x{code:02x} (certificado, serie o CA no coinciden)")
    if finish.get(1) != vault_id(kvault):
        sys.exit("La llave devolvió un vault_id distinto")
    print(f"Llave {serial} dada de alta en el vault {vault_id(kvault).hex()}")


# ---------------------------------------------------------------- copias (export / import)

BLOB_MAGIC = b"PKV\x01"                           # firmware: vault_blob_magic ('P','K','V',1)
LAYER_INFO = b"PicoKeys Vault enrollment v1"      # firmware: vault_enroll_info (derivación por capa)
BLOB_HEADER_LEN = 4 + 32 + 32 + 1 + 16 + 1
VAULT_EXPORT, VAULT_IMPORT = 0x04, 0x05


def blob_decrypt(kvault, blob):
    """Descifra una copia exportada con la clave del vault (sin llave). Devuelve el CBOR interno."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from fido2 import cbor
    if blob[:4] != BLOB_MAGIC:
        raise ValueError("no es una copia del vault")
    vid, cred_hash = blob[4:36], blob[36:68]
    if vid != vault_id(kvault):
        raise ValueError("la copia es de otro vault")
    algorithm = blob[BLOB_HEADER_LEN - 1]
    layers = [{1: [1], 2: [2], 3: [1, 2], 4: [2, 1]}[algorithm]][0]
    nonces = blob[BLOB_HEADER_LEN:BLOB_HEADER_LEN + 12 * len(layers)]
    data = blob[BLOB_HEADER_LEN + 12 * len(layers):]
    for i in range(len(layers) - 1, -1, -1):
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=vid,
                   info=LAYER_INFO + cred_hash + bytes([algorithm, i])).derive(kvault)
        cipher = ChaCha20Poly1305(key) if layers[i] == 1 else AESGCM(key)
        data = cipher.decrypt(nonces[12 * i:12 * (i + 1)], data, blob[:BLOB_HEADER_LEN])
    return cbor.decode(data)


def pin_session(device, pin, permissions):
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin, PinProtocolV2
    ctap = Ctap2(device)
    protocol = PinProtocolV2()
    token = ClientPin(ctap, protocol).get_pin_token(pin, permissions=permissions)
    return ctap, protocol, token


def resident_credentials(ctap, protocol, token):
    from fido2.ctap2 import CredentialManagement
    cm = CredentialManagement(ctap, protocol, token)
    out = []
    if cm.get_metadata().get(CredentialManagement.RESULT.EXISTING_CRED_COUNT, 0) == 0:
        return out
    for rp in cm.enumerate_rps():
        rp_id = rp[CredentialManagement.RESULT.RP]["id"]
        for cred in cm.enumerate_creds(rp[CredentialManagement.RESULT.RP_ID_HASH]):
            out.append((rp_id, cred[CredentialManagement.RESULT.CREDENTIAL_ID]["id"],
                        cred[CredentialManagement.RESULT.USER]))
    return out


def cmd_export(a):
    from fido2.ctap2.pin import ClientPin
    device = open_device()
    pin = read_secret(a.pin_file, "PIN de la llave: ")
    perms = ClientPin.PERMISSION.AUTHENTICATOR_CFG | ClientPin.PERMISSION.CREDENTIAL_MGMT
    ctap, protocol, token = pin_session(device, pin, perms)
    creds = resident_credentials(ctap, protocol, token)
    if not creds:
        sys.exit("La llave no tiene passkeys (credenciales residentes)")
    os.makedirs(a.out_dir, exist_ok=True)
    for rp_id, cred_id, user in creds:
        if a.rp and rp_id != a.rp:
            continue
        code, r = vendor_call(device, VAULT_EXPORT, {1: cred_id}, (protocol, token))
        if code != 0:
            sys.exit(f"Exportación de {rp_id} rechazada: 0x{code:02x}")
        name = f"{rp_id}-{hashlib.sha256(cred_id).hexdigest()[:12]}.pkv"
        Path(a.out_dir, name).write_bytes(r[1])
        print(f"  {rp_id} ({user.get('name', '')}) -> {Path(a.out_dir, name)} ({len(r[1])} B)")


def cmd_import(a):
    device = open_device()
    from fido2.ctap2.pin import ClientPin
    pin = read_secret(a.pin_file, "PIN de la llave: ")
    ctap, protocol, token = pin_session(device, pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    for f in a.files:
        code, _ = vendor_call(device, VAULT_IMPORT, {1: Path(f).read_bytes()}, (protocol, token))
        print(f"  {f}: {'importada' if code == 0 else f'rechazada 0x{code:02x} (¿otro vault?)'}")


def cmd_inspect(a):
    _, kvault, _ = vault_open(a.vault_file, read_secret(a.passphrase_file, "Frase de paso de la identidad del vault: "))
    for f in a.files:
        inner = blob_decrypt(kvault, Path(f).read_bytes())
        print(f"  {f}: rp={inner.get(4)} credencial={(inner.get(6) or inner.get(2)).hex()[:24]}… (descifrada con el vault)")


def cmd_selftest(a):
    """Comprueba el sellado HPKE contra el descifrado espejo del firmware (sin llave)."""
    sender, device = x448.X448PrivateKey.generate(), x448.X448PrivateKey.generate()
    kvault, challenge, cert = os.urandom(32), os.urandom(32), b"certificate-der"
    packet = enrollment_packet(cert, sender, raw_x448_public(device.public_key()), challenge, kvault, "etiqueta")
    n = struct.unpack(">H", packet[:2])[0]
    assert packet[2:2 + n] == cert
    enc, ct = packet[2 + n:2 + n + 56], packet[2 + n + 56:]
    plain = hpke_auth_open(device, raw_x448_public(sender.public_key()), ENROLL_INFO + challenge, cert, enc, ct)
    assert plain == kvault + bytes([8]) + b"etiqueta"
    try:
        hpke_auth_open(device, raw_x448_public(sender.public_key()), ENROLL_INFO + challenge, cert + b"x", enc, ct)
        sys.exit("FALLO: aceptó un AAD alterado")
    except Exception:
        pass
    print("autocomprobación HPKE: OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("new")
    p.add_argument("--out", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--passphrase-file")
    p = sub.add_parser("cert")
    p.add_argument("--vault-file", required=True)
    p.add_argument("--ca-key", required=True)
    p.add_argument("--ca-cert", default=str(DEFAULT_CA_CERT))
    p.add_argument("--serial", help="serie USB de la llave; si se omite, se lee de la llave conectada")
    p.add_argument("--years", type=int, default=10)
    p.add_argument("--out", required=True)
    p = sub.add_parser("status")
    p.add_argument("--pin", action="store_true", help="pedir el PIN para poder leer el alta")
    p.add_argument("--pin-file")
    p = sub.add_parser("export")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--rp")
    p.add_argument("--pin-file")
    p = sub.add_parser("import")
    p.add_argument("files", nargs="+")
    p.add_argument("--pin-file")
    p = sub.add_parser("inspect")
    p.add_argument("--vault-file", required=True)
    p.add_argument("--passphrase-file")
    p.add_argument("files", nargs="+")
    p = sub.add_parser("enroll")
    p.add_argument("--vault-file", required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--passphrase-file")
    p.add_argument("--pin-file")
    p.add_argument("--test-skip-serial-check", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("selftest")
    a = ap.parse_args()
    {"new": cmd_new, "cert": cmd_cert, "status": cmd_status, "enroll": cmd_enroll,
     "export": cmd_export, "import": cmd_import, "inspect": cmd_inspect,
     "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    main()
