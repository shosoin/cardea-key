#!/usr/bin/env python3
"""Cardea Key — genera vault_ca.inc (picokeys_vault_ca_der[]) desde el certificado raíz del vault.

El firmware verifica los certificados de alta del vault contra esta CA. Por defecto es la
"Cardea Key Vault CA" (firmware/certs/cardea-key-vault-ca.crt); cualquiera puede compilar con la
suya (-DKEYV2_VAULT_CA_CERT=/ruta/mi-ca.crt). Solo admite un CERTIFICADO en PEM: si el fichero
contiene una clave privada, se niega a seguir.

Uso: gen_vault_ca.py <certificado.crt> <salida.inc>
"""
import base64
import hashlib
import re
import sys

src, out = sys.argv[1], sys.argv[2]
text = open(src, encoding="ascii").read()
if "PRIVATE KEY" in text:
    sys.exit(f"{src} contiene una CLAVE PRIVADA: aquí solo va el certificado público")
m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
if not m:
    sys.exit(f"{src}: no encuentro un certificado PEM")
der = base64.b64decode("".join(m.group(1).split()))
if der[:1] != b"\x30":
    sys.exit(f"{src}: el contenido no parece DER/X.509")
fp = hashlib.sha256(der).hexdigest()
lines = [", ".join(f"0x{b:02X}" for b in der[i:i + 12]) for i in range(0, len(der), 12)]
with open(out, "w") as f:
    f.write(f"/* GENERADO por firmware/tools/gen_vault_ca.py desde {src.split('/')[-1]}. No editar.\n")
    f.write(f"   SHA-256 del certificado: {fp} */\n")
    f.write("static const uint8_t picokeys_vault_ca_der[] = {\n    " + ",\n    ".join(lines) + "\n};\n")
print(f"vault_ca.inc: {len(der)} B, SHA-256 {fp[:16]}…")
