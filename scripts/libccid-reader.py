#!/usr/bin/env python3
"""Cardea Key — añade (o quita) la llave a la lista de lectores de libccid para que pcscd la vea.

pcscd solo carga el driver CCID para los VID/PID de Info.plist. El VID/PID de pruebas 1209:0001
no está, así que OpenPGP/PIV/OATH (que van por CCID) no funcionan hasta añadirlo. FIDO2 no lo
necesita (va por HID).

- Copia el original a Info.plist.keyv2-orig antes del primer cambio.
- Inserta VID, PID y nombre al final de las tres listas paralelas, sin reescribir el resto.
- El nombre contiene "Yubico YubiKey" porque ykman solo usa lectores PC/SC con ese texto.
- Valida que el plist sigue siendo correcto y que las tres listas miden lo mismo.
- --revert restaura la copia. Una actualización del paquete libccid también lo deshace.

Uso (root): libccid-reader.py [--vid 0x1209 --pid 0x0001] [--revert]
Después: systemctl restart pcscd
"""
import argparse
import os
import plistlib
import re
import shutil
import sys

PLIST = "/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
BACKUP = PLIST + ".keyv2-orig"
NAME = "Cardea Key prototype (Yubico YubiKey compatible) CCID"

ap = argparse.ArgumentParser()
ap.add_argument("--vid", default="0x1209")
ap.add_argument("--pid", default="0x0001")
ap.add_argument("--revert", action="store_true")
a = ap.parse_args()

if a.revert:
    if not os.path.exists(BACKUP):
        sys.exit("No hay copia de seguridad; nada que revertir")
    shutil.copy2(BACKUP, PLIST)
    os.remove(BACKUP)
    print("Restaurado el Info.plist original")
    sys.exit(0)

vid = "0x%04X" % int(a.vid, 0)
pid = "0x%04X" % int(a.pid, 0)
data = plistlib.load(open(PLIST, "rb"))
for v, p in zip(data["ifdVendorID"], data["ifdProductID"]):
    if v.upper() == vid.upper() and p.upper() == pid.upper():
        print(f"{vid}:{pid} ya está en la lista; nada que hacer")
        sys.exit(0)

text = open(PLIST, encoding="utf-8").read()


def append(text, key, value):
    m = re.search(r"(<key>%s</key>\s*<array>)(.*?)(\n(\s*)</array>)" % key, text, re.S)
    if not m:
        sys.exit(f"No encuentro la lista {key}")
    indent = re.search(r"\n(\s*)<string>", m.group(2)).group(1)
    return text[:m.end(2)] + f"\n{indent}<string>{value}</string>" + text[m.end(2):]


for key, value in (("ifdVendorID", vid), ("ifdProductID", pid), ("ifdFriendlyName", NAME)):
    text = append(text, key, value)

new = plistlib.loads(text.encode("utf-8"))
n = {k: len(new[k]) for k in ("ifdVendorID", "ifdProductID", "ifdFriendlyName")}
if len(set(n.values())) != 1 or n["ifdVendorID"] != len(data["ifdVendorID"]) + 1:
    sys.exit(f"Resultado inconsistente, no se escribe nada: {n}")

if not os.path.exists(BACKUP):
    shutil.copy2(PLIST, BACKUP)
with open(PLIST, "w", encoding="utf-8") as f:
    f.write(text)
print(f"Añadido {vid}:{pid} '{NAME}' ({n['ifdVendorID']} lectores). Copia: {BACKUP}")
print("Ahora: sudo systemctl restart pcscd")
