#!/usr/bin/env python3
"""key-v2 — genera fido_file_entries.inc a partir de la tabla de ficheros de pico-fido.

En el firmware unificado solo hay una tabla (file_entries), la de pico-openpgp. Este script
extrae las entradas de pico-fido/src/fido/files.c (sin la raiz MF ni el terminador), sustituye
cada EF_* por su valor numerico segun pico-fido/src/fido/files.h y escribe un fragmento que se
incluye dentro de la tabla de OpenPGP. Asi no se mezclan las cabeceras de las dos apps, que
definen macros EF_* con el mismo nombre y distinto valor.

Uso: gen_fido_file_entries.py <pico-fido/src/fido> <salida.inc> <salida_fids.inc>
(el segundo fichero es la lista de FIDs estaticos de FIDO, para keyv2_glue.c)
Falla si una entrada no tiene padre 0 (MF) o si un EF_* no se puede resolver.
"""
import re
import sys

src_dir, out, out_fids = sys.argv[1], sys.argv[2], sys.argv[3]
fids = []
defs = dict(re.findall(r'#define\s+(EF_\w+)\s+(0x[0-9A-Fa-f]+)', open(f"{src_dir}/files.h").read()))
text = open(f"{src_dir}/files.c").read()
table = re.search(r'file_entry_t file_entries\[\] = \{(.*?)\n\};', text, re.S).group(1)
rows = [r.strip() for r in table.splitlines() if r.strip().startswith('{')]
lines = []
for row in rows:
    fid = re.search(r'\.fid = (\w+)', row).group(1)
    parent = re.search(r'\.parent = (\w+)', row).group(1)
    if fid in ('0x3f00', '0x0000'):
        continue  # MF y terminador: ya estan en la tabla de OpenPGP
    if parent != '0':
        sys.exit(f"entrada FIDO con padre {parent} != 0: {row}")
    if fid.startswith('EF_'):
        if fid not in defs:
            sys.exit(f"no se puede resolver {fid}")
        row = row.replace(f'.fid = {fid}', f'.fid = {defs[fid]} /* {fid} */', 1)
    fids.append(defs.get(fid, fid))
    row = re.sub(r'\s*//.*$', '', row).rstrip(',')
    lines.append(f"    {row},")
with open(out, 'w') as f:
    f.write("/* GENERADO por firmware/tools/gen_fido_file_entries.py desde pico-fido/src/fido/files.c. No editar. */\n")
    f.write("\n".join(lines) + "\n")
with open(out_fids, 'w') as f:
    f.write("/* GENERADO por firmware/tools/gen_fido_file_entries.py. No editar. */\n")
    f.write("    " + ", ".join(fids) + "\n")
print(f"fido_file_entries.inc: {len(lines)} entradas")
