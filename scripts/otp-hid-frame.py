#!/usr/bin/env python3
"""Cardea Key — manda una trama OTP suelta (protocolo de slots compatible con Yubico) por la
interfaz HID de teclado, como hace ykman, pero de una en una. Para diagnóstico.

Trama: 64 bytes de datos + 1 byte de comando (slot) + CRC16 (CCITT invertido, polinomio 0x8408)
de los 64 bytes en little-endian + relleno, troceada en 10 informes de característica (feature
reports) de 8 bytes: 7 de datos + (0x80 | secuencia).

Uso (root o permisos sobre /dev/hidrawN):
  otp-hid-frame.py 0x13              # leer configuración (Management)
  otp-hid-frame.py 0x38 6b65792076   # challenge HMAC del slot 2 (datos en hex)
  otp-hid-frame.py 0xEE              # SOLO firmware de diagnóstico: reiniciar en BOOTSEL
  otp-hid-frame.py 0xEF              # SOLO firmware de diagnóstico: reinicio normal
  otp-hid-frame.py status            # leer el estado (GET_REPORT), sin mandar ningún comando
Opciones: --vid/--pid (por defecto busca 1050:0407 o 1209:0001), --dev /dev/hidrawN
"""
import argparse
import fcntl
import glob
import os
import sys
import time


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            j = crc & 1
            crc >>= 1
            if j:
                crc ^= 0x8408
    return crc & 0xFFFF


def hidiocsfeature(length):
    return (3 << 30) | (length << 16) | (ord('H') << 8) | 0x06


def hidiocgfeature(length):
    return (3 << 30) | (length << 16) | (ord('H') << 8) | 0x07


def find_keyboard(vids):
    for path in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        uevent = open(os.path.join(path, "device", "uevent")).read()
        hid_id = next((l.split("=", 1)[1] for l in uevent.splitlines() if l.startswith("HID_ID=")), "")
        parts = hid_id.split(":")
        if len(parts) != 3:
            continue
        vid, pid = int(parts[1], 16), int(parts[2], 16)
        if (vid, pid) not in vids:
            continue
        rdesc = open(os.path.join(path, "device", "report_descriptor"), "rb").read()
        # Interfaz de teclado: Usage Page Generic Desktop (05 01) + Usage Keyboard (09 06)
        if b"\x05\x01\x09\x06" in rdesc:
            return "/dev/" + os.path.basename(path)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("slot", type=lambda x: x if x == "status" else int(x, 0))
    ap.add_argument("data", nargs="?", default="")
    ap.add_argument("--dev")
    a = ap.parse_args()

    dev = a.dev or find_keyboard({(0x1050, 0x0407), (0x1209, 0x0001)})
    if not dev:
        sys.exit("No encuentro la interfaz de teclado de la llave")
    if a.slot == "status":
        fd = os.open(dev, os.O_RDWR)
        buf = bytearray(9)
        fcntl.ioctl(fd, hidiocgfeature(len(buf)), buf)
        os.close(fd)
        print(f"estado de {dev}: {bytes(buf[1:]).hex()}")
        return
    payload = bytes.fromhex(a.data)[:64].ljust(64, b"\x00")
    frame = payload + bytes([a.slot]) + crc16(payload).to_bytes(2, "little") + b"\x00\x00\x00"
    fd = os.open(dev, os.O_RDWR)
    try:
        for seq in range(10):
            chunk = frame[seq * 7:(seq + 1) * 7]
            report = bytes([0]) + chunk + bytes([0x80 | seq])   # id de informe 0 + 8 bytes
            fcntl.ioctl(fd, hidiocsfeature(len(report)), report)
            time.sleep(0.01)
    finally:
        os.close(fd)
    print(f"trama enviada a {dev}: slot=0x{a.slot:02x} datos={payload.rstrip(b'\x00').hex() or '-'}")


if __name__ == "__main__":
    main()
