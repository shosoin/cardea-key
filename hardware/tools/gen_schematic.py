#!/usr/bin/env python3
"""Cardea Key PCB (phase 4) — generates the KiCad schematic from the table below.

The schematic is label-based: every pin gets a short wire and a net label (or a no-connect flag),
so the netlist is exactly the table in PARTS. Run it again after editing the table; UUIDs are
derived from the reference designators, so diffs stay readable.

    python3 hardware/tools/gen_schematic.py        -> hardware/cardea-pcb/cardea-pcb.kicad_sch

The RP2354A core (regulator, crystal, decoupling, USB, BOOTSEL) follows Raspberry Pi's
"RP2350A Minimal" reference design (MIT) and "Hardware design with RP2350"; see ../README.md.
"""
import os
import uuid

from kicad_lib import flattened, pins

HERE = os.path.dirname(os.path.abspath(__file__))
PRJ = os.path.join(HERE, "..", "cardea-pcb")
NAME = "cardea-pcb"
CARDEA_LIB = os.path.join(PRJ, "lib", "cardea.kicad_sym")
NS = uuid.UUID("6c0b6a3e-2f1e-4b8e-9a51-0c4d3e1f7a10")
ROOT = str(uuid.uuid5(NS, "root"))

# Footprints
FP_0402 = "Resistor_SMD:R_0402_1005Metric"
FP_C0402 = "Capacitor_SMD:C_0402_1005Metric"
FP_C0603 = "Capacitor_SMD:C_0603_1608Metric"
FP_C0805 = "Capacitor_SMD:C_0805_2012Metric"
FP_TP = "TestPoint:TestPoint_Pad_D1.0mm"

# Each part: ref, lib_id, value, footprint, (x, y) of the symbol origin in mm, {pin number: net or None}
# None = not connected (no-connect flag). Extra fields: "LCSC"/"MPN" properties.
P = []


def part(ref, lib_id, value, fp, at, nets, **fields):
    P.append(dict(ref=ref, lib_id=lib_id, value=value, fp=fp, at=at, nets=nets, fields=fields))


def two(ref, kind, value, at, n1, n2, fp=None, **f):
    lib = {"R": "Device:R", "C": "Device:C", "L": "Device:L"}[kind]
    fp = fp or (FP_0402 if kind == "R" else FP_C0402)
    part(ref, lib, value, fp, at, {"1": n1, "2": n2}, **f)


# ---- USB-C, ESD, 3.3 V LDO --------------------------------------------------------------------
part("J1", "Connector:USB_C_Receptacle_USB2.0_16P", "USB-C", "Connector_USB:USB_C_Receptacle_HRO_TYPE-C-31-M-12",
     (45.72, 76.2),
     {"A1": "GND", "A4": "VBUS", "A5": "CC1", "A6": "USB_C_DP", "A7": "USB_C_DM", "A8": None,
      "A9": "VBUS", "A12": "GND", "B1": "GND", "B4": "VBUS", "B5": "CC2", "B6": "USB_C_DP", "B7": "USB_C_DM",
      "B8": None, "B9": "VBUS", "B12": "GND", "SH": "GND"}, LCSC="C165948", MPN="TYPE-C-31-M-12")
two("R11", "R", "5.1k", (76.2, 116.84), "CC1", "GND", LCSC="C25905")
two("R12", "R", "5.1k", (86.36, 116.84), "CC2", "GND", LCSC="C25905")
part("U4", "Power_Protection:USBLC6-2SC6", "USBLC6-2SC6", "Package_TO_SOT_SMD:SOT-23-6", (99.06, 60.96),
     {"1": "USB_C_DP", "6": "USB_C_DP", "3": "USB_C_DM", "4": "USB_C_DM", "5": "VBUS", "2": "GND"},
     LCSC="C7519", MPN="USBLC6-2SC6", stub=10.16)
two("R7", "R", "27", (129.54, 50.8), "USB_C_DP", "USB_DP", LCSC="C25100")
two("R8", "R", "27", (139.7, 50.8), "USB_C_DM", "USB_DM", LCSC="C25100")
# 3.3 V LDO: Diodes Inc. AP2112K-3.3 (600 mA, brand part rather than the cheapest clone)
part("U2", "Regulator_Linear:AP2112K-3.3", "AP2112K-3.3", "Package_TO_SOT_SMD:SOT-23-5", (66.04, 160.02),
     {"1": "VBUS", "3": "VBUS", "2": "GND", "5": "+3V3", "4": None}, LCSC="C51118", MPN="AP2112K-3.3TRG1")
# VBUS surge/ESD clamp at the connector (hot-plug spikes, cheap chargers), in addition to the USBLC6
part("D2", "Device:D_TVS", "SMF5.0A", "Diode_SMD:D_SOD-123F", (30.48, 116.84), {"1": "VBUS", "2": "GND"},
     LCSC="C151296", MPN="SMF5.0A")
two("C1", "C", "10u", (40.64, 162.56), "VBUS", "GND", fp=FP_C0805, LCSC="C15850", MPN="CL21A106KAYNNNE")
two("C5", "C", "10u", (93.98, 162.56), "+3V3", "GND", fp=FP_C0805, LCSC="C15850", MPN="CL21A106KAYNNNE")

# ---- RP2354A (2 MB flash in package) ----------------------------------------------------------
GPIO_NETS = {4: "SE_SDA", 5: "SE_SCL", 6: "SE_ENA", 8: "FP_TX", 9: "FP_RX", 10: "FP_WAKE", 11: "FP_PWR_EN_N",
             18: "LED_R", 19: "LED_G", 20: "LED_B"}
u1 = {"1": "+3V3", "11": "+3V3", "20": "+3V3", "30": "+3V3", "38": "+3V3", "45": "+3V3",
      "6": "+1V1", "23": "+1V1", "39": "+1V1",
      "21": "XIN", "22": "XOUT", "24": "SWCLK", "25": "SWDIO", "26": "RUN",
      "44": "+3V3", "46": "VREG_AVDD", "47": "GND", "48": "VREG_LX", "49": "+3V3", "50": "+1V1",
      "51": "USB_DM", "52": "USB_DP", "53": "+3V3", "54": "+3V3",
      "55": None, "56": None, "57": None, "58": None, "59": None,   # QSPI: internal flash
      "60": "QSPI_SS", "61": "GND"}
gpio_pin = {0: 2, 1: 3, 2: 4, 3: 5, 4: 7, 5: 8, 6: 9, 7: 10, 8: 12, 9: 13, 10: 14, 11: 15, 12: 16, 13: 17,
            14: 18, 15: 19, 16: 27, 17: 28, 18: 29, 19: 31, 20: 32, 21: 33, 22: 34, 23: 35, 24: 36, 25: 37,
            26: 40, 27: 41, 28: 42, 29: 43}
for g, pn in gpio_pin.items():
    u1[str(pn)] = GPIO_NETS.get(g)
part("U1", "MCU_RaspberryPi:RP2354A", "RP2354A", "Package_DFN_QFN:QFN-60-1EP_7x7mm_P0.4mm_EP3.4x3.4mm",
     (215.9, 139.7), u1, MPN="SC1511-A4", LCSC="C41378174")

# Decoupling (Raspberry Pi minimal design): 100 nF per IOVDD, QSPI_IOVDD/USB_OTP_VDD, ADC_AVDD;
# 100 nF per DVDD; 4.7 uF on VREG_VIN and on +1V1 (regulator output); 10 uF bulk on +3V3.
x = 152.4
for i, ref in enumerate(["C10", "C11", "C12", "C13", "C14", "C15", "C16", "C17"]):
    two(ref, "C", "100n", (x + 10.16 * i, 35.56), "+3V3", "GND", LCSC="C1525")
for i, ref in enumerate(["C20", "C21", "C22"]):
    two(ref, "C", "100n", (x + 10.16 * (8 + i), 35.56), "+1V1", "GND", LCSC="C1525")
two("C6", "C", "4.7u", (264.16, 35.56), "+3V3", "GND", LCSC="C23733")      # VREG_VIN
two("C7", "C", "4.7u", (274.32, 35.56), "+1V1", "GND", LCSC="C23733")      # VREG output
two("C19", "C", "10u", (284.48, 35.56), "+3V3", "GND", fp=FP_C0805, LCSC="C15850", MPN="CL21A106KAYNNNE")
# Core regulator: L1 3.3 uH (orientation matters, follow the reference layout), AVDD RC filter
two("L1", "L", "3.3u", (152.4, 233.68), "VREG_LX", "+1V1", fp="Inductor_SMD:L_Abracon_AOTA-B201610S",
    LCSC="C42411119", MPN="AOTA-B201610S3R3-101-T")
two("R3", "R", "33", (165.1, 233.68), "+3V3", "VREG_AVDD", LCSC="C25105")
two("C9", "C", "4.7u", (175.26, 233.68), "VREG_AVDD", "GND", LCSC="C23733")
# Crystal 12 MHz, ABM8-272-T3: 15 pF load caps, 1 k in series on XOUT
part("X1", "Device:Crystal_GND24", "12MHz", "Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm", (124.46, 210.82),
     {"1": "XIN", "3": "XTAL_O", "2": "GND", "4": "GND"}, LCSC="C20625731", MPN="ABM8-272-T3")
two("R2", "R", "1k", (142.24, 210.82), "XOUT", "XTAL_O", LCSC="C11702")
two("C3", "C", "15p", (106.68, 220.98), "XIN", "GND", LCSC="C1548")
two("C4", "C", "15p", (116.84, 228.6), "XTAL_O", "GND", LCSC="C1548")
# BOOTSEL / user-presence button: QSPI_SS -> 1 k -> button -> GND (as on the Pico)
two("R6", "R", "1k", (264.16, 205.74), "QSPI_SS", "BOOT_BTN", LCSC="C11702")
part("SW1", "Switch:SW_Push", "BOOTSEL", "Button_Switch_SMD:SW_Push_1P1T_NO_CK_KMR2", (281.94, 213.36),
     {"1": "BOOT_BTN", "2": "GND"}, LCSC="C72443", MPN="KMR221GLFS")
# SWD: 3 through holes at 2.54 mm (SWCLK, GND, SWDIO), as on the Pico 2: pin header or wires on the
# bench, left empty in the cased key
part("J4", "Connector_Generic:Conn_01x03", "SWD", "Connector_PinHeader_2.54mm:PinHeader_1x03_P2.54mm_Vertical",
     (302.26, 233.68), {"1": "SWCLK", "2": "GND", "3": "SWDIO"}, dnp=True)

# ---- SE051C2 ---------------------------------------------------------------------------------
# Deep power-down wiring (data sheet table 3, as on MIKROE-5392): VIN = 3V3, VOUT -> VCC.
# ENA from GP6 (pulled up: the SE is on unless the firmware turns it off; a power cycle of the SE is
# its only reset). Unused: LA/LB to VSS, IO1/IO2/CLK not connected, RST_N (ISO 7816 only) to VSS.
part("U3", "cardea:SE051C2", "SE051C2", "Package_DFN_QFN:QFN-20-1EP_3x3mm_P0.4mm_EP1.65x1.65mm", (345.44, 76.2),
     {"12": "+3V3", "18": "SE_VCC", "15": "SE_VCC", "11": "SE_ENA", "9": "SE_SDA", "10": "SE_SCL",
      "17": "GND", "1": "GND", "3": None, "16": None, "13": None, "14": "GND", "19": "GND", "21": "GND",
      "2": None, "4": None, "5": None, "6": None, "7": None, "8": None, "20": None},
     LCSC="C5202100", MPN="SE051C2HQ1/Z01XDZ")
two("C30", "C", "100n", (312.42, 50.8), "+3V3", "GND", LCSC="C1525")       # VIN
two("C31", "C", "100n", (322.58, 50.8), "SE_VCC", "GND", LCSC="C1525")     # VCC/VOUT
two("C32", "C", "1u", (332.74, 50.8), "+3V3", "GND", LCSC="C52923", MPN="CL05A105KA5NQNC")  # VIN bulk
two("R30", "R", "3.3k", (373.38, 50.8), "+3V3", "SE_SDA", LCSC="C25890")
two("R31", "R", "3.3k", (383.54, 50.8), "+3V3", "SE_SCL", LCSC="C25890")
two("R32", "R", "10k", (393.7, 50.8), "+3V3", "SE_ENA", LCSC="C25744")

# ---- Fingerprint module (GROW R502-F Pro; pinout to verify on the module) ----------------------
# 1 VCC (switched), 2 GND, 3 TXD (module out), 4 RXD (module in), 5 WAKEUP (finger detect out),
# 6 3.3VT (touch detection supply, always on). The module's cable has a plug on the module side
# only: its wires are soldered into J2, 6 through holes at 2.54 mm (a pin header also fits, for
# dupont wires on the bench). Two holes next to it (H1, H2) take the cable or a tie as strain
# relief. J5 = optional SH1.0 socket in parallel, not fitted (for a cable with plugs at both ends).
FP_NETS = {"1": "FP_VCC", "2": "GND", "3": "FP_RX_J", "4": "FP_TX_J", "5": "FP_WAKE_J", "6": "+3V3"}
part("J2", "Connector_Generic:Conn_01x06", "R502 wires", "Connector_PinHeader_2.54mm:PinHeader_1x06_P2.54mm_Vertical",
     (378.46, 160.02), FP_NETS)
part("J5", "Connector_Generic_MountingPin:Conn_01x06_MountingPin", "SH1.0 (DNP)",
     "Connector_JST:JST_SH_SM06B-SRSS-TB_1x06-1MP_P1.00mm_Horizontal", (398.78, 160.02),
     dict(FP_NETS, MP="GND"), LCSC="C160405", MPN="SM06B-SRSS-TB(LF)(SN)", dnp=True)
for i, ref in enumerate(["H1", "H2"]):
    part(ref, "Mechanical:MountingHole", "strain relief", "MountingHole:MountingHole_2.1mm", (378.46 + 7.62 * i, 182.88), {})
# High-side switch for the module (off by default: gate pulled up)
part("Q1", "Transistor_FET:AO3401A", "AO3401A", "Package_TO_SOT_SMD:SOT-23", (330.2, 147.32),
     {"1": "FP_PWR_EN_N", "2": "+3V3", "3": "FP_VCC"}, LCSC="C15127")
two("R40", "R", "10k", (314.96, 134.62), "+3V3", "FP_PWR_EN_N", LCSC="C25744")
two("C40", "C", "10u", (345.44, 175.26), "FP_VCC", "GND", fp=FP_C0805, LCSC="C15850", MPN="CL21A106KAYNNNE")
# Series resistor on our TX (limits back-powering the module through RXD while it is off)
two("R41", "R", "1k", (342.9, 195.58), "FP_TX", "FP_TX_J", LCSC="C11702")
# Series resistors on the lines coming from the module (ESD from the finger side, back-powering)
two("R43", "R", "220", (373.38, 195.58), "FP_RX_J", "FP_RX", LCSC="C25091")
two("R44", "R", "220", (388.62, 195.58), "FP_WAKE_J", "FP_WAKE", LCSC="C25091")
# WAKEUP pull-down: <= 8.2 k because of RP2350-E9 (pad leakage with the internal pull-down)
two("R42", "R", "4.7k", (358.14, 195.58), "FP_WAKE", "GND", LCSC="C25900")

# ---- RGB LED (common anode, active low). Green/blue Vf ~3 V at 3.3 V: low resistors; tune with the LED chosen
part("D1", "Device:LED_RGBA", "RGB", "LED_SMD:LED_RGB_1210", (373.38, 233.68),
     {"4": "+3V3", "1": "LED_RK", "2": "LED_GK", "3": "LED_BK"})
two("R50", "R", "1k", (340.36, 254.0), "LED_R", "LED_RK", LCSC="C11702")
two("R51", "R", "100", (350.52, 254.0), "LED_G", "LED_GK", LCSC="C25076")
two("R52", "R", "100", (360.68, 254.0), "LED_B", "LED_BK", LCSC="C25076")

# ---- Test points (bring-up; SE bus reachable from a Pico 2 with U1 held in reset via RUN) -------
tps = ["SE_SDA", "SE_SCL", "SE_ENA", "FP_TX", "FP_RX", "FP_WAKE", "RUN", "+3V3", "GND", "VBUS"]
for i, n in enumerate(tps):
    part(f"TP{i + 1}", "Connector:TestPoint", n, FP_TP, (152.4 + 15.24 * i, 271.78), {"1": n})

# ---- power flags (ERC: nets driven from outside the schematic) --------------------------------
for i, n in enumerate(["VBUS", "GND", "+1V1", "VREG_AVDD"]):
    part(f"#FLG0{i + 1}", "power:PWR_FLAG", "PWR_FLAG", "", (30.48 + 15.24 * i, 254.0), {"1": n})


# ======================================================================================== writer
def u(*k):
    return str(uuid.uuid5(NS, "/".join(map(str, k))))


def fnum(v):
    s = f"{v:.4f}".rstrip("0").rstrip(".")
    return s if s != "-0" else "0"


def lib_block(lib_id):
    nick, name = lib_id.split(":")
    if nick == "cardea":
        return flattened(nick, name, CARDEA_LIB)
    return flattened(nick, name)


def main():
    lib_ids = sorted({p["lib_id"] for p in P})
    blocks = {lid: lib_block(lid) for lid in lib_ids}
    out = []
    w = out.append
    w('(kicad_sch\n\t(version 20250114)\n\t(generator "cardea-gen")\n\t(generator_version "1")\n')
    w(f'\t(uuid "{ROOT}")\n\t(paper "A3")\n')
    w('\t(title_block\n\t\t(title "Cardea Key — RP2354A + SE051C2 (rev A)")\n\t\t(date "2026-11-01")\n'
      '\t\t(rev "A-draft")\n\t\t(comment 1 "Generated by hardware/tools/gen_schematic.py — do not edit by hand")\n'
      '\t\t(comment 2 "RP2354A core after Raspberry Pi RP2350A Minimal design (MIT)")\n\t)\n')
    w('\t(lib_symbols\n')
    for lid in lib_ids:
        w('\t\t' + blocks[lid].replace('\n', '\n\t') + '\n')
    w('\t)\n')

    labels, wires, ncs, insts = [], [], [], []
    for p in P:
        sx, sy = p["at"]
        ps = pins(blocks[p["lib_id"]])
        visible = [q for q in ps if not q[6]]
        by_pos = {}
        for q in ps:
            by_pos.setdefault((q[3], q[4]), []).append(q)
        missing = [q[0] for q in ps if q[0] not in p["nets"] and q[2] != "no_connect"]
        if missing:
            raise SystemExit(f"{p['ref']}: pins without a net entry: {missing}")
        done = set()
        for q in visible:
            num, _name, etype, px, py, ang, _h = q
            if (px, py) in done:
                continue
            done.add((px, py))
            nets = {p["nets"].get(o[0]) for o in by_pos[(px, py)] if o[2] != "no_connect"}
            if len(nets) > 1:
                raise SystemExit(f"{p['ref']} pin {num}: stacked pins on different nets {nets}")
            net = nets.pop() if nets else None
            x0, y0 = sx + px, sy - py
            if etype == "no_connect" or net is None:
                if etype != "no_connect":
                    ncs.append((x0, y0, u(p["ref"], num, "nc")))
                continue
            # wire outwards (away from the body), then the label
            st = p["fields"].get("stub", 2.54)
            dx, dy = {0: (-st, 0), 180: (st, 0), 90: (0, st), 270: (0, -st)}[ang]
            x1, y1 = x0 + dx, y0 + dy
            wires.append((x0, y0, x1, y1, u(p["ref"], num, "w")))
            la = {0: 180, 180: 0, 90: 270, 270: 90}[ang]
            labels.append((net, x1, y1, la, u(p["ref"], num, "l")))
        insts.append(p)

    for net, x1, y1, la, uid in labels:
        just = "left bottom" if la in (0, 90) else "right bottom"
        w(f'\t(label "{net}"\n\t\t(at {fnum(x1)} {fnum(y1)} {la})\n'
          f'\t\t(effects (font (size 1.27 1.27)) (justify {just}))\n\t\t(uuid "{uid}")\n\t)\n')
    for x0, y0, x1, y1, uid in wires:
        w(f'\t(wire\n\t\t(pts (xy {fnum(x0)} {fnum(y0)}) (xy {fnum(x1)} {fnum(y1)}))\n'
          f'\t\t(stroke (width 0) (type default))\n\t\t(uuid "{uid}")\n\t)\n')
    for x0, y0, uid in ncs:
        w(f'\t(no_connect\n\t\t(at {fnum(x0)} {fnum(y0)})\n\t\t(uuid "{uid}")\n\t)\n')
    for p in insts:
        sx, sy = p["at"]
        power = p["lib_id"].startswith("power:")
        ref = p["ref"]
        w(f'\t(symbol\n\t\t(lib_id "{p["lib_id"]}")\n\t\t(at {fnum(sx)} {fnum(sy)} 0)\n\t\t(unit 1)\n'
          f'\t\t(exclude_from_sim no)\n\t\t(in_bom {"no" if power else "yes"})\n\t\t(on_board {"no" if power else "yes"})\n'
          f'\t\t(dnp {"yes" if p["fields"].get("dnp") else "no"})\n\t\t(uuid "{u(ref, "sym")}")\n')
        props = [("Reference", ref, 0, -2.54 if not power else 3.81, not power and False or power),
                 ("Value", p["value"], 0, 2.54 if not power else 5.08, False),
                 ("Footprint", p["fp"], 0, 0, True),
                 ("Datasheet", "", 0, 0, True)]
        for k, v in p["fields"].items():
            if k in ("stub", "dnp"):
                continue
            props.append((k, v, 0, 0, True))
        for k, v, dx, dy, hide in props:
            h = " (hide yes)" if hide else ""
            w(f'\t\t(property "{k}" "{v}"\n\t\t\t(at {fnum(sx + dx + 3.81)} {fnum(sy + dy)} 0)\n'
              f'\t\t\t(effects (font (size 1.27 1.27)) (justify left){h})\n\t\t)\n')
        for q in pins(blocks[p["lib_id"]]):
            w(f'\t\t(pin "{q[0]}"\n\t\t\t(uuid "{u(ref, q[0], "pin")}")\n\t\t)\n')
        w(f'\t\t(instances\n\t\t\t(project "{NAME}"\n\t\t\t\t(path "/{ROOT}"\n'
          f'\t\t\t\t\t(reference "{ref}")\n\t\t\t\t\t(unit 1)\n\t\t\t\t)\n\t\t\t)\n\t\t)\n\t)\n')
    w('\t(sheet_instances\n\t\t(path "/"\n\t\t\t(page "1")\n\t\t)\n\t)\n\t(embedded_fonts no)\n)\n')
    open(os.path.join(PRJ, NAME + ".kicad_sch"), "w").write("".join(out))
    nets = sorted({n for p in P for n in p["nets"].values() if n})
    print(f"{len([p for p in P if not p['ref'].startswith('#')])} parts, {len(nets)} nets -> {NAME}.kicad_sch")


if __name__ == "__main__":
    main()
