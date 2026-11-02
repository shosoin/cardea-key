#!/usr/bin/env python3
"""Cardea Key PCB — first placement draft (no tracks), from the parts table in gen_schematic.py.

Runs inside KiCad's Python (Flatpak):
    flatpak run --filesystem=home --command=python3 org.kicad.KiCad hardware/tools/gen_board.py

Writes hardware/cardea-pcb/cardea-pcb.kicad_pcb: 4-layer, 1.6 mm, 45 x 20 mm outline, every
footprint with its nets (ratsnest shown in KiCad). The positions below are a DRAFT to see the size
and the layout; the real placement (core copied from Raspberry Pi's reference layout) comes next.
Re-running overwrites the board.
"""
import os
import sys

import pcbnew

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_schematic as G  # noqa: E402  (only the parts table is used)

FP_DIR = os.environ.get("KICAD_FOOTPRINT_DIR", "/app/extensions/Library/footprints")
OUT = os.path.join(HERE, "..", "cardea-pcb", "cardea-pcb.kicad_pcb")
X0, Y0, W, H = 100.0, 100.0, 45.0, 20.0

# ref: (x, y, rotation, side)   side "B" = bottom.  Coordinates relative to the board's top-left.
PLACE = {
    "J1": (3.6, 10.0, 270, "F"), "D2": (7.0, 10.0, 90, "B"),
    "R11": (7.0, 5.5, 90, "F"), "R12": (7.0, 14.5, 90, "F"),
    "U4": (11.5, 7.0, 0, "F"),
    "R7": (14.8, 8.8, 0, "F"), "R8": (14.8, 10.6, 0, "F"),
    "U2": (11.5, 13.0, 0, "F"), "C1": (13.8, 16.6, 0, "F"), "C5": (13.8, 18.6, 0, "F"),
    "U1": (21.0, 10.0, 0, "F"),
    "C10": (16.3, 7.0, 90, "F"), "C11": (16.3, 13.0, 90, "F"), "C12": (21.0, 4.8, 0, "F"),
    "C13": (21.0, 15.2, 0, "F"), "C14": (25.7, 7.0, 90, "F"), "C15": (25.7, 13.0, 90, "F"),
    "C16": (18.0, 4.8, 0, "F"), "C17": (24.0, 15.2, 0, "F"),
    "C20": (24.0, 4.8, 0, "F"), "C21": (18.0, 15.2, 0, "F"), "C22": (16.3, 10.0, 90, "F"),
    "L1": (18.5, 2.0, 0, "F"), "C6": (15.5, 2.0, 0, "F"), "C7": (21.5, 2.0, 0, "F"), "C19": (13.0, 2.0, 0, "F"),
    "R3": (24.5, 2.0, 0, "F"), "C9": (26.5, 2.0, 0, "F"),
    "X1": (21.0, 18.0, 0, "F"), "C3": (17.8, 18.3, 90, "F"), "C4": (24.2, 18.3, 90, "F"), "R2": (26.0, 16.6, 0, "F"),
    "R6": (9.6, 4.6, 0, "B"), "SW1": (9.6, 2.4, 0, "F"),
    "J4": (29.5, 2.2, 90, "F"),
    "U3": (32.0, 9.5, 0, "F"), "C30": (29.0, 8.0, 90, "F"), "C31": (29.0, 11.0, 90, "F"), "C32": (32.0, 13.0, 0, "F"),
    "R30": (35.0, 7.0, 90, "F"), "R31": (35.0, 10.0, 90, "F"), "R32": (35.0, 13.0, 90, "F"),
    "Q1": (38.0, 3.5, 0, "F"), "R40": (38.0, 6.8, 0, "F"), "C40": (38.0, 9.0, 0, "F"),
    "R41": (38.0, 11.5, 0, "F"), "R42": (38.0, 13.5, 0, "F"),
    "R43": (40.0, 15.5, 90, "B"), "R44": (38.5, 15.5, 90, "B"),
    "J2": (42.5, 3.65, 0, "F"),
    "H1": (37.0, 17.6, 0, "F"), "H2": (40.2, 17.6, 0, "F"),
    "D1": (9.6, 17.6, 0, "F"), "R50": (11.0, 14.5, 90, "B"), "R51": (12.5, 14.5, 90, "B"), "R52": (14.0, 14.5, 90, "B"),
    "J5": (39.0, 10.0, 90, "B"),
}
TP_ROW = [(17.5 + 3.6 * (i // 2), 6.0 if i % 2 else 14.5) for i in range(10)]   # bottom side, 2 rows


def load_fp(fpid):
    lib, name = fpid.split(":")
    fp = pcbnew.FootprintLoad(os.path.join(FP_DIR, lib + ".pretty"), name)
    if fp is None:
        raise SystemExit(f"footprint not found: {fpid}")
    return fp


def main():
    board = pcbnew.BOARD()
    ds = board.GetDesignSettings()
    board.SetCopperLayerCount(4)
    ds.SetBoardThickness(pcbnew.FromMM(1.6))

    nets = {}

    def net(name):
        if name not in nets:
            ni = pcbnew.NETINFO_ITEM(board, name)
            board.Add(ni)
            nets[name] = ni
        return nets[name]

    tp_i = 0
    for p in G.P:
        if not p["fp"]:
            continue
        ref = p["ref"]
        fp = load_fp(p["fp"])
        fp.SetReference(ref)
        fp.SetValue(p["value"])
        fp.SetFPID(pcbnew.LIB_ID(*p["fp"].split(":")))
        if ref.startswith("TP"):
            x, y = TP_ROW[tp_i]
            tp_i += 1
            rot, side = 0, "B"
        else:
            x, y, rot, side = PLACE.get(ref, (W + 5, 5, 0, "F"))   # unplaced: outside the board
        board.Add(fp)
        if side == "B":
            fp.Flip(fp.GetPosition(), pcbnew.FLIP_DIRECTION_LEFT_RIGHT)
        fp.SetPosition(pcbnew.VECTOR2I(pcbnew.FromMM(X0 + x), pcbnew.FromMM(Y0 + y)))
        fp.SetOrientationDegrees(rot)
        if p["fields"].get("dnp"):
            fp.SetDNP(True)
        for pad in fp.Pads():
            n = p["nets"].get(pad.GetNumber())
            if n:
                pad.SetNet(net(n))
    # outline with 1 mm corner radius
    rect = pcbnew.PCB_SHAPE(board, pcbnew.SHAPE_T_RECTANGLE)
    rect.SetLayer(pcbnew.Edge_Cuts)
    rect.SetWidth(pcbnew.FromMM(0.1))
    rect.SetStart(pcbnew.VECTOR2I(pcbnew.FromMM(X0), pcbnew.FromMM(Y0)))
    rect.SetEnd(pcbnew.VECTOR2I(pcbnew.FromMM(X0 + W), pcbnew.FromMM(Y0 + H)))
    board.Add(rect)
    txt = pcbnew.PCB_TEXT(board)
    txt.SetText("CARDEA KEY rev A")
    txt.SetLayer(pcbnew.B_SilkS)
    txt.SetMirrored(True)
    txt.SetPosition(pcbnew.VECTOR2I(pcbnew.FromMM(X0 + 26), pcbnew.FromMM(Y0 + 10.3)))
    board.Add(txt)
    board.Save(OUT)
    print(f"{len(board.GetFootprints())} footprints, {len(nets)} nets -> {OUT}")


if __name__ == "__main__":
    main()
