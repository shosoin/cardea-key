"""Read symbols (flattened, with pins) from KiCad .kicad_sym libraries. No KiCad Python needed."""
import os
import re

SYM_DIR = os.environ.get(
    "KICAD_SYMBOL_DIR",
    "/var/lib/flatpak/runtime/org.kicad.KiCad.Library.Symbols/x86_64/stable/active/files/symbols")


def block_at(s, i):
    """The balanced (...) block starting at s[i] == '('."""
    d = 0
    q = False
    k = i
    while k < len(s):
        c = s[k]
        if q:
            if c == '\\':
                k += 1
            elif c == '"':
                q = False
        elif c == '"':
            q = True
        elif c == '(':
            d += 1
        elif c == ')':
            d -= 1
            if d == 0:
                return s[i:k + 1]
        k += 1
    raise ValueError("unbalanced")


_cache = {}


def _lib_text(path):
    if path not in _cache:
        _cache[path] = open(path).read()
    return _cache[path]


def raw_symbol(path, name):
    s = _lib_text(path)
    m = re.search(r'\n\t\(symbol "%s"\n' % re.escape(name), s)
    if not m:
        raise KeyError(f"{name} not in {path}")
    return block_at(s, m.start() + 2)


def flattened(lib_nick, name, path=None):
    """Symbol block named "lib_nick:name", with `extends` resolved, ready for lib_symbols."""
    path = path or os.path.join(SYM_DIR, lib_nick + ".kicad_sym")
    b = raw_symbol(path, name)
    m = re.search(r'\(extends "([^"]+)"\)', b)
    if m:
        parent = m.group(1)
        pb = raw_symbol(path, parent)
        # child properties replace the parent's; graphics and pins come from the parent
        child_props = {p: block for p, block in _props(b)}
        out = pb
        for p, block in _props(pb):
            if p in child_props:
                out = out.replace(block, child_props[p], 1)
        for p, block in _props(b):
            if p not in dict(_props(pb)):
                # insert before the first sub-symbol
                k = out.index('\n\t\t(symbol "')
                out = out[:k] + '\n\t\t' + block + out[k:]
        out = out.replace(f'(symbol "{parent}_', f'(symbol "{name}_')
        out = out.replace(f'(symbol "{parent}"', f'(symbol "{name}"', 1)
        b = out
    return b.replace(f'(symbol "{name}"', f'(symbol "{lib_nick}:{name}"', 1)


def _props(b):
    res = []
    for m in re.finditer(r'\(property "([^"]+)"', b):
        res.append((m.group(1), block_at(b, m.start())))
    return res


PIN_RE = re.compile(r'\(pin (\w+) (\w+)\s*\(at ([\d.\-]+) ([\d.\-]+) (\d+)\)\s*\(length ([\d.]+)\)(.*?)'
                    r'\(name "([^"]*)".*?\(number "([^"]*)"', re.S)


def pins(block):
    """[(number, name, etype, x, y, angle, hidden)] in symbol coordinates (y up)."""
    out = []
    for m in PIN_RE.finditer(block):
        etype, _style, x, y, a, _l, mid, name, num = m.groups()
        hidden = bool(re.search(r'\(hide yes\)|\bhide\b', mid))
        out.append((num, name, etype, float(x), float(y), int(a), hidden))
    return out


if __name__ == "__main__":
    import sys
    lib, name = sys.argv[1].split(":")
    b = flattened(lib, name, sys.argv[2] if len(sys.argv) > 2 else None)
    for p in pins(b):
        print(*p)
