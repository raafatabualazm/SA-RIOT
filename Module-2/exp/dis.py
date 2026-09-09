#!/usr/bin/env python3
"""Shannon modem image disassembly / xref helper.

Segments come from the FirmWire loader dump:
    modem_40000000.bin  -> 0x40000000
    modem_40010000.bin  -> 0x40010000   (main image, ~39 MB)
    modem_47800000.bin  -> 0x47800000

Usage:
  dis.py dis   <addr> [count]      Thumb disassembly (default 60 insns)
  dis.py disa  <addr> [count]      ARM disassembly
  dis.py back  <addr> [bytes]      dump raw bytes before addr (find func prologue)
  dis.py hex   <addr> [len]        hexdump
  dis.py u32   <addr> [n]          read n little-endian u32s
  dis.py xref  <value> [max]       find every 4-byte LE occurrence of value (literal pools, vtables)
  dis.py str   <text>              find a string and every literal-pool pointer to it
  dis.py fn    <addr> [count]      Thumb disassembly, stopping at an obvious function end

Addresses accept 0x.. hex. Bit 0 is masked off for Thumb.
"""
import sys, os, struct

try:
    from capstone import *
    from capstone.arm import *
except ImportError:
    sys.exit("capstone missing: pip3 install capstone")

WS = os.environ.get(
    "FW_WS",
    "/home/kali/FirmWire/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4_workspace/loader",
)

SEGS = []
for base, name in ((0x40000000, "modem_40000000.bin"),
                   (0x40010000, "modem_40010000.bin"),
                   (0x47800000, "modem_47800000.bin")):
    p = os.path.join(WS, name)
    if os.path.exists(p):
        SEGS.append((base, os.path.getsize(p), p))
SEGS.sort()

_cache = {}


def _seg(addr):
    for base, size, path in SEGS:
        if base <= addr < base + size:
            return base, size, path
    return None


def read(addr, n):
    s = _seg(addr)
    if not s:
        raise ValueError("addr 0x%08x not in any segment" % addr)
    base, size, path = s
    if path not in _cache:
        _cache[path] = open(path, "rb")
    f = _cache[path]
    f.seek(addr - base)
    return f.read(min(n, base + size - addr))


def blob(path):
    if ("BLOB", path) not in _cache:
        with open(path, "rb") as f:
            _cache[("BLOB", path)] = f.read()
    return _cache[("BLOB", path)]


def md(thumb=True):
    m = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    m.detail = False
    m.skipdata = True
    return m


def do_dis(addr, count, thumb=True, stop_on_end=False):
    addr &= ~1
    data = read(addr, count * 4 + 64)
    n = 0
    prev_pop = False
    for i in md(thumb).disasm(data, addr):
        print("0x%08x  %-22s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
        n += 1
        if stop_on_end:
            m = i.mnemonic
            if m.startswith("pop") and "pc" in i.op_str:
                prev_pop = True
            elif m in ("bx",) and "lr" in i.op_str:
                prev_pop = True
            elif prev_pop and not m.startswith(("b", "nop")):
                pass
        if n >= count:
            break


def do_hex(addr, n):
    data = read(addr, n)
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print("0x%08x  %-47s |%s|" % (addr + off, chunk.hex(" "), asc))


def do_u32(addr, n):
    data = read(addr, n * 4)
    for i in range(0, len(data) // 4):
        v = struct.unpack_from("<I", data, i * 4)[0]
        print("0x%08x: 0x%08x  (%d)" % (addr + i * 4, v, v))


def do_xref(value, maxhits=80):
    needle = struct.pack("<I", value)
    total = 0
    for base, size, path in SEGS:
        b = blob(path)
        start = 0
        while True:
            idx = b.find(needle, start)
            if idx < 0:
                break
            print("0x%08x  (%s+0x%x)" % (base + idx, os.path.basename(path), idx))
            total += 1
            if total >= maxhits:
                print("... truncated at %d hits" % maxhits)
                return
            start = idx + 1
    print("[%d hits]" % total)


def do_str(text):
    needle = text.encode() if isinstance(text, str) else text
    for base, size, path in SEGS:
        b = blob(path)
        start = 0
        while True:
            idx = b.find(needle, start)
            if idx < 0:
                break
            saddr = base + idx
            print("STRING 0x%08x  %r" % (saddr, b[idx:idx + 90].split(b"\x00")[0]))
            # find pointers to the start of this string (walk back to preceding NUL)
            s0 = idx
            while s0 > 0 and b[s0 - 1] != 0:
                s0 -= 1
            do_xref(base + s0, 20)
            start = idx + 1
            break  # first hit per segment is enough


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("segments:", [(hex(b), os.path.basename(p), hex(s)) for b, s, p in SEGS])
        return
    cmd = sys.argv[1]
    arg = sys.argv[2]
    n = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
    if cmd == "dis":
        do_dis(int(arg, 0), n or 60, True)
    elif cmd == "fn":
        do_dis(int(arg, 0), n or 200, True, stop_on_end=True)
    elif cmd == "disa":
        do_dis(int(arg, 0), n or 60, False)
    elif cmd == "back":
        a = int(arg, 0) & ~1
        k = n or 64
        do_dis(a - k, (k // 2) + 20, True)
    elif cmd == "hex":
        do_hex(int(arg, 0), n or 128)
    elif cmd == "u32":
        do_u32(int(arg, 0), n or 16)
    elif cmd == "xref":
        do_xref(int(arg, 0), n or 80)
    elif cmd == "str":
        do_str(" ".join(sys.argv[2:]))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
