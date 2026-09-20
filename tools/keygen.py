#!/usr/bin/env python3
"""
Reference keygen for the Aegis crackme -- full spoilers, ground truth.

If you want to solve Aegis blind, don't run this. It exists to:
  - sanity-check the shipped binary actually accepts valid keys,
  - generate fresh test keys for any serial you like,
  - verify a keygen someone else wrote/derived produces the same output.

Usage:
    python tools/keygen.py                 # random serial, prints one key
    python tools/keygen.py HELLO1          # 5-byte ASCII serial (padded/truncated to 5 bytes)
    python tools/keygen.py --hex 48656c6c6f  # 5-byte serial given as hex
    python tools/keygen.py --check AEGIS-XXXX-XXXX-XXXX-XXXX  # verify an existing key
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from proto import make_key, check_key, format_key, parse_key


def serial_from_text(text: str) -> bytes:
    b = text.encode("utf-8")
    if len(b) > 5:
        b = b[:5]
    return b.ljust(5, b"\x00")


def main(argv):
    if len(argv) >= 2 and argv[1] == "--check":
        if len(argv) < 3:
            print("usage: keygen.py --check <KEY>")
            return 1
        key = parse_key(argv[2])
        ok = check_key(key)
        print(f"key:    {format_key(key)}")
        print(f"serial: {key[0:5].hex()}")
        print(f"valid:  {ok}")
        return 0 if ok else 1

    if len(argv) >= 3 and argv[1] == "--hex":
        serial = bytes.fromhex(argv[2])
        if len(serial) != 5:
            print(f"error: --hex serial must be exactly 5 bytes (10 hex chars), got {len(serial)}")
            return 1
    elif len(argv) >= 2:
        serial = serial_from_text(argv[1])
    else:
        serial = os.urandom(5)

    key = make_key(serial)
    assert check_key(key)
    print(f"serial (hex): {serial.hex()}")
    print(f"key:          {format_key(key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
