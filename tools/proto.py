"""
Aegis crackme -- reference prototype.

Verifies the Feistel/MAC scheme in plain Python BEFORE it gets hand-encoded
into VM bytecode and transliterated to C (no C compiler is available on this
machine, so this Python model is the correctness oracle for both).

Key format: AEGIS-SSSS-SSSS-SSCC-CCCC  (16 hex nibbles = 8 bytes)
  - bytes[0:5]  = serial   (5 bytes, free choice -- this is what a keygen picks)
  - bytes[5:8]  = check    (3 bytes, MUST equal mac(serial)[0:3])

mac(serial5):
  block = serial5 + b"\\x00\\x00\\x00"      # 8-byte block, check field zeroed
  cipher = feistel_encrypt(block, subkeys)  # 8 rounds
  return cipher[0:3]
"""

MASK32 = 0xFFFFFFFF
ROUNDS = 8
MIX_CONST = 0x9E3779B1  # odd multiplier (2^32 / golden ratio), standard hash-mixing constant

MASTER_KEY = 0xC0FFEE42  # the "secret" baked into the binary's constant pool


def rotl32(x, n):
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def key_schedule(master_key):
    # subkey[i] = rotl(master_key ^ (i * 0x2545F491), i*3) -- cheap, deterministic, order-dependent
    subkeys = []
    for i in range(ROUNDS):
        sk = (master_key ^ ((i * 0x2545F491) & MASK32)) & MASK32
        sk = rotl32(sk, (i * 3) % 32)
        subkeys.append(sk)
    return subkeys


def round_function(r, subkey):
    x = (r ^ subkey) & MASK32
    x = rotl32(x, 5)
    x = (x * MIX_CONST) & MASK32
    x ^= (x >> 15)
    return x & MASK32


def feistel_encrypt(block8: bytes, subkeys) -> bytes:
    assert len(block8) == 8
    L = int.from_bytes(block8[0:4], "little")
    R = int.from_bytes(block8[4:8], "little")
    for i in range(ROUNDS):
        newL = R
        newR = (L ^ round_function(R, subkeys[i])) & MASK32
        L, R = newL, newR
    return L.to_bytes(4, "little") + R.to_bytes(4, "little")


def mac(serial5: bytes) -> bytes:
    assert len(serial5) == 5
    subkeys = key_schedule(MASTER_KEY)
    block = serial5 + b"\x00\x00\x00"
    cipher = feistel_encrypt(block, subkeys)
    return cipher[0:3]


def check_key(key8: bytes) -> bool:
    assert len(key8) == 8
    serial = key8[0:5]
    given_check = key8[5:8]
    return mac(serial) == given_check


def make_key(serial5: bytes) -> bytes:
    return serial5 + mac(serial5)


def format_key(key8: bytes) -> str:
    h = key8.hex().upper()
    return f"AEGIS-{h[0:4]}-{h[4:8]}-{h[8:10]}{h[10:12]}-{h[12:16]}"
    # groups: 4 / 4 / 2+2 / 4  -- purely cosmetic regrouping of the 16 hex chars


def parse_key(text: str) -> bytes:
    text = text.strip().upper()
    if text.startswith("AEGIS-"):
        text = text[len("AEGIS-"):]
    hexdigits = text.replace("-", "")
    if len(hexdigits) != 16:
        raise ValueError(f"expected 16 hex digits, got {len(hexdigits)}: {hexdigits!r}")
    return bytes.fromhex(hexdigits)


if __name__ == "__main__":
    # sanity: bijection check on a handful of blocks (Feistel must always be invertible
    # regardless of the round function -- if this fails, the transliteration is wrong)
    def feistel_decrypt(block8: bytes, subkeys) -> bytes:
        L = int.from_bytes(block8[0:4], "little")
        R = int.from_bytes(block8[4:8], "little")
        for i in reversed(range(ROUNDS)):
            oldR = L
            oldL = (R ^ round_function(oldR, subkeys[i])) & MASK32
            L, R = oldL, oldR
        return L.to_bytes(4, "little") + R.to_bytes(4, "little")

    sk = key_schedule(MASTER_KEY)
    import os
    for _ in range(2000):
        blk = os.urandom(8)
        c = feistel_encrypt(blk, sk)
        d = feistel_decrypt(c, sk)
        assert d == blk, f"NOT BIJECTIVE: {blk.hex()} -> {c.hex()} -> {d.hex()}"
    print("feistel bijection check: OK (2000 random blocks)")

    # generate a handful of valid test keys
    test_serials = [b"HELLO", b"\x00\x00\x00\x00\x00", b"\xff\xff\xff\xff\xff", os.urandom(5), os.urandom(5)]
    print()
    for s in test_serials:
        k = make_key(s)
        assert check_key(k)
        # mutate one bit of the check field -> must fail
        bad = bytearray(k)
        bad[6] ^= 0x01
        assert not check_key(bytes(bad))
        print(f"serial={s.hex():<12} key={format_key(k)}   parse-roundtrip-ok={parse_key(format_key(k)) == k}")

    print()
    print("MASTER_KEY  =", hex(MASTER_KEY))
    print("subkeys     =", [hex(x) for x in sk])
    print("MIX_CONST   =", hex(MIX_CONST))
