"""
Assembles the Aegis license-check VM program and verifies it against the
plain-Python reference (proto.py) on many random keys, including negative
cases (flipped bits). Only once this agrees 100% does the bytecode get
transliterated into the C project's bytecode_license.h byte array.

Host (C main.c) responsibility, BEFORE calling vm_run():
  mem[0..3]  = serial bytes [0,1,2,3]           (block "L", little-endian u32)
  mem[4]     = serial byte  [4]                 (block "R", low byte)
  mem[5..7]  = 0                                (block "R", high 3 bytes -- the
                                                  zeroed check-field placeholder,
                                                  exactly mirroring proto.py's
                                                  `block = serial5 + b"\\0\\0\\0"`)
  mem[12..14]= given check bytes [key[5],key[6],key[7]]   (the 3 check bytes
                                                            taken FROM the key
                                                            the user typed in)

Bytecode responsibility:
  run 8 Feistel rounds in place on mem[0..7] (L=mem[0..3], R=mem[4..7]),
  then compare mem[0..2] (== cipher[0:3], the COMPUTED check) byte-by-byte
  against mem[12..14] (the GIVEN check), push 1 if all three bytes match,
  else push 0, then HALT.

Memory map (32-byte scratch):
  0..3   L                     (mutated in place across rounds)
  4..7   R                     (mutated in place across rounds)
  8..11  round scratch (tmp)
  12..14 given check (3 bytes, host-loaded)
  15     unused
  16..19 junk sink (opaque-predicate discard target, never read back)
"""

from proto import MASTER_KEY, MIX_CONST, ROUNDS, key_schedule, mac, check_key, make_key, format_key, parse_key
from vm import Asm, VM, OP_PUSH_CONST, OP_PUSH_MEM32, OP_POP_MEM32, OP_PUSH_MEM8, OP_POP_MEM8, \
    OP_XOR, OP_ADD, OP_MUL, OP_OR, OP_ROL, OP_SHR, OP_DUP, OP_SWAP32, OP_JZ, OP_JMP, OP_NOP_JUNK, OP_HALT

MASK32 = 0xFFFFFFFF

MEM_L = 0
MEM_R = 4
MEM_TMP = 8
MEM_GIVEN_CHECK = 12   # 3 individual bytes at 12,13,14
MEM_JUNK_SINK = 16

CONST_MIX = 0          # consts[0] = MIX_CONST
CONST_SUBKEY0 = 1       # consts[1..8] = subkeys[0..7]
CONST_ZERO = 9          # consts[9] = 0
CONST_ONE = 10          # consts[10] = 1


def emit_round(a: Asm, subkey_const_idx: int, junk_a: int, junk_b: int):
    # light opaque-predicate junk before each round: pushes junk_b unconditionally
    # via a computation a static disassembler can't trivially fold without
    # emulating it, then discards it into a scratch slot nothing reads back.
    a.op(OP_NOP_JUNK, junk_a, junk_b)
    a.op(OP_POP_MEM32, MEM_JUNK_SINK)

    # F(R, sk):
    #   x = rotl(R ^ sk, 5)
    #   x = x * MIX_CONST            (mod 2^32)
    #   x = x ^ (x >> 15)
    a.op(OP_PUSH_MEM32, MEM_R)
    a.op(OP_PUSH_CONST, subkey_const_idx)
    a.op(OP_XOR)
    a.op(OP_ROL, 5)
    a.op(OP_PUSH_CONST, CONST_MIX)
    a.op(OP_MUL)
    a.op(OP_POP_MEM32, MEM_TMP)          # tmp = x  (stash so it can be read twice)
    a.op(OP_PUSH_MEM32, MEM_TMP)
    a.op(OP_SHR, 15)
    a.op(OP_PUSH_MEM32, MEM_TMP)
    a.op(OP_XOR)                          # stack: F(R, sk)

    # newR = L ^ F(R, sk)
    a.op(OP_PUSH_MEM32, MEM_L)
    a.op(OP_XOR)
    a.op(OP_POP_MEM32, MEM_TMP)          # tmp = newR

    # newL = oldR ; then R = newR (tmp)
    a.op(OP_PUSH_MEM32, MEM_R)
    a.op(OP_POP_MEM32, MEM_L)
    a.op(OP_PUSH_MEM32, MEM_TMP)
    a.op(OP_POP_MEM32, MEM_R)


def build_program():
    a = Asm()

    junk_pairs = [(0x11, 0x00), (0x22, 0x07), (0x05, 0x19), (0x3A, 0x02),
                  (0x0C, 0x2D), (0x41, 0x08), (0x17, 0x33), (0x09, 0x1F)]
    for i in range(ROUNDS):
        emit_round(a, CONST_SUBKEY0 + i, *junk_pairs[i])

    # compare mem[0..2] (computed check, sitting in L's low 3 bytes after
    # the last round) against mem[12..14] (given check), byte by byte,
    # OR-accumulating the differences on the stack.
    a.op(OP_PUSH_MEM8, MEM_L + 0)
    a.op(OP_PUSH_MEM8, MEM_GIVEN_CHECK + 0)
    a.op(OP_XOR)
    a.op(OP_PUSH_MEM8, MEM_L + 1)
    a.op(OP_PUSH_MEM8, MEM_GIVEN_CHECK + 1)
    a.op(OP_XOR)
    a.op(OP_OR)
    a.op(OP_PUSH_MEM8, MEM_L + 2)
    a.op(OP_PUSH_MEM8, MEM_GIVEN_CHECK + 2)
    a.op(OP_XOR)
    a.op(OP_OR)
    # stack top == 0  <=>  all three bytes matched
    a.jmp_to(OP_JZ, "ok")
    a.op(OP_PUSH_CONST, CONST_ZERO)
    a.jmp_to(OP_JMP, "end")
    a.label("ok")
    a.op(OP_PUSH_CONST, CONST_ONE)
    a.label("end")
    a.op(OP_HALT)

    return a.finish()


def build_consts():
    subkeys = key_schedule(MASTER_KEY)
    consts = [MIX_CONST] + subkeys + [0, 1]
    assert len(consts) == 11
    return consts


def load_mem_for_key(key8: bytes) -> bytes:
    serial = key8[0:5]
    given_check = key8[5:8]
    mem = bytearray(32)
    mem[0:4] = serial[0:4]
    mem[4] = serial[4]
    mem[5:8] = b"\x00\x00\x00"
    mem[12:15] = given_check
    return bytes(mem)


def vm_check_key(vm: VM, code: bytes, key8: bytes) -> bool:
    mem_init = load_mem_for_key(key8)
    result, _ = vm.run(code, mem_init)
    return result == 1


if __name__ == "__main__":
    consts = build_consts()
    code = build_program()
    vm = VM(consts)

    print(f"bytecode length: {len(code)} bytes")
    print(f"consts: {[hex(c) for c in consts]}")
    print()

    import os
    failures = 0
    N = 500
    for _ in range(N):
        serial = os.urandom(5)
        good_key = make_key(serial)
        assert check_key(good_key)  # sanity on the python oracle itself

        vm_result_good = vm_check_key(vm, code, good_key)
        if not vm_result_good:
            print(f"MISMATCH (should ACCEPT): serial={serial.hex()} key={format_key(good_key)}")
            failures += 1

        bad_key = bytearray(good_key)
        bad_key[7] ^= 0x01  # flip one bit of the check field
        bad_key = bytes(bad_key)
        vm_result_bad = vm_check_key(vm, code, bad_key)
        if vm_result_bad:
            print(f"MISMATCH (should REJECT): serial={serial.hex()} key={format_key(bad_key)}")
            failures += 1

    print(f"tested {N} valid + {N} corrupted keys against the VM bytecode.")
    print(f"failures: {failures}")

    if failures == 0:
        print()
        print("VM BYTECODE MATCHES PYTHON REFERENCE FOR ALL TEST CASES.")
        # one concrete demo trace
        demo_serial = b"AEGIS"[:5] if len(b"AEGIS") >= 5 else b"AEGI0"
        demo_key = make_key(b"DEMO1")
        print()
        print("demo valid key:", format_key(demo_key))
        print("VM verdict:", vm_check_key(vm, code, demo_key))

        # dump C-friendly arrays
        print()
        print("---- C header data ----")
        print("static const uint32_t g_consts[] = {")
        print("    " + ", ".join(f"0x{c:08X}u" for c in consts) + ",")
        print("};")
        print()
        code_hex = ", ".join(f"0x{b:02X}" for b in code)
        # wrap at ~16 per line
        bs = [f"0x{b:02X}" for b in code]
        lines = [", ".join(bs[i:i+16]) for i in range(0, len(bs), 16)]
        print("static const uint8_t g_bytecode[] = {")
        for ln in lines:
            print("    " + ln + ",")
        print("};")
        print(f"/* bytecode length: {len(code)} bytes */")
