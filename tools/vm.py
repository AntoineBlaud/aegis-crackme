"""
Aegis VM -- reference interpreter + assembler, mirrored 1:1 by the C VM
(vm.c) later. This is the executable spec: get the bytecode program right
here (where it can actually run), then transliterate the interpreter loop
to C almost mechanically.

Design: stack machine, uint32 stack, byte-addressable scratch memory,
a constant pool of uint32s. No native jumps needed in the shipped program
(the 8 Feistel rounds are fully unrolled), keeping the interpreter tiny
and orthogonal.
"""

MASK32 = 0xFFFFFFFF

# ---- opcodes ---------------------------------------------------------
OP_HALT       = 0x00  # stop; result = pop()
OP_PUSH_CONST = 0x01  # u8 idx           ; push consts[idx]
OP_PUSH_MEM32 = 0x02  # u8 addr          ; push u32-le from mem[addr..addr+3]
OP_POP_MEM32  = 0x03  # u8 addr          ; mem[addr..addr+3] = pop() as u32-le
OP_PUSH_MEM8  = 0x04  # u8 addr          ; push zero-extended mem[addr]
OP_POP_MEM8   = 0x05  # u8 addr          ; mem[addr] = pop() & 0xFF
OP_XOR        = 0x06  #                  ; b=pop, a=pop, push a^b
OP_ADD        = 0x07  #                  ; b=pop, a=pop, push (a+b) mod 2^32
OP_MUL        = 0x08  #                  ; b=pop, a=pop, push (a*b) mod 2^32
OP_OR         = 0x09  #                  ; b=pop, a=pop, push a|b
OP_ROL        = 0x0A  # u8 n             ; a=pop, push rotl32(a, n)
OP_SHR        = 0x0B  # u8 n             ; a=pop, push a >> n
OP_DUP        = 0x0C  #                  ; push top of stack again
OP_SWAP32     = 0x0D  # u8 a1, u8 a2     ; swap 4 bytes at mem[a1..] with mem[a2..]
OP_JZ         = 0x0E  # u16-le target    ; a=pop, if a==0: ip = target
OP_JMP        = 0x0F  # u16-le target    ; ip = target
OP_NOP_JUNK   = 0x10  # u8 a, u8 b       ; opaque predicate: push ((a*a) & 0 | b) -- always == b; junk for static analysis

NAMES = {v: k for k, v in list(globals().items()) if k.startswith("OP_")}


class Asm:
    """Tiny two-pass assembler: emit(...) records ops, label()/here() resolve jump targets."""

    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []  # (offset_of_target_byte, label_name)

    def here(self):
        return len(self.code)

    def label(self, name):
        self.labels[name] = self.here()
        return self

    def _u8(self, v):
        assert 0 <= v <= 0xFF, v
        self.code.append(v)

    def op(self, opcode, *operands):
        self._u8(opcode)
        for o in operands:
            self._u8(o)
        return self

    def jmp_to(self, opcode, label_name):
        self._u8(opcode)
        self.fixups.append((len(self.code), label_name))
        self.code.append(0)  # placeholder lo
        self.code.append(0)  # placeholder hi
        return self

    def finish(self):
        for offset, name in self.fixups:
            assert name in self.labels, f"undefined label {name!r}"
            target = self.labels[name]
            assert 0 <= target <= 0xFFFF, target
            self.code[offset] = target & 0xFF
            self.code[offset + 1] = (target >> 8) & 0xFF
        return bytes(self.code)


class VM:
    STACK_MAX = 32
    MEM_SIZE = 32

    def __init__(self, consts):
        self.consts = consts

    def run(self, code: bytes, mem_init: bytes, trace=False):
        mem = bytearray(self.MEM_SIZE)
        mem[: len(mem_init)] = mem_init
        stack = []
        ip = 0
        steps = 0
        while True:
            steps += 1
            if steps > 100000:
                raise RuntimeError("step limit exceeded (infinite loop?)")
            opcode = code[ip]
            ip += 1
            if opcode == OP_HALT:
                if trace:
                    print(f"[{steps:4}] HALT")
                return stack.pop() & MASK32, bytes(mem)
            elif opcode == OP_PUSH_CONST:
                idx = code[ip]; ip += 1
                stack.append(self.consts[idx])
            elif opcode == OP_PUSH_MEM32:
                addr = code[ip]; ip += 1
                v = int.from_bytes(mem[addr:addr + 4], "little")
                stack.append(v)
            elif opcode == OP_POP_MEM32:
                addr = code[ip]; ip += 1
                v = stack.pop() & MASK32
                mem[addr:addr + 4] = v.to_bytes(4, "little")
            elif opcode == OP_PUSH_MEM8:
                addr = code[ip]; ip += 1
                stack.append(mem[addr])
            elif opcode == OP_POP_MEM8:
                addr = code[ip]; ip += 1
                mem[addr] = stack.pop() & 0xFF
            elif opcode == OP_XOR:
                b = stack.pop(); a = stack.pop(); stack.append((a ^ b) & MASK32)
            elif opcode == OP_ADD:
                b = stack.pop(); a = stack.pop(); stack.append((a + b) & MASK32)
            elif opcode == OP_MUL:
                b = stack.pop(); a = stack.pop(); stack.append((a * b) & MASK32)
            elif opcode == OP_OR:
                b = stack.pop(); a = stack.pop(); stack.append((a | b) & MASK32)
            elif opcode == OP_ROL:
                n = code[ip]; ip += 1
                a = stack.pop() & MASK32
                stack.append(((a << n) | (a >> (32 - n))) & MASK32 if n else a)
            elif opcode == OP_SHR:
                n = code[ip]; ip += 1
                a = stack.pop() & MASK32
                stack.append((a >> n) & MASK32)
            elif opcode == OP_DUP:
                stack.append(stack[-1])
            elif opcode == OP_SWAP32:
                a1 = code[ip]; ip += 1
                a2 = code[ip]; ip += 1
                mem[a1:a1 + 4], mem[a2:a2 + 4] = mem[a2:a2 + 4], mem[a1:a1 + 4]
            elif opcode == OP_JZ:
                target = code[ip] | (code[ip + 1] << 8); ip += 2
                a = stack.pop()
                if a == 0:
                    ip = target
            elif opcode == OP_JMP:
                target = code[ip] | (code[ip + 1] << 8); ip += 2
                ip = target
            elif opcode == OP_NOP_JUNK:
                a = code[ip]; ip += 1
                b = code[ip]; ip += 1
                stack.append(((a * a) & 0) | b)
            else:
                raise RuntimeError(f"bad opcode 0x{opcode:02X} at ip={ip-1}")
            if trace:
                print(f"[{steps:4}] ip={ip:3} op={NAMES.get(opcode,'?'):14} stack={stack}")
