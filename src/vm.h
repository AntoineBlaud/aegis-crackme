/*
 * Aegis VM -- tiny stack-based interpreter. This is a 1:1 port of the
 * reference interpreter in tools/vm.py: same opcodes, same semantics,
 * same memory model. The Python version is the spec (it was executed
 * and cross-checked against tools/proto.py's plain algorithm on 1000
 * random keys before a single byte of this file was written); this file
 * must stay behaviorally identical to it.
 */
#ifndef AEGIS_VM_H
#define AEGIS_VM_H

#include <stdint.h>
#include <stddef.h>

#define VM_STACK_MAX 32
#define VM_MEM_SIZE  32

enum {
    OP_HALT       = 0x00, /*                 result = pop() */
    OP_PUSH_CONST = 0x01, /* u8 idx          push consts[idx] */
    OP_PUSH_MEM32 = 0x02, /* u8 addr         push u32-le from mem[addr..addr+3] */
    OP_POP_MEM32  = 0x03, /* u8 addr         mem[addr..addr+3] = pop() as u32-le */
    OP_PUSH_MEM8  = 0x04, /* u8 addr         push zero-extended mem[addr] */
    OP_POP_MEM8   = 0x05, /* u8 addr         mem[addr] = pop() & 0xFF */
    OP_XOR        = 0x06, /*                 b=pop a=pop push a^b */
    OP_ADD        = 0x07, /*                 b=pop a=pop push (a+b) mod 2^32 */
    OP_MUL        = 0x08, /*                 b=pop a=pop push (a*b) mod 2^32 */
    OP_OR         = 0x09, /*                 b=pop a=pop push a|b */
    OP_ROL        = 0x0A, /* u8 n            a=pop push rotl32(a,n) */
    OP_SHR        = 0x0B, /* u8 n            a=pop push a>>n */
    OP_DUP        = 0x0C, /*                 push top of stack again */
    OP_SWAP32     = 0x0D, /* u8 a1,u8 a2     swap 4 bytes mem[a1..] <-> mem[a2..] */
    OP_JZ         = 0x0E, /* u16-le target   a=pop; if a==0: ip = target */
    OP_JMP        = 0x0F, /* u16-le target   ip = target */
    OP_NOP_JUNK   = 0x10  /* u8 a,u8 b       opaque predicate: push ((a*a)&0)|b -- always == b */
};

typedef struct {
    const uint32_t *consts;
    size_t          num_consts;
} vm_t;

/*
 * Runs `code` (length `code_len`) starting at ip=0, using `mem` (must be
 * VM_MEM_SIZE bytes, pre-loaded by the caller per whatever contract the
 * program expects) as scratch memory. On OP_HALT, writes the popped
 * result into *out_result and returns 0. Returns nonzero on a VM fault
 * (bad opcode, stack under/overflow, step limit exceeded, out-of-range
 * jump) -- a fault must never crash the host process, it's the VM's job
 * to fail closed.
 */
int vm_run(const vm_t *vm, const uint8_t *code, size_t code_len,
           uint8_t mem[VM_MEM_SIZE], uint32_t *out_result);

#endif /* AEGIS_VM_H */
