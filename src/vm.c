#include "vm.h"

#define VM_STEP_LIMIT 100000u

typedef struct {
    uint32_t data[VM_STACK_MAX];
    size_t   top; /* number of valid entries */
} vm_stack_t;

static int stack_push(vm_stack_t *s, uint32_t v) {
    if (s->top >= VM_STACK_MAX) return -1;
    s->data[s->top++] = v;
    return 0;
}

static int stack_pop(vm_stack_t *s, uint32_t *out) {
    if (s->top == 0) return -1;
    *out = s->data[--s->top];
    return 0;
}

static uint32_t rotl32(uint32_t x, unsigned n) {
    n &= 31u;
    if (n == 0) return x;
    return (uint32_t)((x << n) | (x >> (32u - n)));
}

static uint32_t read_u32le(const uint8_t *mem, unsigned addr) {
    return (uint32_t)mem[addr]
         | ((uint32_t)mem[addr + 1] << 8)
         | ((uint32_t)mem[addr + 2] << 16)
         | ((uint32_t)mem[addr + 3] << 24);
}

static void write_u32le(uint8_t *mem, unsigned addr, uint32_t v) {
    mem[addr]     = (uint8_t)(v & 0xFFu);
    mem[addr + 1] = (uint8_t)((v >> 8) & 0xFFu);
    mem[addr + 2] = (uint8_t)((v >> 16) & 0xFFu);
    mem[addr + 3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* addr must leave room for `width` bytes inside VM_MEM_SIZE */
static int mem_addr_ok(unsigned addr, unsigned width) {
    return addr + width <= VM_MEM_SIZE;
}

int vm_run(const vm_t *vm, const uint8_t *code, size_t code_len,
           uint8_t mem[VM_MEM_SIZE], uint32_t *out_result) {
    vm_stack_t stack;
    size_t ip = 0;
    uint32_t steps = 0;

    stack.top = 0;

    for (;;) {
        uint8_t opcode;
        uint32_t a, b;

        if (++steps > VM_STEP_LIMIT) return -1;
        if (ip >= code_len) return -1;

        opcode = code[ip++];

        switch (opcode) {
        case OP_HALT: {
            uint32_t result;
            if (stack_pop(&stack, &result) != 0) return -1;
            *out_result = result;
            return 0;
        }

        case OP_PUSH_CONST: {
            uint8_t idx;
            if (ip >= code_len) return -1;
            idx = code[ip++];
            if (idx >= vm->num_consts) return -1;
            if (stack_push(&stack, vm->consts[idx]) != 0) return -1;
            break;
        }

        case OP_PUSH_MEM32: {
            uint8_t addr;
            if (ip >= code_len) return -1;
            addr = code[ip++];
            if (!mem_addr_ok(addr, 4)) return -1;
            if (stack_push(&stack, read_u32le(mem, addr)) != 0) return -1;
            break;
        }

        case OP_POP_MEM32: {
            uint8_t addr;
            if (ip >= code_len) return -1;
            addr = code[ip++];
            if (!mem_addr_ok(addr, 4)) return -1;
            if (stack_pop(&stack, &a) != 0) return -1;
            write_u32le(mem, addr, a);
            break;
        }

        case OP_PUSH_MEM8: {
            uint8_t addr;
            if (ip >= code_len) return -1;
            addr = code[ip++];
            if (!mem_addr_ok(addr, 1)) return -1;
            if (stack_push(&stack, mem[addr]) != 0) return -1;
            break;
        }

        case OP_POP_MEM8: {
            uint8_t addr;
            if (ip >= code_len) return -1;
            addr = code[ip++];
            if (!mem_addr_ok(addr, 1)) return -1;
            if (stack_pop(&stack, &a) != 0) return -1;
            mem[addr] = (uint8_t)(a & 0xFFu);
            break;
        }

        case OP_XOR:
            if (stack_pop(&stack, &b) != 0) return -1;
            if (stack_pop(&stack, &a) != 0) return -1;
            if (stack_push(&stack, a ^ b) != 0) return -1;
            break;

        case OP_ADD:
            if (stack_pop(&stack, &b) != 0) return -1;
            if (stack_pop(&stack, &a) != 0) return -1;
            if (stack_push(&stack, (uint32_t)(a + b)) != 0) return -1;
            break;

        case OP_MUL:
            if (stack_pop(&stack, &b) != 0) return -1;
            if (stack_pop(&stack, &a) != 0) return -1;
            if (stack_push(&stack, (uint32_t)(a * b)) != 0) return -1;
            break;

        case OP_OR:
            if (stack_pop(&stack, &b) != 0) return -1;
            if (stack_pop(&stack, &a) != 0) return -1;
            if (stack_push(&stack, a | b) != 0) return -1;
            break;

        case OP_ROL: {
            uint8_t n;
            if (ip >= code_len) return -1;
            n = code[ip++];
            if (stack_pop(&stack, &a) != 0) return -1;
            if (stack_push(&stack, rotl32(a, n)) != 0) return -1;
            break;
        }

        case OP_SHR: {
            uint8_t n;
            if (ip >= code_len) return -1;
            n = code[ip++];
            if (stack_pop(&stack, &a) != 0) return -1;
            if (stack_push(&stack, (n >= 32) ? 0u : (a >> n)) != 0) return -1;
            break;
        }

        case OP_DUP:
            if (stack.top == 0) return -1;
            if (stack_push(&stack, stack.data[stack.top - 1]) != 0) return -1;
            break;

        case OP_SWAP32: {
            uint8_t a1, a2, i;
            if (ip + 1 >= code_len) return -1;
            a1 = code[ip++];
            a2 = code[ip++];
            if (!mem_addr_ok(a1, 4) || !mem_addr_ok(a2, 4)) return -1;
            for (i = 0; i < 4; i++) {
                uint8_t t = mem[a1 + i];
                mem[a1 + i] = mem[a2 + i];
                mem[a2 + i] = t;
            }
            break;
        }

        case OP_JZ: {
            unsigned target;
            if (ip + 1 >= code_len) return -1;
            target = (unsigned)code[ip] | ((unsigned)code[ip + 1] << 8);
            ip += 2;
            if (stack_pop(&stack, &a) != 0) return -1;
            if (a == 0) {
                if (target >= code_len) return -1;
                ip = target;
            }
            break;
        }

        case OP_JMP: {
            unsigned target;
            if (ip + 1 >= code_len) return -1;
            target = (unsigned)code[ip] | ((unsigned)code[ip + 1] << 8);
            if (target >= code_len) return -1;
            ip = target;
            break;
        }

        case OP_NOP_JUNK: {
            uint8_t ja, jb;
            if (ip + 1 >= code_len) return -1;
            ja = code[ip++];
            jb = code[ip++];
            (void)ja;
            if (stack_push(&stack, (uint32_t)jb) != 0) return -1;
            break;
        }

        default:
            return -1;
        }
    }
}
