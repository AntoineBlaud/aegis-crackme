#include "checkpoints.h"
#include "trust.h"
#include "vm.h"
#include "bytecode_license.h"
#include "integrity.h"
#include "antidebug.h"
#include <string.h>

const char *g_key_text = "";
uint8_t g_key_bytes[8];

static int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Decoy: an obvious, easily-patched shape check. Deliberately written as
 * a flat sequence any disassembler renders legibly -- someone who finds
 * and neutralizes only this one will still fail checkpoint_vm_mac. */
void checkpoint_format(void) {
    const char *s = g_key_text;
    size_t len = strlen(s);
    int ok = 1;
    size_t i;

    /* "AEGIS-XXXX-XXXX-XXXX-XXXX" is 6 + 4 + 1 + 4 + 1 + 4 + 1 + 4 = 25 chars. */
    if (len != 25) {
        ok = 0;
    } else {
        static const char prefix[6] = { 'A', 'E', 'G', 'I', 'S', '-' };
        for (i = 0; i < 6; i++) {
            char c = s[i];
            if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
            if (c != prefix[i]) { ok = 0; break; }
        }
        if (ok) {
            static const int dash_at[3] = { 10, 15, 20 };
            for (i = 0; i < 3; i++) {
                if (s[(size_t)dash_at[i]] != '-') { ok = 0; break; }
            }
        }
        if (ok) {
            size_t groups[4] = { 6, 11, 16, 21 };
            size_t g, j;
            for (g = 0; g < 4 && ok; g++) {
                for (j = 0; j < 4; j++) {
                    if (!is_hex_digit(s[groups[g] + j])) { ok = 0; break; }
                }
            }
        }
    }

    if (!ok) {
        trust_poison(AEGIS_POISON_FORMAT);
    }
}

void checkpoint_vm_mac(void) {
    vm_t vm;
    uint8_t mem[VM_MEM_SIZE];
    uint32_t result = 0;

    vm.consts = g_aegis_consts;
    vm.num_consts = g_aegis_num_consts;

    memset(mem, 0, sizeof(mem));
    mem[AEGIS_MEM_L + 0] = g_key_bytes[0];
    mem[AEGIS_MEM_L + 1] = g_key_bytes[1];
    mem[AEGIS_MEM_L + 2] = g_key_bytes[2];
    mem[AEGIS_MEM_L + 3] = g_key_bytes[3];
    mem[AEGIS_MEM_R + 0] = g_key_bytes[4];
    /* mem[AEGIS_MEM_R+1..3] already 0 from memset -- matches the
     * zero-padded check field in the block the MAC is defined over */
    mem[AEGIS_MEM_GIVEN_CHECK + 0] = g_key_bytes[5];
    mem[AEGIS_MEM_GIVEN_CHECK + 1] = g_key_bytes[6];
    mem[AEGIS_MEM_GIVEN_CHECK + 2] = g_key_bytes[7];

    if (vm_run(&vm, g_aegis_bytecode, g_aegis_bytecode_len, mem, &result) != 0) {
        /* a VM fault (shouldn't happen with well-formed bytecode+mem) is
         * treated the same as a wrong answer -- fail closed, not open */
        trust_poison(AEGIS_POISON_VM_MAC);
        return;
    }
    if (result != 1u) {
        trust_poison(AEGIS_POISON_VM_MAC);
    }
}

void checkpoint_integrity(void) {
    uint32_t bc_sum = integrity_fnv1a(g_aegis_bytecode, g_aegis_bytecode_len);
    uint32_t co_sum = integrity_fnv1a(g_aegis_consts, sizeof(g_aegis_consts));

    if (bc_sum != AEGIS_EXPECTED_BYTECODE_CHECKSUM) {
        trust_poison(AEGIS_POISON_INTEGRITY);
    }
    if (co_sum != AEGIS_EXPECTED_CONSTS_CHECKSUM) {
        trust_poison(AEGIS_POISON_INTEGRITY);
    }
}

void checkpoint_antidebug(void) {
    antidebug_run_all(); /* pokes trust_poison(AEGIS_POISON_ANTIDEBUG) itself */
}
