/*
 * Aegis -- an educational crackme in the shape of a commercial software
 * protector's license check. See README.md for the full brief; short
 * version: validate a key of the form AEGIS-XXXX-XXXX-XXXX-XXXX, where
 * the license logic itself runs inside a small custom bytecode VM
 * (bytecode_license.h / vm.c) instead of as native code, four
 * independent checkpoints (format, the real VM-executed check,
 * self-integrity, anti-debug) each silently poison a shared trust
 * accumulator on failure instead of branching visibly (trust.h), and the
 * pass/fail decision is made exactly once, at the very end, nowhere
 * near any of the checks themselves.
 *
 * This binary is meant to be built once as-is, then optionally run
 * through VMProtect or Themida/Code Virtualizer for an additional, real
 * commercial-grade layer on top (see src/vmp_markers.h and
 * src/themida_markers.h; a pre-built VMProtect release is on this repo's
 * Releases page) -- the combination is the actual target: reverse the
 * custom VM first, then the commercial one.
 */
#include <stdio.h>
#include <string.h>

#include "checkpoints.h"
#include "trust.h"
#include "keycodec.h"
#include "integrity.h"
#include "bytecode_license.h"
#include "vmp_markers.h"
#include "themida_markers.h"

typedef void (*checkpoint_fn)(void);

/* Indirect dispatch: patching a direct `call checkpoint_vm_mac` instruction
 * at its one call site doesn't help if the call is actually an indirect
 * load-and-call through this table -- and the table itself is inside the
 * region checkpoint_integrity() (indirectly) vouches for the shape of via
 * the bytecode/consts checksums, since a build that ships a different
 * checkpoint set would also need different expected sums. */
static const checkpoint_fn g_checkpoints[4] = {
    checkpoint_format,
    checkpoint_vm_mac,
    checkpoint_integrity,
    checkpoint_antidebug,
};

/* noinline: called from exactly one site today, but /O2 cloning this into
 * more than one compiled copy would emit the "CheckLicense" marker twice,
 * which VMProtect rejects outright ("Address is already used by
 * function") -- the same guard target.c's hot() uses, for the same
 * reason. Cheap to keep even though there's only one call site now. */
#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_all_checkpoints(void) {
    size_t i;
    AEGIS_VMP_BEGIN("CheckLicense");
    AEGIS_THEMIDA_BEGIN("CheckLicense");
    for (i = 0; i < sizeof(g_checkpoints) / sizeof(g_checkpoints[0]); i++) {
        g_checkpoints[i]();
    }
    AEGIS_THEMIDA_END();
    AEGIS_VMP_END();
}

static void print_usage(const char *argv0) {
    printf("usage: %s <LICENSE-KEY>\n", argv0);
    printf("       %s --dump-checksums\n", argv0);
    printf("\n");
    printf("  key format: AEGIS-XXXX-XXXX-XXXX-XXXX  (16 hex digits)\n");
}

static void dump_checksums(void) {
    uint32_t bc_sum = integrity_fnv1a(g_aegis_bytecode, g_aegis_bytecode_len);
    uint32_t co_sum = integrity_fnv1a(g_aegis_consts, sizeof(g_aegis_consts));
    printf("bytecode checksum: 0x%08X\n", (unsigned)bc_sum);
    printf("consts   checksum: 0x%08X\n", (unsigned)co_sum);
    printf("\n");
    printf("paste these into AEGIS_EXPECTED_BYTECODE_CHECKSUM /\n");
    printf("AEGIS_EXPECTED_CONSTS_CHECKSUM in src/integrity.h, then rebuild.\n");
}

int main(int argc, char **argv) {
    int parse_ok;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--dump-checksums") == 0) {
        dump_checksums();
        return 0;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    g_key_text = argv[1];
    parse_ok = (keycodec_parse(g_key_text, g_key_bytes) == 0);
    if (!parse_ok) {
        memset(g_key_bytes, 0, sizeof(g_key_bytes));
    }

    run_all_checkpoints();

    if (trust_is_clean()) {
        printf("License accepted.\n");
        printf("Welcome. Aegis is now unlocked for this session.\n");
        return 0;
    }

    printf("Invalid license.\n");
    return 1;
}
