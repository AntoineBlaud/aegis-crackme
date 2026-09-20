/*
 * FNV-1a checksums over the VM's own bytecode/constant-pool arrays, used
 * to detect byte-patching of the check logic itself (not just a wrong
 * answer from it). See checkpoints.c: a mismatch here does NOT abort on
 * the spot -- it silently poisons the trust accumulator, so the visible
 * failure (if any) shows up far from the actual patch site.
 *
 * The expected constants below come from `aegis --dump-checksums` (always
 * available, no special build needed) run against a build whose bytecode
 * you trust, with the two printed values pasted in here. This mirrors how
 * real protected builds bake integrity hashes in as a post-build step
 * rather than hand-deriving them.
 */
#ifndef AEGIS_INTEGRITY_H
#define AEGIS_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

uint32_t integrity_fnv1a(const void *data, size_t len);

/*
 * Computed by tools/build_bytecode.py's checksum helper (FNV-1a over
 * g_aegis_bytecode as-is, and over g_aegis_consts packed little-endian --
 * see that script) for the exact arrays currently in bytecode_license.h.
 * If you regenerate that file (a different algorithm, different junk
 * bytes, an extra round, anything), these TWO values must be
 * recomputed too, or checkpoint_integrity() will always poison trust.
 * Run `aegis --dump-checksums` and paste the two printed values back in
 * here, then rebuild.
 */
#define AEGIS_EXPECTED_BYTECODE_CHECKSUM 0xFD20FF1Fu
#define AEGIS_EXPECTED_CONSTS_CHECKSUM   0x18C991CDu

#endif /* AEGIS_INTEGRITY_H */
