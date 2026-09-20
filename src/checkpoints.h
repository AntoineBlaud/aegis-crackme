/*
 * The four checkpoints. Each takes whatever state it needs from the
 * globals set up once in main() and pokes trust_poison() on failure --
 * none of them return a pass/fail value, deliberately: there is no
 * single branch anywhere in this program that means "the license is
 * bad," which is the entire point of the exercise (see trust.h).
 */
#ifndef AEGIS_CHECKPOINTS_H
#define AEGIS_CHECKPOINTS_H

#include <stdint.h>

/* Set once by main() before running any checkpoint. */
extern const char *g_key_text;   /* raw argv[1], NUL-terminated */
extern uint8_t      g_key_bytes[8]; /* parsed bytes, or all-zero if parsing failed */

void checkpoint_format(void);     /* decoy: strict "AEGIS-XXXX-XXXX-XXXX-XXXX" shape check */
void checkpoint_vm_mac(void);     /* real check: runs the VM, verifies the Feistel MAC */
void checkpoint_integrity(void);  /* verifies the VM's own bytecode/consts weren't patched */
void checkpoint_antidebug(void);  /* thin wrapper around antidebug_run_all() */

#endif /* AEGIS_CHECKPOINTS_H */
