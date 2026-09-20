/*
 * The "trust accumulator" pattern this whole challenge is built around:
 * no checkpoint ever exits or branches visibly on failure. Each one
 * either leaves g_trust untouched (its condition was fine) or XORs in
 * its own poison constant (something was wrong). Only main(), at the
 * very end and nowhere else, compares g_trust to AEGIS_TRUST_INIT to
 * decide what to print.
 *
 * The point: patching the one `je`/`jne` you find at checkpoint N's call
 * site doesn't fix anything by itself, because the actual decision isn't
 * made there -- it's made later, once, against accumulated state. A
 * correct solve makes every checkpoint's REAL condition true (right key,
 * unmodified bytecode, no debugger attached); a patched solve has to find
 * and neutralize all four poison sites, not just one.
 */
#ifndef AEGIS_TRUST_H
#define AEGIS_TRUST_H

#include <stdint.h>

#define AEGIS_TRUST_INIT 0x5EED1234u

/* Poison constants -- each checkpoint owns exactly one of these and XORs
 * it into g_trust on failure. They're each other's inverse in the sense
 * that XOR-ing the SAME wrong one in twice cancels out -- deliberately,
 * since a checkpoint might run more than once in a more elaborate build;
 * this one only runs each checkpoint once, but the accumulator is built
 * to not assume that. */
#define AEGIS_POISON_FORMAT     0x9F3A1C55u
#define AEGIS_POISON_VM_MAC     0x2B77E081u
#define AEGIS_POISON_INTEGRITY  0x764DAA0Fu
#define AEGIS_POISON_ANTIDEBUG  0x11FE6C93u

extern volatile uint32_t g_trust;

void trust_poison(uint32_t poison);
int  trust_is_clean(void);

#endif /* AEGIS_TRUST_H */
