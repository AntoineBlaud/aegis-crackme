#include "trust.h"

volatile uint32_t g_trust = AEGIS_TRUST_INIT;

void trust_poison(uint32_t poison) {
    g_trust ^= poison;
}

int trust_is_clean(void) {
    return g_trust == AEGIS_TRUST_INIT;
}
