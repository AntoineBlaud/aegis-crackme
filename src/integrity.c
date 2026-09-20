#include "integrity.h"

uint32_t integrity_fnv1a(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 0x811C9DC5u; /* FNV-1a 32-bit offset basis */
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x01000193u; /* FNV prime */
    }
    return h;
}
