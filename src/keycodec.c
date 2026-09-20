#include "keycodec.h"
#include <string.h>
#include <ctype.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int keycodec_parse(const char *text, uint8_t out[8]) {
    char digits[16];
    size_t n = 0;
    size_t i;
    const char *p = text;

    if (p == NULL) return -1;

    /* skip leading/trailing whitespace by only ever consuming
     * dash/hex/prefix characters below; anything else (including
     * whitespace) is rejected once we hit the digit-count check, except
     * we explicitly skip a leading run of spaces/tabs first so
     * " AEGIS-...\n" still parses like the Python strip() would. */
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    if ((p[0] == 'A' || p[0] == 'a') && (p[1] == 'E' || p[1] == 'e') &&
        (p[2] == 'G' || p[2] == 'g') && (p[3] == 'I' || p[3] == 'i') &&
        (p[4] == 'S' || p[4] == 's') && p[5] == '-') {
        p += 6;
    }

    for (; *p != '\0'; p++) {
        char c = *p;
        if (c == '-') continue;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break; /* trailing whitespace: stop */
        if (n >= 16) return -1; /* too many hex digits */
        digits[n++] = c;
    }

    /* anything left after trailing whitespace must itself be whitespace */
    for (; *p != '\0'; p++) {
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return -1;
    }

    if (n != 16) return -1;

    for (i = 0; i < 8; i++) {
        int hi = hex_nibble(digits[i * 2]);
        int lo = hex_nibble(digits[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}
