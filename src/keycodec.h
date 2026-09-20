/*
 * Decodes a license-key string "AEGIS-XXXX-XXXX-XXXX-XXXX" (16 hex
 * digits, case-insensitive, dashes optional/ignored) into 8 raw bytes.
 * Mirrors tools/proto.py's parse_key() exactly -- keep both in sync.
 */
#ifndef AEGIS_KEYCODEC_H
#define AEGIS_KEYCODEC_H

#include <stdint.h>

/* Returns 0 and fills out[8] on success. Returns -1 on malformed input
 * (wrong digit count after stripping dashes/prefix, or a non-hex
 * character) -- never reads or writes past the buffers it's given. */
int keycodec_parse(const char *text, uint8_t out[8]);

#endif /* AEGIS_KEYCODEC_H */
