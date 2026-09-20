/*
 * Anti-debug checks. Each sub-check is independent and silent: it does
 * NOT return a bool for the caller to branch on (that branch would be
 * the obvious patch site). Instead it pokes trust_poison() directly if
 * it thinks something is off. Call antidebug_run_all() once; look at
 * g_trust (via trust.h), if at all, only much later.
 *
 * Windows checks are the primary, fully-implemented target (this
 * challenge is meant to be traced by a Windows-focused DBI tool). A
 * best-effort Linux path exists for convenience when building/testing
 * off-Windows; see antidebug.c for its documented side effect. On any
 * other platform this is a silent no-op -- the VM/integrity checkpoints
 * still work standalone.
 */
#ifndef AEGIS_ANTIDEBUG_H
#define AEGIS_ANTIDEBUG_H

void antidebug_run_all(void);

#endif /* AEGIS_ANTIDEBUG_H */
