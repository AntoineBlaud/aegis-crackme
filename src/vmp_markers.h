/*
 * Seam for VMProtect SDK markers. This project never bundles or
 * fabricates VMProtectSDK.h -- that file belongs to your own VMProtect
 * installation and its exact contents/signatures should come from there,
 * not be guessed here.
 *
 * A build of this project protected with a real VMProtect (Ultra +
 * anti-debug/anti-VM/CRC checks) is published as a GitHub Release
 * alongside the plain build -- see the repo's Releases page. The
 * protection pipeline that produced it is not part of this repo.
 *
 * To build your own VMProtect-ready binary from source:
 *   1. Point at VMProtectSDK.h + VMProtectSDK32.lib/64.lib from your
 *      VMProtect install's SDK folder.
 *   2. Build with -DAEGIS_WITH_VMPROTECT (and optionally
 *      -DAEGIS_VMP_MUTATION or -DAEGIS_VMP_VIRTUALIZATION to pick a
 *      weaker level than the Ultra default -- see below).
 *   3. Enable /MAP (MSVC) so VMProtect can resolve function names/
 *      addresses -- CMakeLists.txt/build.bat already do this.
 *   4. Run VMProtect (GUI or VMProtectCon.exe) against the resulting
 *      .exe + .map, assigning the "CheckLicense" marker (and optionally
 *      individual checkpoint_* functions from the .map) a compilation
 *      type, plus whatever file-level Options (Pack, anti-debug, anti-VM,
 *      memory/CRC checks) you want on top.
 *
 * Without AEGIS_WITH_VMPROTECT (the default), these all compile to
 * nothing -- the crackme is fully self-contained and testable on its
 * own custom VM + anti-debug + integrity layers before VMProtect is
 * ever involved.
 */
#ifndef AEGIS_VMP_MARKERS_H
#define AEGIS_VMP_MARKERS_H

#ifdef AEGIS_WITH_VMPROTECT

#include <stdbool.h> /* VMProtectSDK.h declares bool-returning helpers; in a
                        C translation unit bool needs this (it's a C++
                        keyword otherwise), or the SDK header fails to
                        parse. */
#include "VMProtectSDK.h" /* from YOUR VMProtect install -- not provided here */

/* Protection LEVEL is a compile-time choice baked into which
 * VMProtectBegin* variant gets called -- listing it in the .vmp project
 * instead conflicts with VMProtect's own marker auto-detection ("Address
 * is already used by function"). One build per level via
 * /DAEGIS_VMP_MUTATION / /DAEGIS_VMP_VIRTUALIZATION / default (Ultra,
 * the strongest -- mutation then virtualization of the mutated result). */
#if defined(AEGIS_VMP_MUTATION)
#define AEGIS_VMP_BEGIN(name) VMProtectBeginMutation(name)
#elif defined(AEGIS_VMP_VIRTUALIZATION)
#define AEGIS_VMP_BEGIN(name) VMProtectBeginVirtualization(name)
#else
#define AEGIS_VMP_BEGIN(name) VMProtectBeginUltra(name)
#endif
#define AEGIS_VMP_END() VMProtectEnd()

#else

#define AEGIS_VMP_BEGIN(name) do { (void)(name); } while (0)
#define AEGIS_VMP_END()       do { } while (0)

#endif /* AEGIS_WITH_VMPROTECT */

#endif /* AEGIS_VMP_MARKERS_H */
