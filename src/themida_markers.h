/*
 * Seam for Code Virtualizer / Themida SDK markers. This project never
 * bundles or fabricates VirtualizerSDK.h -- that file belongs to your own
 * Code Virtualizer / Themida installation and its exact contents/
 * signatures should come from there, not be guessed here.
 *
 * This mirrors src/vmp_markers.h exactly, but for Oreans's other SDK.
 * The two are mutually exclusive per build: AEGIS_WITH_VMPROTECT and
 * AEGIS_WITH_THEMIDA are never defined in the same compile, since each
 * links a different SDK .lib and Code Virtualizer's project format
 * targets *unnamed* marker regions (by source order / address) rather
 * than VMProtect's named VMProtectBeginUltra("CheckLicense") style --
 * see run_all_checkpoints() in main.c, which wraps its one call site in
 * whichever pair happens to be active.
 *
 * To build your own Themida-ready binary from source:
 *   1. Point at VirtualizerSDK.h + VirtualizerSDK32.lib/64.lib from your
 *      Code Virtualizer / Themida install's SDK folder (Include/C and
 *      Lib/x86_x64/windows/COFF in a VirtualizerDemo-style checkout).
 *   2. Build with -DAEGIS_WITH_THEMIDA.
 *   3. Enable /MAP (MSVC) so the project file's "MAP File" input can
 *      resolve function names/addresses -- CMakeLists.txt/build.bat
 *      already do this.
 *   4. Run Virtualizer.exe (GUI, to build/save a .cvp project the first
 *      time) or its CLI (`Virtualizer /protect proj.cvp /inputfile in.exe
 *      /outputfile out.exe`) against the resulting .exe -- see
 *      themida/README.md.
 *
 * Without AEGIS_WITH_THEMIDA (the default), these all compile to nothing
 * -- the crackme is fully self-contained and testable on its own custom
 * VM + anti-debug + integrity layers before Themida is ever involved.
 */
#ifndef AEGIS_THEMIDA_MARKERS_H
#define AEGIS_THEMIDA_MARKERS_H

#ifdef AEGIS_WITH_THEMIDA

#include "VirtualizerSDK.h" /* from YOUR Code Virtualizer / Themida install -- not provided here */

/* Unlike VMProtect's named VMProtectBeginUltra(name), Code Virtualizer's
 * markers take no argument -- the region is whatever's between
 * VirtualizerStart() and VirtualizerEnd() in this translation unit, and
 * the project file resolves it by address via the .map, not by a string
 * name. The `name` parameter here is kept only so call sites can stay
 * textually identical to the VMProtect seam. */
#define AEGIS_THEMIDA_BEGIN(name) do { (void)(name); VirtualizerStart(); } while (0)
#define AEGIS_THEMIDA_END()       VirtualizerEnd()

#else

#define AEGIS_THEMIDA_BEGIN(name) do { (void)(name); } while (0)
#define AEGIS_THEMIDA_END()       do { } while (0)

#endif /* AEGIS_WITH_THEMIDA */

#endif /* AEGIS_THEMIDA_MARKERS_H */
