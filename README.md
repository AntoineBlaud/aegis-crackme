# Aegis — an educational, Denuvo-shaped license crackme

Aegis is a small, self-contained Windows CLI program that checks a license
key. It exists purely as a **reverse-engineering practice target** — for
testing an in-house tracer (Protovision) and MCP-driven reversing agents
against something that borrows the *structural* tricks commercial
protectors (Denuvo, VMProtect, Themida) are publicly known to use, without
reproducing any of their actual proprietary code — that's neither possible
(they're closed-source) nor the point. The point is the technique
*categories*, which are all independently documented in public
reverse-engineering literature:

- the real check logic runs inside a small **custom bytecode VM**, not as
  native x86 — a debugger/disassembler sees a dispatch loop, not the
  algorithm;
- **four independent checkpoints** (format, the real VM-executed MAC,
  self-integrity, anti-debug), each of which silently perturbs a shared
  "trust" accumulator on failure instead of branching visibly — patching
  the one `je` you find at a call site doesn't fix anything by itself;
- a **self-integrity check** over the VM's own bytecode/constant pool, so
  naive byte-patching of the check logic is itself detected — and the
  failure shows up later, far from the patch;
- **layered anti-debug** (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
  manual PEB reads, a timing check), each poisoning silently rather than
  exiting;
- an **indirect call table** for the four checkpoints, so patching a direct
  call instruction at one obvious site doesn't disable anything;
- optionally, a **second, real, commercial protection layer on top** via
  VMProtect (Ultra + anti-debug/anti-VM/CRC checks) — a pre-built
  protected binary is published on this repo's Releases page, the actual
  target once the custom VM layer is understood being the *combination*.

This is a **keygen-me**, not a single-serial crackme: a valid key is a
5-byte "serial" (your free choice — any 5 bytes) plus a 3-byte MAC of that
serial under a hidden keyed Feistel construction. There isn't one magic
unlock string; there's an algorithm, and the goal is to recover it well
enough to produce valid keys for *any* serial, the same way a real keygen
works against a real license scheme.

## Prebuilt binaries

The Releases page has two ready-to-run Windows builds:
- **plain** — the crackme on its own, no VMProtect.
- **vmprotect** — the same program run through a real VMProtect (Ultra
  virtualization on the `CheckLicense` marker, plus its own anti-debug/
  anti-VM/memory-CRC checks) — a realistic two-layer target.

## Building from source

Requires a C99 compiler. No third-party dependencies for the plain build.

```
cmake -B build -S .
cmake --build build
```

or, with MSVC directly from a "x64 Native Tools Command Prompt for VS":

```
build.bat
```

Both produce `build/aegis.exe` and a `.map` file (needed if you want to
protect the binary with VMProtect yourself — see `src/vmp_markers.h` for
how the SDK markers are wired in; the pipeline that produced the released
`vmprotect` build isn't part of this repo).

**Stripping.** Both build paths produce a release-mode binary with no
embedded debug symbols by default: no `/Zi` on the compile line means no
`.pdb` is even generated, and the explicit `/DEBUG:NONE` link flag (GCC/
clang: `-s`) guarantees no CodeView debug-directory entry survives in the
`.exe` either. The one file that *does* still carry every function name
and address is `build/aegis.map` — required input if you run this through
VMProtect (or any similar tool) yourself, not something to ship. **Never
distribute `aegis.map`, or an unprotected `aegis.exe`, alongside a
"protected" build** — both are already covered by `.gitignore`.

## Using it

```
aegis.exe AEGIS-XXXX-XXXX-XXXX-XXXX
```

Prints `License accepted.` and exits 0 on a valid key; `Invalid license.`
and exits 1 otherwise — deliberately the same generic message regardless
of *which* checkpoint(s) failed.

`aegis.exe --dump-checksums` prints the FNV-1a checksums of the currently
compiled-in bytecode/constant pool — see "Regenerating the bytecode" below.

## What's deliberately left easy

This is a teaching target, calibrated to be solvable, not a genuine
commercial-grade protector:

- The round function (`rotl` → multiply by an odd constant → xor-shift) is
  a simple, custom mixing function, explicitly **not** claimed to be
  cryptographically secure — the skill being exercised is control-flow and
  VM reversing, not cryptanalysis of a hardened cipher.
- The VM's instruction set is small (~14 opcodes) and every opcode is
  orthogonal (does exactly one thing) — real commercial VMs use hundreds of
  handlers with compound, overlapping semantics specifically to slow this
  step down; this one doesn't.
- The key schedule (subkeys ← master key) runs host-side, not inside the
  VM — only the 8 already-expanded round subkeys are baked into the
  constant pool. Recovering those 8 constants from the binary is enough to
  build a keygen; recovering the master key itself is a bonus, not
  required.
- The anti-debug timing check has a generous threshold and will not
  reliably catch a DBI tool running the target at full speed with only
  occasional callbacks — that's a fundamentally different (and harder)
  detection problem than catching interactive single-stepping, and this
  challenge doesn't attempt it.

## Project layout

```
src/                    the C program
  vm.h / vm.c              bytecode interpreter (ported 1:1 from tools/vm.py)
  bytecode_license.h       generated: the actual check program + constant pool
  checkpoints.h / .c       the four checkpoints
  trust.h / .c             the shared trust accumulator
  antidebug.h / .c         Windows-primary, best-effort Linux fallback
  integrity.h / .c         FNV-1a self-checksum
  keycodec.h / .c          "AEGIS-XXXX-XXXX-XXXX-XXXX" <-> 8 raw bytes
  vmp_markers.h            VMProtect SDK marker seam (no-op without VMProtect)
  main.c                   entry point, checkpoint dispatch, final gate
tools/                  Python reference implementation + build tooling
  proto.py                 the algorithm in plain Python (the spec)
  vm.py                    reference VM interpreter + assembler
  build_bytecode.py        assembles src/bytecode_license.h's arrays,
                            verifies them against proto.py on 1000 keys
  keygen.py                reference key generator (see note below)
```

`tools/keygen.py` and `SOLUTION_NOTES.md` contain the full algorithm and
working test keys — everything you'd need to solve this without reversing
a thing. They're included here for reference/verification, not hidden,
so **if you want to attempt this blind, stop reading here** and don't
open either of those.

## Regenerating the bytecode

If you change the algorithm (extra rounds, a different round function,
more junk instructions), the checked-in `src/bytecode_license.h` and the
two constants in `src/integrity.h` go stale together:

```
python tools/build_bytecode.py     # re-verifies against proto.py, prints new C arrays
# paste the new g_aegis_consts / g_aegis_bytecode into src/bytecode_license.h
cmake --build build
./build/aegis.exe --dump-checksums # prints the two new checksums
# paste those into src/integrity.h
cmake --build build                # final rebuild with correct checksums
```
