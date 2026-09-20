@echo off
REM Quick manual build with MSVC, no CMake. Run from a "x64 Native Tools
REM Command Prompt for VS" (or after calling vcvars64.bat) so cl.exe is
REM on PATH. Produces build\aegis.exe plus build\aegis.map (needed later
REM by VMProtect -- see vmprotect\README.md -- but NEVER distribute the
REM .map alongside a release build: it's a complete function-name/address
REM roadmap). /DEBUG:NONE explicitly guarantees no .pdb and no CodeView
REM debug-directory entry in the .exe, on top of not passing /Zi.
setlocal
if not exist build mkdir build
cl /nologo /W4 /std:c11 /O2 /I src ^
    src\main.c src\vm.c src\checkpoints.c src\trust.c src\antidebug.c src\integrity.c src\keycodec.c ^
    /Fe:build\aegis.exe /Fo:build\ ^
    /link /MAP:build\aegis.map /DEBUG:NONE
endlocal
