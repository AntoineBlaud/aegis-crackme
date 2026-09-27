cmake_minimum_required(VERSION 3.15)
project(aegis_crackme C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Default to a real release build: no debug info to strip in the first
# place, rather than relying on a later stripping step. A single-config
# generator (Ninja/NMake/Makefiles) honors this; a multi-config one
# (Visual Studio) ignores it and needs --config Release on the build line.
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(AEGIS_WITH_VMPROTECT "Include VMProtect SDK markers (needs your own VMProtectSDK.h/.lib -- see vmprotect/README.md)" OFF)
option(AEGIS_WITH_THEMIDA "Include Code Virtualizer/Themida SDK markers (needs your own VirtualizerSDK.h/.lib -- see themida/README.md)" OFF)

add_executable(aegis
    src/main.c
    src/vm.c
    src/checkpoints.c
    src/trust.c
    src/antidebug.c
    src/integrity.c
    src/keycodec.c
)

target_include_directories(aegis PRIVATE src)

if (MSVC)
    target_compile_options(aegis PRIVATE /W4)
    # /MAP: VMProtect (or any post-build tool that resolves functions by
    # name/address) needs this to find marker-delimited regions -- but
    # that file itself is a complete function-name/address roadmap, so it
    # must never ship with a release build (see README "stripping").
    # /DEBUG:NONE: explicit, rather than relying on the absence of /Zi --
    # guarantees no .pdb and no CodeView debug-directory entry in the
    # final .exe, matching VMProtect's own cpStripDebugInfo for the
    # protected build.
    target_link_options(aegis PRIVATE /MAP /DEBUG:NONE)
else()
    target_compile_options(aegis PRIVATE -Wall -Wextra)
    # -s strips the symbol table and relocation info from the final
    # binary at link time (GNU ld/gold; harmless no-op-equivalent if the
    # linker doesn't recognize it, but both ld and lld do).
    target_link_options(aegis PRIVATE -s)
endif()

if (AEGIS_WITH_VMPROTECT)
    target_compile_definitions(aegis PRIVATE AEGIS_WITH_VMPROTECT)
    if (DEFINED VMPROTECT_SDK_DIR)
        target_include_directories(aegis PRIVATE "${VMPROTECT_SDK_DIR}")
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_libraries(aegis PRIVATE "${VMPROTECT_SDK_DIR}/VMProtectSDK64.lib")
        else()
            target_link_libraries(aegis PRIVATE "${VMPROTECT_SDK_DIR}/VMProtectSDK32.lib")
        endif()
    else()
        message(WARNING
            "AEGIS_WITH_VMPROTECT is ON but VMPROTECT_SDK_DIR is not set -- "
            "pass -DVMPROTECT_SDK_DIR=\"C:/path/to/VMProtect/SDK/C\" "
            "(the folder containing VMProtectSDK.h and the .lib files from "
            "your own VMProtect install). See vmprotect/README.md.")
    endif()
endif()

if (AEGIS_WITH_THEMIDA)
    target_compile_definitions(aegis PRIVATE AEGIS_WITH_THEMIDA)
    if (DEFINED THEMIDA_SDK_INCLUDE_DIR AND DEFINED THEMIDA_SDK_LIB_DIR)
        target_include_directories(aegis PRIVATE "${THEMIDA_SDK_INCLUDE_DIR}")
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_libraries(aegis PRIVATE "${THEMIDA_SDK_LIB_DIR}/VirtualizerSDK64.lib")
        else()
            target_link_libraries(aegis PRIVATE "${THEMIDA_SDK_LIB_DIR}/VirtualizerSDK32.lib")
        endif()
    else()
        message(WARNING
            "AEGIS_WITH_THEMIDA is ON but THEMIDA_SDK_INCLUDE_DIR/"
            "THEMIDA_SDK_LIB_DIR are not set -- pass "
            "-DTHEMIDA_SDK_INCLUDE_DIR=\"C:/path/to/VirtualizerDemo/Include/C\" "
            "-DTHEMIDA_SDK_LIB_DIR=\"C:/path/to/VirtualizerDemo/Lib/x86_x64/windows/COFF\" "
            "(from your own Code Virtualizer / Themida install). See "
            "themida/README.md.")
    endif()
endif()
