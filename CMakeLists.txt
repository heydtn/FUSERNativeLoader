cmake_minimum_required(VERSION 3.20)

# FUSERNativeLoader: the FUSER mod loader (winhttp.dll proxy) with the fue reflection core and the FuserNative
# features built in. build.ps1 drives this and also packs FUSERNativeMods_P.pak; see README.md.
project(FUSERNativeLoader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FNL_DEBUG: the diagnostic build - a console with the loader's tracing, the F6-F10 debug keys and the probes.
option(FNL_DEBUG "Diagnostic build of winhttp.dll (console, debug keys, probes)" OFF)

add_library(FUSERNativeLoader SHARED
    src/dllmain.cpp
    src/fnl_entry.cpp
    src/unlocks.cpp
    src/fue/fue.cpp
    src/native/fusernative.cpp
    src/debug/unlock_probe.cpp
)
set_target_properties(FUSERNativeLoader PROPERTIES OUTPUT_NAME "winhttp")
target_include_directories(FUSERNativeLoader PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/lib")
target_link_libraries(FUSERNativeLoader PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib/funchook.lib")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" FNL_VERSION LIMIT_COUNT 1)
target_compile_definitions(FUSERNativeLoader PRIVATE UNICODE FNL_DEBUG=$<BOOL:${FNL_DEBUG}> FNL_VERSION="${FNL_VERSION}")
target_compile_options(FUSERNativeLoader PRIVATE /utf-8 /EHsc /Zi) # /Zi: a PDB for crash and stall stacks
target_link_options(FUSERNativeLoader PRIVATE /DEBUG /OPT:REF /OPT:ICF /IGNORE:4099) # 4099: the prebuilt funchook.lib has no PDB

# fue and the code on it are C++20 (std::format); the original loader source (dllmain.cpp) stays C++17.
set_source_files_properties(src/fnl_entry.cpp src/unlocks.cpp src/fue/fue.cpp src/native/fusernative.cpp src/debug/unlock_probe.cpp
                            PROPERTIES COMPILE_OPTIONS "/std:c++20")
