#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// We implement these exports rather than importing them from winhttp.lib.
#define _WINHTTP_INTERNAL_
#include <winhttp.h>
#undef _WINHTTP_INTERNAL_

namespace
{
    decltype(&WinHttpGetProxyForUrlEx2) g_get_proxy_for_url_ex2 = nullptr;
    decltype(&WinHttpGetProxyResultEx) g_get_proxy_result_ex = nullptr;
    decltype(&WinHttpFreeProxyResultEx) g_free_proxy_result_ex = nullptr;
}

// Called during process attach with the same full-path System32 module that
// supplies the existing exports. These pointers are immutable after startup.
void load_extended_winhttp_functions(HMODULE dll)
{
    g_get_proxy_for_url_ex2 = reinterpret_cast<decltype(g_get_proxy_for_url_ex2)>(GetProcAddress(dll, "WinHttpGetProxyForUrlEx2"));
    g_get_proxy_result_ex = reinterpret_cast<decltype(g_get_proxy_result_ex)>(GetProcAddress(dll, "WinHttpGetProxyResultEx"));
    g_free_proxy_result_ex = reinterpret_cast<decltype(g_free_proxy_result_ex)>(GetProcAddress(dll, "WinHttpFreeProxyResultEx"));
}

// CMake's WINDOWS_EXPORT_ALL_SYMBOLS exports these C names; leaving the
// declarations undecorated also matches the SDK's non-import declarations.
extern "C" DWORD WINAPI WinHttpGetProxyForUrlEx2(
    HINTERNET resolver, PCWSTR url, WINHTTP_AUTOPROXY_OPTIONS* options,
    DWORD selection_size, BYTE* selection, DWORD_PTR context)
{
    if (g_get_proxy_for_url_ex2)
        return g_get_proxy_for_url_ex2(resolver, url, options, selection_size, selection, context);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return ERROR_PROC_NOT_FOUND;
}

extern "C" DWORD WINAPI WinHttpGetProxyResultEx(
    HINTERNET resolver, WINHTTP_PROXY_RESULT_EX* result)
{
    if (g_get_proxy_result_ex) return g_get_proxy_result_ex(resolver, result);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return ERROR_PROC_NOT_FOUND;
}

extern "C" VOID WINAPI WinHttpFreeProxyResultEx(WINHTTP_PROXY_RESULT_EX* result)
{
    if (g_free_proxy_result_ex)
    {
        // The real DLL owns the result allocations and must also free them.
        g_free_proxy_result_ex(result);
        return;
    }
    SetLastError(ERROR_PROC_NOT_FOUND);
}
