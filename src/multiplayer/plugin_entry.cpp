#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

auto host_hook_start() -> void;

extern "C" __declspec(dllexport) bool fnl_multiplayer_start(unsigned int api_version)
{
    if (api_version != 1) return false;
    host_hook_start();
    return true;
}
