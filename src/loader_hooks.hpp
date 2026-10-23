#pragma once
// The byte-pattern search and funchook helpers in dllmain.cpp, for the loader's other source files.
#include <cstddef>
#include <cstdint>

// Searches the game exe, or the given range of it; nullptr when the pattern ("??" for any byte) isn't there
uint8_t *find_function(const char *name, const char *byteSequence);
uint8_t *find_function(const char *name, const char *byteSequence, uint8_t *start, size_t size);

struct HookRequest {
    void **target;
    void *hook;
};

// On success each target points at its original's trampoline. On failure none is installed, except when funchook
// fails partway through installing: any it installed stay, still calling their originals through the trampolines
bool setup_hook(const HookRequest *hooks, size_t count);
bool setup_hook(void **target, void *hook);
