#pragma once
#include <cstddef>
#include <cstdint>

uint8_t *find_function(const char *name, const char *byteSequence);
uint8_t *find_function(const char *name, const char *byteSequence, uint8_t *start, size_t size);

struct HookRequest {
    void **target;
    void *hook;
};

bool setup_hooks(const HookRequest *hooks, size_t count);
bool setup_hook(void **target, void *hook);
