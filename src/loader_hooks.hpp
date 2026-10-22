#pragma once
// The byte-pattern search and funchook helpers in dllmain.cpp, for the loader's other source files.
#include <cstddef>
#include <cstdint>

// Searches the game exe, or the given range of it; nullptr when the pattern ("??" for any byte) isn't there
uint8_t *find_function(const char *name, const char *byteSequence);
uint8_t *find_function(const char *name, const char *byteSequence, uint8_t *start, size_t size);

struct HookRequest {
	void **Target;
	void *Hook;
};

struct CodeRange {
	const void *Start;
	const void *End;
};

/*
 * Either every hook is installed or none is; on success each Target points at its original's trampoline. The hooks
 * only go in while no other thread is anywhere in `idle`, at any depth of its stack.
 */
bool setup_hooks(const HookRequest *hooks, size_t count, const CodeRange *idle = nullptr, size_t idleCount = 0);
bool setup_hook(void **target, void *hook);
