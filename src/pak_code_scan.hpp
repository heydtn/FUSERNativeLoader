#pragma once
// Finds the code the pak list race fix hooks (pak_list_race.cpp); see pak_code_scan.cpp
#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

#include "loader_hooks.hpp"

struct PakCodeScan {
	// Functions that copy the pak list or are handed a pak found in a copy: hooked as readers
	std::set<uint8_t *> Readers;

	// Functions that count a pak's handle down: hooked as scopes that hold back every unmounted pak
	std::set<uint8_t *> HandleDestructors;

	// Every chunk of those functions: a thread already in one when the hooks go in would hold a pak unseen
	std::vector<CodeRange> HookedCode;

	// FPakFile's scalar deleting destructor, and the address Unmount's call to it returns to
	uint8_t *DeletePakFile = nullptr;
	uint8_t *UnmountDeleteReturn = nullptr;

	uint32_t SyncHandlesOffset = 0;
	uint32_t AsyncHandlesOffset = 0;

	size_t ListReaders = 0;
	size_t SkippedWrapperCallers = 0;
};

// False, after logging why, when the code isn't provably what the fix needs; nothing may be hooked then
bool ScanPakCode(uint8_t *moduleBase, size_t moduleSize, PakCodeScan &scan);
