#pragma once
// Lookups in a module's unwind table (its RUNTIME_FUNCTION entries, sorted by address)
#include <algorithm>
#include <cstddef>

#include <Windows.h>

// The entry covering rva, or null (a leaf function, or no code)
inline const RUNTIME_FUNCTION *UnwindEntryFor(const RUNTIME_FUNCTION *entries, size_t count, DWORD rva) {
	const RUNTIME_FUNCTION *end = entries + count;
	const RUNTIME_FUNCTION *entry = std::upper_bound(
		entries,
		end,
		rva,
		[](DWORD value, const RUNTIME_FUNCTION &candidate) { return value < candidate.EndAddress; });
	return entry != end && entry->BeginAddress <= rva ? entry : nullptr;
}
