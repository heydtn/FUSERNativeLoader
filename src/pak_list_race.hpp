#pragma once
#include <cstddef>
#include <cstdint>

// Fixes the crash when an unmounted pak is still in use (scrolling the song list); see pak_list_race.cpp
void ApplyPakListRaceFix(uint8_t *moduleBase, size_t moduleSize);
