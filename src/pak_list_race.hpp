#pragma once

// Fixes the crash when an unmounted pak is still in use (scrolling the song list); see pak_list_race.cpp

void ScanForPakListRaceFix();
void ApplyPakListRaceFix();
