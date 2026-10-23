#pragma once

// Fixes the crash when an unmounted pak is still in use (scrolling the song list); see pak_list_race.cpp

// Finds what to hook. In DLL_PROCESS_ATTACH: the scan reads the game's code as compiled, before the loader's other
// hooks overwrite the start of functions in it (DoSignatureCheck's, for one)
void ScanForPakListRaceFix();
void ApplyPakListRaceFix();
