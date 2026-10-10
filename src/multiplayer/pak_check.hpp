#pragma once

// The custom-song pak layout check. A *_P pak overrides base game content, so a pak
// received from another player is mounted only when it is shaped like every community song pak (all 65 checked
// 2026-10-03, plus 6 sampled from the FUSER Customs sheet):
//   - UE4 pak version 8, unencrypted index, no encrypted entries;
//   - mount point ../../../Fuser/Content/;
//   - every entry under Audio/Songs/<X>/, DLC/Songs/<X>/ or UI/AlbumArt/T_<X>* (no deeper path there);
//   - at most 64 MB.
// The sender checks its own file with the same rule before offering it.

#include <string>

namespace p2p
{
    constexpr unsigned long long kMaxSongPakBytes = 64ull * 1024 * 1024;

    // True when the pak at path has the layout above for song <X>; otherwise why says what is wrong.
    auto check_song_pak(const std::wstring& path, const std::string& x, std::string* why) -> bool;
} // namespace p2p
