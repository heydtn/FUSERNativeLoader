#pragma once

// Community songs: a song whose files stay on its creator's public Google Drive.
// fuserd's api/community/resolve/ says where <X>_P.pak and <X>_P.sig are - inside one .zip / .rar, or loose in a
// folder - and the loader downloads, extracts and checks them itself. The extraction is libarchive (static, built
// by tools/build_libarchive.ps1); only the two named entries are read, and they are written to paths the loader
// chooses, never to a path taken from the archive.

#include <cstdint>
#include <string>

namespace community
{
    constexpr uint64_t kMaxSigBytes = 1024 * 1024;

    // Extracts the pak and sig entries of an archive (zip, rar4 or rar5) to pak_out and sig_out. An entry is matched
    // by its whole '/'-separated path (any case), else by its file name alone when exactly one entry has it. An
    // encrypted entry, a missing one, or one larger than max_pak_bytes (the sig: kMaxSigBytes) fails, with why.
    auto extract_song(const std::wstring& archive, const std::string& pak_entry, const std::string& sig_entry,
                      const std::wstring& pak_out, const std::wstring& sig_out, uint64_t max_pak_bytes, std::string* why) -> bool;

    // True when the file starts like an HTML page (Drive's quota / access / not-found answers come as one).
    auto looks_like_html(const std::wstring& path) -> bool;

    // A .sig file's shape: the FPakSignatureFile magic, as fuserd's catalogue builder checks (catalog.ValidateSig).
    auto sig_ok(const std::wstring& path, std::string* why) -> bool;
} // namespace community
