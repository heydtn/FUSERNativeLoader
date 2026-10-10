#include "multiplayer/pak_check.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <vector>

// Mirrors fuser_pak_extract.py (parse_footer / parse_index / _parse_entry_fields) for the plaintext indexes of
// community paks. The footer (FPakInfo, v8): ... bEncryptedIndex (1 byte), Magic 0x5A6F12E1, Version, IndexOffset,
// IndexSize, IndexHash[20], then the compression method names. The index: MountPoint (FString), NumEntries (int32),
// then per entry Filename (FString) and FPakEntry: Offset, Size, UncompressedSize (int64), CompressionMethodIndex
// (uint32), Hash[20], [NumBlocks (int32) + 16 bytes each, if compressed], Flags (uint8), CompressionBlockSize (uint32).

namespace p2p
{
    namespace
    {
        constexpr uint32_t kPakMagic = 0x5A6F12E1;
        constexpr uint8_t kEntryEncrypted = 0x01;
        constexpr size_t kFooterWindow = 4096, kMaxIndexBytes = 16u * 1024 * 1024, kFooterFromMagic = 204;
        constexpr int32_t kMaxEntries = 20000, kMaxBlocks = 1 << 20;

        struct Reader
        {
            const std::vector<char>& b;
            size_t at = 0;
            bool ok = true;
            template <typename T> auto get() -> T
            {
                T v{};
                if (!ok || at + sizeof(T) > b.size())
                {
                    ok = false;
                    return v;
                }
                std::memcpy(&v, b.data() + at, sizeof(T));
                at += sizeof(T);
                return v;
            }
            auto skip(size_t n) -> void
            {
                if (!ok || at + n > b.size()) ok = false;
                else at += n;
            }
            // An FString: ANSI only (a negative length means UTF-16, which no community pak uses: refused).
            auto fstring(std::string* out) -> bool
            {
                const int32_t n = get<int32_t>();
                if (!ok || n <= 0 || n > 1024 || at + static_cast<size_t>(n) > b.size() || b[at + static_cast<size_t>(n) - 1] != 0) return ok = false;
                out->assign(b.data() + at, static_cast<size_t>(n) - 1);
                at += static_cast<size_t>(n);
                return true;
            }
        };

        auto starts(const std::string& s, const std::string& p) -> bool { return s.rfind(p, 0) == 0; }

        // An entry name (relative to the mount point) inside the song's own folders.
        auto allowed(const std::string& name, const std::string& x) -> bool
        {
            if (name.empty() || name.find('\\') != std::string::npos || name.front() == '/' || name.find("..") != std::string::npos ||
                name.find(':') != std::string::npos)
                return false;
            for (const std::string root : {"Audio/Songs/", "DLC/Songs/"})
                if (starts(name, root + x + "/") && name.size() > root.size() + x.size() + 1) return true;
            const std::string art = "UI/AlbumArt/T_" + x;
            return starts(name, art) && name.find('/', 12) == std::string::npos; // UI/AlbumArt/<file> (12 chars before it), no deeper
        }
    } // namespace

    auto check_song_pak(const std::wstring& path, const std::string& x, std::string* why) -> bool
    {
        const auto fail = [&](std::string w) {
            if (why) *why = std::move(w);
            return false;
        };
        if (x.empty() || x.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
            return fail("bad song name");
        std::error_code ec;
        const uint64_t size = std::filesystem::file_size(path, ec);
        if (ec) return fail("cannot read the file");
        if (size > kMaxSongPakBytes) return fail(std::format("{} bytes is over the 64 MB limit", size));
        if (size < 256) return fail("too small to be a pak");
        std::ifstream in(std::filesystem::path(path), std::ios::binary);
        const size_t window = static_cast<size_t>(std::min<uint64_t>(size, kFooterWindow));
        std::vector<char> tail(window);
        in.seekg(static_cast<std::streamoff>(size - window));
        if (!in.read(tail.data(), static_cast<std::streamsize>(window))) return fail("cannot read the footer");
        // the last magic in the window is the footer's
        size_t magic_at = std::string::npos;
        for (size_t i = window - 4 + 1; i-- > 1;)
        {
            uint32_t m = 0;
            std::memcpy(&m, tail.data() + i, 4);
            if (m == kPakMagic)
            {
                magic_at = i;
                break;
            }
        }
        if (magic_at == std::string::npos || magic_at + 44 > window) return fail("no pak footer");
        // A v8 FPakInfo ends 204 bytes after its magic (magic 4, version 4, offset 8, size 8, hash 20, 5 compression
        // method names of 32): anything else is a cut or padded file.
        if (window - magic_at != kFooterFromMagic) return fail(std::format("footer ends {} bytes after the magic (want {})", window - magic_at, kFooterFromMagic));
        const uint8_t encrypted_index = static_cast<uint8_t>(tail[magic_at - 1]);
        uint32_t version = 0;
        uint64_t index_offset = 0, index_size = 0;
        std::memcpy(&version, tail.data() + magic_at + 4, 4);
        std::memcpy(&index_offset, tail.data() + magic_at + 8, 8);
        std::memcpy(&index_size, tail.data() + magic_at + 16, 8);
        if (version != 8) return fail(std::format("pak version {} (community paks are version 8)", version));
        if (encrypted_index != 0) return fail("encrypted index");
        const uint64_t footer_at = size - window + magic_at;
        if (index_size == 0 || index_size > kMaxIndexBytes || index_offset > footer_at || index_size > footer_at - index_offset)
            return fail("index outside the file");
        std::vector<char> index(static_cast<size_t>(index_size));
        in.seekg(static_cast<std::streamoff>(index_offset));
        if (!in.read(index.data(), static_cast<std::streamsize>(index_size))) return fail("cannot read the index");

        Reader r{index};
        std::string mount;
        if (!r.fstring(&mount)) return fail("unreadable mount point");
        if (mount != "../../../Fuser/Content/") return fail("mount point '" + mount + "' (want ../../../Fuser/Content/)");
        const int32_t entries = r.get<int32_t>();
        if (!r.ok || entries <= 0 || entries > kMaxEntries) return fail("implausible entry count");
        for (int32_t i = 0; i < entries; ++i)
        {
            std::string name;
            if (!r.fstring(&name)) return fail(std::format("entry {}: unreadable name", i));
            const int64_t offset = r.get<int64_t>(), length = r.get<int64_t>(), uncompressed = r.get<int64_t>();
            const uint32_t method = r.get<uint32_t>();
            r.skip(20);
            if (method != 0)
            {
                const int32_t blocks = r.get<int32_t>();
                if (!r.ok || blocks < 0 || blocks > kMaxBlocks) return fail(std::format("{}: bad compression blocks", name));
                r.skip(static_cast<size_t>(blocks) * 16);
            }
            const uint8_t flags = r.get<uint8_t>();
            r.skip(4);
            if (!r.ok) return fail(std::format("entry {}: index ends early", i));
            if (flags & kEntryEncrypted) return fail(name + ": encrypted entry");
            if (offset < 0 || length < 0 || uncompressed < 0 || static_cast<uint64_t>(offset) + static_cast<uint64_t>(length) > index_offset)
                return fail(name + ": data outside the file");
            if (!allowed(name, x)) return fail("'" + name + "' is outside the song's folders (Audio/Songs/" + x + "/, DLC/Songs/" + x + "/, UI/AlbumArt/T_" + x + "*)");
        }
        return true;
    }
} // namespace p2p
