#include "multiplayer/community_fetch.hpp"

#define LIBARCHIVE_STATIC
#include "libarchive/archive.h"
#include "libarchive/archive_entry.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <vector>

namespace community
{
    namespace
    {
        constexpr uint32_t kSigMagic = 0x73832DAA; // FPakSignatureFile

        auto lower(std::string s) -> std::string
        {
            std::ranges::transform(s, s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        auto base_name(const std::string& path) -> std::string
        {
            const size_t slash = path.rfind('/');
            return slash == std::string::npos ? path : path.substr(slash + 1);
        }

        // An entry's path as UTF-8 with '/' separators (RAR4 archives made on Windows use '\').
        auto entry_path(archive_entry* e) -> std::string
        {
            const char* utf8 = archive_entry_pathname_utf8(e);
            std::string p = utf8 ? utf8 : (archive_entry_pathname(e) ? archive_entry_pathname(e) : "");
            std::ranges::replace(p, '\\', '/');
            return p;
        }

        struct Archive
        {
            archive* a = archive_read_new();
            ~Archive()
            {
                if (a) archive_read_free(a);
            }
            auto open(const std::wstring& path) -> bool
            {
                archive_read_support_format_zip(a);
                archive_read_support_format_rar(a);
                archive_read_support_format_rar5(a);
                archive_read_support_filter_none(a);
                return archive_read_open_filename_w(a, path.c_str(), 64 * 1024) == ARCHIVE_OK;
            }
            auto error() const -> std::string
            {
                const char* s = archive_error_string(a);
                return s ? s : "unknown libarchive error";
            }
        };

        // Which of the archive's entries is pak_entry / sig_entry: the exact path, or the only entry with that name.
        auto pick(const std::vector<std::string>& paths, const std::string& want, std::string* why) -> std::string
        {
            const std::string w = lower(want), name = lower(base_name(want));
            std::vector<std::string> by_name;
            for (const std::string& p : paths)
            {
                if (lower(p) == w) return p;
                if (lower(base_name(p)) == name) by_name.push_back(p);
            }
            if (by_name.size() == 1) return by_name[0];
            *why = by_name.empty() ? std::format("the archive has no {}", want)
                                   : std::format("the archive has {} entries named {}", by_name.size(), base_name(want));
            return {};
        }
    } // namespace

    auto extract_song(const std::wstring& archive_path, const std::string& pak_entry, const std::string& sig_entry,
                      const std::wstring& pak_out, const std::wstring& sig_out, uint64_t max_pak_bytes, std::string* why) -> bool
    {
        // Pass 1: the entry list (headers only), so the two entries are chosen before anything is written.
        std::vector<std::string> paths;
        {
            Archive ar;
            if (!ar.open(archive_path))
            {
                *why = "cannot open the archive: " + ar.error();
                return false;
            }
            archive_entry* e = nullptr;
            int r;
            while ((r = archive_read_next_header(ar.a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN)
            {
                if (archive_entry_filetype(e) == AE_IFREG) paths.push_back(entry_path(e));
                if (paths.size() > 4096) break;
            }
            if (r == ARCHIVE_FATAL)
            {
                *why = "cannot read the archive: " + ar.error();
                return false;
            }
        }
        const std::string pak = pick(paths, pak_entry, why);
        if (pak.empty()) return false;
        const std::string sig = pick(paths, sig_entry, why);
        if (sig.empty()) return false;

        // Pass 2: stream the two entries out.
        Archive ar;
        if (!ar.open(archive_path))
        {
            *why = "cannot open the archive: " + ar.error();
            return false;
        }
        bool got_pak = false, got_sig = false;
        archive_entry* e = nullptr;
        int r;
        while (!(got_pak && got_sig) && ((r = archive_read_next_header(ar.a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN))
        {
            if (archive_entry_filetype(e) != AE_IFREG) continue;
            const std::string p = entry_path(e);
            const bool is_pak = !got_pak && p == pak, is_sig = !got_sig && p == sig;
            if (!is_pak && !is_sig) continue;
            if (archive_entry_is_encrypted(e))
            {
                *why = std::format("{} is encrypted", p);
                return false;
            }
            const uint64_t cap = is_pak ? max_pak_bytes : kMaxSigBytes;
            if (archive_entry_size_is_set(e) && static_cast<uint64_t>(archive_entry_size(e)) > cap)
            {
                *why = std::format("{} is {} bytes, over the {} byte limit", p, archive_entry_size(e), cap);
                return false;
            }
            const std::wstring& out_path = is_pak ? pak_out : sig_out;
            std::ofstream out(std::filesystem::path(out_path), std::ios::binary | std::ios::trunc);
            if (!out)
            {
                *why = "cannot write " + std::filesystem::path(out_path).string();
                return false;
            }
            std::vector<char> buf(256 * 1024);
            uint64_t total = 0;
            for (;;)
            {
                const la_ssize_t n = archive_read_data(ar.a, buf.data(), buf.size());
                if (n == 0) break;
                if (n < 0)
                {
                    *why = std::format("cannot extract {}: {}", p, ar.error());
                    return false;
                }
                total += static_cast<uint64_t>(n);
                if (total > cap) // the header's size can be missing or wrong; the cap holds anyway
                {
                    *why = std::format("{} is over the {} byte limit", p, cap);
                    return false;
                }
                out.write(buf.data(), n);
            }
            out.close();
            if (!out || total == 0)
            {
                *why = std::format("{}: {}", p, total == 0 ? "empty" : "write failed");
                return false;
            }
            (is_pak ? got_pak : got_sig) = true;
        }
        if (!(got_pak && got_sig))
        {
            *why = std::format("the archive ended before {}: {}", got_pak ? sig : pak, ar.error());
            return false;
        }
        return true;
    }

    auto looks_like_html(const std::wstring& path) -> bool
    {
        std::ifstream in(std::filesystem::path(path), std::ios::binary);
        char head[512]{};
        in.read(head, sizeof(head));
        std::string s(head, static_cast<size_t>(in.gcount()));
        s = lower(s);
        const size_t start = s.find_first_not_of(" \t\r\n\xef\xbb\xbf");
        return start != std::string::npos && (s.compare(start, 9, "<!doctype") == 0 || s.compare(start, 5, "<html") == 0);
    }

    auto sig_ok(const std::wstring& path, std::string* why) -> bool
    {
        std::error_code ec;
        const uint64_t size = std::filesystem::file_size(path, ec);
        if (ec || size < 12 || size > kMaxSigBytes)
        {
            *why = std::format(".sig is {} bytes", ec ? 0 : size);
            return false;
        }
        std::ifstream in(std::filesystem::path(path), std::ios::binary);
        uint32_t magic = 0;
        in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (!in || magic != kSigMagic)
        {
            *why = ".sig has no FPakSignatureFile magic";
            return false;
        }
        return true;
    }
} // namespace community
