#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

#include "multiplayer/p2p_tunnel.hpp"
#include "multiplayer/pak_check.hpp"

#include "fue/fue.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

using namespace fue;

namespace p2p
{
    namespace
    {
        // ---- constants --------------------------------------------------------------------------------------
        constexpr uint8_t kMagic0 = 'F', kMagic1 = 'T', kVersion = 2;
        constexpr size_t kHeader = 8, kTag = 8;
        enum Channel : uint8_t
        {
            kControl = 0,
            kGame = 1,
            kBeacon = 2,
            kBye = 3,
        };
        enum Control : uint8_t
        {
            kProbe = 1,
            kAck = 2,
            kKeepalive = 3,
            kKeepaliveAck = 4,
        };
        constexpr size_t kMaxDatagram = 65507;
        constexpr uint64_t kProbeEveryMs = 200, kProbeForMs = 20000, kSlowProbeMs = 2000, kUpgradeMs = 1000;
        constexpr uint64_t kKeepaliveMs = 5000, kIdleMs = 60000, kStatsMs = 30000, kReportAfterMs = 1500;
        // A path with nothing from the other side for kLostMs is probed again; a validated address replaces a path
        // that has been quiet for kMoveSilentMs (more than kKeepaliveMs: an idle path still hears a keepalive answer
        // every 5 s); validation probes to one address go out at most every kValidateEveryMs.
        constexpr uint64_t kLostMs = 15000, kMoveSilentMs = 6000, kValidateEveryMs = 500;
        constexpr uint32_t kStunCookie = 0x2112A442;

        auto now_ms() -> uint64_t { return GetTickCount64(); }

        auto rng() -> std::mt19937_64&
        {
            thread_local std::mt19937_64 r{std::random_device{}() ^ (static_cast<uint64_t>(std::random_device{}()) << 32)};
            return r;
        }

        // ---- addresses --------------------------------------------------------------------------------------
        auto addr_text(const sockaddr_in& a) -> std::wstring
        {
            wchar_t ip[INET_ADDRSTRLEN]{};
            InetNtopW(AF_INET, &a.sin_addr, ip, INET_ADDRSTRLEN);
            return std::format(L"{}:{}", ip, ntohs(a.sin_port));
        }
        auto ip_text(const in_addr& a) -> std::string
        {
            char ip[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &a, ip, INET_ADDRSTRLEN);
            return ip;
        }
        auto same(const sockaddr_in& a, const sockaddr_in& b) -> bool { return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port; }
        auto loopback(uint16_t port) -> sockaddr_in
        {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = htons(port);
            return a;
        }
        auto to_sockaddr(const Candidate& c, sockaddr_in* out) -> bool
        {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(c.port);
            if (c.port == 0 || inet_pton(AF_INET, c.ip.c_str(), &a.sin_addr) != 1) return false;
            *out = a;
            return true;
        }
        auto resolve(const std::wstring& host, uint16_t port, sockaddr_in* out) -> bool
        {
            addrinfoW hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            if (GetAddrInfoW(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
            *out = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
            out->sin_port = htons(port);
            FreeAddrInfoW(res);
            return true;
        }
        auto wide(const std::string& s) -> std::wstring { return std::wstring(s.begin(), s.end()); }

        // ---- sockets ----------------------------------------------------------------------------------------
        auto wsa_ready() -> bool
        {
            static const bool ok = [] {
                WSADATA d{};
                return WSAStartup(MAKEWORD(2, 2), &d) == 0;
            }();
            return ok;
        }
        // Windows reports an ICMP port-unreachable on a later recvfrom as WSAECONNRESET: off (SIO_UDP_CONNRESET).
        auto udp_socket(const sockaddr_in& addr) -> SOCKET
        {
            SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (s == INVALID_SOCKET) return s;
            BOOL off = FALSE;
            DWORD ret = 0;
            WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &ret, nullptr, nullptr);
            int buf = 1 << 20;
            setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf), sizeof(buf));
            setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf), sizeof(buf));
            if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
            {
                closesocket(s);
                return INVALID_SOCKET;
            }
            return s;
        }
        auto bound_port(SOCKET s) -> uint16_t
        {
            sockaddr_in a{};
            int len = sizeof(a);
            getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
            return ntohs(a.sin_port);
        }

        // ---- packet authentication --------------------------------------------------------------------------
        // HMAC-SHA256 over header + payload, truncated to 8 bytes. One reusable BCrypt hash per key.
        BCRYPT_ALG_HANDLE g_hmac_alg = nullptr;
        struct Mac
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            Key key{};
            Mac() = default;
            Mac(const Mac&) = delete;
            Mac& operator=(const Mac&) = delete;
            ~Mac() { reset(); }
            auto reset() -> void
            {
                if (h) BCryptDestroyHash(h);
                h = nullptr;
            }
            auto init(const Key& k) -> bool
            {
                if (h && k == key) return true;
                reset();
                key = k;
                if (!g_hmac_alg && BCryptOpenAlgorithmProvider(&g_hmac_alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
                    return false;
                return BCryptCreateHash(g_hmac_alg, &h, nullptr, 0, key.data(), static_cast<ULONG>(key.size()), BCRYPT_HASH_REUSABLE_FLAG) == 0;
            }
            auto tag(const char* data, size_t len, uint8_t out[kTag]) -> bool
            {
                uint8_t full[32]{};
                if (!h || BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(data)), static_cast<ULONG>(len), 0) != 0 ||
                    BCryptFinishHash(h, full, sizeof(full), 0) != 0)
                    return false;
                std::memcpy(out, full, kTag);
                return true;
            }
        };

        auto frame(Mac& mac, uint8_t channel, uint32_t peer, const char* payload, size_t len, std::vector<char>& out) -> bool
        {
            out.resize(kHeader + len + kTag);
            out[0] = static_cast<char>(kMagic0);
            out[1] = static_cast<char>(kMagic1);
            out[2] = static_cast<char>(kVersion);
            out[3] = static_cast<char>(channel);
            std::memcpy(out.data() + 4, &peer, 4);
            if (len) std::memcpy(out.data() + kHeader, payload, len);
            return mac.tag(out.data(), kHeader + len, reinterpret_cast<uint8_t*>(out.data() + kHeader + len));
        }
        // The header of a tunnel packet; its tag is checked separately (the key depends on the peer id).
        auto header(const char* buf, int len, uint8_t* channel, uint32_t* peer) -> bool
        {
            if (len < static_cast<int>(kHeader + kTag) || static_cast<uint8_t>(buf[0]) != kMagic0 || static_cast<uint8_t>(buf[1]) != kMagic1 ||
                static_cast<uint8_t>(buf[2]) != kVersion)
                return false;
            *channel = static_cast<uint8_t>(buf[3]);
            std::memcpy(peer, buf + 4, 4);
            return true;
        }
        auto verify(Mac& mac, const char* buf, int len) -> bool
        {
            uint8_t want[kTag]{};
            if (!mac.tag(buf, static_cast<size_t>(len) - kTag, want)) return false;
            uint8_t diff = 0;
            for (size_t i = 0; i < kTag; ++i) diff |= static_cast<uint8_t>(want[i] ^ static_cast<uint8_t>(buf[len - kTag + i]));
            return diff == 0;
        }

        // ---- traffic counters -------------------------------------------------------------------------------
        struct Counter
        {
            uint64_t packets = 0, bytes = 0;
            int max = 0;
            auto add(int len) -> void
            {
                ++packets;
                bytes += static_cast<uint64_t>(len);
                if (len > max) max = len;
            }
        };
        struct Stats
        {
            Counter game_out, game_in, beacon_out, beacon_in; // out = from FUSER into the tunnel
            uint64_t dropped = 0;                             // FUSER datagrams with no path yet
            auto text() const -> std::wstring
            {
                return std::format(L"game {}/{} pkts {}/{} B (max {}/{}), beacon {}/{} pkts{}", game_out.packets, game_in.packets, game_out.bytes,
                                   game_in.bytes, game_out.max, game_in.max, beacon_out.packets, beacon_in.packets,
                                   dropped ? std::format(L", {} dropped before a path", dropped) : std::wstring{});
            }
        };

        // ---- candidates and paths ---------------------------------------------------------------------------
        // Lower is better: a LAN path avoids the router (and hairpinning); a public one is the punched path.
        // A relayed path is the last resort: it costs the server bandwidth and adds a hop.
        auto rank_of(const std::string& type) -> int { return type == "host" ? 0 : type == "srflx" ? 1 : type == "relay" ? 3 : 2; }
        auto path_of(const std::string& type) -> std::string
        {
            return type == "host" ? "lan" : type == "srflx" ? "direct" : type == "relay" ? "relay" : "prflx";
        }
        // The candidate (by index) an address is, or -1.
        auto match(const std::vector<Candidate>& cands, const sockaddr_in& a) -> int
        {
            for (size_t i = 0; i < cands.size(); ++i)
            {
                sockaddr_in c{};
                if (to_sockaddr(cands[i], &c) && same(c, a)) return static_cast<int>(i);
            }
            return -1;
        }
        // A probe this side sent: which candidate it went to (-1: an address no candidate lists), when, and whether it
        // validates an address the other side's traffic came from. Its nonce is erased when answered, so an ack counts
        // once: a replayed ack, from anywhere, finds nothing.
        struct Sent
        {
            int index;
            uint64_t at;
            bool validate = false;
        };

        // ---- state ------------------------------------------------------------------------------------------
        enum class Role
        {
            None,
            Host,
            Joiner
        };
        struct Peer // a joiner, on the host
        {
            uint32_t id = 0;
            Mac mac;
            bool signaled = false;
            std::vector<Candidate> cands;
            sockaddr_in remote{};
            bool has_remote = false;
            std::string path = "none";
            int rank = 9, rtt = -1;
            uint64_t confirmed_at = 0, probe_start = 0, last_probe = 0, last_seen = 0, last_stats = 0;
            bool reported = false, failed_reported = false;
            std::map<uint64_t, Sent> nonces;
            SOCKET game = INVALID_SOCKET, beacon = INVALID_SOCKET;
            Stats stats{};
            // The address being validated, the last packet on the path, and a probe window after a loss or new
            // candidates.
            sockaddr_in pending{};
            bool has_pending = false, lost = false;
            uint64_t pending_at = 0, remote_heard = 0, reprobe_until = 0;
        };
        struct Joiner // this machine joining
        {
            JoinRole role{};
            Mac mac;
            SOCKET game = INVALID_SOCKET, beacon = INVALID_SOCKET;
            std::vector<Candidate> host;
            sockaddr_in selected{};
            bool has_sel = false;
            bool sel_relay = false; // the selected path goes through this joiner's relay allocation
            std::string path = "none";
            int rank = 9, rtt = -1;
            uint64_t sel_at = 0, probe_start = 0, last_probe = 0, last_keepalive = 0, last_heard = 0, last_stats = 0;
            bool reported = false, failed_reported = false, silent_warned = false;
            std::map<uint64_t, Sent> nonces;
            sockaddr_in game_src{}, beacon_src{};
            bool have_game = false, have_beacon = false;
            Stats stats{};
            // As Peer's (sel_heard: the last packet on the selected path).
            sockaddr_in pending{};
            bool has_pending = false, pending_relayed = false, lost = false, reprobe = false;
            uint64_t pending_at = 0, sel_heard = 0;
        };

        SOCKET g_sock = INVALID_SOCKET;
        uint16_t g_port = 0;
        bool g_open_result = false;
        std::once_flag g_open_once;

        std::mutex g_mu; // everything below
        Role g_role = Role::None;
        HostRole g_host_role{};
        std::map<uint32_t, std::unique_ptr<Peer>> g_peers;
        std::unique_ptr<Joiner> g_join;
        std::vector<SOCKET> g_close; // closed by the loop between selects
        std::vector<Report> g_reports;

        // STUN answers, by transaction id.
        std::mutex g_stun_mu;
        std::condition_variable g_stun_cv;
        std::map<std::string, sockaddr_in> g_stun_answers;

        auto push_report(Report r) -> void
        {
            if (g_reports.size() >= 64) g_reports.erase(g_reports.begin());
            g_reports.push_back(std::move(r));
        }
        auto send_to(const std::vector<char>& pkt, const sockaddr_in& to) -> void
        {
            sendto(g_sock, pkt.data(), static_cast<int>(pkt.size()), 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
        }
        auto send_control(Mac& mac, uint32_t peer, uint8_t sub, uint64_t nonce, const sockaddr_in& to) -> void
        {
            char body[9]{};
            body[0] = static_cast<char>(sub);
            std::memcpy(body + 1, &nonce, 8);
            std::vector<char> pkt;
            if (frame(mac, kControl, peer, body, sizeof(body), pkt)) send_to(pkt, to);
        }
        auto new_nonce(std::map<uint64_t, Sent>& nonces, int index, uint64_t now, bool validate = false) -> uint64_t
        {
            if (nonces.size() > 512) nonces.clear();
            const uint64_t n = rng()();
            nonces[n] = Sent{index, now, validate};
            return n;
        }
        // Takes an answered probe's record out (once).
        auto take_nonce(std::map<uint64_t, Sent>& nonces, uint64_t nonce) -> std::optional<Sent>
        {
            auto it = nonces.find(nonce);
            if (it == nonces.end()) return std::nullopt;
            const Sent s = it->second;
            nonces.erase(it);
            return s;
        }
        auto close_later(SOCKET& s) -> void
        {
            if (s != INVALID_SOCKET) g_close.push_back(s);
            s = INVALID_SOCKET;
        }

        // ---- STUN (RFC 8489 Binding, client side) -----------------------------------------------------------
        auto is_stun(const char* b, int n) -> bool
        {
            if (n < 20 || (static_cast<uint8_t>(b[0]) & 0xC0) != 0) return false;
            uint32_t cookie = 0;
            std::memcpy(&cookie, b + 4, 4);
            return ntohl(cookie) == kStunCookie;
        }
        // A Binding success answer: its transaction id and XOR-MAPPED-ADDRESS (IPv4).
        auto stun_answer(const char* b, int n, std::string* txid, sockaddr_in* mapped) -> bool
        {
            const auto u8 = [&](int i) { return static_cast<uint8_t>(b[i]); };
            if ((u8(0) << 8 | u8(1)) != 0x0101) return false;
            const int len = u8(2) << 8 | u8(3);
            if (20 + len > n) return false;
            txid->assign(b + 8, 12);
            for (int at = 20; at + 4 <= 20 + len;)
            {
                const int type = u8(at) << 8 | u8(at + 1), alen = u8(at + 2) << 8 | u8(at + 3);
                const int v = at + 4;
                if (v + alen > 20 + len) return false;
                if (type == 0x0020 && alen >= 8 && u8(v + 1) == 0x01)
                {
                    sockaddr_in a{};
                    a.sin_family = AF_INET;
                    const uint16_t port = static_cast<uint16_t>((u8(v + 2) << 8 | u8(v + 3)) ^ (kStunCookie >> 16));
                    uint32_t ip = 0;
                    std::memcpy(&ip, b + v + 4, 4);
                    a.sin_port = htons(port);
                    a.sin_addr.s_addr = ip ^ htonl(kStunCookie);
                    *mapped = a;
                    return true;
                }
                at = v + ((alen + 3) & ~3);
            }
            return false;
        }

        // ---- TURN client (RFC 8656), for the joiner's relay ---------------------------------------------------
        // The joiner allocates a relay address on fuserd's TURN server and registers it as a "relay" candidate; the
        // host sends to it like any other candidate. The joiner grants the host's public IPs (CreatePermission) and
        // talks to the host through Send / Data indications on the tunnel socket. Allocation answers are waited for
        // by relay_allocate (the worker thread); everything else is handled on the loop.
        enum : uint16_t
        {
            kAttrUsername = 0x0006,
            kAttrIntegrity = 0x0008,
            kAttrError = 0x0009,
            kAttrLifetime = 0x000D,
            kAttrPeer = 0x0012,
            kAttrData = 0x0013,
            kAttrRealm = 0x0014,
            kAttrNonce = 0x0015,
            kAttrRelayed = 0x0016,
            kAttrTransport = 0x0019,
            kTurnAllocate = 0x0003,
            kTurnRefresh = 0x0004,
            kTurnSend = 0x0016,     // Send indication
            kTurnData = 0x0017,     // Data indication (method 0x007, indication class 0x0010; 0x0117 would be an error response)
            kTurnPermission = 0x0008,
        };

        auto bcrypt_digest(LPCWSTR alg, bool hmac, const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t* out, size_t out_len) -> bool
        {
            BCRYPT_ALG_HANDLE a = nullptr;
            BCRYPT_HASH_HANDLE h = nullptr;
            bool ok = BCryptOpenAlgorithmProvider(&a, alg, nullptr, hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) == 0 &&
                      BCryptCreateHash(a, &h, nullptr, 0, const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) == 0 &&
                      BCryptHashData(h, static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(len), 0) == 0 &&
                      BCryptFinishHash(h, out, static_cast<ULONG>(out_len), 0) == 0;
            if (h) BCryptDestroyHash(h);
            if (a) BCryptCloseAlgorithmProvider(a, 0);
            return ok;
        }

        // An outgoing STUN/TURN message.
        struct StunOut
        {
            std::vector<uint8_t> b;
            StunOut(uint16_t type, const std::string& txid) : b(20, 0)
            {
                b[0] = static_cast<uint8_t>(type >> 8);
                b[1] = static_cast<uint8_t>(type);
                const uint32_t cookie = htonl(kStunCookie);
                std::memcpy(&b[4], &cookie, 4);
                std::memcpy(&b[8], txid.data(), 12);
            }
            auto set_length(size_t len) -> void
            {
                b[2] = static_cast<uint8_t>(len >> 8);
                b[3] = static_cast<uint8_t>(len);
            }
            auto attr(uint16_t type, const void* v, size_t n) -> void
            {
                b.push_back(static_cast<uint8_t>(type >> 8));
                b.push_back(static_cast<uint8_t>(type));
                b.push_back(static_cast<uint8_t>(n >> 8));
                b.push_back(static_cast<uint8_t>(n));
                const auto* p = static_cast<const uint8_t*>(v);
                b.insert(b.end(), p, p + n);
                while (b.size() % 4) b.push_back(0);
                set_length(b.size() - 20);
            }
            auto addr(uint16_t type, const sockaddr_in& a) -> void // XOR-…-ADDRESS, IPv4
            {
                uint8_t v[8]{0, 0x01};
                const uint16_t port = static_cast<uint16_t>(ntohs(a.sin_port) ^ (kStunCookie >> 16));
                v[2] = static_cast<uint8_t>(port >> 8);
                v[3] = static_cast<uint8_t>(port);
                const uint32_t ip = a.sin_addr.s_addr ^ htonl(kStunCookie);
                std::memcpy(v + 4, &ip, 4);
                attr(type, v, sizeof(v));
            }
            // MESSAGE-INTEGRITY, last: HMAC-SHA1 over the message with its length already counting the attribute.
            auto integrity(const std::array<uint8_t, 16>& key) -> void
            {
                const size_t at = b.size();
                set_length(at - 20 + 24);
                uint8_t mac[20]{};
                bcrypt_digest(BCRYPT_SHA1_ALGORITHM, true, key.data(), key.size(), b.data(), at, mac, sizeof(mac));
                attr(kAttrIntegrity, mac, sizeof(mac));
            }
        };

        // An incoming STUN/TURN message.
        struct StunIn
        {
            uint16_t type = 0;
            std::string txid;
            std::vector<std::pair<uint16_t, std::string>> attrs;
            auto get(uint16_t t) const -> const std::string*
            {
                for (const auto& [k, v] : attrs)
                    if (k == t) return &v;
                return nullptr;
            }
            auto error() const -> int
            {
                const std::string* v = get(kAttrError);
                return v && v->size() >= 4 ? (static_cast<uint8_t>((*v)[2]) & 7) * 100 + static_cast<uint8_t>((*v)[3]) : 0;
            }
        };
        auto stun_parse(const char* b, int n, StunIn* m) -> bool
        {
            if (!is_stun(b, n)) return false;
            const auto u8 = [&](int i) { return static_cast<uint8_t>(b[i]); };
            const int len = u8(2) << 8 | u8(3);
            if (20 + len > n) return false;
            m->type = static_cast<uint16_t>(u8(0) << 8 | u8(1));
            m->txid.assign(b + 8, 12);
            for (int at = 20; at + 4 <= 20 + len;)
            {
                const int type = u8(at) << 8 | u8(at + 1), alen = u8(at + 2) << 8 | u8(at + 3);
                if (at + 4 + alen > 20 + len) return false;
                m->attrs.emplace_back(static_cast<uint16_t>(type), std::string(b + at + 4, static_cast<size_t>(alen)));
                at += 4 + ((alen + 3) & ~3);
            }
            return true;
        }
        auto xor_addr(const std::string* v, sockaddr_in* out) -> bool
        {
            if (!v || v->size() < 8 || static_cast<uint8_t>((*v)[1]) != 0x01) return false;
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(static_cast<uint16_t>(((static_cast<uint8_t>((*v)[2]) << 8) | static_cast<uint8_t>((*v)[3])) ^ (kStunCookie >> 16)));
            uint32_t ip = 0;
            std::memcpy(&ip, v->data() + 4, 4);
            a.sin_addr.s_addr = ip ^ htonl(kStunCookie);
            *out = a;
            return true;
        }
        auto new_txid() -> std::string
        {
            std::string t(12, '\0');
            for (char& c : t) c = static_cast<char>(rng()());
            return t;
        }
        // A public IPv4 address (worth a TURN permission): not private, loopback, link-local or CGNAT-shared.
        auto is_public(uint32_t ip_net) -> bool
        {
            const uint32_t ip = ntohl(ip_net);
            return !((ip >> 24) == 10 || (ip >> 24) == 127 || (ip >> 20) == 0xAC1 || (ip >> 16) == 0xC0A8 || (ip >> 16) == 0xA9FE ||
                     (ip >> 22) == (0x64400000u >> 22) || ip == 0);
        }

        struct Relay
        {
            sockaddr_in server{};
            std::string username, password, realm, nonce;
            std::array<uint8_t, 16> key{};
            sockaddr_in relayed{};
            bool allocated = false;
            uint32_t lifetime = 600;
            uint64_t refreshed_at = 0;
            std::map<uint32_t, uint64_t> permissions;               // peer IP (network order) -> last asked
            std::map<std::string, std::pair<uint16_t, uint32_t>> pending; // txid -> (method, permission IP)
        };
        std::unique_ptr<Relay> g_relay; // under g_mu
        std::mutex g_turn_mu;           // relay_allocate's answers
        std::condition_variable g_turn_cv;
        std::map<std::string, StunIn> g_turn_answers;

        auto relay_key(Relay& r) -> void
        {
            const std::string s = r.username + ":" + r.realm + ":" + r.password;
            bcrypt_digest(BCRYPT_MD5_ALGORITHM, false, nullptr, 0, s.data(), s.size(), r.key.data(), r.key.size());
        }
        auto relay_send(const Relay& r, const StunOut& m) -> void
        {
            sendto(g_sock, reinterpret_cast<const char*>(m.b.data()), static_cast<int>(m.b.size()), 0, reinterpret_cast<const sockaddr*>(&r.server),
                   sizeof(r.server));
        }
        auto relay_auth(const Relay& r, StunOut& m) -> void
        {
            m.attr(kAttrUsername, r.username.data(), r.username.size());
            m.attr(kAttrRealm, r.realm.data(), r.realm.size());
            m.attr(kAttrNonce, r.nonce.data(), r.nonce.size());
            m.integrity(r.key);
        }
        auto relay_refresh(Relay& r, uint32_t lifetime, uint64_t now) -> void
        {
            const std::string txid = new_txid();
            StunOut m(kTurnRefresh, txid);
            const uint32_t lt = htonl(lifetime);
            m.attr(kAttrLifetime, &lt, 4);
            relay_auth(r, m);
            r.pending[txid] = {kTurnRefresh, 0};
            r.refreshed_at = now;
            relay_send(r, m);
        }
        auto relay_permit(Relay& r, uint32_t ip, uint64_t now) -> void
        {
            const std::string txid = new_txid();
            StunOut m(kTurnPermission, txid);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = ip;
            m.addr(kAttrPeer, a);
            relay_auth(r, m);
            r.pending[txid] = {kTurnPermission, ip};
            r.permissions[ip] = now;
            relay_send(r, m);
        }
        // A tunnel packet to peer through the relay (Send indication: no authentication).
        auto relay_send_data(const Relay& r, const sockaddr_in& peer, const std::vector<char>& pkt) -> void
        {
            StunOut m(kTurnSend, new_txid());
            m.addr(kAttrPeer, peer);
            m.attr(kAttrData, pkt.data(), pkt.size());
            relay_send(r, m);
        }
        // Keep the allocation and the permissions for the host's public IPs alive. Callers hold g_mu.
        auto relay_tick(const std::vector<Candidate>& host, uint64_t now) -> void
        {
            if (!g_relay || !g_relay->allocated) return;
            Relay& r = *g_relay;
            if (now - r.refreshed_at > static_cast<uint64_t>(std::max<uint32_t>(r.lifetime / 2, 30)) * 1000) relay_refresh(r, r.lifetime, now);
            for (const Candidate& c : host)
            {
                sockaddr_in a{};
                if (!to_sockaddr(c, &a) || !is_public(a.sin_addr.s_addr)) continue;
                auto it = r.permissions.find(a.sin_addr.s_addr);
                if (it == r.permissions.end())
                    Output::send<LogLevel::Normal>(STR("[p2p] relay: asking the relay to admit the host's {}\n"), wide(c.ip));
                if (it == r.permissions.end() || now - it->second > 240000) relay_permit(r, a.sin_addr.s_addr, now);
            }
            if (r.pending.size() > 64) r.pending.clear();
        }
        auto relay_release_locked() -> void
        {
            if (g_relay && g_relay->allocated)
            {
                relay_refresh(*g_relay, 0, now_ms()); // lifetime 0: delete the allocation
                Output::send<LogLevel::Normal>(STR("[p2p] relay: released {}\n"), addr_text(g_relay->relayed));
            }
            g_relay.reset();
        }

        // ---- the loop: host side ----------------------------------------------------------------------------
        auto host_peer_sockets(Peer& p) -> bool
        {
            if (p.game != INVALID_SOCKET) return true;
            p.game = udp_socket(loopback(0));
            p.beacon = udp_socket(loopback(0));
            if (p.game == INVALID_SOCKET || p.beacon == INVALID_SOCKET)
            {
                Output::send<LogLevel::Error>(STR("[p2p] host: cannot open local sockets for peer {:08x} (error {})\n"), p.id, WSAGetLastError());
                close_later(p.game);
                close_later(p.beacon);
                return false;
            }
            Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} -> local game 127.0.0.1:{}, beacon 127.0.0.1:{}\n"), p.id, bound_port(p.game),
                                           bound_port(p.beacon));
            return true;
        }
        // Peer p's path is where an ack of one of this side's own fresh probes came from. Every packet is
        // authenticated, but a captured one can be replayed from anywhere; an ack of a fresh nonce can't be. So the first
        // fresh ack sets the path, and traffic or a keepalive from another address only starts a validation - a probe to
        // it - and the path moves when that probe is answered (NAT rebinding, or the peer's network changed).
        auto host_set_path(Peer& p, const sockaddr_in& from, uint64_t now) -> void
        {
            const int i = match(p.cands, from);
            const std::string type = i >= 0 ? p.cands[static_cast<size_t>(i)].type : "prflx";
            if (!p.has_remote)
            {
                Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} reached via {} {} ({} s after it appeared)\n"), p.id, wide(path_of(type)),
                                               addr_text(from), (now - p.probe_start) / 1000);
                p.confirmed_at = now;
            }
            else
                Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} moved {} -> {} ({}, validated)\n"), p.id, addr_text(p.remote), addr_text(from),
                                               wide(path_of(type)));
            p.remote = from;
            p.has_remote = true;
            p.has_pending = false;
            p.remote_heard = now;
            p.lost = false;
            p.path = path_of(type);
            p.rank = rank_of(type);
        }
        auto host_validate(Peer& p, const sockaddr_in& from, uint64_t now) -> void
        {
            if (p.has_pending && same(p.pending, from) && now - p.pending_at < kValidateEveryMs) return;
            p.pending = from;
            p.has_pending = true;
            p.pending_at = now;
            send_control(p.mac, p.id, kProbe, new_nonce(p.nonces, match(p.cands, from), now, true), from);
        }
        auto host_packet(const char* buf, int n, const sockaddr_in& from, uint64_t now) -> void
        {
            uint8_t ch = 0;
            uint32_t id = 0;
            if (!header(buf, n, &ch, &id)) return;
            auto it = g_peers.find(id);
            if (it == g_peers.end())
            {
                if (!g_host_role.accept_unknown || ch == kBye || g_peers.size() >= 24) return;
                auto p = std::make_unique<Peer>();
                p->id = id;
                p->mac.init(Key{});
                p->probe_start = now;
                if (!verify(p->mac, buf, n)) return;
                Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} (manual mode) from {}\n"), id, addr_text(from));
                it = g_peers.emplace(id, std::move(p)).first;
            }
            Peer& p = *it->second;
            if (!verify(p.mac, buf, n)) return;
            const char* payload = buf + kHeader;
            const int len = n - static_cast<int>(kHeader + kTag);
            p.last_seen = now;
            const bool keepalive = ch == kControl && len >= 1 && static_cast<uint8_t>(payload[0]) == kKeepalive;
            if (p.has_remote && same(p.remote, from))
            {
                p.remote_heard = now;
                if (p.lost) Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} heard again on {}\n"), p.id, addr_text(from));
                p.lost = false;
            }
            else if (ch == kGame || ch == kBeacon || keepalive || (!p.has_remote && ch == kControl))
                host_validate(p, from, now);
            if (ch == kControl && len >= 9)
            {
                uint64_t nonce = 0;
                std::memcpy(&nonce, payload + 1, 8);
                switch (static_cast<uint8_t>(payload[0]))
                {
                case kProbe:
                    send_control(p.mac, p.id, kAck, nonce, from);
                    break;
                case kAck:
                    if (const auto s = take_nonce(p.nonces, nonce))
                    {
                        p.rtt = static_cast<int>(now - s->at);
                        if (!p.has_remote || (s->validate && !same(p.remote, from))) host_set_path(p, from, now);
                    }
                    break;
                case kKeepalive:
                    send_control(p.mac, p.id, kKeepaliveAck, nonce, from);
                    break;
                default:
                    break;
                }
            }
            else if (ch == kGame || ch == kBeacon)
            {
                if (!host_peer_sockets(p)) return;
                const sockaddr_in dst = loopback(ch == kGame ? g_host_role.game_port : g_host_role.beacon_port);
                (ch == kGame ? p.stats.game_out : p.stats.beacon_out).add(len);
                sendto(ch == kGame ? p.game : p.beacon, payload, len, 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
            }
            else if (ch == kBye && p.has_remote && same(p.remote, from)) // only on the path: a replayed bye from elsewhere is ignored
            {
                Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} said bye; {}\n"), p.id, p.stats.text());
                close_later(p.game);
                close_later(p.beacon);
                p.has_remote = false;
                if (!p.signaled) g_peers.erase(it);
            }
        }
        auto host_tick(uint64_t now) -> void
        {
            for (auto it = g_peers.begin(); it != g_peers.end();)
            {
                Peer& p = *it->second;
                // A path gone quiet (the peer's network changed, or its NAT dropped the mapping): probe its candidates
                // again, while the path stays as it is - a validated address replaces it. The per-peer local
                // sockets stay too, so FUSER keeps seeing the same client connection.
                if (p.has_remote && !p.lost && now - p.remote_heard > kLostMs)
                {
                    p.lost = true;
                    p.reprobe_until = now + kProbeForMs;
                    Output::send<LogLevel::Warning>(STR("[p2p] host: nothing from peer {:08x} on {} for {} s; probing its candidates again\n"), p.id,
                                                    addr_text(p.remote), (now - p.remote_heard) / 1000);
                }
                // Probe its candidates (this side's half of the hole punch) until it answers, briefly after, and in a
                // re-probe window.
                const bool probing = p.signaled && !p.cands.empty() &&
                                     ((!p.has_remote && now - p.probe_start < kProbeForMs) || (p.has_remote && now - p.confirmed_at < kUpgradeMs) ||
                                      now < p.reprobe_until);
                const bool slow = p.signaled && !p.has_remote && now - p.probe_start >= kProbeForMs;
                if ((probing && now - p.last_probe >= kProbeEveryMs) || (slow && now - p.last_probe >= kSlowProbeMs))
                {
                    p.last_probe = now;
                    for (size_t i = 0; i < p.cands.size(); ++i)
                    {
                        sockaddr_in to{};
                        if (to_sockaddr(p.cands[i], &to)) send_control(p.mac, p.id, kProbe, new_nonce(p.nonces, static_cast<int>(i), now), to);
                    }
                }
                if (p.has_remote && !p.reported && now - p.confirmed_at >= kReportAfterMs)
                {
                    p.reported = true;
                    push_report(Report{p.id, "connected", p.path, p.rtt});
                }
                if (p.signaled && !p.has_remote && !p.failed_reported && now - p.probe_start >= kProbeForMs)
                {
                    p.failed_reported = true;
                    Output::send<LogLevel::Warning>(STR("[p2p] host: no path to peer {:08x} after {} s ({} candidates)\n"), p.id, kProbeForMs / 1000,
                                                    p.cands.size());
                    push_report(Report{p.id, "failed", "none", -1});
                }
                if (p.has_remote && now - p.last_seen > kIdleMs)
                {
                    Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} idle; {}\n"), p.id, p.stats.text());
                    close_later(p.game);
                    close_later(p.beacon);
                    p.has_remote = false;
                    p.reported = false;
                    p.probe_start = now;
                    if (!p.signaled)
                    {
                        it = g_peers.erase(it);
                        continue;
                    }
                }
                if (p.game != INVALID_SOCKET && now - p.last_stats > kStatsMs)
                {
                    p.last_stats = now;
                    Output::send<LogLevel::Verbose>(STR("[p2p] host: peer {:08x} ({}) {}\n"), p.id, wide(p.path), p.stats.text());
                }
                ++it;
            }
        }

        // ---- the loop: joiner side --------------------------------------------------------------------------
        // Sends a tunnel packet to the host along a route: straight from the tunnel socket, or through the relay.
        auto joiner_send(const std::vector<char>& pkt, const sockaddr_in& to, bool relayed) -> void
        {
            if (relayed && g_relay && g_relay->allocated) relay_send_data(*g_relay, to, pkt);
            else if (!relayed) send_to(pkt, to);
        }
        auto joiner_control(Joiner& j, uint8_t sub, uint64_t nonce, const sockaddr_in& to, bool relayed) -> void
        {
            char body[9]{};
            body[0] = static_cast<char>(sub);
            std::memcpy(body + 1, &nonce, 8);
            std::vector<char> pkt;
            if (frame(j.mac, kControl, j.role.peer_id, body, sizeof(body), pkt)) joiner_send(pkt, to, relayed);
        }
        // A path: at is the host's address (as the relay sees it, for a relayed one). A better-ranked path replaces
        // the current one within kUpgradeMs of the first, or at any time while the current one is the relay.
        // Called only for an ack of one of this side's fresh probes (see host_set_path). It also replaces a path
        // that has been quiet for kMoveSilentMs - the host moved, or this machine's network changed.
        auto joiner_select(Joiner& j, const sockaddr_in& at, int index, int rtt, uint64_t now, bool relayed) -> void
        {
            const std::string type = relayed ? "relay" : index >= 0 ? j.host[static_cast<size_t>(index)].type : "prflx";
            const int rank = rank_of(type);
            const bool quiet = j.has_sel && now - j.sel_heard > kMoveSilentMs;
            if (j.has_sel && same(j.selected, at) && j.sel_relay == relayed) return;
            if (j.has_sel && !quiet && (rank >= j.rank || (now - j.sel_at > kUpgradeMs && !j.sel_relay))) return;
            Output::send<LogLevel::Normal>(STR("[p2p] join: {} path to the host via {} {}{} ({} ms after probing began)\n"),
                                           !j.has_sel ? STR("found a") : quiet ? STR("replacing a quiet") : STR("better"), wide(path_of(type)), addr_text(at),
                                           rtt >= 0 ? std::format(L", rtt {} ms", rtt) : std::wstring{}, now - j.probe_start);
            if (!j.has_sel) j.sel_at = now;
            j.selected = at;
            j.has_sel = true;
            j.sel_relay = relayed;
            j.sel_heard = now;
            j.has_pending = false;
            j.lost = false;
            j.rank = rank;
            j.path = path_of(type);
            if (rtt >= 0) j.rtt = rtt;
        }
        auto joiner_validate(Joiner& j, const sockaddr_in& from, bool relayed, uint64_t now) -> void
        {
            if (j.has_pending && same(j.pending, from) && j.pending_relayed == relayed && now - j.pending_at < kValidateEveryMs) return;
            j.pending = from;
            j.pending_relayed = relayed;
            j.has_pending = true;
            j.pending_at = now;
            joiner_control(j, kProbe, new_nonce(j.nonces, match(j.host, from), now, true), from, relayed);
        }
        auto joiner_packet(const char* buf, int n, const sockaddr_in& from, uint64_t now, bool relayed) -> void
        {
            Joiner& j = *g_join;
            uint8_t ch = 0;
            uint32_t id = 0;
            if (!header(buf, n, &ch, &id) || id != j.role.peer_id || !verify(j.mac, buf, n)) return;
            j.last_heard = now;
            j.silent_warned = false;
            const bool on_path = j.has_sel && same(j.selected, from) && j.sel_relay == relayed;
            if (on_path)
            {
                j.sel_heard = now;
                if (j.lost) Output::send<LogLevel::Normal>(STR("[p2p] join: host heard again on {}\n"), addr_text(from));
                j.lost = false;
            }
            const char* payload = buf + kHeader;
            const int len = n - static_cast<int>(kHeader + kTag);
            if (ch == kControl && len >= 9)
            {
                uint64_t nonce = 0;
                std::memcpy(&nonce, payload + 1, 8);
                const uint8_t sub = static_cast<uint8_t>(payload[0]);
                if (sub == kProbe)
                {
                    joiner_control(j, kAck, nonce, from, relayed); // the host punching toward us (or reaching our relay)
                    if (!on_path) joiner_validate(j, from, relayed, now);
                }
                else if (sub == kAck)
                {
                    if (const auto s = take_nonce(j.nonces, nonce)) joiner_select(j, from, s->index, static_cast<int>(now - s->at), now, relayed);
                }
                return;
            }
            if (!on_path) joiner_validate(j, from, relayed, now); // the host's traffic from another address: follow it once it answers
            if (ch == kGame && j.have_game)
            {
                j.stats.game_in.add(len);
                sendto(j.game, payload, len, 0, reinterpret_cast<const sockaddr*>(&j.game_src), sizeof(j.game_src));
            }
            else if (ch == kBeacon && j.have_beacon)
            {
                j.stats.beacon_in.add(len);
                sendto(j.beacon, payload, len, 0, reinterpret_cast<const sockaddr*>(&j.beacon_src), sizeof(j.beacon_src));
            }
        }
        auto joiner_local(Joiner& j, SOCKET sock, uint8_t channel, const char* buf, int n, const sockaddr_in& from) -> void
        {
            sockaddr_in& src = channel == kGame ? j.game_src : j.beacon_src;
            bool& have = channel == kGame ? j.have_game : j.have_beacon;
            if (!have || !same(src, from))
            {
                Output::send<LogLevel::Normal>(STR("[p2p] join: FUSER {} socket is {}\n"), channel == kGame ? STR("game") : STR("beacon"), addr_text(from));
                src = from;
                have = true;
            }
            (void)sock;
            if (!j.has_sel)
            {
                ++j.stats.dropped;
                return;
            }
            (channel == kGame ? j.stats.game_out : j.stats.beacon_out).add(n);
            std::vector<char> pkt;
            if (frame(j.mac, channel, j.role.peer_id, buf, static_cast<size_t>(n), pkt)) joiner_send(pkt, j.selected, j.sel_relay);
        }
        auto joiner_tick(uint64_t now) -> void
        {
            Joiner& j = *g_join;
            relay_tick(j.host, now);
            // A quiet path (the host's network changed, or a NAT dropped the mapping): probe the host's candidates again,
            // keeping the path until a validated one replaces it.
            if (j.has_sel && !j.lost && now - j.sel_heard > kLostMs)
            {
                j.lost = true;
                j.probe_start = now;
                j.last_probe = 0;
                Output::send<LogLevel::Warning>(STR("[p2p] join: nothing from the host on {} for {} s; probing its candidates again\n"), addr_text(j.selected),
                                                (now - j.sel_heard) / 1000);
            }
            // Direct probes run while there is no path, briefly after one is found, after a loss, and for as long as the
            // path is the relay (a punched path may still open up). Relay-only mode doesn't probe directly at all.
            const bool direct = !j.host.empty() && !j.role.relay_only;
            const bool probing = direct && now - j.probe_start < kProbeForMs && (!j.has_sel || j.sel_relay || j.lost || j.reprobe || now - j.sel_at < kUpgradeMs);
            const bool slow = direct && (!j.has_sel || j.sel_relay || j.lost) && now - j.probe_start >= kProbeForMs;
            if (j.reprobe && now - j.probe_start >= kProbeForMs) j.reprobe = false;
            if ((probing && now - j.last_probe >= kProbeEveryMs) || (slow && now - j.last_probe >= kSlowProbeMs))
            {
                j.last_probe = now;
                for (size_t i = 0; i < j.host.size(); ++i)
                {
                    sockaddr_in to{};
                    if (to_sockaddr(j.host[i], &to)) send_control(j.mac, j.role.peer_id, kProbe, new_nonce(j.nonces, static_cast<int>(i), now), to);
                }
            }
            if (j.has_sel && now - j.last_keepalive >= kKeepaliveMs)
            {
                j.last_keepalive = now;
                joiner_control(j, kKeepalive, rng()(), j.selected, j.sel_relay);
                if (now - j.last_heard > 3 * kKeepaliveMs && !j.silent_warned)
                {
                    j.silent_warned = true;
                    Output::send<LogLevel::Warning>(STR("[p2p] join: host {} silent for {} s\n"), addr_text(j.selected), (now - j.last_heard) / 1000);
                }
            }
            if (j.has_sel && !j.reported && now - j.sel_at >= kReportAfterMs)
            {
                j.reported = true;
                push_report(Report{j.role.peer_id, "connected", j.path, j.rtt});
            }
            if (!j.has_sel && !j.host.empty() && !j.failed_reported && now - j.probe_start >= kProbeForMs)
            {
                j.failed_reported = true;
                Output::send<LogLevel::Warning>(STR("[p2p] join: no path to the host after {} s ({} candidates)\n"), kProbeForMs / 1000, j.host.size());
                push_report(Report{j.role.peer_id, "failed", "none", -1});
            }
            if ((j.stats.game_out.packets || j.stats.dropped) && now - j.last_stats > kStatsMs)
            {
                j.last_stats = now;
                Output::send<LogLevel::Verbose>(STR("[p2p] join: ({}) {}\n"), wide(j.path), j.stats.text());
            }
        }

        // A packet from the relay server. Callers hold g_mu.
        auto relay_packet(const char* buf, int n, uint64_t now) -> void
        {
            StunIn m;
            if (!g_relay || !stun_parse(buf, n, &m)) return;
            Relay& r = *g_relay;
            if (m.type == kTurnData) // the host's packet, relayed
            {
                sockaddr_in peer{};
                const std::string* data = m.get(kAttrData);
                if (data && xor_addr(m.get(kAttrPeer), &peer) && g_role == Role::Joiner && g_join)
                {
                    static uint64_t relayed_packets = 0;
                    if (relayed_packets++ == 0)
                        Output::send<LogLevel::Normal>(STR("[p2p] relay: first packet through the relay, from {} ({} bytes)\n"), addr_text(peer), data->size());
                    joiner_packet(data->data(), static_cast<int>(data->size()), peer, now, true);
                }
                return;
            }
            {
                std::lock_guard lock(g_turn_mu); // an Allocate answer relay_allocate waits for
                if (auto it = g_turn_answers.find(m.txid); it != g_turn_answers.end())
                {
                    it->second = m;
                    g_turn_cv.notify_all();
                    return;
                }
            }
            auto it = r.pending.find(m.txid);
            if (it == r.pending.end()) return;
            const auto [method, ip] = it->second;
            r.pending.erase(it);
            const int err = m.error();
            if (err == 438 && m.get(kAttrNonce)) // stale nonce: take the new one and ask again
            {
                r.nonce = *m.get(kAttrNonce);
                if (method == kTurnRefresh) relay_refresh(r, r.lifetime, now);
                else relay_permit(r, ip, now);
                return;
            }
            if (err)
            {
                sockaddr_in a{};
                a.sin_addr.s_addr = ip;
                Output::send<LogLevel::Warning>(STR("[p2p] relay: {} refused (error {}){}\n"), method == kTurnRefresh ? STR("refresh") : STR("permission"), err,
                                                method == kTurnRefresh ? std::wstring{} : std::format(L" for {}", wide(ip_text(a.sin_addr))));
                return;
            }
            if (method == kTurnPermission)
            {
                sockaddr_in a{};
                a.sin_addr.s_addr = ip;
                Output::send<LogLevel::Verbose>(STR("[p2p] relay: permission for {} granted\n"), wide(ip_text(a.sin_addr)));
            }
            if (method == kTurnRefresh)
                if (const std::string* lt = m.get(kAttrLifetime); lt && lt->size() == 4)
                {
                    uint32_t v = 0;
                    std::memcpy(&v, lt->data(), 4);
                    r.lifetime = std::max<uint32_t>(ntohl(v), 60);
                }
        }

        // ---- song transfers ---------------------------------------------------------------------------------
        // A transfer pair moves one song (its pak, then its .sig) between two players, beside whatever session role
        // the agent has: the same socket, header and HMAC, on channels 4 (control) and 5 (data), with the pair id
        // from fuserd's p2p/song/ signaling as the header's peer id. Both sides probe each other's candidates; a path
        // is set or moved only by an ack of a fresh probe, as for sessions.
        //
        //   control 1 probe / 2 ack [nonce 8]
        //   control 8 manifest [pak size 8][sig size 8][pak sha256 32][sig sha256 32][name length 1][name]
        //   control 9 acks [file 1][base 4][echo ts 4][bitmap 256]   chunks base.. of the 2048 after base, as bits
        //   control 10 done [ok 1]   control 11 cancel [reason length 1][reason]
        //   data [file 1][chunk 4][ts 4][payload]   file 0 = pak, 1 = sig; chunk i holds bytes i*1100.. of the file
        //
        // The sender resends the manifest until the receiver acks, then paces chunks: it starts at 256 KB/s and, once a
        // round trip, adds 25% (up to the cap) while under 5% of its packets were resends and the RTT is near its
        // minimum, or cuts 30% (never below 64 KB/s) when over 15% were resends or the RTT queues past twice the
        // minimum. Unacked chunks are resent after max(2 RTT + 50, 200) ms. The receiver keeps the files in memory
        // (the pak is at most 64 MB), acks every 8 chunks, within 20 ms of a chunk, and every 250 ms, and at the end
        // checks both sha256 values and the pak layout (pak_check.hpp) before writing them.
        // A pair with no path after 20 s, or no progress for 20 s, fails.
        enum : uint8_t
        {
            kXControl = 4,
            kXData = 5,
            kXManifest = 8,
            kXAcks = 9,
            kXDone = 10,
            kXCancel = 11,
        };
        constexpr uint32_t kXChunk = 1100, kXWindow = 2048, kXBitmap = kXWindow / 8;
        constexpr uint64_t kXSigMax = 1024 * 1024, kXNoPathMs = 20000, kXStallMs = 20000, kXAckEveryMs = 250, kXKeepMs = 60000;
        constexpr double kXStartRate = 256.0 * 1024, kXMinRate = 64.0 * 1024;

        auto sha256_hex(const char* data, size_t len) -> std::string
        {
            uint8_t d[32]{};
            bcrypt_digest(BCRYPT_SHA256_ALGORITHM, false, nullptr, 0, data, len, d, sizeof(d));
            std::string out;
            for (uint8_t b : d) out += std::format("{:02x}", b);
            return out;
        }
        auto hex_bytes(const std::string& hex, uint8_t* out, size_t n) -> bool
        {
            if (hex.size() != n * 2) return false;
            for (size_t i = 0; i < n; ++i)
            {
                const auto v = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
                const int hi = v(hex[2 * i]), lo = v(hex[2 * i + 1]);
                if (hi < 0 || lo < 0) return false;
                out[i] = static_cast<uint8_t>(hi << 4 | lo);
            }
            return true;
        }
        auto bytes_hex(const uint8_t* p, size_t n) -> std::string
        {
            std::string out;
            for (size_t i = 0; i < n; ++i) out += std::format("{:02x}", p[i]);
            return out;
        }
        auto song_name_ok(const std::string& name) -> bool // <X>_P
        {
            return name.size() > 2 && name.size() <= 98 && name.ends_with("_P") &&
                   name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == std::string::npos;
        }

        struct XFile
        {
            std::vector<char> bytes;
            uint64_t size = 0;
            uint32_t chunks = 0;
            std::vector<uint8_t> done;  // receiver: have it; sender: acked
            std::vector<uint64_t> sent; // sender: last sent (0 = never)
            uint32_t base = 0;          // the first chunk not done
            uint32_t next = 0;          // sender: the next never-sent chunk
            std::string sha;            // hex
            auto setup(uint64_t n, bool sender) -> void
            {
                size = n;
                chunks = static_cast<uint32_t>((n + kXChunk - 1) / kXChunk);
                done.assign(chunks, 0);
                if (sender) sent.assign(chunks, 0);
                else bytes.assign(static_cast<size_t>(n), 0);
                base = next = 0;
            }
            auto chunk_len(uint32_t i) const -> uint32_t { return static_cast<uint32_t>(std::min<uint64_t>(kXChunk, size - static_cast<uint64_t>(i) * kXChunk)); }
            auto complete() const -> bool { return base >= chunks; }
            auto advance() -> void
            {
                while (base < chunks && done[base]) ++base;
            }
        };

        struct Xfer
        {
            uint32_t id = 0;
            bool sending = false;
            Mac mac;
            std::vector<Candidate> peer;
            std::string name; // <X>_P
            // the path
            sockaddr_in remote{};
            bool has_remote = false;
            std::string path = "none";
            int rank = 9, rtt = -1;
            uint64_t started = 0, last_probe = 0, sel_at = 0, heard = 0;
            std::map<uint64_t, Sent> nonces;
            sockaddr_in pending{};
            bool has_pending = false;
            uint64_t pending_at = 0;
            // the files
            XFile files[2];
            bool manifest = false; // receiver: got it; sender: the receiver acked it
            uint64_t want_size[2]{};
            std::string want_sha[2];
            std::wstring dir;
            // sender pacing
            double rate = kXStartRate, tokens = 0, cap = 2048.0 * 1024;
            uint64_t refill_at = 0, epoch_at = 0, last_manifest = 0;
            int srtt = -1, min_rtt = -1;
            uint32_t epoch_sent = 0, epoch_resent = 0;
            double loss = -1; // the smoothed resend share (-1: none yet)
            // receiver acks
            uint32_t echo_ts = 0;
            int since_ack[2]{};
            uint64_t unacked_at[2]{}; // receiver: when the oldest chunk not yet acked arrived
            uint64_t last_ack = 0, last_done = 0;
            bool verdict = false; // receiver: the files checked out
            // progress
            uint64_t progress_at = 0, bytes = 0, transfer_start = 0, last_log = 0;
            std::string state = "probing", error;
            uint64_t finished_at = 0, finished_ms = 0;
            std::wstring pak_out, sig_out;
        };
        std::map<uint32_t, std::unique_ptr<Xfer>> g_xfers; // under g_mu

        auto xfer_total(const Xfer& x) -> uint64_t { return x.files[0].size + x.files[1].size; }
        auto xfer_label(const Xfer& x) -> std::wstring { return std::format(L"xfer {:08x} ({} {})", x.id, x.sending ? L"sending" : L"receiving", wide(x.name)); }

        auto xfer_control(Xfer& x, const char* body, size_t len, const sockaddr_in& to) -> void
        {
            std::vector<char> pkt;
            if (frame(x.mac, kXControl, x.id, body, len, pkt)) send_to(pkt, to);
        }
        auto xfer_probe(Xfer& x, const sockaddr_in& to, int index, uint64_t now, bool validate) -> void
        {
            char body[9]{};
            body[0] = static_cast<char>(kProbe);
            const uint64_t nonce = new_nonce(x.nonces, index, now, validate);
            std::memcpy(body + 1, &nonce, 8);
            xfer_control(x, body, sizeof(body), to);
        }
        auto xfer_finish(Xfer& x, bool ok, const std::string& error, uint64_t now) -> void
        {
            if (x.state == "done" || x.state == "failed") return;
            x.state = ok ? "done" : "failed";
            x.error = error;
            x.finished_at = now;
            x.finished_ms = x.transfer_start ? now - x.transfer_start : 0;
            const uint64_t total = xfer_total(x);
            if (ok)
                Output::send<LogLevel::Normal>(STR("[p2p] {}: done - {} bytes in {} ms ({} KB/s) via {} {}{}\n"), xfer_label(x), total, x.finished_ms,
                                               x.finished_ms ? total * 1000 / 1024 / x.finished_ms : 0, wide(x.path), addr_text(x.remote),
                                               x.sending ? std::wstring{} : L", sha256 and layout ok");
            else
                Output::send<LogLevel::Warning>(STR("[p2p] {}: failed - {} ({} of {} bytes)\n"), xfer_label(x), wide(error), x.bytes, total);
        }
        auto xfer_cancel_locked(Xfer& x, const std::string& reason) -> void
        {
            if (x.has_remote)
            {
                std::string body(1, static_cast<char>(kXCancel));
                body += static_cast<char>(std::min<size_t>(reason.size(), 100));
                body += reason.substr(0, 100);
                xfer_control(x, body.data(), body.size(), x.remote);
            }
        }

        // The path: as for sessions (host_set_path / joiner_select), with both sides probing.
        auto xfer_set_path(Xfer& x, const sockaddr_in& from, int index, uint64_t now) -> void
        {
            const std::string type = index >= 0 && index < static_cast<int>(x.peer.size()) ? x.peer[static_cast<size_t>(index)].type : "prflx";
            Output::send<LogLevel::Normal>(STR("[p2p] {}: {} via {} {}{}\n"), xfer_label(x), x.has_remote ? STR("path moved") : STR("path"), wide(path_of(type)),
                                           addr_text(from), x.rtt >= 0 ? std::format(L", rtt {} ms", x.rtt) : std::wstring{});
            if (!x.has_remote) x.sel_at = now;
            x.remote = from;
            x.has_remote = true;
            x.has_pending = false;
            x.heard = now;
            x.rank = rank_of(type);
            x.path = path_of(type);
            if (x.state == "probing")
            {
                x.state = "transferring";
                x.progress_at = now;
            }
        }
        auto xfer_validate(Xfer& x, const sockaddr_in& from, uint64_t now) -> void
        {
            if (x.has_pending && same(x.pending, from) && now - x.pending_at < kValidateEveryMs) return;
            x.pending = from;
            x.has_pending = true;
            x.pending_at = now;
            xfer_probe(x, from, match(x.peer, from), now, true);
        }

        auto xfer_send_manifest(Xfer& x, uint64_t now) -> void
        {
            std::string body(1, static_cast<char>(kXManifest));
            body.append(reinterpret_cast<const char*>(&x.files[0].size), 8);
            body.append(reinterpret_cast<const char*>(&x.files[1].size), 8);
            uint8_t sha[32]{};
            for (int f = 0; f < 2; ++f)
            {
                hex_bytes(x.files[f].sha, sha, 32);
                body.append(reinterpret_cast<const char*>(sha), 32);
            }
            body += static_cast<char>(x.name.size());
            body += x.name;
            xfer_control(x, body.data(), body.size(), x.remote);
            x.last_manifest = now;
        }
        auto xfer_send_acks(Xfer& x, int f) -> void
        {
            XFile& file = x.files[f];
            char body[1 + 1 + 4 + 4 + kXBitmap]{};
            body[0] = static_cast<char>(kXAcks);
            body[1] = static_cast<char>(f);
            std::memcpy(body + 2, &file.base, 4);
            std::memcpy(body + 6, &x.echo_ts, 4);
            for (uint32_t i = 0; i < kXWindow && file.base + i < file.chunks; ++i)
                if (file.done[file.base + i]) body[10 + i / 8] |= static_cast<char>(1 << (i % 8));
            xfer_control(x, body, sizeof(body), x.remote);
            x.since_ack[f] = 0;
            x.unacked_at[f] = 0;
        }

        // The receiver: both files in, then the checks, then write them.
        auto xfer_receive_end(Xfer& x, uint64_t now) -> void
        {
            std::string why;
            for (int f = 0; f < 2 && why.empty(); ++f)
            {
                const std::string got = sha256_hex(x.files[f].bytes.data(), x.files[f].bytes.size());
                if (got != x.files[f].sha) why = std::format("{} sha256 {} is not the offer's {}", f == 0 ? "pak" : "sig", got, x.files[f].sha);
            }
            std::error_code ec;
            const std::filesystem::path dir(x.dir);
            const std::filesystem::path pak = dir / (wide(x.name) + L".pak"), sig = dir / (wide(x.name) + L".sig");
            std::filesystem::path pak_part = pak;
            pak_part += L".part";
            if (why.empty())
            {
                std::filesystem::create_directories(dir, ec);
                std::ofstream out(pak_part, std::ios::binary | std::ios::trunc);
                out.write(x.files[0].bytes.data(), static_cast<std::streamsize>(x.files[0].bytes.size()));
                if (!out.good()) why = "cannot write " + pak_part.string();
            }
            if (why.empty() && !check_song_pak(pak_part.wstring(), x.name.substr(0, x.name.size() - 2), &why)) why = "pak layout: " + why;
            if (why.empty())
            {
                std::ofstream out(sig, std::ios::binary | std::ios::trunc);
                out.write(x.files[1].bytes.data(), static_cast<std::streamsize>(x.files[1].bytes.size()));
                out.close();
                if (!out.good()) why = "cannot write " + sig.string();
            }
            if (why.empty())
            {
                std::string note;
                const SigVerdict v = check_song_sig(pak_part.wstring(), sig.wstring(), &note);
                if (v == SigVerdict::Bad)
                {
                    why = "sig: " + note;
                    std::filesystem::remove(sig, ec);
                }
                else if (v == SigVerdict::Repaired)
                    Output::send<LogLevel::Warning>(STR("[p2p] {}: {}\n"), xfer_label(x), wide(note));
            }
            if (why.empty() && !MoveFileExW(pak_part.c_str(), pak.c_str(), MOVEFILE_REPLACE_EXISTING)) why = "cannot write " + pak.string();
            if (!why.empty()) std::filesystem::remove(pak_part, ec);
            x.verdict = why.empty();
            if (x.verdict)
            {
                x.pak_out = pak.wstring();
                x.sig_out = sig.wstring();
            }
            for (XFile& f : x.files) std::vector<char>().swap(f.bytes);
            const char body[2] = {static_cast<char>(kXDone), static_cast<char>(x.verdict ? 1 : 0)};
            xfer_control(x, body, sizeof(body), x.remote);
            x.last_done = now;
            xfer_finish(x, x.verdict, why.empty() ? std::string{} : "rejected: " + why, now);
        }

        auto xfer_packet(const char* buf, int n, const sockaddr_in& from, uint64_t now, uint8_t ch, uint32_t id) -> void
        {
            auto it = g_xfers.find(id);
            if (it == g_xfers.end()) return;
            Xfer& x = *it->second;
            if (!verify(x.mac, buf, n)) return;
            const char* p = buf + kHeader;
            const int len = n - static_cast<int>(kHeader + kTag);
            const bool on_path = x.has_remote && same(x.remote, from);
            if (on_path) x.heard = now;
            if (ch == kXControl && len >= 1)
            {
                const uint8_t sub = static_cast<uint8_t>(p[0]);
                if ((sub == kProbe || sub == kAck) && len >= 9)
                {
                    uint64_t nonce = 0;
                    std::memcpy(&nonce, p + 1, 8);
                    if (sub == kProbe)
                    {
                        char body[9]{};
                        body[0] = static_cast<char>(kAck);
                        std::memcpy(body + 1, &nonce, 8);
                        xfer_control(x, body, sizeof(body), from);
                        if (!on_path) xfer_validate(x, from, now);
                    }
                    else if (const auto s = take_nonce(x.nonces, nonce))
                    {
                        x.rtt = static_cast<int>(now - s->at);
                        const std::string type = s->index >= 0 && s->index < static_cast<int>(x.peer.size()) ? x.peer[static_cast<size_t>(s->index)].type : "prflx";
                        const bool quiet = x.has_remote && now - x.heard > kMoveSilentMs;
                        const bool better = x.has_remote && rank_of(type) < x.rank && now - x.sel_at <= kUpgradeMs;
                        if (!x.has_remote || (!on_path && (quiet || better || s->validate))) xfer_set_path(x, from, s->index, now);
                    }
                    return;
                }
                if (!on_path) xfer_validate(x, from, now);
                if (sub == kXCancel)
                {
                    const size_t rl = len >= 2 ? std::min<size_t>(static_cast<uint8_t>(p[1]), static_cast<size_t>(len - 2)) : 0;
                    xfer_finish(x, false, "the other side cancelled" + (rl ? ": " + std::string(p + 2, rl) : std::string{}), now);
                    return;
                }
                if (x.state == "done" || x.state == "failed") return;
                if (x.sending && sub == kXAcks && len >= static_cast<int>(10 + kXBitmap))
                {
                    const int f = static_cast<uint8_t>(p[1]);
                    if (f > 1) return;
                    XFile& file = x.files[f];
                    uint32_t base = 0, ts = 0;
                    std::memcpy(&base, p + 2, 4);
                    std::memcpy(&ts, p + 6, 4);
                    if (!x.manifest)
                    {
                        x.manifest = true;
                        x.transfer_start = x.refill_at = x.epoch_at = now;
                        Output::send<LogLevel::Normal>(STR("[p2p] {}: the receiver has the manifest; sending {} bytes\n"), xfer_label(x), xfer_total(x));
                    }
                    if (ts)
                    {
                        const int r = static_cast<int>(static_cast<uint32_t>(now) - ts);
                        if (r >= 0 && r < 30000)
                        {
                            x.srtt = x.srtt < 0 ? r : (7 * x.srtt + r) / 8;
                            x.min_rtt = x.min_rtt < 0 ? r : (std::min)(x.min_rtt, r);
                        }
                    }
                    bool advanced = false;
                    for (uint32_t i = file.base; i < (std::min)(base, file.chunks); ++i)
                        if (!file.done[i]) file.done[i] = 1, x.bytes += file.chunk_len(i), advanced = true;
                    for (uint32_t i = 0; i < kXWindow && base + i < file.chunks; ++i)
                        if ((static_cast<uint8_t>(p[10 + i / 8]) >> (i % 8) & 1) && !file.done[base + i])
                            file.done[base + i] = 1, x.bytes += file.chunk_len(base + i), advanced = true;
                    file.advance();
                    if (advanced) x.progress_at = now;
                    return;
                }
                if (x.sending && sub == kXDone && len >= 2)
                {
                    xfer_finish(x, p[1] != 0, p[1] ? std::string{} : "the receiver rejected the file", now);
                    return;
                }
                if (!x.sending && sub == kXManifest && len >= 1 + 16 + 64 + 1)
                {
                    if (!x.manifest)
                    {
                        uint64_t size[2]{};
                        std::memcpy(&size[0], p + 1, 8);
                        std::memcpy(&size[1], p + 9, 8);
                        const std::string sha[2] = {bytes_hex(reinterpret_cast<const uint8_t*>(p + 17), 32), bytes_hex(reinterpret_cast<const uint8_t*>(p + 49), 32)};
                        const size_t nl = static_cast<uint8_t>(p[81]);
                        const std::string name = len >= static_cast<int>(82 + nl) ? std::string(p + 82, nl) : std::string{};
                        std::string why;
                        if (!song_name_ok(name) || (!x.name.empty() && name != x.name)) why = "manifest names '" + name + "', not '" + x.name + "'";
                        else if (size[0] == 0 || size[0] > kMaxSongPakBytes || size[1] == 0 || size[1] > kXSigMax) why = "manifest sizes out of range";
                        else
                            for (int f = 0; f < 2; ++f)
                                if ((x.want_size[f] && x.want_size[f] != size[f]) || (!x.want_sha[f].empty() && x.want_sha[f] != sha[f]))
                                    why = "the manifest differs from the offer";
                        if (!why.empty())
                        {
                            xfer_cancel_locked(x, why);
                            xfer_finish(x, false, why, now);
                            return;
                        }
                        x.name = name;
                        for (int f = 0; f < 2; ++f)
                        {
                            x.files[f].setup(size[f], false);
                            x.files[f].sha = sha[f];
                        }
                        x.manifest = true;
                        x.transfer_start = x.progress_at = now;
                        Output::send<LogLevel::Normal>(STR("[p2p] {}: manifest - pak {} bytes, sig {} bytes\n"), xfer_label(x), size[0], size[1]);
                    }
                    xfer_send_acks(x, 0);
                    xfer_send_acks(x, 1);
                    x.last_ack = now;
                }
                return;
            }
            if (ch != kXData || x.sending) return;
            if (!on_path) xfer_validate(x, from, now);
            if (x.state == "done" || x.state == "failed")
            {
                if (now - x.last_done > 500) // the sender missed our verdict
                {
                    const char body[2] = {static_cast<char>(kXDone), static_cast<char>(x.verdict ? 1 : 0)};
                    xfer_control(x, body, sizeof(body), x.remote);
                    x.last_done = now;
                }
                return;
            }
            if (!x.manifest || len < 9) return;
            const int f = static_cast<uint8_t>(p[0]);
            if (f > 1) return;
            uint32_t index = 0, ts = 0;
            std::memcpy(&index, p + 1, 4);
            std::memcpy(&ts, p + 5, 4);
            XFile& file = x.files[f];
            const int plen = len - 9;
            if (index >= file.chunks || plen != static_cast<int>(file.chunk_len(index))) return;
            x.echo_ts = ts;
            if (!file.done[index])
            {
                std::memcpy(file.bytes.data() + static_cast<size_t>(index) * kXChunk, p + 9, static_cast<size_t>(plen));
                file.done[index] = 1;
                x.bytes += static_cast<uint64_t>(plen);
                x.progress_at = now;
                file.advance();
            }
            if (!x.since_ack[f]++) x.unacked_at[f] = now;
            if (x.since_ack[f] >= 8 || file.complete())
            {
                xfer_send_acks(x, f);
                x.last_ack = now;
            }
            if (x.files[0].complete() && x.files[1].complete()) xfer_receive_end(x, now);
        }

        // The sender's pacing: refill tokens at the current rate, resend what is overdue, then send new chunks.
        auto xfer_send_tick(Xfer& x, uint64_t now) -> void
        {
            if (!x.manifest)
            {
                if (now - x.last_manifest >= 500) xfer_send_manifest(x, now);
                return;
            }
            const uint64_t rtt = x.srtt > 0 ? static_cast<uint64_t>(x.srtt) : 100;
            // Once a round trip (at least 100 ms). Congestion on a home uplink shows first as queueing delay, and random
            // loss on Wi-Fi or mobile isn't congestion: so a queueing RTT (past 2x its minimum + 30 ms; the slack
            // absorbs the receiver's up-to-20 ms ack delay) or a smoothed resend share over 25% cuts the rate by 30%,
            // and otherwise, below 20% smoothed resends, it grows by 25%. A round trip that sent fewer than 4 new
            // chunks says nothing (window full behind a lost chunk, or the files done) and is skipped. (Tested with
            // FUSER_NATIVE_XferTestDrop=10: "halve on any resend" held 82 KB/s; per-round-trip shares 435 KB/s.)
            if (now - x.epoch_at >= std::max<uint64_t>(rtt, 100))
            {
                const uint32_t fresh = x.epoch_sent - x.epoch_resent;
                if (fresh >= 4)
                {
                    const double before = x.rate, loss = static_cast<double>(x.epoch_resent) / x.epoch_sent;
                    x.loss = x.loss < 0 ? loss : 0.75 * x.loss + 0.25 * loss;
                    const bool queueing = x.min_rtt >= 0 && x.srtt > 2 * x.min_rtt + 30;
                    if (queueing || x.loss > 0.25) x.rate = (std::max)(x.rate * 0.7, kXMinRate);
                    else if (x.loss < 0.20) x.rate = (std::min)(x.rate * 1.25, x.cap);
                    if (x.rate < before)
                        Output::send<LogLevel::Verbose>(STR("[p2p] {}: rate {} -> {} KB/s ({}; {}% resent, rtt {} ms, min {} ms)\n"), xfer_label(x),
                                                        static_cast<int>(before / 1024), static_cast<int>(x.rate / 1024), queueing ? STR("queueing") : STR("loss"),
                                                        static_cast<int>(x.loss * 100), x.srtt, x.min_rtt);
                }
                x.epoch_at = now;
                x.epoch_sent = x.epoch_resent = 0;
            }
            x.tokens = (std::min)(x.tokens + x.rate * static_cast<double>(now - x.refill_at) / 1000.0, (std::max)(x.rate * 0.05, 16.0 * kXChunk));
            x.refill_at = now;
            const uint64_t rto = x.srtt > 0 ? std::max<uint64_t>(2 * static_cast<uint64_t>(x.srtt) + 50, 200) : 1000;
            std::vector<char> pkt;
            char data[9 + kXChunk];
            // Test only: FUSER_NATIVE_XferTestDrop=<percent> drops that share of data packets, to exercise resends and
            // the back-off (an environment variable, so no ini setting can turn it on in normal play).
            static const int drop_pct = [] {
                wchar_t v[8]{};
                return GetEnvironmentVariableW(L"FUSER_NATIVE_XferTestDrop", v, 8) ? (std::min)(_wtoi(v), 90) : 0;
            }();
            const auto send_chunk = [&](int f, uint32_t i) {
                XFile& file = x.files[f];
                const uint32_t clen = file.chunk_len(i), ts = static_cast<uint32_t>(now) | 1;
                data[0] = static_cast<char>(f);
                std::memcpy(data + 1, &i, 4);
                std::memcpy(data + 5, &ts, 4);
                std::memcpy(data + 9, file.bytes.data() + static_cast<size_t>(i) * kXChunk, clen);
                const bool dropped = drop_pct > 0 && static_cast<int>(rng()() % 100) < drop_pct;
                if (!dropped && frame(x.mac, kXData, x.id, data, 9 + clen, pkt)) send_to(pkt, x.remote);
                file.sent[i] = now;
                ++x.epoch_sent;
                x.tokens -= clen;
            };
            for (int f = 0; f < 2 && x.tokens >= kXChunk; ++f) // overdue resends first
            {
                XFile& file = x.files[f];
                for (uint32_t i = file.base; i < file.next && x.tokens >= kXChunk; ++i)
                    if (!file.done[i] && now - file.sent[i] > rto)
                    {
                        send_chunk(f, i);
                        ++x.epoch_resent;
                    }
            }
            for (int f = 0; f < 2 && x.tokens >= kXChunk; ++f) // then new ones, the pak first
            {
                XFile& file = x.files[f];
                while (x.tokens >= kXChunk && file.next < file.chunks && file.next < file.base + kXWindow) send_chunk(f, file.next++);
                if (file.next < file.chunks) break; // finish the pak before the sig
            }
        }

        auto xfer_tick(uint64_t now) -> void
        {
            for (auto it = g_xfers.begin(); it != g_xfers.end();)
            {
                Xfer& x = *it->second;
                if (x.state == "done" || x.state == "failed")
                {
                    if (now - x.finished_at > kXKeepMs) it = g_xfers.erase(it); // nobody collected it
                    else ++it;
                    continue;
                }
                // probe the peer's candidates until there is a path, and for a second after (a LAN path may answer)
                if ((!x.has_remote || now - x.sel_at < kUpgradeMs) && now - x.last_probe >= kProbeEveryMs)
                {
                    x.last_probe = now;
                    for (size_t i = 0; i < x.peer.size(); ++i)
                    {
                        sockaddr_in to{};
                        if (to_sockaddr(x.peer[i], &to)) xfer_probe(x, to, static_cast<int>(i), now, false);
                    }
                }
                if (!x.has_remote)
                {
                    if (now - x.started > kXNoPathMs) xfer_finish(x, false, std::format("no path after {} s ({} candidates)", kXNoPathMs / 1000, x.peer.size()), now);
                    ++it;
                    continue;
                }
                if (x.sending) xfer_send_tick(x, now);
                else if (x.manifest)
                {
                    for (int f = 0; f < 2; ++f) // a chunk waits at most 20 ms for its ack (else the RTT the sender sees grows)
                        if (x.since_ack[f] && now - x.unacked_at[f] >= 20) xfer_send_acks(x, f);
                }
                if (!x.sending && x.manifest && now - x.last_ack >= kXAckEveryMs)
                {
                    xfer_send_acks(x, 0);
                    xfer_send_acks(x, 1);
                    x.last_ack = now;
                }
                if (x.progress_at && now - x.progress_at > kXStallMs)
                {
                    xfer_cancel_locked(x, "stalled");
                    xfer_finish(x, false, std::format("stalled: no progress for {} s", kXStallMs / 1000), now);
                }
                else if (x.manifest && now - x.last_log >= 5000 && x.state == "transferring")
                {
                    x.last_log = now;
                    const uint64_t total = xfer_total(x), ms = now - x.transfer_start;
                    Output::send<LogLevel::Verbose>(STR("[p2p] {}: {}% ({} of {} bytes), {} KB/s{}, rtt {} ms\n"), xfer_label(x), total ? x.bytes * 100 / total : 0,
                                                    x.bytes, total, ms ? x.bytes * 1000 / 1024 / ms : 0,
                                                    x.sending ? std::format(L" (rate {} KB/s)", static_cast<int>(x.rate / 1024)) : std::wstring{}, x.sending ? x.srtt : x.rtt);
                }
                ++it;
            }
        }
        auto xfer_busy() -> bool // a transfer is moving bytes: the loop wakes every few ms (pacing, prompt acks)
        {
            for (const auto& [id, x] : g_xfers)
                if (x->manifest && x->state == "transferring") return true;
            return false;
        }

        // ---- the loop ---------------------------------------------------------------------------------------
        auto loop() -> void
        {
            std::vector<char> buf(kMaxDatagram + kHeader + kTag);
            for (;;)
            {
                fd_set rd;
                FD_ZERO(&rd);
                FD_SET(g_sock, &rd);
                bool pacing = false;
                {
                    std::lock_guard lock(g_mu);
                    pacing = xfer_busy();
                    for (SOCKET s : g_close) closesocket(s);
                    g_close.clear();
                    if (g_role == Role::Host)
                        for (auto& [id, p] : g_peers)
                        {
                            if (p->game != INVALID_SOCKET) FD_SET(p->game, &rd);
                            if (p->beacon != INVALID_SOCKET) FD_SET(p->beacon, &rd);
                        }
                    if (g_role == Role::Joiner && g_join)
                    {
                        FD_SET(g_join->game, &rd);
                        FD_SET(g_join->beacon, &rd);
                    }
                }
                timeval tv{0, pacing ? 2000 : 50000}; // a song upload paces its chunks: wake every 2 ms
                if (select(0, &rd, nullptr, nullptr, &tv) == SOCKET_ERROR)
                {
                    Sleep(10); // a socket closed under us; the next round rebuilds the set
                    continue;
                }
                const uint64_t now = now_ms();
                if (FD_ISSET(g_sock, &rd))
                {
                    sockaddr_in from{};
                    int fl = sizeof(from);
                    const int n = recvfrom(g_sock, buf.data(), static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&from), &fl);
                    bool from_relay = false;
                    if (n > 0)
                    {
                        std::lock_guard lock(g_mu);
                        from_relay = g_relay && same(from, g_relay->server);
                        if (from_relay) relay_packet(buf.data(), n, now);
                    }
                    if (!from_relay && n > 0 && is_stun(buf.data(), n))
                    {
                        std::string txid;
                        sockaddr_in mapped{};
                        if (stun_answer(buf.data(), n, &txid, &mapped))
                        {
                            std::lock_guard lock(g_stun_mu);
                            if (auto it = g_stun_answers.find(txid); it != g_stun_answers.end())
                            {
                                it->second = mapped;
                                g_stun_cv.notify_all();
                            }
                        }
                    }
                    else if (!from_relay && n > 0)
                    {
                        std::lock_guard lock(g_mu);
                        uint8_t ch = 0;
                        uint32_t id = 0;
                        if (header(buf.data(), n, &ch, &id) && (ch == kXControl || ch == kXData)) xfer_packet(buf.data(), n, from, now, ch, id);
                        else if (g_role == Role::Host) host_packet(buf.data(), n, from, now);
                        else if (g_role == Role::Joiner && g_join) joiner_packet(buf.data(), n, from, now, false);
                    }
                }
                std::lock_guard lock(g_mu);
                xfer_tick(now); // song transfers run beside any role
                if (g_role == Role::Host)
                {
                    for (auto& [id, pp] : g_peers)
                    {
                        Peer& p = *pp;
                        for (auto [sock, channel] : {std::pair{p.game, kGame}, std::pair{p.beacon, kBeacon}})
                        {
                            if (sock == INVALID_SOCKET || !FD_ISSET(sock, &rd)) continue;
                            const int n = recv(sock, buf.data(), static_cast<int>(kMaxDatagram), 0);
                            if (n <= 0 || !p.has_remote) continue;
                            (channel == kGame ? p.stats.game_in : p.stats.beacon_in).add(n);
                            std::vector<char> pkt;
                            if (frame(p.mac, channel, p.id, buf.data(), static_cast<size_t>(n), pkt)) send_to(pkt, p.remote);
                        }
                    }
                    host_tick(now);
                }
                else if (g_role == Role::Joiner && g_join)
                {
                    Joiner& j = *g_join;
                    for (auto [sock, channel] : {std::pair{j.game, kGame}, std::pair{j.beacon, kBeacon}})
                    {
                        if (sock == INVALID_SOCKET || !FD_ISSET(sock, &rd)) continue;
                        sockaddr_in from{};
                        int fl = sizeof(from);
                        const int n = recvfrom(sock, buf.data(), static_cast<int>(kMaxDatagram), 0, reinterpret_cast<sockaddr*>(&from), &fl);
                        if (n > 0) joiner_local(j, sock, channel, buf.data(), n, from);
                    }
                    joiner_tick(now);
                }
            }
        }

        auto drop_role_locked() -> void
        {
            if (g_role == Role::Joiner && g_join)
            {
                Joiner& j = *g_join;
                if (j.has_sel)
                {
                    std::vector<char> pkt;
                    if (frame(j.mac, kBye, j.role.peer_id, nullptr, 0, pkt)) joiner_send(pkt, j.selected, j.sel_relay);
                }
                Output::send<LogLevel::Normal>(STR("[p2p] join: role ended ({}); {}\n"), wide(j.path), j.stats.text());
                close_later(j.game);
                close_later(j.beacon);
                g_join.reset();
            }
            relay_release_locked();
            for (auto& [id, p] : g_peers)
            {
                close_later(p->game);
                close_later(p->beacon);
            }
            g_peers.clear();
            g_role = Role::None;
        }
    } // namespace

    // ---- public -------------------------------------------------------------------------------------------------
    auto open(uint16_t port) -> bool
    {
        std::call_once(g_open_once, [port] {
            if (!wsa_ready())
            {
                Output::send<LogLevel::Error>(STR("[p2p] Winsock unavailable\n"));
                return;
            }
            sockaddr_in any{};
            any.sin_family = AF_INET;
            any.sin_addr.s_addr = htonl(INADDR_ANY);
            any.sin_port = htons(port);
            g_sock = udp_socket(any);
            if (g_sock == INVALID_SOCKET)
            {
                Output::send<LogLevel::Error>(STR("[p2p] cannot bind the tunnel socket to UDP {} (error {})\n"), port, WSAGetLastError());
                return;
            }
            g_port = bound_port(g_sock);
            g_open_result = true;
            Output::send<LogLevel::Normal>(STR("[p2p] tunnel socket on UDP 0.0.0.0:{}\n"), g_port);
            std::thread(loop).detach();
        });
        return g_open_result;
    }

    auto local_port() -> uint16_t { return g_port; }

    auto stun(const std::vector<std::pair<std::wstring, uint16_t>>& servers) -> StunResult
    {
        StunResult r{};
        std::vector<std::optional<sockaddr_in>> seen;
        for (const auto& [host, port] : servers)
        {
            sockaddr_in to{};
            if (!resolve(host, port, &to))
            {
                r.detail += std::format(L" {}:{} unresolved;", host, port);
                seen.emplace_back();
                continue;
            }
            char req[20]{};
            req[1] = 0x01; // Binding request, no attributes
            const uint32_t cookie = htonl(kStunCookie);
            std::memcpy(req + 4, &cookie, 4);
            for (int i = 8; i < 20; ++i) req[i] = static_cast<char>(rng()());
            const std::string txid(req + 8, 12);
            std::optional<sockaddr_in> got;
            {
                std::unique_lock lock(g_stun_mu);
                g_stun_answers[txid] = sockaddr_in{};
            }
            for (int attempt = 0; attempt < 3 && !got; ++attempt)
            {
                sendto(g_sock, req, sizeof(req), 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
                std::unique_lock lock(g_stun_mu);
                g_stun_cv.wait_for(lock, std::chrono::milliseconds(500), [&] { return g_stun_answers[txid].sin_family == AF_INET; });
                if (g_stun_answers[txid].sin_family == AF_INET) got = g_stun_answers[txid];
            }
            {
                std::lock_guard lock(g_stun_mu);
                g_stun_answers.erase(txid);
            }
            r.detail += got ? std::format(L" {} sees {};", addr_text(to), addr_text(*got)) : std::format(L" {} no answer;", addr_text(to));
            seen.push_back(got);
        }
        for (const auto& s : seen)
        {
            if (!s) continue;
            const Candidate c{"srflx", ip_text(s->sin_addr), ntohs(s->sin_port)};
            if (std::none_of(r.srflx.begin(), r.srflx.end(), [&](const Candidate& x) { return x.ip == c.ip && x.port == c.port; })) r.srflx.push_back(c);
        }
        const auto& a = seen.size() > 0 ? seen[0] : std::optional<sockaddr_in>{};
        const auto& b = seen.size() > 1 ? seen[1] : std::optional<sockaddr_in>{};
        const auto is_local = [](const sockaddr_in& m) {
            if (ntohs(m.sin_port) != g_port) return false;
            for (const Candidate& c : interface_candidates(true))
                if (c.ip == ip_text(m.sin_addr)) return true;
            return false;
        };
        if (!a || !b) r.mapping = a && is_local(*a) ? "none" : "unknown";
        else if (!same(*a, *b)) r.mapping = "endpoint-dependent";
        else r.mapping = is_local(*a) ? "none" : "endpoint-independent";
        return r;
    }

    // Only adapters with a default gateway, unless all: host-only virtual adapters (VirtualBox, Hyper-V, WSL) have
    // none, and their addresses only gave the other side probes that could never land.
    auto interface_candidates(bool all, std::vector<std::wstring>* skipped) -> std::vector<Candidate>
    {
        std::vector<Candidate> out;
        ULONG size = 16 * 1024;
        std::vector<uint8_t> buf(size);
        auto* list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
        ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, list, &size);
        if (rc == ERROR_BUFFER_OVERFLOW)
        {
            buf.resize(size);
            list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
            rc = GetAdaptersAddresses(AF_INET, flags, nullptr, list, &size);
        }
        if (rc != NO_ERROR) return out;
        for (auto* a = list; a && out.size() < 4; a = a->Next)
        {
            if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (!all && !a->FirstGatewayAddress)
            {
                if (skipped && a->FriendlyName) skipped->push_back(a->FriendlyName);
                continue;
            }
            for (auto* u = a->FirstUnicastAddress; u && out.size() < 4; u = u->Next)
            {
                if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
                const auto* in = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
                const uint32_t ip = ntohl(in->sin_addr.s_addr);
                if ((ip >> 24) == 127 || (ip >> 16) == 0xA9FE || ip == 0) continue; // loopback, link-local
                out.push_back(Candidate{"host", ip_text(in->sin_addr), g_port});
            }
        }
        return out;
    }

    auto become_host(const HostRole& role) -> void
    {
        std::lock_guard lock(g_mu);
        drop_role_locked();
        g_host_role = role;
        g_role = Role::Host;
        Output::send<LogLevel::Normal>(STR("[p2p] host: forwarding to FUSER game 127.0.0.1:{}, beacon 127.0.0.1:{}{}\n"), role.game_port, role.beacon_port,
                                       role.accept_unknown ? STR(" (manual mode: any peer)") : STR(""));
    }

    auto set_peers(const std::vector<PeerInfo>& peers) -> void
    {
        std::lock_guard lock(g_mu);
        if (g_role != Role::Host) return;
        const uint64_t now = now_ms();
        for (auto it = g_peers.begin(); it != g_peers.end();)
        {
            const bool kept = !it->second->signaled ||
                              std::any_of(peers.begin(), peers.end(), [&](const PeerInfo& p) { return p.id == it->first; });
            if (kept)
            {
                ++it;
                continue;
            }
            Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} left the session; {}\n"), it->first, it->second->stats.text());
            close_later(it->second->game);
            close_later(it->second->beacon);
            it = g_peers.erase(it);
        }
        for (const PeerInfo& info : peers)
        {
            auto& slot = g_peers[info.id];
            const bool fresh = !slot;
            if (fresh)
            {
                slot = std::make_unique<Peer>();
                slot->id = info.id;
                slot->probe_start = now;
            }
            Peer& p = *slot;
            p.signaled = true;
            p.mac.init(info.key);
            const bool changed = p.cands.size() != info.candidates.size() ||
                                 !std::equal(p.cands.begin(), p.cands.end(), info.candidates.begin(),
                                             [](const Candidate& a, const Candidate& b) { return a.ip == b.ip && a.port == b.port && a.type == b.type; });
            if (changed)
            {
                p.cands = info.candidates;
                if (!p.has_remote) p.probe_start = now, p.failed_reported = false;
                else if (!fresh) p.reprobe_until = now + kProbeForMs; // it registered again (its network changed): probe the new ones
                std::wstring list;
                for (const Candidate& c : p.cands) list += std::format(L" {} {}:{}", wide(c.type), wide(c.ip), c.port);
                Output::send<LogLevel::Normal>(STR("[p2p] host: peer {:08x} {}:{}\n"), p.id, fresh ? STR("joins, candidates") : STR("candidates now"), list);
            }
        }
    }

    auto become_joiner(const JoinRole& role) -> bool
    {
        std::lock_guard lock(g_mu);
        drop_role_locked();
        // Free the local ports now (a previous joiner held them); the loop copes with a socket closed mid-select.
        for (SOCKET s : g_close) closesocket(s);
        g_close.clear();
        auto j = std::make_unique<Joiner>();
        j->role = role;
        j->mac.init(role.key);
        j->game = udp_socket(loopback(role.local_port));
        j->beacon = udp_socket(loopback(static_cast<uint16_t>(role.local_port + 100)));
        if (j->game == INVALID_SOCKET || j->beacon == INVALID_SOCKET)
        {
            Output::send<LogLevel::Error>(STR("[p2p] join: cannot bind 127.0.0.1:{}/{} (error {})\n"), role.local_port, role.local_port + 100, WSAGetLastError());
            close_later(j->game);
            close_later(j->beacon);
            return false;
        }
        Output::send<LogLevel::Normal>(STR("[p2p] join: peer {:08x}; FUSER joins 127.0.0.1:{} (beacon {})\n"), role.peer_id, role.local_port,
                                       role.local_port + 100);
        g_join = std::move(j);
        g_role = Role::Joiner;
        return true;
    }

    auto set_host(const std::vector<Candidate>& candidates) -> void
    {
        std::lock_guard lock(g_mu);
        if (g_role != Role::Joiner || !g_join) return;
        Joiner& j = *g_join;
        const bool changed = j.host.size() != candidates.size() ||
                             !std::equal(j.host.begin(), j.host.end(), candidates.begin(),
                                         [](const Candidate& a, const Candidate& b) { return a.ip == b.ip && a.port == b.port && a.type == b.type; });
        if (!changed) return;
        j.host = candidates;
        // New candidates (the host registered again: its network changed): probe them, even with a path.
        if (!j.has_sel) j.probe_start = now_ms(), j.failed_reported = false, j.last_probe = 0;
        else j.reprobe = true, j.probe_start = now_ms(), j.last_probe = 0;
        std::wstring list;
        for (const Candidate& c : j.host) list += std::format(L" {} {}:{}", wide(c.type), wide(c.ip), c.port);
        Output::send<LogLevel::Normal>(STR("[p2p] join: host candidates:{}\n"), list);
    }

    auto joiner_connected() -> bool
    {
        std::lock_guard lock(g_mu);
        return g_role == Role::Joiner && g_join && g_join->has_sel;
    }

    auto stop() -> void
    {
        std::lock_guard lock(g_mu);
        drop_role_locked();
    }

    auto relay_allocate(const RelayInfo& info) -> std::optional<Candidate>
    {
        sockaddr_in server{};
        if (!resolve(info.host, info.port, &server))
        {
            Output::send<LogLevel::Warning>(STR("[p2p] relay: cannot resolve {}\n"), info.host);
            return {};
        }
        {
            std::lock_guard lock(g_mu);
            if (g_role != Role::Joiner) return {};
            relay_release_locked();
            g_relay = std::make_unique<Relay>();
            g_relay->server = server;
            g_relay->username = info.username;
            g_relay->password = info.password;
            g_relay->realm = info.realm;
        }
        // One Allocate transaction (REQUESTED-TRANSPORT UDP), answered through g_turn_answers.
        const auto allocate = [&](bool auth) -> std::optional<StunIn> {
            const std::string txid = new_txid();
            StunOut m(kTurnAllocate, txid);
            const uint8_t udp[4] = {17, 0, 0, 0};
            m.attr(kAttrTransport, udp, sizeof(udp));
            {
                std::lock_guard lock(g_mu);
                if (!g_relay) return {};
                if (auth) relay_auth(*g_relay, m);
                std::lock_guard tlock(g_turn_mu);
                g_turn_answers[txid] = StunIn{};
            }
            std::optional<StunIn> got;
            for (int attempt = 0; attempt < 3 && !got; ++attempt)
            {
                sendto(g_sock, reinterpret_cast<const char*>(m.b.data()), static_cast<int>(m.b.size()), 0, reinterpret_cast<const sockaddr*>(&server),
                       sizeof(server));
                std::unique_lock lock(g_turn_mu);
                if (g_turn_cv.wait_for(lock, std::chrono::milliseconds(700), [&] { return g_turn_answers[txid].type != 0; })) got = g_turn_answers[txid];
            }
            std::lock_guard lock(g_turn_mu);
            g_turn_answers.erase(txid);
            return got;
        };
        auto answer = allocate(false);
        for (int round = 0; answer && (answer->error() == 401 || answer->error() == 438) && round < 2; ++round)
        {
            std::lock_guard lock(g_mu);
            if (!g_relay) return {};
            if (const std::string* realm = answer->get(kAttrRealm)) g_relay->realm = *realm;
            if (const std::string* nonce = answer->get(kAttrNonce)) g_relay->nonce = *nonce;
            relay_key(*g_relay);
        }
        if (answer && answer->error() != 0) answer = allocate(true);
        if (answer && answer->error() == 438)
        {
            {
                std::lock_guard lock(g_mu);
                if (g_relay && answer->get(kAttrNonce)) g_relay->nonce = *answer->get(kAttrNonce);
            }
            answer = allocate(true);
        }
        sockaddr_in relayed{};
        if (!answer || answer->type != 0x0103 || !xor_addr(answer->get(kAttrRelayed), &relayed))
        {
            Output::send<LogLevel::Warning>(STR("[p2p] relay: allocation on {} failed ({})\n"), addr_text(server),
                                            answer ? std::format(L"error {}", answer->error()) : std::wstring(L"no answer"));
            std::lock_guard lock(g_mu);
            g_relay.reset();
            return {};
        }
        std::lock_guard lock(g_mu);
        if (!g_relay) return {};
        g_relay->relayed = relayed;
        g_relay->allocated = true;
        g_relay->refreshed_at = now_ms();
        if (const std::string* lt = answer->get(kAttrLifetime); lt && lt->size() == 4)
        {
            uint32_t v = 0;
            std::memcpy(&v, lt->data(), 4);
            g_relay->lifetime = std::max<uint32_t>(ntohl(v), 60);
        }
        Output::send<LogLevel::Normal>(STR("[p2p] relay: allocated {} on {} (lifetime {} s)\n"), addr_text(relayed), addr_text(server), g_relay->lifetime);
        return Candidate{"relay", ip_text(relayed.sin_addr), ntohs(relayed.sin_port)};
    }

    auto take_reports() -> std::vector<Report>
    {
        // (Nothing collects them in the manual test mode; the queue is capped below.)
        std::lock_guard lock(g_mu);
        return std::exchange(g_reports, {});
    }

    // ---- song transfers -----------------------------------------------------------------------------------------
    auto file_digest(const std::wstring& path, uint64_t* size, std::string* sha256) -> bool
    {
        std::ifstream in(std::filesystem::path(path), std::ios::binary);
        if (!in) return false;
        std::vector<char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        *size = bytes.size();
        *sha256 = sha256_hex(bytes.data(), bytes.size());
        return true;
    }

    auto xfer_send(const XferSend& s) -> bool
    {
        if (!song_name_ok(s.name) || s.pair_id == 0)
        {
            Output::send<LogLevel::Error>(STR("[p2p] xfer: bad send request (name '{}', pair {:08x})\n"), wide(s.name), s.pair_id);
            return false;
        }
        auto x = std::make_unique<Xfer>();
        x->id = s.pair_id;
        x->sending = true;
        x->name = s.name;
        x->peer = s.peer;
        x->cap = (std::max)(static_cast<double>(s.cap_kbps), 64.0) * 1024;
        x->mac.init(s.key);
        std::string why;
        if (!check_song_pak(s.pak, s.name.substr(0, s.name.size() - 2), &why))
        {
            Output::send<LogLevel::Warning>(STR("[p2p] xfer {:08x}: not sending {} - its pak fails the layout check: {}\n"), s.pair_id, s.pak, wide(why));
            return false;
        }
        const std::wstring paths[2] = {s.pak, s.sig};
        for (int f = 0; f < 2; ++f)
        {
            std::ifstream in(std::filesystem::path(paths[f]), std::ios::binary);
            std::vector<char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            if (!in.good() && !in.eof() || bytes.empty() || bytes.size() > (f == 0 ? kMaxSongPakBytes : kXSigMax))
            {
                Output::send<LogLevel::Warning>(STR("[p2p] xfer {:08x}: cannot send {} ({} bytes)\n"), s.pair_id, paths[f], bytes.size());
                return false;
            }
            x->files[f].setup(bytes.size(), true);
            x->files[f].sha = sha256_hex(bytes.data(), bytes.size());
            x->files[f].bytes = std::move(bytes);
        }
        std::lock_guard lock(g_mu);
        if (g_xfers.contains(s.pair_id)) return false;
        x->started = now_ms();
        Output::send<LogLevel::Normal>(STR("[p2p] {}: pak {} bytes, sig {} bytes, cap {} KB/s; probing {} candidate(s)\n"), xfer_label(*x), x->files[0].size,
                                       x->files[1].size, s.cap_kbps, x->peer.size());
        g_xfers[s.pair_id] = std::move(x);
        return true;
    }

    auto xfer_recv(const XferRecv& r) -> bool
    {
        if ((!r.name.empty() && !song_name_ok(r.name)) || r.pair_id == 0 || r.dir.empty() || r.pak_size > kMaxSongPakBytes || r.sig_size > kXSigMax)
        {
            Output::send<LogLevel::Error>(STR("[p2p] xfer: bad receive request (name '{}', pair {:08x}, pak {} bytes)\n"), wide(r.name), r.pair_id, r.pak_size);
            return false;
        }
        auto x = std::make_unique<Xfer>();
        x->id = r.pair_id;
        x->name = r.name;
        x->peer = r.peer;
        x->dir = r.dir;
        x->want_size[0] = r.pak_size;
        x->want_size[1] = r.sig_size;
        x->want_sha[0] = r.pak_sha256;
        x->want_sha[1] = r.sig_sha256;
        x->mac.init(r.key);
        std::lock_guard lock(g_mu);
        if (g_xfers.contains(r.pair_id)) return false;
        x->started = now_ms();
        Output::send<LogLevel::Normal>(STR("[p2p] {}: expecting pak {} bytes into {}; probing {} candidate(s)\n"), xfer_label(*x), r.pak_size, r.dir, x->peer.size());
        g_xfers[r.pair_id] = std::move(x);
        return true;
    }

    auto xfer_set_peer(uint32_t pair_id, const std::vector<Candidate>& peer) -> void
    {
        std::lock_guard lock(g_mu);
        auto it = g_xfers.find(pair_id);
        if (it == g_xfers.end()) return;
        Xfer& x = *it->second;
        const bool changed = x.peer.size() != peer.size() ||
                             !std::equal(x.peer.begin(), x.peer.end(), peer.begin(), [](const Candidate& a, const Candidate& b) { return a.ip == b.ip && a.port == b.port; });
        if (!changed) return;
        x.peer = peer;
        x.last_probe = 0;
        if (x.has_remote) x.sel_at = now_ms(); // probe the new ones for a second; a validated answer moves the path
    }

    auto xfer_cancel(uint32_t pair_id) -> void
    {
        std::lock_guard lock(g_mu);
        auto it = g_xfers.find(pair_id);
        if (it == g_xfers.end()) return;
        if (it->second->state != "done" && it->second->state != "failed") xfer_cancel_locked(*it->second, "cancelled");
        g_xfers.erase(it);
    }

    auto xfer_status() -> std::vector<XferStatus>
    {
        std::lock_guard lock(g_mu);
        std::vector<XferStatus> out;
        const uint64_t now = now_ms();
        for (const auto& [id, x] : g_xfers)
        {
            XferStatus s{};
            s.pair_id = id;
            s.sending = x->sending;
            s.name = x->name;
            s.state = x->state;
            s.error = x->error;
            s.path = x->path;
            s.bytes = x->bytes;
            s.total = xfer_total(*x);
            s.rate_kbps = x->sending ? static_cast<uint32_t>(x->rate / 1024) : 0;
            s.rtt_ms = x->sending ? x->srtt : x->rtt;
            s.ms = x->finished_ms ? x->finished_ms : x->transfer_start ? now - x->transfer_start : 0;
            s.pak_out = x->pak_out;
            s.sig_out = x->sig_out;
            out.push_back(std::move(s));
        }
        return out;
    }

    // ---- manual mode (endpoints from the ini) -----------------------------------------------------------------
    auto start_host(const HostConfig& cfg) -> bool
    {
        if (!open(cfg.listen_port)) return false;
        become_host(HostRole{cfg.game_port, cfg.beacon_port, true});
        return true;
    }

    auto start_join(const JoinConfig& cfg) -> bool
    {
        const size_t colon = cfg.host.rfind(L':');
        sockaddr_in host{};
        if (colon == std::wstring::npos || !wsa_ready() || !resolve(cfg.host.substr(0, colon), static_cast<uint16_t>(_wtoi(cfg.host.c_str() + colon + 1)), &host))
        {
            Output::send<LogLevel::Error>(STR("[p2p] join: bad host address '{}'\n"), cfg.host);
            return false;
        }
        if (!open(0)) return false;
        JoinRole role{};
        role.local_port = cfg.local_port;
        role.peer_id = static_cast<uint32_t>(rng()()) | 1;
        if (!become_joiner(role)) return false;
        set_host({Candidate{"host", ip_text(host.sin_addr), ntohs(host.sin_port)}});
        return true;
    }
} // namespace p2p
