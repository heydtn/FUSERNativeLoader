#pragma once

// The P2P tunnel agent. FUSER's own UDP sockets are left alone: the game talks to the
// agent over localhost, and the agent carries the datagrams to the other machine over one UDP socket - the same
// socket that learned its public endpoint from fuserd's STUN service and punched through the NATs.
//
//   joiner:  FUSER -> 127.0.0.1:P (game) / P+100 (beacon) -> tunnel socket  ==UDP==>  host tunnel socket
//   host:    tunnel socket -> one local socket per remote peer -> 127.0.0.1:game_port / beacon_port -> FUSER host
//
// Every packet: an 8-byte header ("FT", version 2, channel, 4-byte peer id), the payload, then an 8-byte HMAC-SHA256
// tag over the rest with the pair's key (from fuserd's signaling; all zero in the manual test mode).
//
// Connection: both sides send authenticated probes to every candidate of the other (host interface addresses,
// STUN-mapped ones, the joiner's relay address) until one is acknowledged; a LAN candidate that answers within a
// second of the first wins over a public one. A path is only ever set or moved by an ack of a fresh probe of this
// side's own: traffic from a new address (NAT rebinding, a changed network) is followed once a probe to that
// address is answered, so a replayed packet can't redirect a pair. A quiet path is probed again.
//
// One agent per process. The socket and its thread live until the process exits; roles come and go.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace p2p
{
    struct Candidate
    {
        std::string type; // "host" (an interface address), "srflx" (seen by STUN), "relay" (a TURN allocation)
        std::string ip;
        uint16_t port = 0;
    };
    using Key = std::array<uint8_t, 32>;

    struct StunResult
    {
        std::vector<Candidate> srflx; // distinct public endpoints seen
        std::string mapping;          // "none", "endpoint-independent", "endpoint-dependent", "unknown"
        std::wstring detail;          // for the log
    };

    // Opens the tunnel socket once (port 0 = any free port) and starts its thread. Later calls return the first result.
    auto open(uint16_t port) -> bool;
    auto local_port() -> uint16_t;
    // STUN Binding requests from the tunnel socket to each server (host, port), primary first.
    auto stun(const std::vector<std::pair<std::wstring, uint16_t>>& servers) -> StunResult;
    // This machine's usable IPv4 interface addresses, as "host" candidates on the tunnel port: those of adapters with a
    // default gateway, or every adapter's with all. skipped collects the names of the adapters left out.
    auto interface_candidates(bool all = false, std::vector<std::wstring>* skipped = nullptr) -> std::vector<Candidate>;

    // ---- roles (a new role replaces the current one) ----
    struct HostRole
    {
        uint16_t game_port = 7777;
        uint16_t beacon_port = 7877;
        bool accept_unknown = false; // manual test mode: any peer id, zero key
    };
    struct PeerInfo
    {
        uint32_t id = 0;
        Key key{};
        std::vector<Candidate> candidates;
    };
    auto become_host(const HostRole& role) -> void;
    auto set_peers(const std::vector<PeerInfo>& peers) -> void; // the joiners fuserd authorised

    struct JoinRole
    {
        uint16_t local_port = 17777; // FUSER joins 127.0.0.1:local_port; beacon local_port + 100
        uint32_t peer_id = 0;
        Key key{};
        bool relay_only = false; // test mode: no direct probing; only the relay path
    };
    auto become_joiner(const JoinRole& role) -> bool;           // false when the local ports can't be bound

    // The joiner's relay (fuserd's TURN server, credentials from p2p/join/). relay_allocate blocks for up to a few
    // seconds and returns the relayed address as a "relay" candidate to register; the agent then keeps the allocation
    // and the permissions for the host's public IPs alive, and releases it with the role.
    struct RelayInfo
    {
        std::wstring host;
        uint16_t port = 0;
        std::string realm, username, password;
    };
    auto relay_allocate(const RelayInfo& info) -> std::optional<Candidate>;
    auto set_host(const std::vector<Candidate>& candidates) -> void;
    auto joiner_connected() -> bool;                            // a path to the host is selected
    auto stop() -> void;                                        // drop the role (a joiner says bye)

    // What the agent found per pair, for p2p/report/: state "connected" or "failed", path "lan" / "direct" /
    // "prflx" (an address neither side listed) / "none".
    struct Report
    {
        uint32_t peer_id = 0;
        std::string state, path;
        int rtt_ms = -1;
    };
    auto take_reports() -> std::vector<Report>;

    // ---- song transfers ----
    // A transfer pair moves one song's pak and .sig between two players, beside any session role: the pair id and
    // key come from fuserd's p2p/song/ signaling (or the ini test mode). Both sides probe the other's candidates; the
    // receiver checks both sha256 values and the pak layout (pak_check.hpp) before it writes <dir>\<name>.pak/.sig.
    struct XferSend
    {
        uint32_t pair_id = 0;
        Key key{};
        std::vector<Candidate> peer; // the requester's candidates
        std::wstring pak, sig;       // the files to send
        std::string name;            // <X>_P
        uint32_t cap_kbps = 2048;    // the upload cap (SendSongsKBps)
    };
    struct XferRecv
    {
        uint32_t pair_id = 0;
        Key key{};
        std::vector<Candidate> peer;         // the owner's candidates
        std::wstring dir;                    // where <name>.pak / .sig are written
        std::string name;                    // <X>_P; empty: the sender's manifest names it (test mode)
        uint64_t pak_size = 0, sig_size = 0; // from the offer; 0: the manifest's (test mode)
        std::string pak_sha256, sig_sha256;  // hex, from the offer; empty: the manifest's (test mode)
    };
    auto xfer_send(const XferSend& s) -> bool; // false: unreadable, over the limits, or the pak fails the layout check
    auto xfer_recv(const XferRecv& r) -> bool;
    auto xfer_set_peer(uint32_t pair_id, const std::vector<Candidate>& peer) -> void; // the other side registered again
    auto xfer_cancel(uint32_t pair_id) -> void;                                       // drop the pair (tells the other side)
    struct XferStatus
    {
        uint32_t pair_id = 0;
        bool sending = false;
        std::string name, state, error, path; // state: probing, transferring, done, failed; path: lan, direct, prflx
        uint64_t bytes = 0, total = 0, ms = 0;
        uint32_t rate_kbps = 0; // the sender's current pacing rate
        int rtt_ms = -1;
        std::wstring pak_out, sig_out; // the receiver's files, once done
    };
    auto xfer_status() -> std::vector<XferStatus>; // every pair; a finished one stays until xfer_cancel, or a minute
    // A file's size and sha256 (hex), for an owner's offer.
    auto file_digest(const std::wstring& path, uint64_t* size, std::string* sha256) -> bool;

    // ---- the manual test mode (endpoints from the ini, no signaling) ----
    struct HostConfig
    {
        uint16_t listen_port = 0;
        uint16_t game_port = 7777;
        uint16_t beacon_port = 7877;
    };
    struct JoinConfig
    {
        std::wstring host; // "ip:port"
        uint16_t local_port = 17777;
    };
    auto start_host(const HostConfig& cfg) -> bool;
    auto start_join(const JoinConfig& cfg) -> bool;
} // namespace p2p
