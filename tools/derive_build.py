"""Derive fue's per-build addresses for a new FUSER executable by static analysis.

fue needs 8 addresses per game build (fue.cpp, kBuilds). They are known for the EGS v1.4.2 exe (from UE4SS's scan). For
another build of the same engine (4.24.3 hype_release, e.g. the Steam exe) this tool finds them without running it:

  functions (ProcessEvent, StaticConstructObject, FName ctor / ToString, GameEngine::Tick)
    A. prologue: the reference function's first instructions (RIP-relative / rel32 fields wildcarded), grown until
       unique in the reference, must match exactly once in the target;
    B. callers: each direct call site in the reference (call/jmp rel32 to it), as a wildcarded signature of the call
       and the instructions after it, unique in the reference, is found in the target and its call decoded; votes.
  data (GUObjectArray, GMalloc, GNatives)
    C. references: each RIP-relative instruction in the reference that addresses the variable (or a field of it) is
       found in the target the same way and its displacement decoded; votes.
  An address is CONFIRMED when two methods / sites agree and none disagree.

It also checks that the target is the same engine build (version string), that the UObject / UProperty vtable layout
matches around the slots fue calls (0x210 ProcessEvent, 0x2C0 / 0x2F8 / 0x300 property copy / destroy / init), and
emits the fue.cpp kBuilds entry, including the prologue patterns fue verifies at startup before it detours anything.

Usage:
  python derive_build.py --target <Fuser-Win64-Shipping.exe> [--name "Steam v1.4.2"] [--ref <FuserEOS exe>] [--json out.json]
         [--identity <shipped exe>]  (a SteamStub-wrapped exe: analyse a Steamless-unpacked copy as --target, and take
                                      the kBuilds identity from the shipped, packed exe - the one that runs)
  python derive_build.py --self-test        (reference against itself: exercises every method, all must CONFIRM)
Needs pefile, capstone, numpy.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter

import capstone
import numpy as np
import pefile

# The EGS exe: --ref, or FuserEOS-Win64-Shipping.exe under %FUSER_GAME_ROOT% (the folder holding Fuser\)
DEFAULT_REF = os.path.join(os.environ.get("FUSER_GAME_ROOT", ""), "Fuser", "Binaries", "Win64", "FuserEOS-Win64-Shipping.exe")

# The reference build: EGS v1.4.2 (fue.cpp kBuilds[0]). kind: fn = function, data = variable, with the field range
# (bytes from its start) that referencing instructions may address.
REF_BUILD = {
    "name": "EGS v1.4.2", "stamp": 0x6143E115, "size": 0x04138000,
    "symbols": [
        ("ProcessEvent", "fn", 0xB78890, 0),
        ("StaticConstructObject", "fn", 0xB7EE90, 0),
        ("FNameToString", "fn", 0x9F6A30, 0),
        ("FNameCtor", "fn", 0x9DB500, 0),
        ("GameEngineTick", "fn", 0x1A76E80, 0),
        ("GUObjectArray", "data", 0x3BE0028, 0x140),
        ("GMalloc", "data", 0x3BC2D38, 0x8),
        ("GNatives", "data", 0x3BDF430, 0x800),
    ],
}
FN_ORDER = [s[0] for s in REF_BUILD["symbols"]]
VERIFY_BYTES = 16          # prologue bytes fue checks at startup
MAX_SIG = 96               # longest signature tried
MAX_SITES = 40             # call / reference sites tried per symbol
VT_PE_SLOT = 0x210         # UObject::ProcessEvent vtable offset
VT_CHECK = (0x210, 0x2C0, 0x2F8, 0x300)  # vtable offsets fue calls


class Image:
    def __init__(self, path):
        self.path = path
        pe = pefile.PE(path, fast_load=True)
        self.stamp = pe.FILE_HEADER.TimeDateStamp
        self.size = pe.OPTIONAL_HEADER.SizeOfImage
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.mem = bytes(pe.get_memory_mapped_image())
        self.arr = np.frombuffer(self.mem, dtype=np.uint8)
        self.exec = []   # [(start, end)] RVAs of executable sections
        self.rdata = []  # [(start, end)] initialised read-only data
        for s in pe.sections:
            a, b = s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if s.Characteristics & 0x20000000:
                self.exec.append((a, b))
            elif s.Characteristics & 0x40000000 and not s.Characteristics & 0x80000000:
                self.rdata.append((a, b))
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
        self.fn_starts = np.array(sorted({e.struct.BeginAddress for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])}), dtype=np.int64)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def fn_start(self, rva):
        """Start of the .pdata function (fragment) containing rva - an instruction boundary."""
        i = int(np.searchsorted(self.fn_starts, rva, side="right")) - 1
        return int(self.fn_starts[i]) if i >= 0 else None

    def is_code(self, rva):
        return any(a <= rva < b for a, b in self.exec)

    def insns(self, rva, max_bytes):
        return list(self.md.disasm(self.mem[rva:rva + max_bytes + 16], rva))

    def find_all(self, sig, regions, limit=1000):
        """RVAs where sig (list of int | None) matches, within regions."""
        runs, cur = [], []
        for i, b in enumerate(sig):
            if b is None:
                if cur: runs.append(cur); cur = []
            else:
                cur.append((i, b))
        if cur: runs.append(cur)
        anchor = max(runs, key=len)
        a_off, a_bytes = anchor[0][0], bytes(b for _, b in anchor)
        hits = []
        for lo, hi in regions:
            p = self.mem.find(a_bytes, lo + a_off, hi)
            while p >= 0:
                s = p - a_off
                if s + len(sig) <= hi and all(b is None or self.mem[s + i] == b for i, b in enumerate(sig)):
                    hits.append(s)
                    if len(hits) >= limit: return hits
                p = self.mem.find(a_bytes, p + 1, hi)
        return hits


def rel_target(insn):
    """Target RVA of a rel32 branch or RIP-relative operand, or None."""
    if insn.disp_size == 4 and "rip" in insn.op_str:
        disp = int.from_bytes(bytes(insn.bytes[insn.disp_offset:insn.disp_offset + 4]), "little", signed=True)
        return insn.address + insn.size + disp
    if insn.imm_size == 4 and insn.mnemonic.startswith(("call", "j")) and insn.bytes[0] in (0xE8, 0xE9, 0x0F):
        return insn.operands[0].imm if insn.operands else None
    return None


def wildcard(insn):
    """The instruction's bytes with RIP-relative displacements and rel32 branch targets as None."""
    b = [int(x) for x in insn.bytes]
    if insn.disp_size == 4 and "rip" in insn.op_str:
        for i in range(insn.disp_offset, insn.disp_offset + 4): b[i] = None
    elif insn.imm_size == 4 and insn.mnemonic.startswith(("call", "j")) and insn.bytes[0] in (0xE8, 0xE9, 0x0F):
        for i in range(insn.imm_offset, insn.imm_offset + 4): b[i] = None
    return b


def sig_from(img, rva, min_bytes, max_bytes):
    """Yield growing wildcarded signatures of whole instructions starting at rva."""
    sig = []
    for insn in img.insns(rva, max_bytes):
        sig += wildcard(insn)
        if len(sig) >= min_bytes: yield list(sig)
        if len(sig) >= max_bytes or insn.mnemonic in ("int3",): return


def unique_sig(img, rva, min_bytes=12):
    for sig in sig_from(img, rva, min_bytes, MAX_SIG):
        hits = img.find_all(sig, img.exec, limit=2)
        if hits == [rva]: return sig
    return None


def site_sig(img, site):
    """A wildcarded signature of whole instructions around the instruction at site, grown back and forward until
    unique in img: (sig, offset of site in sig), or None. Backward context needs the containing function's start
    from .pdata; leaf functions have none, so they fall back to forward context only."""
    start = img.fn_start(site)
    ins = img.insns(start, site - start + MAX_SIG) if start is not None and site - start <= 0x4000 else []
    idx = next((i for i, x in enumerate(ins) if x.address == site), None)
    if idx is None:
        sig = unique_sig(img, site, min_bytes=16)
        return (sig, 0) if sig else None
    parts = [wildcard(x) for x in ins]
    lo, hi = idx, idx + 1
    grow_back = True
    while True:
        sig = [b for part in parts[lo:hi] for b in part]
        off = ins[idx].address - ins[lo].address
        if len(sig) >= 16:
            hits = img.find_all(sig, img.exec, limit=2)
            if hits == [ins[lo].address]: return sig, off
        if len(sig) >= MAX_SIG * 2: return None
        if (grow_back and lo > 0) or hi >= len(parts): lo -= 1
        else: hi += 1
        if lo < 0: return None
        grow_back = not grow_back


def resolve_sites(ref, tgt, sites):
    """Find each reference site in the target and decode its rel32 / RIP-relative target: [(target, field)]."""
    out, usable = [], 0
    step = max(1, len(sites) // MAX_SITES)  # a spread of sites, not just the lowest addresses
    for site, field in sites[::step][:MAX_SITES]:
        r = site_sig(ref, site)
        if not r: continue
        usable += 1
        sig, off = r
        hits = tgt.find_all(sig, tgt.exec, limit=2)
        if len(hits) != 1: continue
        ins = tgt.insns(hits[0] + off, 16)
        t = rel_target(ins[0]) if ins else None
        if t is not None: out.append(t - field)
    return out, usable


def fmt_sig(sig):
    return " ".join("??" if b is None else f"{b:02X}" for b in sig)


def verify_pattern(img, rva):
    """The first whole instructions covering VERIFY_BYTES, wildcarded - what fue checks before detouring."""
    sig = []
    for insn in img.insns(rva, VERIFY_BYTES + 16):
        sig += wildcard(insn)
        if len(sig) >= VERIFY_BYTES: break
    return fmt_sig(sig[:VERIFY_BYTES])


# ---------------------------------------------------------------- site discovery (reference) ----------------
def scan_rel32(img, predicate_lo, predicate_hi, opcodes=None):
    """RVAs p of 4-byte little-endian fields (in exec sections) with p + 4 + field in [lo, hi). opcodes: if set,
    only fields preceded by one of these bytes (call / jmp rel32 sites)."""
    out = []
    for a, b in img.exec:
        chunk = 1 << 24
        for s in range(a, b - 4, chunk):
            e = min(s + chunk, b - 4)
            v = img.arr[s:e + 4].astype(np.int64)
            n = e - s
            d = v[:n] | (v[1:n + 1] << 8) | (v[2:n + 2] << 16) | (v[3:n + 3] << 24)
            d = np.where(d >= 1 << 31, d - (1 << 32), d)
            dest = np.arange(s, e, dtype=np.int64) + 4 + d
            hit = (dest >= predicate_lo) & (dest < predicate_hi)
            if opcodes is not None:
                prev = img.arr[s - 1:e - 1] if s > 0 else np.concatenate(([0], img.arr[s:e - 1]))
                hit &= np.isin(prev, list(opcodes))
            out += [int(x) for x in np.nonzero(hit)[0] + s]
    return out


def call_sites(img, fn):
    return [p - 1 for p in scan_rel32(img, fn, fn + 1, opcodes=(0xE8, 0xE9))]


def data_sites(img, var, extent):
    """(insn RVA, field offset) of RIP-relative instructions addressing [var, var + extent)."""
    sites = []
    for imm in (0, 1, 4):  # the displacement may be followed by an immediate
        for p in scan_rel32(img, var + imm, var + imm + extent):
            for k in range(1, 10):
                ins = img.insns(p - k, 16)
                if ins and ins[0].address == p - k and ins[0].disp_size == 4 and ins[0].disp_offset == k and "rip" in ins[0].op_str:
                    t = rel_target(ins[0])
                    if t is not None and var <= t < var + extent:
                        sites.append((p - k, t - var))
                        break
    return sorted(set(sites))


# ---------------------------------------------------------------- resolution ---------------------------------
def resolve_function(ref, tgt, rva):
    votes = Counter()
    notes = []
    sig = unique_sig(ref, rva)
    if sig:
        hits = tgt.find_all(sig, tgt.exec, limit=3)
        if len(hits) == 1:
            votes[hits[0]] += 1; notes.append(f"prologue ({len(sig)} B) -> {hits[0]:#x}")
        else:
            notes.append(f"prologue ({len(sig)} B): {len(hits)} target matches")
    else:
        notes.append("prologue: not unique in reference")
    sites = call_sites(ref, rva)
    found, usable = resolve_sites(ref, tgt, [(s, 0) for s in sites])
    for t in found: votes[t] += 1
    notes.append(f"callers: {len(sites)} in reference, {usable} usable, {len(found)} resolved in target")
    # virtual functions have few direct callers: the vtable slots holding the function, with the functions in the
    # neighbouring slots, must look the same for exactly one target candidate
    # neighbouring slots, must look the same for exactly one candidate (the other methods' results, or failing
    # those every target match of the prologue)
    candidates = list(votes) or (tgt.find_all(sig, tgt.exec, limit=8) if sig else [])
    vt = vtable_vote(ref, tgt, rva, candidates)
    if vt is not None:
        votes[vt[0]] += 1; notes.append(vt[1])
    return votes, notes


def resolve_data(ref, tgt, rva, extent):
    sites = data_sites(ref, rva, extent)
    found, usable = resolve_sites(ref, tgt, sites)
    return Counter(found), [f"references: {len(sites)} in reference, {usable} usable, {len(found)} resolved in target"]


def verdict(votes, methods_needed=2):
    if not votes: return None, "NOT FOUND"
    (best, n), *rest = votes.most_common()
    if rest: return best, f"CONFLICT {dict((hex(k), v) for k, v in votes.items())}"
    return best, "CONFIRMED" if n >= methods_needed else "SINGLE (unconfirmed)"


# ---------------------------------------------------------------- checks -------------------------------------
def version_strings(img):
    """The engine build identity: the UTF-16 "<branch>-CL-<changelist>" strings, and the changelist returned by
    BuildSettings::GetCurrentChangelist (mov eax, imm32; ret, between int3 padding)."""
    out = {m.group().decode("utf-16-le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}-\x00C\x00L\x00-\x00(?:[0-9]\x00)+", img.mem)}
    for m in re.finditer(r"-CL-([0-9]+)", "".join(out)):
        cl = int(m.group(1))
        if img.mem.find(b"\xcc\xb8" + cl.to_bytes(4, "little") + b"\xc3\xcc") >= 0: out.add(f"GetCurrentChangelist() = {cl}")
    return sorted(out)


def fingerprint(img, rva):
    """Build-independent identity of a function for vtable comparison: its first wildcarded instruction bytes."""
    sig = []
    for insn in img.insns(rva, 24):
        sig += wildcard(insn)
        if len(sig) >= 12: break
    return tuple(sig[:12])


def vtables_with(img, fn_rva):
    """RVAs of vtable slots (8-byte aligned, read-only data) holding fn's VA."""
    va = (img.base + fn_rva).to_bytes(8, "little")
    out = []
    for a, b in img.rdata:
        p = img.mem.find(va, a, b)
        while p >= 0:
            if p % 8 == 0: out.append(p)
            p = img.mem.find(va, p + 1, b)
    return out


def vtable_profile(img, fn_rva):
    """How fn sits in vtables: its slot count, and the functions in the slots around its first occurrences."""
    slots = vtables_with(img, fn_rva)

    def around(p):
        fps = []
        for k in (-2, -1, 1, 2):
            q = int.from_bytes(img.mem[p + 8 * k:p + 8 * k + 8], "little") - img.base
            fps.append(fingerprint(img, q) if img.is_code(q) else None)
        return tuple(fps)
    return len(slots), [around(p) for p in slots[:16]]


def vtable_vote(ref, tgt, rva, candidates):
    """The one candidate whose vtable profile matches the reference function's (virtual functions), or None."""
    n, prof = vtable_profile(ref, rva)
    if n == 0: return None
    matches = []
    for c in candidates:
        cn, cprof = vtable_profile(tgt, c)
        if cn == n and sum(a == b for a, b in zip(prof, cprof)) >= 0.75 * len(prof): matches.append(c)
    if len(matches) != 1: return None
    return matches[0], f"vtables: {n} slots, neighbours match -> {matches[0]:#x}"


def vtable_check(ref, tgt, ref_pe, tgt_pe):
    """Compare the vtable slots fue calls across every vtable holding ProcessEvent. The builds may have a few more or
    fewer UObject classes, so vtables are not paired: for each slot, the multiset of functions found there (by
    fingerprint) must overlap - a shifted layout would put other functions in the slot and the overlap collapses."""
    rs, ts = vtables_with(ref, ref_pe), vtables_with(tgt, tgt_pe)
    lines = [f"vtables holding ProcessEvent at a slot: reference {len(rs)}, target {len(ts)}"]
    if not rs or not ts:
        lines.append("  none found - layout not verified")
        return False, lines

    def slot_fp(img, pe_slot, off):
        q = int.from_bytes(img.mem[pe_slot - VT_PE_SLOT + off:pe_slot - VT_PE_SLOT + off + 8], "little") - img.base
        return fingerprint(img, q) if img.is_code(q) else ("data",)

    ok = True
    n = min(len(rs), len(ts))
    for off in VT_CHECK:
        a, b = Counter(slot_fp(ref, r, off) for r in rs), Counter(slot_fp(tgt, t, off) for t in ts)
        overlap = sum((a & b).values())
        lines.append(f"  slot {off:#x}: {overlap}/{n} vtables' functions match between the builds ({len(a)} distinct functions)")
        ok &= overlap >= 0.95 * n
    return ok, lines


# ---------------------------------------------------------------- main -------------------------------------
def run(ref_path, tgt_path, name, json_out, identity_path=None):
    ref, tgt = Image(ref_path), Image(tgt_path)
    if (ref.stamp, ref.size) != (REF_BUILD["stamp"], REF_BUILD["size"]):
        sys.exit(f"reference is not {REF_BUILD['name']} (stamp {ref.stamp:#x}, size {ref.size:#x})")
    print(f"reference {REF_BUILD['name']}: {ref_path}")
    print(f"target    {name}: {tgt_path}\n  TimeDateStamp {tgt.stamp:#010x}, SizeOfImage {tgt.size:#010x}")
    rv, tv = version_strings(ref), version_strings(tgt)
    print(f"engine version strings: reference {rv}\n                        target    {tv}")
    same_engine = bool(set(rv) & set(tv))
    print(f"  {'same engine build' if same_engine else 'WARNING: engine version differs - member offsets / vtable slots are NOT guaranteed'}\n")

    result, all_ok = {}, same_engine
    for sym, kind, rva, extent in REF_BUILD["symbols"]:
        votes, notes = resolve_function(ref, tgt, rva) if kind == "fn" else resolve_data(ref, tgt, rva, extent)
        addr, status = verdict(votes)
        all_ok &= status == "CONFIRMED"
        entry = {"rva": addr, "status": status, "notes": notes}
        if kind == "fn" and addr is not None:
            entry["verify"] = verify_pattern(tgt, addr)
            entry["same_prologue"] = verify_pattern(ref, rva) == entry["verify"]
        result[sym] = entry
        print(f"{sym:22} {('%#x' % addr) if addr is not None else '-':>11}  {status}")
        for n in notes: print(f"{'':24}{n}")
        if kind == "fn" and addr is not None: print(f"{'':24}verify: {entry['verify']}")

    if result["ProcessEvent"]["rva"] is not None:
        vt_ok, lines = vtable_check(ref, tgt, dict((s[0], s[2]) for s in REF_BUILD["symbols"])["ProcessEvent"], result["ProcessEvent"]["rva"])
        print("\n" + "\n".join(lines))
        all_ok &= vt_ok

    print("\nfue.cpp kBuilds entry:")
    stamp, size = tgt.stamp, tgt.size
    if identity_path:
        ident = pefile.PE(identity_path, fast_load=True)
        stamp, size = ident.FILE_HEADER.TimeDateStamp, ident.OPTIONAL_HEADER.SizeOfImage
        print(f"(identity from {identity_path}: TimeDateStamp {stamp:#010x}, SizeOfImage {size:#010x})")
    print(cpp_entry(name, stamp, size, result))
    print(f"\nOVERALL: {'all addresses CONFIRMED - safe to add (runtime self-checks still apply)' if all_ok else 'NOT all confirmed - review before adding'}")
    if json_out:
        with open(json_out, "w") as f:
            json.dump({"name": name, "stamp": stamp, "size": size, "engine": tv, "symbols": result, "ok": all_ok}, f, indent=2)
    return all_ok


def cpp_entry(name, stamp, size, result):
    def a(sym):
        v = result[sym]["rva"]
        return f"{v:#x}" if v is not None else "0 /* NOT FOUND */"

    def p(sym):
        return f'"{result[sym].get("verify", "")}"'
    fns = [s for s, k, *_ in REF_BUILD["symbols"] if k == "fn"]
    return ("        {\n"
            f"            STR(\"{name}\"), {stamp:#010x}, {size:#010x},\n"
            f"            /* ProcessEvent */ {a('ProcessEvent')}, /* StaticConstructObject */ {a('StaticConstructObject')}, "
            f"/* FName::ToString */ {a('FNameToString')}, /* FName ctor */ {a('FNameCtor')},\n"
            f"            /* GameEngine::Tick */ {a('GameEngineTick')}, /* GUObjectArray */ {a('GUObjectArray')}, "
            f"/* GMalloc */ {a('GMalloc')}, /* GNatives */ {a('GNatives')},\n"
            "            {" + ", ".join(p(s) for s in fns) + "},\n"
            "        },")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", default=DEFAULT_REF, help="reference exe (EGS v1.4.2)")
    ap.add_argument("--target", help="exe to derive addresses for")
    ap.add_argument("--name", default="Steam v1.4.2", help="build name for the kBuilds entry and the log")
    ap.add_argument("--json", help="write the result as JSON")
    ap.add_argument("--identity", help="exe whose PE identity goes into the entry (the packed original of an unpacked --target)")
    ap.add_argument("--self-test", action="store_true", help="derive the reference from itself")
    a = ap.parse_args()
    if a.self_test:
        ok = run(a.ref, a.ref, REF_BUILD["name"], a.json)
        sys.exit(0 if ok else 1)
    if not a.target: ap.error("--target or --self-test")
    sys.exit(0 if run(a.ref, a.target, a.name, a.json, a.identity) else 1)


if __name__ == "__main__":
    main()
