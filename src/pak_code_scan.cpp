/*
 * Finds the code pak_list_race.cpp hooks, from what the code does rather than from a list of addresses, so the same
 * rules cover other builds of the game (EGS and Steam).
 *
 * Candidates are found by scanning the code for a few opcode bytes, then decoded as instructions (HDE64, lib/hde)
 * starting from their function, so bytes inside another instruction don't count. Every doubt is resolved towards
 * safety: an unclear reader is hooked anyway, and anything that could hand a pak to code that isn't hooked fails the
 * scan, which leaves the game exactly as it is.
 */
#include "pak_code_scan.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "hde/hde64.h"
#include "loader_hooks.hpp"
#include "unwind_table.hpp"

using byte = uint8_t;

// Defined by the offline test harness to print each decision
#ifdef PAK_SCAN_TRACE
#define TRACE(...) printf(__VA_ARGS__)
#else
#define TRACE(...)
#endif

namespace {

constexpr int Rax = 0;
constexpr int Rcx = 1;
constexpr int Rdx = 2;
constexpr int Rbx = 3;
constexpr int Rsp = 4;
constexpr int Rbp = 5;
constexpr int Rsi = 6;
constexpr int Rdi = 7;
constexpr int R8 = 8;
constexpr int R9 = 9;
constexpr int R11 = 11;
constexpr uint16_t ArgumentRegisters = 1 << Rcx | 1 << Rdx | 1 << R8 | 1 << R9;
constexpr uint16_t VolatileRegisters = ArgumentRegisters | 1 << Rax | 1 << 10 | 1 << 11;

/* ---- The exe ---- */

struct Range {
	byte *Start = nullptr;
	byte *End = nullptr;

	bool Contains(const byte *p) const {
		return p >= Start && p < End;
	}
};

struct Image {
	byte *Base = nullptr;
	size_t Size = 0;
	Range Text;
	Range Rdata;
	std::vector<Range> Code;
	std::vector<Range> Data;

	// The unwind table, by address; a function's cold paths are chunks of their own
	const RUNTIME_FUNCTION *Chunks = nullptr;
	size_t ChunkCount = 0;

	bool InCode(const byte *p) const {
		return std::any_of(Code.begin(), Code.end(), [p](const Range &range) { return range.Contains(p); });
	}
};

bool LoadImage(byte *base, size_t size, Image &image) {
	image.Base = base;
	image.Size = size;
	auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + reinterpret_cast<IMAGE_DOS_HEADER *>(base)->e_lfanew);
	IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
		const Range range{base + section->VirtualAddress, base + section->VirtualAddress + section->Misc.VirtualSize};
		const char *name = reinterpret_cast<const char *>(section->Name);
		if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			image.Code.push_back(range);
		} else if (section->Characteristics & IMAGE_SCN_MEM_READ) {
			image.Data.push_back(range);
		}
		if (strncmp(name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
			image.Text = range;
		} else if (strncmp(name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
			image.Rdata = range;
		}
	}

	const IMAGE_DATA_DIRECTORY &unwind = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	image.Chunks = reinterpret_cast<const RUNTIME_FUNCTION *>(base + unwind.VirtualAddress);
	image.ChunkCount = unwind.Size / sizeof(RUNTIME_FUNCTION);
	return image.Text.Start && image.Rdata.Start && image.ChunkCount;
}

const byte *UnwindInfo(const Image &image, const RUNTIME_FUNCTION *chunk) {
	return image.Base + chunk->UnwindData;
}

const RUNTIME_FUNCTION *ChunkAt(const Image &image, const byte *p) {
	if (p < image.Base || p >= image.Base + image.Size) {
		return nullptr;
	}
	return UnwindEntryFor(image.Chunks, image.ChunkCount, (DWORD)(p - image.Base));
}

bool Chained(const Image &image, const RUNTIME_FUNCTION *chunk) {
	return ((UnwindInfo(image, chunk)[0] >> 3) & UNW_FLAG_CHAININFO) != 0;
}

bool InPrologue(const Image &image, const byte *pc) {
	const RUNTIME_FUNCTION *chunk = ChunkAt(image, pc);
	return chunk && pc < image.Base + chunk->BeginAddress + UnwindInfo(image, chunk)[1];
}

// The entry a chained chunk's unwind info continues in, after its (even-padded) unwind codes
const RUNTIME_FUNCTION *ChainedTo(const Image &image, const RUNTIME_FUNCTION *chunk) {
	const byte *info = UnwindInfo(image, chunk);
	return reinterpret_cast<const RUNTIME_FUNCTION *>(info + 4 + 2 * ((info[2] + 1) & ~1));
}

const RUNTIME_FUNCTION *PrimaryOf(const Image &image, const RUNTIME_FUNCTION *chunk) {
	for (int links = 0; chunk && links < 16; links++) {
		if (!Chained(image, chunk)) {
			return chunk;
		}
		chunk = ChainedTo(image, chunk);
	}
	return nullptr;
}

byte *FunctionStart(const Image &image, const byte *p) {
	const RUNTIME_FUNCTION *chunk = ChunkAt(image, p);
	const RUNTIME_FUNCTION *primary = chunk ? PrimaryOf(image, chunk) : nullptr;
	return primary ? image.Base + primary->BeginAddress : nullptr;
}

// Most functions are one chunk, so only the chained chunks are indexed, by their function
std::map<const byte *, std::vector<Range>> IndexChainedChunks(const Image &image) {
	std::map<const byte *, std::vector<Range>> chained;
	for (size_t i = 0; i < image.ChunkCount; i++) {
		const RUNTIME_FUNCTION *chunk = &image.Chunks[i];
		const RUNTIME_FUNCTION *primary = Chained(image, chunk) ? PrimaryOf(image, chunk) : nullptr;
		if (primary) {
			chained[image.Base + primary->BeginAddress].push_back(
				{image.Base + chunk->BeginAddress, image.Base + chunk->EndAddress});
		}
	}
	return chained;
}

/*
 * rsp at an instruction, and rbp when it is the frame register, relative to rsp at the function's entry. Read from the
 * unwind codes of the instruction's chunk and the chunks it chains to; inside a prologue, only the codes of the
 * instructions already run count.
 */
struct StackFrame {
	bool Known = false;
	int32_t Rsp = 0;
	bool RbpFrame = false;
	int32_t Rbp = 0;
};

StackFrame StackAt(const Image &image, const byte *pc) {
	StackFrame frame;
	const RUNTIME_FUNCTION *chunk = ChunkAt(image, pc);
	if (!chunk) {
		// A leaf function never moves rsp
		frame.Known = true;
		return frame;
	}

	const RUNTIME_FUNCTION *chain[16];
	int links = 0;
	for (const RUNTIME_FUNCTION *link = chunk; link; links++) {
		if (links == 16) {
			return frame;
		}
		chain[links] = link;
		link = Chained(image, link) ? ChainedTo(image, link) : nullptr;
	}

	int32_t rsp = 0;
	for (int i = links - 1; i >= 0; i--) {
		const byte *info = UnwindInfo(image, chain[i]);
		const byte *codes = info + 4;
		const int count = info[2];
		const uint32_t into = (uint32_t)(pc - (image.Base + chain[i]->BeginAddress));

		struct Op {
			byte CodeOffset;
			byte Kind;
			byte Info;
			uint32_t Size;
		};
		Op ops[256];
		int opCount = 0;
		for (int j = 0; j < count;) {
			const byte kind = codes[2 * j + 1] & 0x0F;
			const byte opInfo = codes[2 * j + 1] >> 4;
			Op op{codes[2 * j], kind, opInfo, 0};
			int slots = 1;
			switch (kind) {
				case 0: // UWOP_PUSH_NONVOL
					op.Size = 8;
					break;
				case 1: // UWOP_ALLOC_LARGE
					slots = opInfo == 0 ? 2 : 3;
					if (j + slots > count) {
						return frame;
					}
					op.Size = opInfo == 0 ? *reinterpret_cast<const uint16_t *>(codes + 2 * j + 2) * 8u
										  : *reinterpret_cast<const uint32_t *>(codes + 2 * j + 2);
					break;
				case 2: // UWOP_ALLOC_SMALL
					op.Size = opInfo * 8u + 8;
					break;
				case 3: // UWOP_SET_FPREG
					break;
				case 4: // UWOP_SAVE_NONVOL
				case 8: // UWOP_SAVE_XMM128
					slots = 2;
					break;
				case 5: // UWOP_SAVE_NONVOL_FAR
				case 9: // UWOP_SAVE_XMM128_FAR
					slots = 3;
					break;
				case 6: // UWOP_EPILOG, version 2 only: where an epilogue is, which doesn't move rsp in the body
					if ((info[0] & 7) != 2) {
						return frame;
					}
					op.Kind = 0xFF;
					break;
				default:
					return frame;
			}
			ops[opCount] = op;
			opCount++;
			j += slots;
		}

		// Listed from the prologue's end back to its start
		for (int j = opCount - 1; j >= 0; j--) {
			if (i == 0 && ops[j].CodeOffset > into) {
				continue;
			}
			rsp -= (int32_t)ops[j].Size;
			if (ops[j].Kind == 3) {
				if ((info[3] & 0x0F) != Rbp) {
					return frame;
				}
				frame.RbpFrame = true;
				frame.Rbp = rsp + 16 * (info[3] >> 4);
			}
		}
	}
	frame.Known = true;
	frame.Rsp = rsp;
	return frame;
}

/* ---- Instructions ---- */

struct Insn {
	const byte *At = nullptr;
	hde64s H{};

	const byte *Next() const {
		return At + H.len;
	}

	bool HasModRM() const {
		return (H.flags & F_MODRM) != 0;
	}

	bool RegisterOperand() const {
		return HasModRM() && H.modrm_mod == 3;
	}

	int Reg() const {
		return H.modrm_reg | (H.rex_r << 3);
	}

	int RmRegister() const {
		return H.modrm_rm | (H.rex_b << 3);
	}

	bool RipRelative() const {
		return HasModRM() && H.modrm_mod == 0 && H.modrm_rm == 5;
	}

	const byte *RipTarget() const {
		return Next() + (int32_t)H.disp.disp32;
	}

	int32_t Displacement() const {
		if (H.flags & F_DISP8) {
			return (int8_t)H.disp.disp8;
		}
		return (H.flags & F_DISP32) ? (int32_t)H.disp.disp32 : 0;
	}

	// A memory operand's base register, or -1 (none, or rip)
	int AddressBase() const {
		if (!HasModRM() || H.modrm_mod == 3 || RipRelative()) {
			return -1;
		}
		if (!(H.flags & F_SIB)) {
			return RmRegister();
		}
		return H.sib_base == 5 && H.modrm_mod == 0 ? -1 : H.sib_base | (H.rex_b << 3);
	}

	// A memory operand's index register, or -1
	int AddressIndex() const {
		if (!HasModRM() || H.modrm_mod == 3 || !(H.flags & F_SIB)) {
			return -1;
		}
		const int index = H.sib_index | (H.rex_x << 3);
		return index == Rsp ? -1 : index;
	}

	// The base of a [base + displacement] operand, or -1 when there's an index or no base
	int Base() const {
		return AddressIndex() < 0 ? AddressBase() : -1;
	}

	int64_t Immediate() const {
		if (H.flags & F_IMM8) {
			return (int8_t)H.imm.imm8;
		}
		if (H.flags & F_IMM16) {
			return (int16_t)H.imm.imm16;
		}
		if (H.flags & F_IMM64) {
			return (int64_t)H.imm.imm64;
		}
		return (int32_t)H.imm.imm32;
	}

	// A switch statement's table read, [reg + index*4 + table]: the bytes after the switch's jump aren't all code
	bool ReadsJumpTable() const {
		return AddressIndex() >= 0 && H.sib_scale == 2 && (H.flags & F_DISP32);
	}

	const byte *Target() const {
		return (H.flags & F_RELATIVE) ? Next() + Immediate() : nullptr;
	}

	bool Call() const {
		return H.opcode == 0xE8 || (H.opcode == 0xFF && HasModRM() && (H.modrm_reg == 2 || H.modrm_reg == 3));
	}

	bool CallThrough(const byte *importSlot) const {
		return H.opcode == 0xFF && HasModRM() && H.modrm_reg == 2 && RipRelative() && RipTarget() == importSlot;
	}

	bool IndirectJump() const {
		return H.opcode == 0xFF && HasModRM() && (H.modrm_reg == 4 || H.modrm_reg == 5);
	}

	bool Return() const {
		return H.opcode == 0xC3 || H.opcode == 0xC2;
	}

	bool Jump() const {
		return Target() && H.opcode != 0xE8;
	}

	bool UnconditionalJump() const {
		return H.opcode == 0xE9 || H.opcode == 0xEB;
	}

	// int3 and ud2 end a path: they follow calls that don't return
	bool Stops() const {
		return H.opcode == 0xCC || (H.opcode == 0x0F && H.opcode2 == 0x0B);
	}
};

bool Decode(const byte *p, Insn &insn) {
	insn.At = p;
	hde64_disasm(p, &insn.H);
	return !(insn.H.flags & F_ERROR);
}

// rbp only addresses the stack when it is the frame register; otherwise it's an ordinary register
bool StackAddress(const Insn &insn, const StackFrame &frame) {
	return insn.Base() == Rsp || (insn.Base() == Rbp && frame.RbpFrame);
}

// A stack operand's offset from rsp at the function's entry
int32_t StackOffset(const Insn &insn, const StackFrame &frame) {
	return (insn.Base() == Rsp ? frame.Rsp : frame.Rbp) + insn.Displacement();
}

bool Between(byte value, byte low, byte high) {
	return value >= low && value <= high;
}

// Integer instructions that read their r/m operand and write their reg operand
bool LoadsIntoReg(const Insn &insn) {
	const byte op = insn.H.opcode;
	const byte op2 = insn.H.opcode2;
	if (op == 0x0F) {
		return op2 == 0xAF || Between(op2, 0x40, 0x4F) || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF;
	}
	return op == 0x8A || op == 0x8B || op == 0x63 || (op < 0x40 && (op & 7) <= 3 && (op & 2) != 0) || op == 0x69 ||
		op == 0x6B;
}

// Integer instructions that write their r/m operand from their reg operand (movnti among them)
bool StoresFromReg(const Insn &insn) {
	const byte op = insn.H.opcode;
	if (op == 0x0F) {
		return insn.H.opcode2 == 0xC3;
	}
	return op == 0x88 || op == 0x89 || (op < 0x40 && (op & 7) <= 1 && (op & 0x38) != 0x38);
}

// SSE stores to memory: overwriting a slot with them can't move a pak anywhere
bool StoresFromXmm(const Insn &insn) {
	const byte op2 = insn.H.opcode2;
	return insn.H.opcode == 0x0F &&
		(op2 == 0x11 || op2 == 0x13 || op2 == 0x17 || op2 == 0x29 || op2 == 0x2B || op2 == 0x7F || op2 == 0xD6 ||
		 op2 == 0xE7 || (op2 == 0x7E && insn.H.p_66));
}

// Integer instructions under 0F, which use general registers the way one-byte opcodes do
bool IntegerTwoByte(const Insn &insn) {
	const byte op2 = insn.H.opcode2;
	return LoadsIntoReg(insn) || Between(op2, 0x90, 0x9F) || op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 ||
		op2 == 0xBB || op2 == 0xBA || op2 == 0xBC || op2 == 0xBD || op2 == 0xB8 || op2 == 0x1F || op2 == 0xA4 ||
		op2 == 0xA5 || op2 == 0xAC || op2 == 0xAD || op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1 ||
		op2 == 0xC3 || op2 == 0xC7;
}

/*
 * Opcodes under 0F whose register operands are vector registers, apart from the general-register ones Destinations
 * lists (cvt*2si, movmsk, pextrw, movd). 0F 38 and 0F 3A aren't among them: some of those take general registers.
 */
bool VectorOpcode(const Insn &insn) {
	const byte op2 = insn.H.opcode2;
	return insn.H.opcode == 0x0F &&
		(Between(op2, 0x10, 0x17) || Between(op2, 0x28, 0x2F) || Between(op2, 0x50, 0x7F) || op2 == 0xC2 ||
		 Between(op2, 0xC4, 0xC6) || Between(op2, 0xD0, 0xFF) || Between(op2, 0x18, 0x1E) || op2 == 0x0D);
}

// Writes that replace a whole register: anything narrower leaves the rest of a pak pointer in it
bool ReplacesReg(const Insn &insn) {
	const byte op = insn.H.opcode;
	if (insn.H.p_66) {
		return false;
	}
	if (op == 0x0F) {
		const byte op2 = insn.H.opcode2;
		return op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF || op2 == 0xAF;
	}
	return op == 0x8B || op == 0x8D || op == 0x63 || op == 0x69 || op == 0x6B || Between(op, 0xB8, 0xBF) ||
		(op == 0xC7 && insn.RegisterOperand()) || (op < 0x40 && (op & 7) <= 3 && (op & 1) != 0);
}

// Opcodes whose reg field extends the opcode instead of naming a register
bool GroupOpcode(const Insn &insn) {
	const byte op = insn.H.opcode;
	const byte op2 = insn.H.opcode2;
	if (op == 0x0F) {
		return op2 == 0xBA || Between(op2, 0x90, 0x9F) || op2 == 0x1F;
	}
	return op == 0x80 || op == 0x81 || op == 0x83 || op == 0x8F || op == 0xC0 || op == 0xC1 || op == 0xC6 ||
		op == 0xC7 || Between(op, 0xD0, 0xD3) || op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF;
}

// Compares, tests and nops: they read their operands and write none
bool ReadsOnly(const Insn &insn) {
	const byte op = insn.H.opcode;
	const byte op2 = insn.H.opcode2;
	if (op == 0x0F) {
		return op2 == 0xA3 || (op2 == 0xBA && insn.H.modrm_reg == 4) || op2 == 0x1F;
	}
	return Between(op, 0x38, 0x3B) || op == 0x84 || op == 0x85 ||
		((op == 0x80 || op == 0x81 || op == 0x83) && insn.H.modrm_reg == 7) ||
		((op == 0xF6 || op == 0xF7) && insn.H.modrm_reg <= 1);
}

/*
 * The general registers an instruction writes, by its encoding. An opcode with operands that isn't recognized counts
 * as writing both of them; the pointer-flow walk refuses those outright when they touch what it follows.
 */
uint16_t Destinations(const Insn &insn) {
	const byte op = insn.H.opcode;
	const byte op2 = insn.H.opcode2;
	const int reg = insn.Reg();
	const int rm = insn.RmRegister();
	const uint16_t rmIfRegister = insn.RegisterOperand() ? 1 << rm : 0;
	if (!insn.HasModRM()) {
		const int opReg = (op & 7) | (insn.H.rex_b << 3);
		if (op == 0x0F) {
			if (Between(op2, 0xC8, 0xCF)) {
				return 1 << ((op2 & 7) | (insn.H.rex_b << 3));
			}
			if (op2 == 0x31) {
				return 1 << Rax | 1 << Rdx;
			}
			if (op2 == 0xA2) {
				return 1 << Rax | 1 << Rbx | 1 << Rcx | 1 << Rdx;
			}
			return op2 == 0x05 ? 1 << Rax | 1 << Rcx | 1 << R11 : 0;
		}
		if (Between(op, 0xB8, 0xBF) || Between(op, 0x58, 0x5F)) {
			return 1 << opReg;
		}
		if (Between(op, 0xB0, 0xB7)) {
			// Without REX, B4-B7 are ah, ch, dh and bh
			return 1 << (insn.H.rex || op < 0xB4 ? opReg : op & 3);
		}
		if (Between(op, 0x91, 0x97) || (op == 0x90 && insn.H.rex_b)) {
			return 1 << opReg | 1 << Rax;
		}
		if (op == 0x98 || op == 0x99) {
			return op == 0x98 ? 1 << Rax : 1 << Rdx;
		}
		// Arithmetic on al/eax/rax with an immediate; cmp only reads
		if (op < 0x40 && ((op & 7) == 4 || (op & 7) == 5) && op != 0x3C && op != 0x3D) {
			return 1 << Rax;
		}
		if (Between(op, 0xA4, 0xAF) && op != 0xA8 && op != 0xA9) {
			const bool movesRsi = op <= 0xA7 || op == 0xAC || op == 0xAD;
			const bool movesRdi = op <= 0xA7 || op >= 0xAA;
			const bool loadsRax = op == 0xAC || op == 0xAD;
			return (movesRsi ? 1 << Rsi : 0) | (movesRdi ? 1 << Rdi : 0) | (loadsRax ? 1 << Rax : 0) |
				(insn.H.p_rep ? 1 << Rcx : 0);
		}
		if (op == 0xD7 || op == 0x9F) {
			return 1 << Rax;
		}
		return op == 0xC9 ? 1 << Rbp | 1 << Rsp : 0;
	}
	if (op == 0x0F) {
		if (ReadsOnly(insn)) {
			return 0;
		}
		if (Between(op2, 0x40, 0x4F) || op2 == 0xAF || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
			op2 == 0xBC || op2 == 0xBD || op2 == 0xB8) {
			return 1 << reg;
		}
		if (VectorOpcode(insn)) {
			const bool toGeneral = ((op2 == 0x2C || op2 == 0x2D) && insn.H.p_rep) || op2 == 0x50 || op2 == 0xC5 ||
				op2 == 0xD7;
			return toGeneral ? 1 << reg : (op2 == 0x7E && insn.H.p_66) ? rmIfRegister : 0;
		}
		if (Between(op2, 0x90, 0x9F) || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB || op2 == 0xBA || op2 == 0xA4 ||
			op2 == 0xA5 || op2 == 0xAC || op2 == 0xAD) {
			return rmIfRegister;
		}
		if (op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1) {
			return 1 << Rax | 1 << reg | rmIfRegister;
		}
		if (op2 == 0xC7) {
			return 1 << Rax | 1 << Rdx | rmIfRegister;
		}
		return op2 == 0xC3 ? 0 : 1 << reg | rmIfRegister;
	}
	if (Between(op, 0xD8, 0xDF) || ReadsOnly(insn)) {
		return 0;
	}
	if ((op == 0xF6 || op == 0xF7) && insn.H.modrm_reg >= 4) {
		return 1 << Rax | 1 << Rdx;
	}
	if (GroupOpcode(insn)) {
		return (op == 0xFF && insn.H.modrm_reg >= 2) ? 0 : rmIfRegister;
	}
	if (LoadsIntoReg(insn) || op == 0x8D) {
		return 1 << reg;
	}
	if (StoresFromReg(insn)) {
		return rmIfRegister;
	}
	return 1 << reg | rmIfRegister;
}

/*
 * Whether p may start an instruction: false only when decoding p's chunk from its start steps over p. Code with no
 * unwind entry (leaf functions), a decoding error or a switch on the way (its table's bytes aren't code) leave it
 * open, and a candidate that may be real is treated as real.
 */
bool MayStartInstruction(const Image &image, const byte *p) {
	const RUNTIME_FUNCTION *chunk = ChunkAt(image, p);
	if (!chunk) {
		return true;
	}
	Insn insn;
	for (const byte *q = image.Base + chunk->BeginAddress; q <= p; q = insn.Next()) {
		if (q == p || !Decode(q, insn) || insn.ReadsJumpTable() || insn.IndirectJump()) {
			return true;
		}
	}
	return false;
}

/*
 * What a function's control flow allows: whether it decoded cleanly with no switch (whose targets can't be known),
 * and where its jumps land.
 */
struct Flow {
	bool Known = true;
	std::vector<const byte *> JumpTargets;
};

Flow FlowOf(const std::vector<Range> &chunks) {
	Flow flow;
	Insn insn;
	for (const Range &chunk : chunks) {
		for (const byte *q = chunk.Start; q < chunk.End; q = insn.Next()) {
			if (!Decode(q, insn) || insn.ReadsJumpTable()) {
				flow.Known = false;
				break;
			}
			if (insn.Jump()) {
				flow.JumpTargets.push_back(insn.Target());
			}
		}
	}
	return flow;
}

enum class OutPak { Null, Local, Unknown };

struct OutPakFile {
	OutPak Kind = OutPak::Unknown;
	int32_t Slot = 0;
};

/*
 * What a call's r8 (a search's OutPakFile) holds: null (xor r8d,r8d), the address of a stack local
 * (lea r8,[rsp+x], or [rbp+x] in a function with an rbp frame), or anything else. Decoded from the call's chunk; the
 * value only counts when it was set in the same chunk, nothing between the setting and the call changes r8 or calls
 * out, and no jump lands in between.
 */
template <typename FrameOf>
OutPakFile OutPakSource(const Image &image, const Flow &flow, const byte *call, FrameOf frameAt) {
	const RUNTIME_FUNCTION *chunk = ChunkAt(image, call);
	if (!flow.Known || !chunk) {
		return {};
	}

	OutPakFile source;
	const byte *setAt = nullptr;
	Insn insn;
	const byte *q = image.Base + chunk->BeginAddress;
	for (; q < call; q = insn.Next()) {
		if (!Decode(q, insn)) {
			return {};
		}
		if (insn.Call() || (Destinations(insn) & 1 << R8)) {
			setAt = q;
			source = {};
			const bool zeroes = (insn.H.opcode == 0x33 || insn.H.opcode == 0x31) && insn.RegisterOperand() &&
				insn.Reg() == R8 && insn.RmRegister() == R8;
			const StackFrame frame = frameAt(q);
			const bool local = !insn.Call() && insn.H.opcode == 0x8D && insn.Reg() == R8 && frame.Known &&
				StackAddress(insn, frame);
			if (!insn.Call() && zeroes) {
				source.Kind = OutPak::Null;
			} else if (local) {
				source = {OutPak::Local, StackOffset(insn, frame)};
			}
		}
	}
	if (q != call || !setAt) {
		return {};
	}
	for (const byte *target : flow.JumpTargets) {
		if (target > setAt && target <= call) {
			return {};
		}
	}
	return source;
}

/* ---- Scanning ---- */

bool HasAvx2() {
	int info[4];
	__cpuid(info, 0);
	if (info[0] < 7) {
		return false;
	}
	__cpuid(info, 1);
	const bool osSavesAvx = (info[2] & (1 << 27)) && (info[2] & (1 << 28)) && (_xgetbv(0) & 6) == 6;
	if (!osSavesAvx) {
		return false;
	}
	__cpuidex(info, 7, 0);
	return (info[1] & (1 << 5)) != 0;
}

/*
 * Calls visit(p) for each byte in [from, to) that is one of the values. The scans look at tens of megabytes of code
 * for a few opcode bytes, so 32 bytes (AVX2) or 16 (SSE2) are compared at once and only the matches looked at closely.
 */
template <size_t Count, typename Visit>
void ForEachByteOf(const byte *from, const byte *to, const byte (&values)[Count], Visit visit) {
	static_assert(Count >= 1 && Count <= 8, "up to eight values");
	static const bool avx2 = HasAvx2();
	const byte *p = from;

	if (avx2) {
		__m256i wanted[Count];
		for (size_t i = 0; i < Count; i++) {
			wanted[i] = _mm256_set1_epi8((char)values[i]);
		}
		for (; p + 32 <= to; p += 32) {
			const __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(p));
			__m256i matches = _mm256_cmpeq_epi8(chunk, wanted[0]);
			for (size_t i = 1; i < Count; i++) {
				matches = _mm256_or_si256(matches, _mm256_cmpeq_epi8(chunk, wanted[i]));
			}
			for (unsigned mask = (unsigned)_mm256_movemask_epi8(matches); mask; mask &= mask - 1) {
				unsigned long bit;
				_BitScanForward(&bit, mask);
				visit(const_cast<byte *>(p + bit));
			}
		}
		_mm256_zeroupper();
	}

	__m128i wanted[Count];
	for (size_t i = 0; i < Count; i++) {
		wanted[i] = _mm_set1_epi8((char)values[i]);
	}
	for (; p + 16 <= to; p += 16) {
		const __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
		__m128i matches = _mm_cmpeq_epi8(chunk, wanted[0]);
		for (size_t i = 1; i < Count; i++) {
			matches = _mm_or_si128(matches, _mm_cmpeq_epi8(chunk, wanted[i]));
		}
		for (unsigned mask = (unsigned)_mm_movemask_epi8(matches); mask; mask &= mask - 1) {
			unsigned long bit;
			_BitScanForward(&bit, mask);
			visit(const_cast<byte *>(p + bit));
		}
	}
	for (; p < to; p++) {
		if (std::find(std::begin(values), std::end(values), *p) != std::end(values)) {
			visit(const_cast<byte *>(p));
		}
	}
}

// Calls visit(p) for each qword in [from, to), 8-byte aligned from `from`, whose value lies in [low, high]
template <typename Visit>
void ForEachPointerIn(const byte *from, const byte *to, const byte *low, const byte *high, Visit visit) {
	static const bool avx2 = HasAvx2();
	const byte *p = from;
	if (avx2) {
		const __m256i below = _mm256_set1_epi64x((int64_t)(low - 1));
		const __m256i above = _mm256_set1_epi64x((int64_t)(high + 1));
		for (; p + 32 <= to; p += 32) {
			const __m256i values = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(p));
			const __m256i inRange =
				_mm256_and_si256(_mm256_cmpgt_epi64(values, below), _mm256_cmpgt_epi64(above, values));
			for (unsigned mask = (unsigned)_mm256_movemask_pd(_mm256_castsi256_pd(inRange)); mask; mask &= mask - 1) {
				unsigned long lane;
				_BitScanForward(&lane, mask);
				visit(p + lane * 8);
			}
		}
		_mm256_zeroupper();
	}
	for (; p + 8 <= to; p += 8) {
		const byte *value = *reinterpret_cast<const byte *const *>(p);
		if (value >= low && value <= high) {
			visit(p);
		}
	}
}

byte *Rel32Target(const byte *displacement) {
	return const_cast<byte *>(displacement) + 4 + *reinterpret_cast<const int32_t *>(displacement);
}

enum class CountWrite { None, Raise, Lower, Unknown };

// A locked write to dword [reg + displacement], decoded: inc, dec, add or sub an immediate; xadd and the rest unknown
CountWrite LockedCountWrite(const Insn &insn, int64_t displacement) {
	if (!insn.H.p_lock || insn.Base() < 0 || insn.Displacement() != displacement) {
		return CountWrite::None;
	}
	const byte opcode = insn.H.opcode;
	const byte reg = insn.H.modrm_reg;
	if (opcode == 0x0F && (insn.H.opcode2 == 0xB0 || insn.H.opcode2 == 0xB1)) {
		return CountWrite::None; // cmpxchg: how the engine reads the counts
	}
	if (opcode == 0xFF && reg <= 1) {
		return reg == 0 ? CountWrite::Raise : CountWrite::Lower;
	}
	if ((opcode == 0x83 || opcode == 0x81) && (reg == 0 || reg == 5)) {
		const int64_t amount = insn.Immediate();
		return (amount > 0) == (reg == 0) ? CountWrite::Raise : CountWrite::Lower;
	}
	return CountWrite::Unknown;
}

/* ---- The pak code ---- */

struct PakCode {
	Image Exe;
	byte *Wrapper = nullptr;
	byte *FindFileInPakFiles = nullptr;
	byte *Memcpy = nullptr;
	byte *EnterSlot = nullptr;
	byte *LeaveSlot = nullptr;
	byte *CreatePakFileHandle = nullptr;
	uint8_t PakListCriticalOffset = 0;
	uint8_t PakFilesOffset = 0;
	uint32_t SyncHandlesOffset = 0;
	uint32_t AsyncHandlesOffset = 0;

	// The pak code is compiled together, so what belongs to it is looked for around the search
	byte *PakFrom = nullptr;
	byte *PakTo = nullptr;

	struct CountWriteSite {
		const byte *At;
		uint32_t Offset;
		CountWrite Write;
	};

	std::vector<const byte *> EnterCalls;
	std::vector<const byte *> WrapperCalls;
	std::vector<const byte *> SearchCalls;
	std::vector<const byte *> CreateCalls;
	std::vector<const byte *> TailJumps; // jmp to the wrapper, the search or CreatePakFileHandle
	std::vector<CountWriteSite> CountWrites;

	// Ways to the lock or the counts the scan can't follow: the lock's import used other than by call [slot], or a
	// count's address taken with lea in the pak code
	std::vector<const byte *> OtherEnterUses;
	std::vector<const byte *> CountAddresses;

	std::map<const byte *, std::vector<Range>> ChainedChunks;

	struct RbpBase {
		bool Set = false;
		const byte *SetAt = nullptr;
		int32_t Offset = 0;
	};
	mutable std::map<const byte *, RbpBase> RbpBases;
	mutable std::unordered_map<const byte *, StackFrame> Frames;
};

std::vector<Range> ChunksOf(const PakCode &code, const byte *function) {
	const RUNTIME_FUNCTION *chunk = ChunkAt(code.Exe, function);
	if (!chunk) {
		return {};
	}
	std::vector<Range> chunks{{code.Exe.Base + chunk->BeginAddress, code.Exe.Base + chunk->EndAddress}};
	auto chained = code.ChainedChunks.find(function);
	if (chained != code.ChainedChunks.end()) {
		chunks.insert(chunks.end(), chained->second.begin(), chained->second.end());
	}
	return chunks;
}

bool InChunks(const std::vector<Range> &chunks, const byte *p) {
	return std::any_of(chunks.begin(), chunks.end(), [p](const Range &chunk) { return chunk.Contains(p); });
}

// Whether only an epilogue follows: pops, rsp restored, saved registers reloaded, then a return or a tail jump
bool EpilogueFollows(const byte *q) {
	Insn insn;
	for (int i = 0; i < 16 && Decode(q, insn); i++) {
		const byte op = insn.H.opcode;
		if (insn.Return() || insn.UnconditionalJump() || insn.IndirectJump()) {
			return true;
		}
		const bool pop = Between(op, 0x58, 0x5F);
		const bool movesRsp = (op == 0x8D && insn.Reg() == Rsp) || (op == 0x8B && insn.Reg() == Rsp) ||
			((op == 0x83 || op == 0x81) && insn.RegisterOperand() && insn.RmRegister() == Rsp && insn.H.modrm_reg == 0);
		const bool reloads = op == 0x8B && !insn.RegisterOperand() && (insn.Base() == Rsp || insn.Base() == R11);
		if (!pop && !movesRsp && !reloads) {
			return false;
		}
		q = insn.Next();
	}
	return false;
}

/*
 * MSVC often points rbp into the frame for shorter displacements without making it the unwind frame register. rbp
 * then addresses the stack when the prologue sets it from rsp, directly or through a copy of rsp (mov r11,rsp;
 * lea rbp,[r11-x]), and the only other writes to it are the epilogue's restores (pop rbp, mov rbp,[rsp+x]).
 */
PakCode::RbpBase RbpBaseOf(const PakCode &code, const byte *function) {
	auto cached = code.RbpBases.find(function);
	if (cached != code.RbpBases.end()) {
		return cached->second;
	}
	PakCode::RbpBase base;
	const RUNTIME_FUNCTION *primary = ChunkAt(code.Exe, function);
	const byte *prologEnd = primary ? function + UnwindInfo(code.Exe, primary)[1] : nullptr;

	// In the prologue: registers holding a stack address, as offsets from rsp at the entry
	bool stackAddress[16] = {};
	int32_t offset[16] = {};
	bool other = false;
	Insn insn;
	for (const Range &chunk : ChunksOf(code, function)) {
		for (const byte *q = chunk.Start; q < chunk.End && !other; q = insn.Next()) {
			if (!Decode(q, insn)) {
				other = true;
				break;
			}
			const byte op = insn.H.opcode;
			const bool prolog = q >= function && q < prologEnd;
			int from = -1;
			int32_t displacement = 0;
			if (insn.H.rex_w && op == 0x8D && insn.Base() >= 0) {
				from = insn.Base();
				displacement = insn.Displacement();
			} else if (insn.H.rex_w && op == 0x8B && insn.RegisterOperand()) {
				from = insn.RmRegister();
			}
			const bool fromStack = prolog && (from == Rsp || (from >= 0 && stackAddress[from]));
			if (fromStack) {
				const StackFrame frame = StackAt(code.Exe, q);
				if (!frame.Known) {
					other = true;
					break;
				}
				stackAddress[insn.Reg()] = true;
				offset[insn.Reg()] = (from == Rsp ? frame.Rsp : offset[from]) + displacement;
			} else if (prolog) {
				for (int reg = 0; reg < 16; reg++) {
					stackAddress[reg] = stackAddress[reg] && !(Destinations(insn) & 1 << reg);
				}
			}

			if (!(Destinations(insn) & 1 << Rbp)) {
				continue;
			}
			const bool reload = op == 0x5D || (op == 0x8B && insn.H.rex_w && insn.Reg() == Rbp &&
				!insn.RegisterOperand() && (insn.Base() == Rsp || insn.Base() == R11));
			const bool restore = reload && EpilogueFollows(insn.Next());
			if (fromStack && insn.Reg() == Rbp && !base.Set) {
				base = {true, insn.Next(), offset[Rbp]};
			} else if (!restore) {
				other = true;
			}
		}
	}
	if (other) {
		base = {};
	}
	code.RbpBases[function] = base;
	return base;
}

// StackAt, with rbp also counted as a frame base when RbpBaseOf finds one
StackFrame FrameAt(const PakCode &code, const byte *pc) {
	auto cached = code.Frames.find(pc);
	if (cached != code.Frames.end()) {
		return cached->second;
	}
	StackFrame frame = StackAt(code.Exe, pc);
	if (!frame.Known || frame.RbpFrame) {
		code.Frames[pc] = frame;
		return frame;
	}
	const byte *function = FunctionStart(code.Exe, pc);
	const PakCode::RbpBase base = function ? RbpBaseOf(code, function) : PakCode::RbpBase{};
	const RUNTIME_FUNCTION *chunk = ChunkAt(code.Exe, pc);
	const bool sameChunk = chunk && pc >= code.Exe.Base + chunk->BeginAddress && base.SetAt &&
		base.SetAt >= code.Exe.Base + chunk->BeginAddress && base.SetAt <= code.Exe.Base + chunk->EndAddress;
	if (base.Set && (!sameChunk || pc >= base.SetAt)) {
		frame.RbpFrame = true;
		frame.Rbp = base.Offset;
	}
	code.Frames[pc] = frame;
	return frame;
}

void Refuse(const char *why, const PakCode &code, const byte *at = nullptr) {
	if (at) {
		printf("Pak list race fix: %s (RVA 0x%llx) - not applied\n", why, (unsigned long long)(at - code.Exe.Base));
	} else {
		printf("Pak list race fix: %s - not applied\n", why);
	}
}

// Near the search first, where the pak code is, then anywhere in the exe
byte *FindPakFunction(const char *name, const char *pattern, const PakCode &code) {
	byte *found = find_function(name, pattern, code.PakFrom, code.PakTo - code.PakFrom);
	return found ? found : find_function(name, pattern, code.Exe.Base, code.Exe.Size);
}

/*
 * FPakPlatformFile::FindFileInPakFiles: copies the list under the lock and searches the copy. Its operands give the
 * lock, the list, the import slots, memcpy and the search, which the rest is matched against.
 */
bool FindWrapper(PakCode &code) {
	byte *wrapper = find_function(
		"FindFileInPakFiles_Wrapper",
		"33ff"              // xor    edi,edi
		"488d59??"          // lea    rbx,[rcx+PakListCritical]
		"4c8bf1"            // mov    r14,rcx
		"48897c2420"        // mov    [rsp+20h],rdi                  (the copy)
		"488bcb"            // mov    rcx,rbx
		"48897c2428"        // mov    [rsp+28h],rdi
		"4d8bf9"            // mov    r15,r9
		"4d8be0"            // mov    r12,r8
		"4c8bea"            // mov    r13,rdx
		"8bf7"              // mov    esi,edi
		"ff15????????"      // call   [EnterCriticalSection]
		"49636e??"          // movsxd rbp,[r14+PakFiles.Num]
		"85ed"              // test   ebp,ebp
		"7437"              // je     (empty list)
		"7e15"              // jle
		"8bd5"              // mov    edx,ebp
		"488d4c2420"        // lea    rcx,[rsp+20h]
		"e8????????"        // call   (grow the copy)
		"8b742428"          // mov    esi,[rsp+28h]
		"488b7c2420"        // mov    rdi,[rsp+20h]
		"498b56??"          // mov    rdx,[r14+PakFiles.Data]
		"4c8bc5"            // mov    r8,rbp
		"4863ce"            // movsxd rcx,esi
		"48c1e104"          // shl    rcx,4
		"4803cf"            // add    rcx,rdi
		"49c1e004"          // shl    r8,4
		"e8????????"        // call   memcpy
		"03f5"              // add    esi,ebp
		"89742428"          // mov    [rsp+28h],esi
		"488bcb"            // mov    rcx,rbx
		"ff15????????"      // call   [LeaveCriticalSection]
		"4d8bcf"            // mov    r9,r15
		"488d4c2420"        // lea    rcx,[rsp+20h]
		"4d8bc4"            // mov    r8,r12
		"498bd5"            // mov    rdx,r13
		"e8????????"        // call   FindFileInPakFiles             (search the copy)
		"0fb6d8",           // movzx  ebx,al
		code.Exe.Text.Start,
		code.Exe.Text.End - code.Exe.Text.Start);
	if (!wrapper) {
		Refuse("FindFileInPakFiles wrapper not found", code);
		return false;
	}

	code.Wrapper = FunctionStart(code.Exe, wrapper);
	code.EnterSlot = Rel32Target(wrapper + 0x23);
	code.Memcpy = Rel32Target(wrapper + 0x5C);
	code.LeaveSlot = Rel32Target(wrapper + 0x6B);
	code.FindFileInPakFiles = Rel32Target(wrapper + 0x7E);
	code.PakListCriticalOffset = wrapper[0x05];
	code.PakFilesOffset = wrapper[0x49];

	// The slots hold the addresses Windows filled in, the same ones GetProcAddress returns
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	void *enterCriticalSection = (void *)GetProcAddress(kernel32, "EnterCriticalSection");
	void *leaveCriticalSection = (void *)GetProcAddress(kernel32, "LeaveCriticalSection");

	// A TArray's element count is 8 bytes after its data pointer
	bool expected =
		code.Wrapper &&
		code.Exe.InCode(code.Memcpy) &&
		code.Exe.InCode(code.FindFileInPakFiles) &&
		*(void **)code.EnterSlot == enterCriticalSection &&
		*(void **)code.LeaveSlot == leaveCriticalSection &&
		wrapper[0x2A] == code.PakFilesOffset + 8;
	if (!expected) {
		Refuse("the FindFileInPakFiles wrapper is not as expected", code, wrapper);
		return false;
	}

	code.PakFrom = std::max(code.FindFileInPakFiles - 0x40000, code.Exe.Text.Start);
	code.PakTo = std::min(code.FindFileInPakFiles + 0x40000, code.Exe.Text.End);
	return true;
}

// The sync count's offset is what CreatePakFileHandle's own lock inc adds to; the async count follows it
bool FindHandleCountOffsets(PakCode &code) {
	code.CreatePakFileHandle = FindPakFunction(
		"FPakPlatformFile_CreatePakFileHandle",
		"4c8bdc574881ec90000000488b05????????4833c44889442470488b410849895b0849896b10498be9",
		code);
	if (!code.CreatePakFileHandle) {
		Refuse("CreatePakFileHandle not found", code);
		return false;
	}

	Insn insn;
	const byte *end = code.CreatePakFileHandle + 0x400;
	for (const byte *q = code.CreatePakFileHandle; q < end && !code.SyncHandlesOffset; q = insn.Next()) {
		if (!Decode(q, insn)) {
			break;
		}
		if (insn.H.p_lock && insn.H.opcode == 0xFF && insn.H.modrm_reg == 0 && insn.Base() >= 0 &&
			insn.Displacement() > 0) {
			code.SyncHandlesOffset = (uint32_t)insn.Displacement();
		}
	}
	code.AsyncHandlesOffset = code.SyncHandlesOffset + 4;
	if (!code.SyncHandlesOffset) {
		Refuse("CreatePakFileHandle doesn't count its handle", code, code.CreatePakFileHandle);
	}
	return code.SyncHandlesOffset != 0;
}

// The instruction whose opcode is at p: at p - 1 with a REX prefix, or at p; null when neither may start one
const byte *InstructionAt(const Image &exe, const byte *p) {
	if ((p[-1] & 0xF0) == 0x40 && MayStartInstruction(exe, p - 1)) {
		return p - 1;
	}
	return MayStartInstruction(exe, p) ? p : nullptr;
}

bool RipRelativeTo(const byte *opcode, const byte *address) {
	return (opcode[1] & 0xC7) == 0x05 && Rel32Target(opcode + 2) == address;
}

// In the pak code, the other uses of the lock's import (mov or lea of its slot) and lea of a handle count
void ScanPakRegion(PakCode &code) {
	const Image &exe = code.Exe;
	const byte candidates[] = {0x8B, 0x8D};
	ForEachByteOf(code.PakFrom, code.PakTo, candidates, [&](byte *p) {
		if (RipRelativeTo(p, code.EnterSlot)) {
			if (const byte *use = InstructionAt(exe, p)) {
				code.OtherEnterUses.push_back(use);
			}
			return;
		}
		if (p[0] != 0x8D || (p[1] >> 6) != 2) {
			return;
		}
		const uint32_t offset = *reinterpret_cast<const uint32_t *>(p + ((p[1] & 7) == 4 ? 3 : 2));
		if (offset != code.SyncHandlesOffset && offset != code.AsyncHandlesOffset) {
			return;
		}
		for (const byte *start : {p, p - 1}) {
			Insn insn;
			if (MayStartInstruction(exe, start) && Decode(start, insn) && insn.H.opcode == 0x8D &&
				insn.Next() > p + 1 && (uint32_t)insn.Displacement() == offset) {
				// A local at the same offset in a frame isn't a pak's count
				if (!StackAddress(insn, FrameAt(code, start))) {
					code.CountAddresses.push_back(start);
				}
				return;
			}
		}
	});
}

// The candidates in every executable section, from one pass for their opcode bytes, kept when they decode as such
void ScanCode(PakCode &code) {
	const Image &exe = code.Exe;
	const byte candidates[] = {0xF0, 0xFF, 0xE8, 0xE9};
	for (const Range &section : exe.Code) {
		if (section.End - section.Start < 32) {
			continue;
		}
		// Candidates read up to 9 bytes past themselves, which the image always has after a code section
		const byte *end = std::min(section.End, exe.Base + exe.Size - 16);
		ForEachByteOf(section.Start, end, candidates, [&](byte *p) {
			if (p[0] == 0xF0) {
				// The offset is in the last 4 bytes of the operand, which is enough to skip almost every lock
				const int32_t sync = (int32_t)code.SyncHandlesOffset;
				bool mentionsCount = false;
				for (int i = 2; i <= 8 && !mentionsCount; i++) {
					const int32_t value = *reinterpret_cast<const int32_t *>(p + i);
					mentionsCount = value == sync || value == sync + 4;
				}
				Insn insn;
				if (!mentionsCount || !MayStartInstruction(exe, p) || !Decode(p, insn)) {
					return;
				}
				for (uint32_t offset : {code.SyncHandlesOffset, code.AsyncHandlesOffset}) {
					const CountWrite write = LockedCountWrite(insn, offset);
					if (write != CountWrite::None) {
						code.CountWrites.push_back({p, offset, write});
					}
				}
			} else if (p[0] == 0xFF) {
				if (!RipRelativeTo(p, code.EnterSlot)) {
					return;
				}
				if (p[1] == 0x15 && MayStartInstruction(exe, p)) {
					code.EnterCalls.push_back(p);
				} else if (p[1] != 0x15 && p >= code.PakFrom && p < code.PakTo) {
					if (const byte *use = InstructionAt(exe, p)) {
						code.OtherEnterUses.push_back(use);
					}
				}
			} else {
				const byte *target = Rel32Target(p + 1);
				const bool watched = target == code.Wrapper || target == code.FindFileInPakFiles ||
					target == code.CreatePakFileHandle;
				if (!watched || !MayStartInstruction(exe, p)) {
					return;
				}
				if (p[0] == 0xE9) {
					code.TailJumps.push_back(p);
				} else if (target == code.Wrapper) {
					code.WrapperCalls.push_back(p);
				} else if (target == code.FindFileInPakFiles) {
					code.SearchCalls.push_back(p);
				} else {
					code.CreateCalls.push_back(p);
				}
			}
		});
	}
}

/*
 * What a locked section (an EnterCriticalSection call up to the LeaveCriticalSection call) does with the pak list,
 * over every path through it. Decoded only when every path reaches the LeaveCriticalSection call.
 */
struct LockedSection {
	bool Decoded = false;
	bool ReadsList = false;    // any operand at the list's data or count, through an object
	bool Copies = false;       // reads the count, and copies from the list's data (memcpy or rep movs)
	bool IntoLocal = false;    // the array copied into is a local, grown with lea rcx,[stack]
};

LockedSection ReadLockedSection(const PakCode &code, const byte *enter) {
	LockedSection section;
	Insn insn;
	if (!Decode(enter, insn) || !insn.CallThrough(code.EnterSlot)) {
		return section;
	}
	// Most sections never address through rbp, and finding whether rbp is a frame base decodes the whole function
	int rbpFrame = -1;
	auto rbpIsFrame = [&]() {
		if (rbpFrame < 0) {
			rbpFrame = FrameAt(code, enter).RbpFrame ? 1 : 0;
		}
		return rbpFrame == 1;
	};
	const uint8_t countOffset = code.PakFilesOffset + 8;

	struct Path {
		const byte *At;
		bool ReadsCount;
		uint16_t ListData; // registers holding the list's data pointer
		bool RcxIsLocal;

		bool operator==(const Path &other) const {
			return At == other.At && ReadsCount == other.ReadsCount && ListData == other.ListData &&
				RcxIsLocal == other.RcxIsLocal;
		}
	};

	// A section has few paths, so the ones seen are searched in a vector
	std::vector<Path> pending{{insn.Next(), false, 0, false}};
	std::vector<Path> seen;
	auto firstVisit = [&seen](const Path &path) {
		if (std::find(seen.begin(), seen.end(), path) != seen.end()) {
			return false;
		}
		seen.push_back(path);
		return true;
	};
	int budget = 4096;
	while (!pending.empty()) {
		Path path = pending.back();
		pending.pop_back();
		while (firstVisit(path)) {
			budget--;
			if (budget < 0 || !Decode(path.At, insn) || insn.Return() || insn.IndirectJump()) {
				return section;
			}
			if (insn.CallThrough(code.LeaveSlot) || insn.Stops()) {
				break;
			}

			const int base = insn.Base();
			const bool throughObject = base >= 0 && base != Rsp && !(base == Rbp && rbpIsFrame());
			const byte opcode = insn.H.opcode;
			const uint16_t written = Destinations(insn);
			const bool atList = insn.Displacement() == countOffset || insn.Displacement() == code.PakFilesOffset;
			section.ReadsList = section.ReadsList || (throughObject && atList);
			if (throughObject && (opcode == 0x63 || opcode == 0x8B) && insn.Displacement() == countOffset) {
				path.ReadsCount = true;
			}

			// Checked before the registers are updated: a call sees the registers set before it, then clobbers them
			if (opcode == 0xE8) {
				if (insn.Target() == code.Memcpy) {
					section.Copies = section.Copies || (path.ReadsCount && (path.ListData & 1 << Rdx));
				} else {
					section.IntoLocal = section.IntoLocal || path.RcxIsLocal;
				}
			}
			const bool repMovs = (opcode == 0xA4 || opcode == 0xA5) && insn.H.p_rep;
			section.Copies = section.Copies || (repMovs && path.ReadsCount && (path.ListData & 1 << Rsi));

			const bool loadsData = throughObject && opcode == 0x8B && insn.H.rex_w &&
				insn.Displacement() == code.PakFilesOffset;
			const bool movesData = opcode == 0x8B && insn.RegisterOperand() && insn.H.rex_w &&
				(path.ListData & 1 << insn.RmRegister());
			if (insn.Call()) {
				path.ListData &= ~VolatileRegisters;
			} else if (loadsData || movesData) {
				path.ListData |= 1 << insn.Reg();
			} else {
				path.ListData &= ~written;
			}

			if (opcode == 0x8D && insn.Reg() == Rcx) {
				path.RcxIsLocal = insn.Base() == Rsp || (insn.Base() == Rbp && rbpIsFrame());
			} else if (insn.Call() || (written & 1 << Rcx)) {
				path.RcxIsLocal = false;
			}

			if (insn.Jump()) {
				if (!insn.UnconditionalJump()) {
					Path taken = path;
					taken.At = insn.Target();
					pending.push_back(taken);
				}
				path.At = insn.UnconditionalJump() ? insn.Target() : insn.Next();
			} else {
				path.At = insn.Next();
			}
		}
	}
	section.Decoded = true;
	return section;
}

/*
 * Which lock a lock call takes, from how its argument was formed, as some object plus an offset. Followed from the
 * function's entry over every path (switch tables included) for lea r,[base+x], add r,x and register moves; where paths
 * meet, an offset only stays known if they agree. At the entry every register is taken as an object at offset 0. A
 * static (lea r,[rip+x]) or a member at another offset than the pak lock's is some other lock. A pointer at offset 0
 * was handed in or loaded and may be the pak lock itself, so like an argument formed any other way it can't be told
 * apart.
 */
enum class Lock { Pak, Other, Unknown };

Lock LockOf(const PakCode &code, const byte *enter) {
	const byte *function = FunctionStart(code.Exe, enter);
	if (!function) {
		return Lock::Unknown;
	}
	constexpr int Unknown = -1;
	constexpr int Static = -2;
	using Offsets = std::array<int, 16>;
	struct Path {
		const byte *At;
		Offsets Offset;
		const byte *Table;
	};

	const std::vector<Range> chunks = ChunksOf(code, function);
	std::map<const byte *, Offsets> seen;
	Offsets entry;
	entry.fill(0);
	std::vector<Path> pending{{function, entry, nullptr}};
	int budget = 20000;
	Insn insn;
	while (!pending.empty()) {
		Path path = pending.back();
		pending.pop_back();
		while (InChunks(chunks, path.At)) {
			auto visit = seen.find(path.At);
			if (visit != seen.end()) {
				Offsets joined = visit->second;
				for (int reg = 0; reg < 16; reg++) {
					joined[reg] = joined[reg] == path.Offset[reg] ? joined[reg] : Unknown;
				}
				if (joined == visit->second) {
					break;
				}
				visit->second = joined;
				path.Offset = joined;
			} else {
				seen[path.At] = path.Offset;
			}

			budget--;
			if (budget < 0 || !Decode(path.At, insn)) {
				return Lock::Unknown;
			}
			if (insn.Return() || insn.Stops()) {
				break;
			}
			if (insn.IndirectJump()) {
				if (!path.Table || insn.H.modrm_mod != 3) {
					break;
				}
				for (const byte *entry = path.Table; entry + 4 <= code.Exe.Base + code.Exe.Size; entry += 4) {
					const byte *target = code.Exe.Base + *reinterpret_cast<const uint32_t *>(entry);
					if (!InChunks(chunks, target)) {
						break;
					}
					pending.push_back({target, path.Offset, nullptr});
				}
				break;
			}
			if (insn.ReadsJumpTable()) {
				path.Table = code.Exe.Base + (uint32_t)insn.H.disp.disp32;
			}

			Offsets &offset = path.Offset;
			const byte opcode = insn.H.opcode;
			if (insn.Call()) {
				for (int volatileRegister : {0, 1, 2, 8, 9, 10, 11}) {
					offset[volatileRegister] = Unknown;
				}
			} else if (opcode == 0x8D && insn.RipRelative()) {
				offset[insn.Reg()] = Static;
			} else if (opcode == 0x8D && insn.Base() >= 0 && insn.Base() != Rsp) {
				offset[insn.Reg()] = insn.Displacement();
			} else if ((opcode == 0x83 || opcode == 0x81) && insn.RegisterOperand() && insn.H.modrm_reg == 0 &&
					   offset[insn.RmRegister()] >= 0) {
				offset[insn.RmRegister()] += (int)insn.Immediate();
			} else if ((opcode == 0x8B || opcode == 0x89) && insn.RegisterOperand() && insn.H.rex_w) {
				const int to = opcode == 0x8B ? insn.Reg() : insn.RmRegister();
				const int from = opcode == 0x8B ? insn.RmRegister() : insn.Reg();
				offset[to] = offset[from];
			} else {
				for (int reg = 0; reg < 16; reg++) {
					offset[reg] = (Destinations(insn) & 1 << reg) ? Unknown : offset[reg];
				}
			}

			if (insn.Jump()) {
				if (!insn.UnconditionalJump()) {
					pending.push_back({insn.Target(), path.Offset, path.Table});
				}
				path.At = insn.UnconditionalJump() ? insn.Target() : insn.Next();
			} else {
				path.At = insn.Next();
			}
		}
	}

	auto atEnter = seen.find(enter);
	if (atEnter == seen.end() || atEnter->second[Rcx] == Unknown || atEnter->second[Rcx] == 0) {
		return Lock::Unknown;
	}
	return atEnter->second[Rcx] == code.PakListCriticalOffset ? Lock::Pak : Lock::Other;
}

/*
 * Readers, found two independent ways so a build that compiles one of them differently is still covered (hooking a
 * function that turns out not to need it only costs time):
 *   - a copy anywhere: in a locked section, the list's count is read, its data loaded as memcpy's source, and
 *     memcpy called. The copy must go into a local array: one handed in by a caller would be used after the hooked
 *     function returns, so that fails the scan;
 *   - in the pak code: a locked section whose lock is formed at the pak lock's offset and that reads the list.
 */
bool FindReaders(const PakCode &code, std::set<byte *> &readers) {
	/*
	 * The pak lock is a private member, taken through FScopeLock, which always inlines to call [EnterCriticalSection].
	 * Other uses of the import (lock functions, jumps to it) belong to other code, but in the pak code they would hide
	 * the sections they lock.
	 */
	for (const byte *use : code.OtherEnterUses) {
		if (use >= code.PakFrom && use < code.PakTo) {
			Refuse("EnterCriticalSection is reached other than by a direct call in the pak code", code, use);
			return false;
		}
	}
	for (const byte *enter : code.EnterCalls) {
		const LockedSection section = ReadLockedSection(code, enter);

		// Outside the pak code a lock is some other one; inside, it has to be told apart from the pak lock
		const bool pakCode = enter >= code.PakFrom && enter < code.PakTo;
		const Lock lock = pakCode ? LockOf(code, enter) : Lock::Other;
		if (lock == Lock::Unknown) {
			Refuse("a lock in the pak code can't be told apart from the pak lock", code, enter);
			return false;
		}
		if (!section.Decoded) {
			if (lock == Lock::Pak) {
				Refuse("a section under the pak lock can't be followed", code, enter);
				return false;
			}
			continue;
		}
		if (section.Copies && !section.IntoLocal) {
			Refuse("a pak list copy goes into an array that isn't a local", code, enter);
			return false;
		}
		const bool locksPakList = section.ReadsList && lock == Lock::Pak;
		TRACE("  lock at %llX: copies %d (into local %d), reads list %d, pak lock %d\n",
			(unsigned long long)(enter - code.Exe.Base), section.Copies, section.IntoLocal, section.ReadsList,
			locksPakList);
		if (section.Copies || locksPakList) {
			byte *function = FunctionStart(code.Exe, enter);
			if (!function) {
				Refuse("a pak list reader has no unwind entry", code, enter);
				return false;
			}
			readers.insert(function);
		}
	}
	if (!readers.count(code.Wrapper)) {
		Refuse("the wrapper's own copy wasn't recognized", code, code.Wrapper);
		return false;
	}
	return true;
}

/*
 * Searches outside the readers are safe when they can't hand out a pak (OutPakFile is null) and they search a copy
 * owned by a reader. The directory visitors are such searches: methods only reached through their object's vtable,
 * and the objects are only made inside readers, so every place that stores one of their vtables has to be in one.
 * Any other way to reach a visitor (a call, a jump, its address taken in code or stored outside .rdata) fails.
 */
bool VisitorsCovered(const PakCode &code, const std::set<byte *> &readers, const std::set<byte *> &visitors) {
	if (visitors.empty()) {
		return true;
	}
	const Image &exe = code.Exe;

	/*
	 * Where a visitor's vtable starts isn't marked (this exe has no type information before its vtables, so adjacent
	 * vtables run together), only that it starts at or before the slot. So every vtable address that lands between
	 * the start of the run of code pointers and the slot counts as a possible store of the visitor's vtable.
	 */
	struct Slot {
		const byte *RunStart;
		const byte *At;
		bool Stored = false;
	};
	std::vector<Slot> slots;
	std::set<byte *> found;
	bool storedOutsideRdata = false;
	for (const Range &section : exe.Data) {
		ForEachPointerIn(section.Start, section.End, *visitors.begin(), *visitors.rbegin(), [&](const byte *p) {
			byte *entry = *(byte *const *)p;
			if (!visitors.count(entry)) {
				return;
			}
			storedOutsideRdata = storedOutsideRdata || !exe.Rdata.Contains(p);
			const byte *start = p;
			while (start - 8 >= exe.Rdata.Start && exe.InCode(*(const byte *const *)(start - 8))) {
				start -= 8;
			}
			slots.push_back({start, p});
			found.insert(entry);
		});
	}
	if (storedOutsideRdata || found.size() != visitors.size()) {
		return false;
	}

	bool covered = true;
	const byte candidates[] = {0x8D, 0xE8, 0xE9};
	for (const Range &section : exe.Code) {
		ForEachByteOf(section.Start + 1, section.End - 8, candidates, [&](byte *p) {
			if (!covered) {
				return;
			}
			Insn insn;
			if (p[0] != 0x8D) {
				if (visitors.count(Rel32Target(p + 1)) && MayStartInstruction(exe, p)) {
					covered = false;
				}
				return;
			}

			// lea r64, [rip+disp32]: the REX prefix is the byte before the 8D
			const byte *lea = p - 1;
			if ((lea[0] != 0x48 && lea[0] != 0x4C) || (p[1] & 0xC7) != 0x05) {
				return;
			}
			const byte *address = Rel32Target(p + 2);
			const bool namesVisitor = visitors.count(const_cast<byte *>(address)) != 0;
			const bool namesVtable = std::any_of(slots.begin(), slots.end(), [address](const Slot &slot) {
				return address >= slot.RunStart && address <= slot.At;
			});
			if ((!namesVisitor && !namesVtable) || !MayStartInstruction(exe, lea)) {
				return;
			}
			if (namesVisitor || !readers.count(FunctionStart(exe, lea))) {
				covered = false;
				return;
			}
			for (Slot &slot : slots) {
				slot.Stored = slot.Stored || (address >= slot.RunStart && address <= slot.At);
			}
		});
	}
	return covered && std::all_of(slots.begin(), slots.end(), [](const Slot &slot) { return slot.Stored; });
}

/*
 * Handles: CreatePakFileHandle counts a sync handle in the pak, the async open counts an async one, and each handle
 * class's destructor counts it down.
 *   - A count raised outside a reader could still be zero when the pak's last reader returns (and would mean a pak
 *     reached code that isn't covered), so every raise, and every call to CreatePakFileHandle, has to be in a reader.
 *   - A function that lowers a count is hooked as a handle destructor: it may still use the pak after the count
 *     drops, so it holds back every unmounted pak until it returns.
 *   - A write outside the pak code is unexpected, maybe a pak path that isn't covered, so it fails.
 */
bool FindHandleCounts(const PakCode &code, const std::set<byte *> &readers, std::set<byte *> &destructors) {
	if (!code.CountAddresses.empty()) {
		Refuse("a handle count's address is taken, so its writes can't all be seen", code, code.CountAddresses[0]);
		return false;
	}
	size_t asyncRaises = 0;
	size_t syncLowers = 0;
	size_t asyncLowers = 0;
	for (const PakCode::CountWriteSite &site : code.CountWrites) {
		if (site.At < code.PakFrom || site.At >= code.PakTo) {
			Refuse("a handle count is changed outside the pak code", code, site.At);
			return false;
		}
		byte *function = FunctionStart(code.Exe, site.At);
		const bool inReader = function == code.CreatePakFileHandle || readers.count(function);
		if ((site.Write == CountWrite::Raise || site.Write == CountWrite::Unknown) && !inReader) {
			Refuse("a handle count is raised outside the readers", code, site.At);
			return false;
		}
		asyncRaises += site.Write == CountWrite::Raise && site.Offset == code.AsyncHandlesOffset ? 1 : 0;
		if (site.Write == CountWrite::Lower || site.Write == CountWrite::Unknown) {
			if (!function) {
				Refuse("a handle count is lowered where there's no unwind entry", code, site.At);
				return false;
			}
			destructors.insert(function);
			(site.Offset == code.SyncHandlesOffset ? syncLowers : asyncLowers)++;
		}
	}
	for (const byte *call : code.CreateCalls) {
		if (!readers.count(FunctionStart(code.Exe, call))) {
			Refuse("CreatePakFileHandle is called outside the readers", code, call);
			return false;
		}
	}
	if (!asyncRaises || code.CreateCalls.empty() || !syncLowers || !asyncLowers) {
		printf(
			"Pak list race fix: handle counts are not as expected (%zu async raises, %zu CreatePakFileHandle calls, "
			"%zu/%zu destructors) - not applied\n",
			asyncRaises,
			code.CreateCalls.size(),
			syncLowers,
			asyncLowers);
		return false;
	}
	return true;
}

bool FindUnmountDelete(const PakCode &code, const std::set<byte *> &readers, PakCodeScan &scan) {
	byte *unmount = FindPakFunction(
		"FPakPlatformFile_Unmount",
		"40535557415441554883ec30833d????????004c8be2488be97422488b1d",
		code);
	if (!unmount) {
		Refuse("Unmount not found", code);
		return false;
	}

	byte *deleteCall = find_function(
		"FPakPlatformFile_Unmount delete",
		"488d0d????????"    // lea    rcx,[pak signatures lock]
		"ff15????????"      // call   [LeaveCriticalSection]
		"488b4e08"          // mov    rcx,[rsi+8]                    (the FPakFile being unmounted)
		"4885c9"            // test   rcx,rcx
		"740a"              // je     (no pak)
		"ba01000000"        // mov    edx,1                          (delete flag)
		"e8????????",       // call   FPakFile's scalar deleting destructor
		unmount,
		0x200);
	if (!deleteCall || Rel32Target(deleteCall + 9) != code.LeaveSlot) {
		Refuse("Unmount's delete is not as expected", code, unmount);
		return false;
	}

	// A pak Unmount takes out of the list is only safe to hold back while Unmount itself is a reader
	if (!readers.count(FunctionStart(code.Exe, unmount))) {
		Refuse("Unmount isn't a pak list reader", code, unmount);
		return false;
	}

	// Unmount checks both handle counts before deleting (in development builds), so the offsets are confirmed there
	bool readsSync = false;
	bool readsAsync = false;
	Insn insn;
	for (const byte *q = unmount; q < deleteCall; q = insn.Next()) {
		if (!Decode(q, insn)) {
			break;
		}
		const bool compareExchange = insn.H.p_lock && insn.H.opcode == 0x0F && insn.H.opcode2 == 0xB1;
		readsSync = readsSync || (compareExchange && insn.Displacement() == (int32_t)code.SyncHandlesOffset);
		readsAsync = readsAsync || (compareExchange && insn.Displacement() == (int32_t)code.AsyncHandlesOffset);
	}
	if (!readsSync || !readsAsync) {
		Refuse("Unmount doesn't read the handle counts", code, unmount);
		return false;
	}

	scan.UnmountDeleteReturn = deleteCall + 32;
	scan.DeletePakFile = Rel32Target(deleteCall + 28);
	return code.Exe.InCode(scan.DeletePakFile);
}

/*
 * funchook overwrites a function's first instructions (at least 5 bytes) with a jump and moves them to a trampoline,
 * which is only safe when no code jumps into those bytes and none of them is a branch. Prologue code is never a jump
 * target, so the moved instructions have to be prologue: the function's own (its unwind info gives the length), or,
 * when the compiler split the prologue, the start of the chained chunk the first chunk runs straight into.
 */
bool SafeToPatch(const Image &exe, const byte *function) {
	const RUNTIME_FUNCTION *chunk = ChunkAt(exe, function);
	const RUNTIME_FUNCTION *primary = chunk ? PrimaryOf(exe, chunk) : nullptr;
	if (!primary || exe.Base + chunk->BeginAddress != function || primary->BeginAddress != chunk->BeginAddress) {
		return false;
	}

	size_t moved = 0;
	Insn insn;
	for (const byte *q = function; moved < 5; q = insn.Next()) {
		if (!Decode(q, insn) || insn.Target() || insn.Call() || insn.Return() || insn.IndirectJump()) {
			return false;
		}
		moved += insn.H.len;
	}
	if (moved <= UnwindInfo(exe, chunk)[1]) {
		return true;
	}

	// Chained unwind info holds a copy of the first chunk's entry, so chunks are compared by address
	const byte *chunkEnd = exe.Base + chunk->EndAddress;
	const RUNTIME_FUNCTION *next = ChunkAt(exe, chunkEnd);
	const RUNTIME_FUNCTION *nextPrimary = next ? PrimaryOf(exe, next) : nullptr;
	if (!nextPrimary || exe.Base + next->BeginAddress != chunkEnd || nextPrimary->BeginAddress != chunk->BeginAddress) {
		return false;
	}

	// The moved instructions past the first chunk have to save registers to the stack: mov [rsp+x], reg
	for (const byte *q = chunkEnd; q < function + moved; q = insn.Next()) {
		if (!Decode(q, insn) || insn.H.opcode != 0x89 || insn.Base() != Rsp) {
			return false;
		}
	}
	return true;
}

/*
 * Follows a pointer through code: over every path of a function (switch tables included), through registers and stack
 * slots, and into the functions it's passed to. Two uses:
 *   - Pak: whether a pak a reader finds into a local OutPakFile can outlive the reader. The reader is hooked, so
 *     anything done with the pak while it runs is safe; the pak just mustn't be kept. Returning it, storing it
 *     anywhere but the stack, or handing it where it can't be followed (an indirect call, an xmm register, a function
 *     too deep) fails. CreatePakFileHandle may take it (the engine counts the handle), and memcpy keeps nothing.
 *   - OutPakFile: whether a search writes its OutPakFile only when it returns true. Every path that writes through it
 *     must return a nonzero al: a constant, or the result of a search already shown to do the same. A slot a search
 *     fills then only holds a pak on the found side of the test of al that follows the call.
 *
 * A pointer to one of a function's locals is taken to reach only that local (separate locals don't overlap), so
 * passing it on only matters when it points at a slot holding the pak.
 *
 * Not followed: paks a reader reads straight out of its own copy of the list. They're trusted not to outlive the
 * reader, as no FPakPlatformFile method keeps one; only paks found through a search are followed.
 */
class PointerFlow {
public:
	enum class Mode { Pak, OutPakFile };

	PointerFlow(const PakCode &code, Mode mode) : Code(code), Kind(mode) {}

	// Pak mode: the slots the function's searches fill hold the pak from then on
	bool Kept(const byte *function) {
		return !Follow(function, 0, 0, {}, 0).Escapes;
	}

	// OutPakFile mode: the function's OutPakFile arrives in r8
	bool WritesOnlyOnSuccess(const byte *function) {
		return !Follow(function, 1 << R8, 1 << R8, {}, 0).Escapes;
	}

	// Searches shown to write OutPakFile only when they return true
	std::set<const byte *> Searches;

	const byte *EscapeAt = nullptr;
	std::vector<const byte *> EscapeCalls;

private:
	// What a register's low byte says about a search's result; Zero means the whole register is zero
	enum Result : uint8_t { Unknown, Zero, NonZero, Tied };
	enum class Wrote : uint8_t { No, Tied, Yes };

	static constexpr int32_t NoAddress = INT32_MIN;
	static constexpr int MaxDepth = 4;
	static constexpr int Budget = 40000;
	static constexpr size_t MaxStatesPerInstruction = 64;

	struct State {
		const byte *At = nullptr;
		uint16_t Value = 0;     // registers holding the pointer, or one derived from it
		uint16_t Written = 0;   // registers this function set since its entry or its last call
		uint16_t Forwarded = 0; // its declared arguments, untouched and before any call
		const byte *Table = nullptr;
		std::vector<int32_t> Slots;   // stack slots holding the pointer, as offsets from rsp at the entry
		std::vector<int32_t> Spilled; // those this function stored it to, which may be stack arguments
		std::array<int32_t, 16> Address; // the stack address each register holds, or NoAddress
		int32_t Filled = NoAddress;      // a slot a search just filled,
		bool FilledBefore = false;       // whether it held the pak before,
		uint8_t FillStage = 0;           // and how far the test of the result has got: 1 after the call, 2 after test
		Wrote Writes = Wrote::No;
		std::array<Result, 16> Results;
		std::array<int32_t, 16> LoadedFrom; // the slot each register was loaded from, while it still matches
		int8_t NullTested = -1;             // a register holding the pointer just tested against null
		std::vector<int32_t> HandedOut;     // stack addresses stored to memory or passed to a call

		bool operator<(const State &other) const {
			return std::tie(At, Value, Written, Forwarded, Table, Slots, Spilled, Address, Filled, FilledBefore,
					   FillStage, Writes, Results, LoadedFrom, NullTested, HandedOut) <
				std::tie(other.At, other.Value, other.Written, other.Forwarded, other.Table, other.Slots,
					other.Spilled, other.Address, other.Filled, other.FilledBefore, other.FillStage, other.Writes,
					other.Results, other.LoadedFrom, other.NullTested, other.HandedOut);
		}
	};

	struct Outcome {
		bool Escapes = false;
		bool Returns = false;
	};

	/*
	 * States reaching an instruction are joined unless they differ in what the checks read per path: stack addresses,
	 * the switch table, a pending test of a search's result or of null, and (for OutPakFile) the writes and results.
	 * The rest only grows: registers and slots holding the pointer, and registers set for calls.
	 */
	using JoinKey = std::tuple<std::array<int32_t, 16>, const byte *, int32_t, bool, uint8_t, int8_t, Wrote,
		std::array<Result, 16>>;

	JoinKey KeyOf(const State &state) const {
		std::array<Result, 16> results;
		results.fill(Unknown);
		return {state.Address, state.Table, state.Filled, state.FilledBefore, state.FillStage, state.NullTested,
			state.Writes, Kind == Mode::OutPakFile ? state.Results : results};
	}

	// Joins a state into one already seen; false when it adds nothing
	static bool Join(State &into, const State &from) {
		State before = into;
		into.Value |= from.Value;
		into.Written |= from.Written;
		into.Forwarded |= from.Forwarded;
		for (int32_t slot : from.Slots) {
			Insert(into.Slots, slot);
		}
		for (int32_t slot : from.Spilled) {
			Insert(into.Spilled, slot);
		}
		for (int32_t address : from.HandedOut) {
			Insert(into.HandedOut, address);
		}
		for (int reg = 0; reg < 16; reg++) {
			into.LoadedFrom[reg] = into.LoadedFrom[reg] == from.LoadedFrom[reg] ? into.LoadedFrom[reg] : NoAddress;
		}
		return into.Value != before.Value || into.Written != before.Written || into.Forwarded != before.Forwarded ||
			into.Slots != before.Slots || into.Spilled != before.Spilled || into.LoadedFrom != before.LoadedFrom ||
			into.HandedOut != before.HandedOut;
	}

	const PakCode &Code;
	const Mode Kind;
	std::map<std::tuple<const byte *, uint16_t, uint16_t, std::vector<int32_t>>, Outcome> Done;
	std::set<std::tuple<const byte *, uint16_t, uint16_t, std::vector<int32_t>>> Running;
	std::vector<const byte *> CallStack;

	Outcome Escape(const byte *at) {
		if (!EscapeAt) {
			EscapeAt = at;
			EscapeCalls = CallStack;
		}
		Outcome outcome;
		outcome.Escapes = true;
		return outcome;
	}

	Outcome Follow(
		const byte *function,
		uint16_t value,
		uint16_t declared,
		const std::vector<int32_t> &slots,
		int depth) {
		if (depth > MaxDepth) {
			return Escape(function);
		}
		const auto key = std::make_tuple(function, value, declared, slots);
		auto done = Done.find(key);
		if (done != Done.end()) {
			return done->second;
		}
		if (!Running.insert(key).second) {
			return Escape(function);
		}
		const Outcome outcome = Walk(function, value, declared, slots, depth);
		Running.erase(key);
		Done[key] = outcome;
		return outcome;
	}

	static bool Contains(const std::vector<int32_t> &slots, int32_t slot) {
		return std::find(slots.begin(), slots.end(), slot) != slots.end();
	}

	static void Insert(std::vector<int32_t> &slots, int32_t slot) {
		if (!Contains(slots, slot)) {
			slots.insert(std::upper_bound(slots.begin(), slots.end(), slot), slot);
		}
	}

	static void Erase(std::vector<int32_t> &slots, int32_t slot) {
		slots.erase(std::remove(slots.begin(), slots.end(), slot), slots.end());
	}

	static bool Overlaps(const std::vector<int32_t> &slots, int32_t offset, int width) {
		return std::any_of(slots.begin(), slots.end(), [&](int32_t slot) {
			return offset < slot + 8 && slot < offset + width;
		});
	}

	// Whether a stack address points into a slot holding the pointer
	static bool PointsAtSlot(const State &state, int32_t address) {
		return address != NoAddress && Overlaps(state.Slots, address, 1);
	}

	static void ClearRegisters(State &state, uint16_t registers) {
		state.Value &= ~registers;
		for (int reg = 0; reg < 16; reg++) {
			if (registers & 1 << reg) {
				state.Address[reg] = NoAddress;
				state.Results[reg] = Unknown;
				state.LoadedFrom[reg] = NoAddress;
			}
		}
	}

	// Registers loaded from a slot no longer match it once it's written
	static void Forget(State &state, int32_t slot) {
		for (int32_t &loadedFrom : state.LoadedFrom) {
			loadedFrom = loadedFrom == slot ? NoAddress : loadedFrom;
		}
	}

	static void Kill(State &state, int32_t slot) {
		Erase(state.Slots, slot);
		Erase(state.Spilled, slot);
		Forget(state, slot);
	}

	// False when the slot's address was handed out before: whoever has it could read the pointer unseen
	static bool Taint(State &state, int32_t slot, bool spilled) {
		Forget(state, slot);
		Insert(state.Slots, slot);
		if (spilled) {
			Insert(state.Spilled, slot);
		}
		return std::none_of(state.HandedOut.begin(), state.HandedOut.end(), [slot](int32_t address) {
			return address >= slot && address < slot + 8;
		});
	}

	// Enter/LeaveCriticalSection, through their import slots: they lock or unlock their argument and keep nothing
	bool LockCall(const byte *target, const byte *call) const {
		Insn insn;
		return !target && Decode(call, insn) && insn.RipRelative() &&
			(insn.RipTarget() == Code.EnterSlot || insn.RipTarget() == Code.LeaveSlot);
	}

	/*
	 * A call or a tail jump. The pointer may go in argument registers, in stack arguments the function stored it to,
	 * or behind a stack address.
	 *
	 * A register can still hold the pointer without being an argument: a volatile register the function never touched
	 * keeps its value into every call until the first one. A callee only reads the argument registers its signature
	 * declares, which its caller sets for the call or forwards from its own declared arguments. So a call that can't be
	 * followed only takes the pointer in a register set in this function since the last call, or in one of this
	 * function's declared arguments forwarded untouched; a followed callee is told which registers were set for it.
	 * Not covered: a pointer forwarded untouched through two functions into one that can't be followed.
	 */
	bool Call(const byte *target, const byte *call, State &state, const StackFrame &frame, int depth, bool tail) {
		const uint16_t valueArguments = state.Value & ArgumentRegisters;
		const uint16_t declared = valueArguments & (state.Written | state.Forwarded);
		std::vector<int32_t> stackArguments;
		for (int32_t slot : tail ? state.Slots : state.Spilled) {
			if (tail ? slot >= 0x28 : slot - frame.Rsp >= 0x20) {
				stackArguments.push_back(tail ? slot : slot - frame.Rsp + 8);
			}
		}
		const bool search = target && (target == Code.Wrapper || target == Code.FindFileInPakFiles);
		const bool verified = search && Searches.count(target);
		bool pointsAtSlot = false;
		for (int reg : {Rcx, Rdx, R8, R9}) {
			const bool searchFill = search && reg == R8;
			pointsAtSlot = pointsAtSlot || (!searchFill && PointsAtSlot(state, state.Address[reg]));
		}
		if (pointsAtSlot && !search) {
			return false;
		}

		// A callee may keep a stack address it's given; memcpy, the lock calls and the searches don't
		const bool keepsNothing = search || LockCall(target, call) || (target && target == Code.Memcpy);
		for (int reg : {Rcx, Rdx, R8, R9}) {
			if (!keepsNothing && state.Address[reg] != NoAddress) {
				Insert(state.HandedOut, state.Address[reg]);
			}
		}

		bool returnsValue = false;
		Result result = Unknown;
		int32_t filled = NoAddress;
		if (target && target == Code.Memcpy) {
			// Copies bytes through the pointers it's given and keeps none; it returns the destination
			if (Kind == Mode::OutPakFile && (state.Value & 1 << Rcx)) {
				if (depth > 0) {
					return false;
				}
				state.Writes = Wrote::Yes;
			}
			if (PointsAtSlot(state, state.Address[Rdx])) {
				return false;
			}
			returnsValue = (state.Value & 1 << Rcx) != 0;
		} else if (target && target == Code.CreatePakFileHandle) {
			// The handle keeps its pak, counted in the pak's sync handle count
			if (Kind == Mode::OutPakFile && valueArguments) {
				return false;
			}
		} else if (search) {
			if (Kind == Mode::Pak) {
				// The search's other arguments are its own lookup's: the copy to search and the entry to fill
				if (valueArguments || !stackArguments.empty() || state.Address[R8] == NoAddress) {
					return false;
				}
				filled = state.Address[R8];
			} else {
				if ((valueArguments & ~(1 << R8)) || !stackArguments.empty() || !verified || depth > 0) {
					return false;
				}
				if (valueArguments) {
					// A second search that may write loses the tie: the first may have written and the second fail
					state.Writes = state.Writes == Wrote::No ? Wrote::Tied : Wrote::Yes;
					result = Tied;
				}
			}
		} else if (LockCall(target, call)) {
			if (Kind == Mode::OutPakFile && (valueArguments & 1 << Rcx)) {
				return false;
			}
		} else if (!target || !Code.Exe.InCode(target)) {
			if (declared || !stackArguments.empty()) {
				return false;
			}
		} else if (valueArguments || !stackArguments.empty()) {
			const uint16_t setForCallee = valueArguments & (tail ? state.Written | state.Forwarded : state.Written);
			CallStack.push_back(target);
			const Outcome callee = Follow(target, valueArguments, setForCallee, stackArguments, depth + 1);
			CallStack.pop_back();
			if (callee.Escapes) {
				return false;
			}
			returnsValue = callee.Returns;
		}

		const bool filledBefore = filled != NoAddress && Contains(state.Slots, filled);
		ClearRegisters(state, VolatileRegisters);
		state.Written = (state.Written & ~VolatileRegisters) | 1 << Rax;
		state.Forwarded = 0;
		state.Results[Rax] = result;
		state.Filled = NoAddress;
		state.FillStage = 0;
		if (returnsValue) {
			state.Value |= 1 << Rax;
		}
		if (filled != NoAddress) {
			if (!Taint(state, filled, false)) {
				return false;
			}
			if (verified) {
				state.Filled = filled;
				state.FilledBefore = filledBefore;
				state.FillStage = 1;
			}
		}
		return true;
	}

	// The checks on leaving the function, by a return or after a tail jump
	bool Leaves(const State &state, int depth, Outcome &outcome) {
		if (Kind == Mode::Pak) {
			if (state.Value & 1 << Rax) {
				if (depth == 0) {
					return false;
				}
				outcome.Returns = true;
			}
			return true;
		}
		if (depth > 0) {
			outcome.Returns = outcome.Returns || (state.Value & 1 << Rax);
			return true;
		}
		const Result result = state.Results[Rax];
		switch (state.Writes) {
			case Wrote::No:
				return true;
			case Wrote::Tied:
				return result == Tied || result == NonZero;
			case Wrote::Yes:
			default:
				return result == NonZero;
		}
	}

	// What a register set to a constant says about a result
	static Result ResultOf(int64_t constant) {
		return constant == 0 ? Zero : (constant & 0xFF) ? NonZero : Unknown;
	}

	// Where a memory operand is: the stack at a known offset, the stack at an unknown one, or elsewhere
	enum class Place { Elsewhere, Stack, IndexedStack };

	Place PlaceOf(const Insn &insn, const StackFrame &frame, const State &state, int32_t &offset) const {
		const int base = insn.AddressBase();
		if (base < 0) {
			return Place::Elsewhere;
		}
		const bool frameBase = base == Rsp || (base == Rbp && frame.RbpFrame);
		if (!frameBase && state.Address[base] == NoAddress) {
			return Place::Elsewhere;
		}
		if (insn.AddressIndex() >= 0) {
			return Place::IndexedStack;
		}
		offset = frameBase ? StackOffset(insn, frame) : state.Address[base] + insn.Displacement();
		return Place::Stack;
	}

	Outcome Walk(
		const byte *function,
		uint16_t value,
		uint16_t declared,
		const std::vector<int32_t> &slots,
		int depth) {
		const std::vector<Range> chunks = ChunksOf(Code, function);
		Outcome outcome;
		State start;
		start.At = function;
		start.Value = value;
		start.Forwarded = declared;
		start.Slots = slots;
		start.Address.fill(NoAddress);
		start.Results.fill(Unknown);
		start.LoadedFrom.fill(NoAddress);

		std::map<const byte *, std::map<JoinKey, State>> seen;
		std::vector<State> pending{start};
		int budget = Budget;
		while (!pending.empty()) {
			State state = std::move(pending.back());
			pending.pop_back();
			for (;;) {
				// Running out of the function's chunks only happens after a call that doesn't return
				if (!chunks.empty() && !InChunks(chunks, state.At)) {
					break;
				}
				std::map<JoinKey, State> &here = seen[state.At];
				const JoinKey key = KeyOf(state);
				auto joined = here.find(key);
				if (joined != here.end()) {
					if (!Join(joined->second, state)) {
						break;
					}
					state = joined->second;
				} else if (here.size() >= MaxStatesPerInstruction) {
					return Escape(state.At);
				} else {
					here.emplace(key, state);
				}

				budget--;
				Insn insn;
				if (budget < 0 || !Decode(state.At, insn)) {
					return Escape(state.At);
				}
				const StackFrame frame = FrameAt(Code, state.At);
				if (!frame.Known) {
					return Escape(state.At);
				}
				const byte *at = state.At;
				if (!Step(insn, frame, state, pending, chunks, depth, outcome)) {
					return Escape(at);
				}
				if (!state.At) {
					break;
				}
			}
		}
		return outcome;
	}

	/*
	 * An instruction with no ModRM operand. Writes that replace a register clear it; ones that derive from it (string
	 * instructions advancing rsi and rdi, arithmetic on al/eax with an immediate, mov to a byte register) keep the
	 * pointer but lose what else was known. Anything else that writes a register refuses once the walk follows
	 * something, as does a push, which would move rsp where the slots' offsets assume it doesn't.
	 */
	bool StepWithoutOperands(const Insn &insn, const StackFrame &frame, State &state, uint16_t destinations) {
		const byte op = insn.H.opcode;
		const byte op2 = insn.H.opcode2;
		const int opReg = (op & 7) | (insn.H.rex_b << 3);
		const uint16_t tracked = state.Value;
		const bool following = tracked || !state.Slots.empty() ||
			std::any_of(state.Address.begin(), state.Address.end(), [](int32_t a) { return a != NoAddress; });

		if (Between(op, 0x91, 0x97) || (op == 0x90 && insn.H.rex_b)) {
			const bool involved = (tracked & (1 << opReg | 1 << Rax)) || state.Address[opReg] != NoAddress ||
				state.Address[Rax] != NoAddress;
			ClearRegisters(state, destinations);
			return !involved;
		}
		if (Between(op, 0xA4, 0xAF) && op != 0xA8 && op != 0xA9) {
			// stos stores rax at rdi; movs, cmps and lods read from rsi, for a length not known here
			const bool storesValue = (op == 0xAA || op == 0xAB) && (tracked & 1 << Rax);
			const bool writesThrough = Kind == Mode::OutPakFile && (tracked & 1 << Rdi) &&
				(op == 0xA4 || op == 0xA5 || op == 0xAA || op == 0xAB);
			const int32_t from = state.Address[Rsi];
			const bool readsSlots = (destinations & 1 << Rsi) && from != NoAddress &&
				std::any_of(state.Slots.begin(), state.Slots.end(), [from](int32_t slot) { return slot + 8 > from; });
			if (storesValue || writesThrough || readsSlots) {
				return false;
			}
			for (int reg : {Rsi, Rdi}) {
				if (destinations & 1 << reg) {
					const bool value = (state.Value & 1 << reg) != 0;
					ClearRegisters(state, 1 << reg);
					state.Value |= value ? 1 << reg : 0;
				}
			}
			ClearRegisters(state, destinations & (1 << Rax | 1 << Rcx));
			return true;
		}

		const bool replaces = Between(op, 0xB8, 0xBF) || Between(op, 0x58, 0x5F) || op == 0x99 ||
			(op == 0x0F && (op2 == 0x31 || op2 == 0xA2 || op2 == 0x05));
		const bool derives = op == 0x98 || op == 0xD7 || op == 0x9F || Between(op, 0xB0, 0xB7) ||
			(op == 0x0F && Between(op2, 0xC8, 0xCF)) ||
			(op < 0x40 && ((op & 7) == 4 || (op & 7) == 5) && op != 0x3C && op != 0x3D);
		if (replaces) {
			// pop reads the stack, which only an epilogue does, but the slot it reads may hold the pointer
			const bool popsSlot = Between(op, 0x58, 0x5F) && Overlaps(state.Slots, frame.Rsp, 8);
			ClearRegisters(state, destinations);
			state.Value |= popsSlot ? destinations : 0;
			if (Between(op, 0xB8, 0xBF)) {
				state.Results[opReg] = ResultOf(insn.Immediate());
			}
			return true;
		}
		if (derives) {
			const uint16_t value = state.Value & destinations;
			ClearRegisters(state, destinations);
			state.Value |= value;
			if (Between(op, 0xB0, 0xB7) && (insn.H.rex || op < 0xB4)) {
				state.Results[opReg] = (insn.Immediate() & 0xFF) ? NonZero : Unknown;
			}
			return true;
		}
		// A prologue's pushes are in its unwind codes, which the slots' offsets come from
		if (Between(op, 0x50, 0x57) && InPrologue(Code.Exe, insn.At)) {
			return !(tracked & 1 << opReg) && state.Address[opReg] == NoAddress;
		}
		const bool push = Between(op, 0x50, 0x57) || op == 0x68 || op == 0x6A || op == 0x9C;
		if (push || destinations) {
			ClearRegisters(state, destinations);
			return !following;
		}
		return true;
	}

	// One instruction; false when the pointer may escape, and state.At null when the path ends
	bool Step(
		const Insn &insn,
		const StackFrame &frame,
		State &state,
		std::vector<State> &pending,
		const std::vector<Range> &chunks,
		int depth,
		Outcome &outcome) {
		const byte op = insn.H.opcode;
		const byte op2 = insn.H.opcode2;
		const int reg = insn.Reg();
		const int rm = insn.RmRegister();
		const uint16_t destinations = Destinations(insn);
		const bool testsResult = op == 0x84 && insn.H.modrm == 0xC0 && !insn.H.rex;
		const int nullTested = state.NullTested;
		state.NullTested = -1;

		// The test of a search's result has to follow the call before anything else changes al or the flags
		if (state.FillStage == 1 && testsResult) {
			state.FillStage = 2;
		} else if (state.FillStage == 1 && (destinations & 1 << Rax || insn.Call() || insn.Jump() ||
										   insn.IndirectJump() || insn.Return())) {
			state.FillStage = 0;
		} else if (state.FillStage == 2 && !(insn.Jump() && !insn.UnconditionalJump())) {
			state.FillStage = 0;
		}

		if (insn.Stops()) {
			state.At = nullptr;
			return true;
		}
		if (insn.Return()) {
			state.At = nullptr;
			return Leaves(state, depth, outcome);
		}
		if (insn.Call()) {
			if (!Call(op == 0xE8 ? insn.Target() : nullptr, insn.At, state, frame, depth, false)) {
				return false;
			}
			state.At = insn.Next();
			return true;
		}

		const bool tailJump = (insn.Jump() && !chunks.empty() && !InChunks(chunks, insn.Target())) ||
			(insn.IndirectJump() && !state.Table && insn.H.modrm_mod != 3);
		if (tailJump) {
			const byte *target = insn.Jump() ? insn.Target() : nullptr;
			if (!Call(target, insn.At, state, frame, depth, true)) {
				return false;
			}
			state.At = nullptr;
			return Leaves(state, depth, outcome);
		}
		if (insn.Jump()) {
			if (insn.UnconditionalJump()) {
				state.At = insn.Target();
				return true;
			}
			State taken = state;
			taken.At = insn.Target();
			const bool jumpsIfZero = op == 0x74 || (op == 0x0F && op2 == 0x84);
			const bool jumpsIfNonZero = op == 0x75 || (op == 0x0F && op2 == 0x85);
			if (state.FillStage == 2) {
				// The side where the search returned false holds what the slot held before the call
				State *notFound = jumpsIfZero ? &taken : jumpsIfNonZero ? &state : nullptr;
				if (notFound && !notFound->FilledBefore) {
					Kill(*notFound, notFound->Filled);
				}
				taken.FillStage = 0;
				state.FillStage = 0;
			}
			if (nullTested >= 0) {
				// On the side where the register is null, so is the slot it was loaded from
				State *null = jumpsIfZero ? &taken : jumpsIfNonZero ? &state : nullptr;
				if (null) {
					const int32_t slot = null->LoadedFrom[nullTested];
					for (int r = 0; r < 16; r++) {
						const bool same = r == nullTested || (slot != NoAddress && null->LoadedFrom[r] == slot);
						null->Value &= same ? ~(1 << r) : 0xFFFF;
					}
					if (slot != NoAddress) {
						Kill(*null, slot);
					}
				}
			}
			pending.push_back(std::move(taken));
			state.At = insn.Next();
			return true;
		}
		if (insn.IndirectJump()) {
			// A switch: its table holds the RVAs of its cases, which all lie in the function
			if (!state.Table) {
				return false;
			}
			size_t cases = 0;
			for (const byte *entry = state.Table; entry + 4 <= Code.Exe.Base + Code.Exe.Size; entry += 4) {
				const byte *target = Code.Exe.Base + *reinterpret_cast<const uint32_t *>(entry);
				if (!InChunks(chunks, target)) {
					break;
				}
				State next = state;
				next.At = target;
				next.Table = nullptr;
				pending.push_back(std::move(next));
				cases++;
			}
			state.At = nullptr;
			return cases != 0;
		}
		if (insn.ReadsJumpTable()) {
			state.Table = Code.Exe.Base + (uint32_t)insn.H.disp.disp32;
		}
		state.At = insn.Next();

		const uint16_t tracked = state.Value;
		state.Written |= destinations;
		state.Forwarded &= ~destinations;

		if (!insn.HasModRM()) {
			return StepWithoutOperands(insn, frame, state, destinations);
		}

		int32_t offset = 0;
		const Place place = PlaceOf(insn, frame, state, offset);
		const bool memory = insn.H.modrm_mod != 3;
		const bool sse = VectorOpcode(insn) || Between(op, 0xD8, 0xDF);
		const int width = sse ? 16 : 8;
		const bool readsSlot = (place == Place::Stack && Overlaps(state.Slots, offset, width)) ||
			(place == Place::IndexedStack && !state.Slots.empty());
		const int base = insn.AddressBase();
		const int index = insn.AddressIndex();
		const bool throughValue = (base >= 0 && (tracked & 1 << base)) || (index >= 0 && (tracked & 1 << index));

		const bool group = GroupOpcode(insn);
		const uint16_t operands = (group ? 0 : 1 << reg) | (memory ? 0 : 1 << rm);
		const bool readsOnly = ReadsOnly(insn);

		// A 0F instruction that's neither a known integer one nor a vector one can't be followed
		if (op == 0x0F && !sse && !IntegerTwoByte(insn)) {
			const bool involved = (tracked & operands) || readsSlot || throughValue ||
				state.Address[reg] != NoAddress || (!memory && state.Address[rm] != NoAddress);
			ClearRegisters(state, destinations);
			return !involved;
		}

		const bool storesToMemory = memory && !readsOnly &&
			(StoresFromReg(insn) || op == 0xC6 || op == 0xC7 || StoresFromXmm(insn) ||
			 (group && op != 0xFF && op != 0x8F) || (op == 0xFF && insn.H.modrm_reg <= 1) ||
			 (op == 0x0F && (Between(op2, 0x90, 0x9F) || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB ||
							 (op2 == 0xBA && insn.H.modrm_reg >= 5) || op2 == 0xA4 || op2 == 0xA5 || op2 == 0xAC ||
							 op2 == 0xAD || op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1 || op2 == 0xC3 ||
							 op2 == 0xC7)) ||
			op == 0x86 || op == 0x87);

		// Raising the pak's handle count gives it to a handle, which the engine keeps it alive for until it closes
		const bool countsHandle = Kind == Mode::Pak && throughValue && insn.H.p_lock &&
			(LockedCountWrite(insn, Code.SyncHandlesOffset) == CountWrite::Raise ||
			 LockedCountWrite(insn, Code.AsyncHandlesOffset) == CountWrite::Raise);
		if (countsHandle) {
			state.Value = 0;
			state.Slots.clear();
			state.Spilled.clear();
			state.LoadedFrom.fill(NoAddress);
			return true;
		}

		// A write through OutPakFile: only on success at the top, and never in a callee
		if (Kind == Mode::OutPakFile && storesToMemory && throughValue) {
			const bool storesZero = ((op == 0xC6 || op == 0xC7) && insn.Immediate() == 0) ||
				((op == 0x88 || op == 0x89) && state.Results[reg] == Zero);
			if (!storesZero) {
				if (depth > 0) {
					return false;
				}
				state.Writes = Wrote::Yes;
			}
		}

		// The address of a slot holding the pointer, stored anywhere, could be read back without the scan knowing
		if (storesToMemory && !group && !sse && state.Address[reg] != NoAddress) {
			if (PointsAtSlot(state, state.Address[reg])) {
				return false;
			}
			Insert(state.HandedOut, state.Address[reg]);
		}
		if (op == 0xFF && insn.H.modrm_reg == 6 && (readsSlot || (tracked & operands))) {
			return false;
		}

		if (op == 0x8D) {
			const bool derives = throughValue;
			ClearRegisters(state, 1 << reg);
			if (derives) {
				state.Value |= 1 << reg;
			}
			if (place == Place::Stack && insn.H.rex_w) {
				state.Address[reg] = offset;
			}
			return true;
		}

		if (sse) {
			// The pointer can't be followed into a vector or x87 register; stores from them only overwrite
			const bool gprIn = !memory && (tracked & 1 << rm);
			if ((readsSlot && !StoresFromXmm(insn)) || gprIn) {
				return false;
			}
			if (StoresFromXmm(insn) && place == Place::Stack) {
				// movss and movd store 4 bytes; movsd, movq, movlps and movhps 8; the rest 16
				int stored = 16;
				if ((op2 == 0x11 && insn.H.p_rep == 0xF3) || (op2 == 0x7E && !insn.H.rex_w)) {
					stored = 4;
				} else if ((op2 == 0x11 && insn.H.p_rep == 0xF2) || op2 == 0x7E || op2 == 0xD6 || op2 == 0x13 ||
						   op2 == 0x17) {
					stored = 8;
				}
				for (int32_t slot : std::vector<int32_t>(state.Slots)) {
					if (offset <= slot && slot + 8 <= offset + stored) {
						Kill(state, slot);
					}
				}
			}
			ClearRegisters(state, destinations);
			return true;
		}

		if (readsOnly) {
			if (op == 0x85 && !memory && reg == rm && insn.H.rex_w && (tracked & 1 << reg)) {
				state.NullTested = (int8_t)reg;
			}
			return true;
		}

		const bool exchanges = op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1 || op2 == 0xC7;
		if (op == 0x86 || op == 0x87 || (op == 0x0F && exchanges)) {
			const bool involved = (tracked & operands) || readsSlot || state.Address[reg] != NoAddress ||
				(!memory && state.Address[rm] != NoAddress);
			ClearRegisters(state, destinations);
			return !involved;
		}

		if (memory && (StoresFromReg(insn) || op == 0xC6 || op == 0xC7)) {
			const bool storesValue = !(op == 0xC6 || op == 0xC7) && (tracked & 1 << reg);
			if (storesValue) {
				if (place != Place::Stack || offset >= 0x28) {
					return false;
				}
				return Taint(state, offset, true);
			}
			if (place == Place::Stack && insn.H.rex_w && (op == 0x89 || op == 0xC7)) {
				// A whole slot overwritten: the pointer is no longer in it
				Kill(state, offset);
			}
			return true;
		}

		if (!memory && (op == 0x8B || op == 0x89 || op == 0x8A || op == 0x88)) {
			const int to = (op == 0x8B || op == 0x8A) ? reg : rm;
			const int from = (op == 0x8B || op == 0x8A) ? rm : reg;
			const bool whole = insn.H.rex_w;
			const bool fromValue = (tracked & 1 << from) != 0;
			const bool fromRsp = whole && from == Rsp;
			const int32_t fromAddress = whole ? (fromRsp ? frame.Rsp : state.Address[from]) : NoAddress;
			const Result fromResult = state.Results[from];
			const int32_t fromSlot = whole ? state.LoadedFrom[from] : NoAddress;
			const bool keepsRest = op == 0x8A || op == 0x88 || insn.H.p_66;
			const bool toValue = fromValue || (keepsRest && (tracked & 1 << to));
			ClearRegisters(state, 1 << to);
			state.Value |= toValue ? 1 << to : 0;
			state.Address[to] = fromAddress;
			state.Results[to] = fromResult == Zero && keepsRest ? Unknown : fromResult;
			state.LoadedFrom[to] = fromSlot;
			return true;
		}

		// Moves, and imul with an immediate, only write their reg operand
		const bool pureLoad = op == 0x8A || op == 0x8B || op == 0x63 || op == 0x69 || op == 0x6B ||
			(op == 0x0F && (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF));
		const bool onlyWrites = op == 0xC6 || op == 0xC7 || op == 0x8F;
		const uint16_t sources = onlyWrites ? 0 : pureLoad ? operands & ~(1 << reg) : operands;
		const bool loads = LoadsIntoReg(insn);
		const bool sourceValue = (tracked & sources) || (readsSlot && (loads || group));
		if (memory && !group && !loads && (tracked & 1 << reg)) {
			// Some other write to memory from the pointer's register
			return false;
		}
		if (memory && group && op == 0x8F && readsSlot) {
			return false;
		}

		const bool zeroes = (op == 0x31 || op == 0x33 || op == 0x29 || op == 0x2B) && !memory && reg == rm;
		const bool adjustsAddress = (op == 0x83 || op == 0x81) && !memory && insn.H.rex_w &&
			(insn.H.modrm_reg == 0 || insn.H.modrm_reg == 5) && state.Address[rm] != NoAddress;
		const int32_t adjusted = adjustsAddress
			? state.Address[rm] + (insn.H.modrm_reg == 0 ? 1 : -1) * (int32_t)insn.Immediate()
			: NoAddress;
		const bool copiesResult = op == 0x0F && (op2 == 0xB6 || op2 == 0xB7) && !memory;
		const Result copied = copiesResult ? state.Results[rm] : Unknown;
		const bool keepsValue = !zeroes && !ReplacesReg(insn) && (tracked & destinations);

		ClearRegisters(state, destinations);
		if (zeroes) {
			state.Results[reg] = Zero;
		} else if (sourceValue || keepsValue) {
			state.Value |= destinations;
		}
		if (adjustsAddress) {
			state.Address[rm] = adjusted;
		}
		if (op == 0x8B && insn.H.rex_w && place == Place::Stack && Contains(state.Slots, offset)) {
			state.LoadedFrom[reg] = offset;
		}
		if (copiesResult) {
			state.Results[reg] = copied;
		}
		if (op == 0xC7 && !memory) {
			state.Results[rm] = ResultOf(insn.Immediate());
		} else if (op == 0xC6 && !memory && (insn.H.rex || rm < 4)) {
			state.Results[rm] = ((insn.Immediate() & 0xFF) ? NonZero : Unknown);
		}
		return true;
	}
};

} // namespace

bool ScanPakCode(uint8_t *moduleBase, size_t moduleSize, PakCodeScan &scan) {
	PakCode code;
	if (!LoadImage(moduleBase, moduleSize, code.Exe)) {
		Refuse("the exe's sections or unwind table weren't found", code);
		return false;
	}
	if (!FindWrapper(code) || !FindHandleCountOffsets(code)) {
		return false;
	}
	scan.SyncHandlesOffset = code.SyncHandlesOffset;
	scan.AsyncHandlesOffset = code.AsyncHandlesOffset;

	code.ChainedChunks = IndexChainedChunks(code.Exe);
	ScanCode(code);
	ScanPakRegion(code);
	TRACE("  %zu lock calls, %zu other uses of the lock's import, %zu count addresses\n", code.EnterCalls.size(),
		code.OtherEnterUses.size(), code.CountAddresses.size());
	if (!code.TailJumps.empty()) {
		Refuse("a jump hands a pak search's result on", code, code.TailJumps[0]);
		return false;
	}

	std::set<byte *> readers;
	if (!FindReaders(code, readers)) {
		return false;
	}
	scan.ListReaders = readers.size();

	std::set<byte *> callers;
	for (const std::vector<const byte *> *calls : {&code.WrapperCalls, &code.SearchCalls}) {
		for (const byte *call : *calls) {
			callers.insert(FunctionStart(code.Exe, call));
		}
	}
	if (callers.count(nullptr)) {
		Refuse("a pak search is called where there's no unwind entry", code);
		return false;
	}
	std::map<byte *, Flow> flows;
	for (byte *function : callers) {
		flows[function] = FlowOf(ChunksOf(code, function));
	}
	auto outPak = [&](const byte *call) {
		const auto frameAt = [&](const byte *q) { return FrameAt(code, q); };
		return OutPakSource(code.Exe, flows[FunctionStart(code.Exe, call)], call, frameAt);
	};

	// The inner search first: the wrapper's result is the inner search's
	PointerFlow searches(code, PointerFlow::Mode::OutPakFile);
	for (const byte *search : {(const byte *)code.FindFileInPakFiles, (const byte *)code.Wrapper}) {
		const bool onSuccess = searches.WritesOnlyOnSuccess(search);
		TRACE("  search %llX writes OutPakFile only on success: %d\n", (unsigned long long)(search - code.Exe.Base),
			onSuccess);
		if (onSuccess) {
			searches.Searches.insert(search);
		}
	}
	PointerFlow escape(code, PointerFlow::Mode::Pak);
	escape.Searches = searches.Searches;
	std::map<const byte *, bool> keptIn;
	auto kept = [&](const byte *call) {
		const byte *function = FunctionStart(code.Exe, call);
		auto known = keptIn.find(function);
		if (known != keptIn.end()) {
			return known->second;
		}
		const bool isKept = escape.Kept(function);
		keptIn[function] = isKept;
		if (isKept) {
			return true;
		}
		TRACE("  the pak found at %llX can escape at %llX, through", (unsigned long long)(call - code.Exe.Base),
			(unsigned long long)(escape.EscapeAt - code.Exe.Base));
		for (const byte *callee : escape.EscapeCalls) {
			TRACE(" %llX", (unsigned long long)(callee - code.Exe.Base));
		}
		TRACE("\n");
		Refuse("a pak found into a local may outlive the function", code, call);
		return false;
	};

	/*
	 * The wrapper hands the pak it finds to its caller, which uses it after the wrapper has returned: a caller that
	 * passes a local is a reader, one that passes null is skipped, and one that passes anything else (perhaps its
	 * own caller's pointer, handing the pak further up) fails.
	 */
	for (const byte *call : code.WrapperCalls) {
		const OutPakFile source = outPak(call);
		TRACE("  wrapper call at %llX: OutPakFile %d\n", (unsigned long long)(call - code.Exe.Base), (int)source.Kind);
		switch (source.Kind) {
			case OutPak::Null:
				scan.SkippedWrapperCallers++;
				break;
			case OutPak::Local:
				if (!kept(call)) {
					return false;
				}
				readers.insert(FunctionStart(code.Exe, call));
				break;
			case OutPak::Unknown:
				Refuse("a wrapper caller's OutPakFile isn't provably a local or null", code, call);
				return false;
		}
	}

	// Every other search keeps its pak to itself (OutPakFile a local or null); one outside the readers is a visitor's
	std::set<byte *> visitors;
	for (const byte *call : code.SearchCalls) {
		byte *function = FunctionStart(code.Exe, call);
		if (function == code.Wrapper) {
			continue;
		}
		const OutPakFile source = outPak(call);
		TRACE("  search call at %llX: OutPakFile %d, in reader %d\n", (unsigned long long)(call - code.Exe.Base),
			(int)source.Kind, (int)readers.count(function));
		const bool covered = readers.count(function) ? source.Kind != OutPak::Unknown : source.Kind == OutPak::Null;
		if (!covered) {
			Refuse("a pak search may hand its pak on", code, call);
			return false;
		}
		if (source.Kind == OutPak::Local && !kept(call)) {
			return false;
		}
		if (!readers.count(function)) {
			visitors.insert(function);
		}
	}
	if (!VisitorsCovered(code, readers, visitors)) {
		Refuse("a pak search outside the readers isn't covered", code);
		return false;
	}

	std::set<byte *> destructors;
	if (!FindHandleCounts(code, readers, destructors) || !FindUnmountDelete(code, readers, scan)) {
		return false;
	}

	// A reader that also closes a handle is hooked once, as a destructor, which holds back more
	for (byte *function : destructors) {
		readers.erase(function);
	}

	std::vector<const byte *> patched(readers.begin(), readers.end());
	patched.insert(patched.end(), destructors.begin(), destructors.end());
	patched.push_back(scan.DeletePakFile);
	for (const byte *function : patched) {
		if (!SafeToPatch(code.Exe, function)) {
			Refuse("a function can't be hooked safely", code, function);
			return false;
		}
	}

	for (const std::set<byte *> *functions : {&readers, &destructors}) {
		for (byte *function : *functions) {
			for (const Range &chunk : ChunksOf(code, function)) {
				scan.HookedCode.push_back({chunk.Start, chunk.End});
			}
		}
	}
	scan.Readers = std::move(readers);
	scan.HandleDestructors = std::move(destructors);
	return true;
}
