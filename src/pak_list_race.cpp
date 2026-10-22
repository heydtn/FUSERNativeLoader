/*
 * FPakPlatformFile copies its pak list under PakListCritical, leaves the lock, and then uses the FPakFile pointers in
 * the copy. Unmount deletes a pak while holding that lock, so a thread still using its copy reads a freed FPakFile.
 * The song list's previews mount and unmount song paks while it is scrolled, which is where the crash shows up.
 *
 * Instead of deleting, Unmount's delete is handed to whoever releases the pak last:
 *   - Every function that copies the pak list, or is handed a pak found in one, is a reader while it runs. A reader
 *     publishes the epoch it started in; a pak unmounted in epoch E can only be in the copies of readers that started
 *     in an epoch <= E, because a later reader copies the list after Unmount took the pak out of it.
 *   - An open file handle also keeps its pak in use. The engine already counts those in each FPakFile (it only checks
 *     the counts in development builds), so they are read from there.
 * The pak is deleted on a thread-pool thread once the last old reader has returned and the last handle has closed.
 * Nothing waits on a timer, Unmount never blocks on a reader (a reader can call Mount and Unmount itself), and the
 * fix never takes PakListCritical; Unmount holds it for less time than before, since the destructor no longer runs
 * under it.
 *
 * pak_code_scan.cpp finds the readers and the rest; pak_reader_thunk.asm runs each hooked reader between
 * PakReaderEnter and PakReaderExit.
 */
#include "pak_list_race.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "loader_hooks.hpp"
#include "pak_code_scan.hpp"

using byte = uint8_t;

// The layout pak_reader_thunk.asm reads: rax points at this when the thunk is entered
struct ReaderHook {
	void *Original;
	bool AnyPak;
#if FNL_DEBUG
	void *Function;
	std::atomic<uint64_t> Calls{0};
#endif
};

extern "C" void PakReaderThunk();
extern "C" uint64_t PakReaderEnter(const ReaderHook *hook);
extern "C" void PakReaderExit(uint64_t previousEpoch);

namespace {

// Kept on a cache line of its own: these are read on every reader's entry or exit and rarely written
template <typename T>
struct alignas(64) OwnLine {
	std::atomic<T> Value;
};

/* ---- Readers ---- */

constexpr uint64_t NotReading = 0;
// A handle destructor: the engine's handle counts drop before the destructor is done, so it holds back every pak
constexpr uint64_t AnyPakEpoch = 1;

OwnLine<uint64_t> CurrentEpoch{2};

// One per thread, on its own cache line, so readers on different threads never write to shared memory
struct alignas(64) ReaderSlot {
	std::atomic<uint64_t> Epoch{NotReading};
	std::atomic<bool> Owned{true};
	ReaderSlot *Next = nullptr;
};

// Slots are reused by later threads but never freed, so the list can be walked without a lock
std::atomic<ReaderSlot *> ReaderSlots{nullptr};

struct ThreadSlot {
	ReaderSlot *Slot = nullptr;

	// Cleared too, so hooked code that still runs on this thread afterwards claims a new slot instead of sharing one
	~ThreadSlot() {
		if (Slot) {
			Slot->Epoch.store(NotReading);
			Slot->Owned.store(false, std::memory_order_release);
			Slot = nullptr;
		}
	}
};

thread_local ThreadSlot ThisThread;

ReaderSlot *ClaimSlot() {
	for (ReaderSlot *slot = ReaderSlots.load(std::memory_order_acquire); slot; slot = slot->Next) {
		bool owned = false;
		if (!slot->Owned.load(std::memory_order_relaxed) &&
			slot->Owned.compare_exchange_strong(owned, true, std::memory_order_acquire)) {
			return slot;
		}
	}

	auto *slot = new ReaderSlot;
	slot->Next = ReaderSlots.load(std::memory_order_relaxed);
	while (!ReaderSlots.compare_exchange_weak(
		slot->Next,
		slot,
		std::memory_order_release,
		std::memory_order_relaxed)) {
	}
	return slot;
}

uint64_t OldestReaderEpoch() {
	uint64_t oldest = UINT64_MAX;
	for (ReaderSlot *slot = ReaderSlots.load(std::memory_order_acquire); slot; slot = slot->Next) {
		uint64_t epoch = slot->Epoch.load();
		if (epoch != NotReading && epoch < oldest) {
			oldest = epoch;
		}
	}
	return oldest;
}

/* ---- Unmounted paks ---- */

void *(*FPakFile_Delete)(void *PakFile, uint32_t Flags);

// Only Unmount's delete is postponed; Mount also deletes a pak that failed to mount, which no reader has seen
byte *UnmountDeleteReturn;

uint32_t SyncHandlesOffset;
uint32_t AsyncHandlesOffset;

struct UnmountedPak {
	void *PakFile;
	uint32_t Flags;
	uint64_t Epoch;
};

std::mutex UnmountedLock;
std::vector<UnmountedPak> Unmounted;

OwnLine<size_t> UnmountedCount{0};

// A reader that started after this epoch began can't have any unmounted pak in its copy
OwnLine<uint64_t> NewestUnmountedEpoch{0};

// Release work is queued once until it starts, however many threads ask for it
PTP_WORK ReleaseWork;
OwnLine<bool> ReleaseQueued{false};

// Set once the game starts exiting, when paks are no longer deleted
std::atomic<bool> Exiting{false};

// On the thread running the release work, which exit mustn't wait for
thread_local bool Releasing = false;

#if FNL_DEBUG
byte *DebugModuleBase;
std::vector<ReaderHook *> DebugHooks;
std::atomic<uint32_t> DebugUnmounts{0};
#endif

int32_t OpenHandles(void *pakFile, uint32_t offset) {
	return InterlockedOr(reinterpret_cast<volatile LONG *>(static_cast<byte *>(pakFile) + offset), 0);
}

bool HasHandles(const UnmountedPak &pak) {
	return OpenHandles(pak.PakFile, SyncHandlesOffset) != 0 || OpenHandles(pak.PakFile, AsyncHandlesOffset) != 0;
}

/*
 * Needs UnmountedLock held; moves the paks that can be deleted to `released`.
 *
 * A pak is free when no reader that could have it is running and no handle is open, read as counts, then readers,
 * then counts again. Either order alone misses a thread caught between the two reads: a destructor that publishes
 * itself and counts down after the readers were read (counts then readers sees it), or a reader that opens a handle
 * and returns after the counts were read (readers then counts sees it).
 */
void TakeReleased(std::vector<UnmountedPak> &released) {
	std::vector<bool> withoutHandles;
	withoutHandles.reserve(Unmounted.size());
	for (const UnmountedPak &pak : Unmounted) {
		withoutHandles.push_back(!HasHandles(pak));
	}

	const uint64_t oldestReader = OldestReaderEpoch();
	size_t kept = 0;
	for (size_t i = 0; i < Unmounted.size(); i++) {
		const UnmountedPak pak = Unmounted[i];
		if (withoutHandles[i] && pak.Epoch < oldestReader && !HasHandles(pak)) {
			released.push_back(pak);
		} else {
			Unmounted[kept] = pak;
			kept++;
		}
	}
	Unmounted.resize(kept);
}

/*
 * The release work, on a thread-pool thread: it finds the paks nothing uses any more and deletes them. The destructor
 * stops the pak's signature-check thread and waits for it, which would stall a game thread.
 */
void CALLBACK ReleasePaks(PTP_CALLBACK_INSTANCE, void *, PTP_WORK) {
	// Cleared before the scan: a thread asking from here on queues another round, which sees what it published
	ReleaseQueued.Value.store(false);
	if (Exiting.load()) {
		return;
	}

	std::vector<UnmountedPak> released;
	Releasing = true;
	struct ClearReleasing {
		~ClearReleasing() {
			Releasing = false;
		}
	} clearReleasing;
	{
		std::lock_guard<std::mutex> guard(UnmountedLock);
		TakeReleased(released);
#if FNL_DEBUG
		printf("Pak list race fix: %zu unmounted paks deleted, %zu still in use\n", released.size(), Unmounted.size());
#endif
	}
	if (released.empty()) {
		return;
	}
	UnmountedCount.Value.fetch_sub(released.size());
	for (const UnmountedPak &pak : released) {
		FPakFile_Delete(pak.PakFile, pak.Flags);
	}
}

void RequestRelease() {
	if (!ReleaseQueued.Value.exchange(true)) {
		SubmitThreadpoolWork(ReleaseWork);
	}
}

/*
 * Called by Unmount, which holds PakListCritical from before the delete until after it takes the pak out of the list,
 * so a reader that copies the list from here on doesn't get the pak. Unmount is a hooked reader too, so the pak waits
 * at least until Unmount returns.
 *
 * The pak's file stays open until the delete runs, so replacing a .pak file right after unmounting it can still fail
 * with a sharing violation for that long.
 */
void DeleteWhenReleased(void *pakFile, uint32_t flags) {
	{
		std::lock_guard<std::mutex> guard(UnmountedLock);
		const uint64_t epoch = CurrentEpoch.Value.fetch_add(1);
		Unmounted.push_back({pakFile, flags, epoch});
		NewestUnmountedEpoch.Value.store(epoch);
	}

#if FNL_DEBUG
	// Which hooked functions run, by RVA and call count, every 64 unmounts
	if (DebugUnmounts.fetch_add(1) % 64 == 63) {
		printf("Pak list race fix: calls since start:");
		for (ReaderHook *hook : DebugHooks) {
			printf(" %llx:%llu", (unsigned long long)((byte *)hook->Function - DebugModuleBase),
				(unsigned long long)hook->Calls.load());
		}
		printf("\n");
	}
#endif

	// Ordered against PakReaderExit's slot store: either the reader sees this pak, or the release sees it done
	UnmountedCount.Value.fetch_add(1);
	RequestRelease();
}

__declspec(noinline) void *FPakFile_Delete_Hook(void *PakFile, uint32_t Flags) {
	if (_ReturnAddress() != UnmountDeleteReturn) {
		return FPakFile_Delete(PakFile, Flags);
	}
	DeleteWhenReleased(PakFile, Flags);

	// A scalar deleting destructor returns its object; Unmount ignores it
	return PakFile;
}

bool CreateReleaseWork() {
	ReleaseWork = CreateThreadpoolWork(ReleasePaks, nullptr, nullptr);
	return ReleaseWork != nullptr;
}

/* ---- Exit ---- */

/*
 * The CRT's exit runs the exe's static destructors while other threads still run, and a pak's destructor may need one
 * of those statics (the pak signature check's lock, for one). So once exit starts, a release already running is
 * waited for and no pak is deleted after it; the process is ending anyway.
 */
void (*CrtExit)(int);
void (*CrtCexit)();

void StopReleasing() {
	Exiting.store(true);
	if (!Releasing) {
		WaitForThreadpoolWorkCallbacks(ReleaseWork, FALSE);
	}
}

void CrtExit_Hook(int status) {
	StopReleasing();
	CrtExit(status);
}

void CrtCexit_Hook() {
	StopReleasing();
	CrtCexit();
}

// The exe's import slot for a function of the CRT's runtime, which the exe's own calls go through
void **CrtImportSlot(byte *module, const char *function) {
	auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(module + reinterpret_cast<IMAGE_DOS_HEADER *>(module)->e_lfanew);
	const IMAGE_DATA_DIRECTORY &imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto *descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(module + imports.VirtualAddress);
	for (; imports.VirtualAddress && descriptor->Name; descriptor++) {
		const char *dll = reinterpret_cast<const char *>(module + descriptor->Name);
		if (_strnicmp(dll, "api-ms-win-crt-runtime", 22) != 0 && _stricmp(dll, "ucrtbase.dll") != 0) {
			continue;
		}
		auto *names = reinterpret_cast<IMAGE_THUNK_DATA *>(module + descriptor->OriginalFirstThunk);
		auto *slots = reinterpret_cast<IMAGE_THUNK_DATA *>(module + descriptor->FirstThunk);
		for (; descriptor->OriginalFirstThunk && names->u1.AddressOfData; names++, slots++) {
			if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) {
				continue;
			}
			auto *byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(module + names->u1.AddressOfData);
			if (strcmp(reinterpret_cast<const char *>(byName->Name), function) == 0) {
				return reinterpret_cast<void **>(&slots->u1.Function);
			}
		}
	}
	return nullptr;
}

void Redirect(void **slot, void *hook, void **original) {
	DWORD protection;
	VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &protection);
	*original = *slot;
	*slot = hook;
	VirtualProtect(slot, sizeof(void *), protection, &protection);
}

bool HookExit(byte *module) {
	void **exitSlot = CrtImportSlot(module, "exit");
	void **cexitSlot = CrtImportSlot(module, "_cexit");
	if (!exitSlot || !cexitSlot) {
		return false;
	}
	Redirect(exitSlot, (void *)CrtExit_Hook, (void **)&CrtExit);
	Redirect(cexitSlot, (void *)CrtCexit_Hook, (void **)&CrtCexit);
	return true;
}

/* ---- Hooks ---- */

// mov rax, <hook>; jmp [rip]; <PakReaderThunk>
constexpr size_t StubSize = 24;

byte *MakeStubs(const std::vector<ReaderHook *> &hooks) {
	auto *stubs = (byte *)VirtualAlloc(nullptr, hooks.size() * StubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!stubs) {
		return nullptr;
	}
	for (size_t i = 0; i < hooks.size(); i++) {
		byte *stub = stubs + i * StubSize;
		const void *thunk = (const void *)&PakReaderThunk;
		stub[0] = 0x48;
		stub[1] = 0xB8;
		memcpy(stub + 2, &hooks[i], 8);
		stub[10] = 0xFF;
		stub[11] = 0x25;
		memset(stub + 12, 0, 4);
		memcpy(stub + 16, &thunk, 8);
	}
	DWORD old;
	if (!VirtualProtect(stubs, hooks.size() * StubSize, PAGE_EXECUTE_READ, &old)) {
		VirtualFree(stubs, 0, MEM_RELEASE);
		return nullptr;
	}
	FlushInstructionCache(GetCurrentProcess(), stubs, hooks.size() * StubSize);
	return stubs;
}

} // namespace

extern "C" uint64_t PakReaderEnter(const ReaderHook *hook) {
	ReaderSlot *&slot = ThisThread.Slot;
	if (!slot) {
		slot = ClaimSlot();
	}
#if FNL_DEBUG
	const_cast<ReaderHook *>(hook)->Calls.fetch_add(1, std::memory_order_relaxed);
#endif

	const uint64_t previous = slot->Epoch.load(std::memory_order_relaxed);
	uint64_t epoch = previous;
	if (hook->AnyPak) {
		epoch = AnyPakEpoch;
	} else if (previous == NotReading) {
		epoch = CurrentEpoch.Value.load(std::memory_order_relaxed);
	}

	/*
	 * A plain store is enough. A reader copies the list under the pak lock, which Unmount takes before removing a
	 * pak, so the store (made before this thread enters the lock, and kept there by the call into the original) is
	 * visible to everything Unmount does next. A handle destructor's store is followed by the engine's lock dec of
	 * the count, which on x64 makes it visible before the count drops.
	 */
	if (previous == NotReading || epoch < previous) {
		slot->Epoch.store(epoch, std::memory_order_relaxed);
	}
	return previous;
}

// Not reached when an exception unwinds through a reader: its slot then keeps holding back every pak unmounted since,
// which leaks them but never frees one early
extern "C" void PakReaderExit(uint64_t previousEpoch) {
	ReaderSlot *slot = ThisThread.Slot;
	const uint64_t ending = slot->Epoch.load(std::memory_order_relaxed);
	if (ending == previousEpoch) {
		return;
	}
	slot->Epoch.store(previousEpoch);

	/*
	 * Ordered against the delete hook's count: either this sees the unmounted pak, or its release sees this scope
	 * done. Only a scope that started before the newest unmount can have been holding an unmounted pak back (a
	 * handle destructor's epoch is lower than any unmount's).
	 */
	if (UnmountedCount.Value.load() != 0 && ending <= NewestUnmountedEpoch.Value.load()) {
		RequestRelease();
	}
}

void ApplyPakListRaceFix(uint8_t *moduleBase, size_t moduleSize) {
	LARGE_INTEGER started, scanned, finished, frequency;
	QueryPerformanceCounter(&started);

	PakCodeScan scan;
	if (!ScanPakCode(moduleBase, moduleSize, scan)) {
		return;
	}
	QueryPerformanceCounter(&scanned);
	SyncHandlesOffset = scan.SyncHandlesOffset;
	AsyncHandlesOffset = scan.AsyncHandlesOffset;
	UnmountDeleteReturn = scan.UnmountDeleteReturn;
	FPakFile_Delete = (decltype(FPakFile_Delete))scan.DeletePakFile;

	if (!CreateReleaseWork()) {
		printf("Pak list race fix: no thread-pool work - not applied\n");
		return;
	}

	std::vector<ReaderHook *> readerHooks;
	for (const std::set<uint8_t *> *functions : {&scan.Readers, &scan.HandleDestructors}) {
		for (uint8_t *function : *functions) {
			auto *hook = new ReaderHook{function, functions == &scan.HandleDestructors};
#if FNL_DEBUG
			hook->Function = function;
			DebugHooks.push_back(hook);
			DebugModuleBase = moduleBase;
#endif
			readerHooks.push_back(hook);
		}
	}
	auto discardHooks = [&readerHooks]() {
#if FNL_DEBUG
		DebugHooks.clear();
#endif
		for (ReaderHook *hook : readerHooks) {
			delete hook;
		}
		CloseThreadpoolWork(ReleaseWork);
		ReleaseWork = nullptr;
	};

	byte *stubs = MakeStubs(readerHooks);
	if (!stubs) {
		printf("Pak list race fix: no memory for the hook stubs - not applied\n");
		discardHooks();
		return;
	}

	std::vector<HookRequest> requests;
	for (size_t i = 0; i < readerHooks.size(); i++) {
		requests.push_back({&readerHooks[i]->Original, stubs + i * StubSize});
	}
	requests.push_back({(void **)&FPakFile_Delete, (void *)FPakFile_Delete_Hook});

	if (!setup_hooks(requests.data(), requests.size(), scan.HookedCode.data(), scan.HookedCode.size())) {
		printf("Pak list race fix: hooks not installed - not applied\n");
		VirtualFree(stubs, 0, MEM_RELEASE);
		discardHooks();
		return;
	}
	if (!HookExit(moduleBase)) {
		printf("Pak list race fix: the CRT's exit isn't imported, so paks are still deleted while the game exits\n");
	}

	QueryPerformanceCounter(&finished);
	QueryPerformanceFrequency(&frequency);
	printf(
		"Pak list race fix: %zu readers (%zu using the pak list, %zu wrapper callers skipped) and %zu handle "
		"destructors hooked (scan %lld ms, install %lld ms), Unmount's deletes wait for them\n",
		scan.Readers.size(),
		scan.ListReaders,
		scan.SkippedWrapperCallers,
		scan.HandleDestructors.size(),
		(scanned.QuadPart - started.QuadPart) * 1000 / frequency.QuadPart,
		(finished.QuadPart - scanned.QuadPart) * 1000 / frequency.QuadPart);
}
