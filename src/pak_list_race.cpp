// FPakPlatformFile's readers copy the pak list under PakListCritical, leave the lock, then use the FPakFile pointers in
// the copy, while Unmount deletes paks under that lock: scrolling the song list frees paks still in use.
//
// Unmount's delete is deferred until nothing can hold the pak. A thread entering the pak lock (seen through the exe's
// EnterCriticalSection import) is a reader until its function returns, which a stub in its return address reports.
// A pak unmounted in epoch E is freed once no reader from epoch <= E is running and the engine's own handle counts are
// 0. Unmount never blocks on a reader (a reader can mount and unmount itself), and when the fix can't be applied or a
// reader can't be tracked, it deletes right away, as the game does.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "pak_list_race.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "loader_hooks.hpp"
#include "pe_image.hpp"

using byte = uint8_t;

extern "C" void pak_return_thunk();
extern "C" void pak_return_exit(void **stack);

namespace {

// Kept on a cache line of its own: these are read on every reader's entry or exit and rarely written
template <typename T>
struct alignas(64) OwnLine {
    std::atomic<T> value;
};

// UNWIND_INFO: version and flags, prologue size, code count and frame register, then the codes (padded to an even
// count), then the entry it continues when UNW_FLAG_CHAININFO is set
size_t unwind_codes_size(const byte *info) {
    return ((info[2] + 1) & ~1) * 2;
}

const RUNTIME_FUNCTION *chained_entry(const byte *info) {
    return (info[0] >> 3) & UNW_FLAG_CHAININFO
        ? reinterpret_cast<const RUNTIME_FUNCTION *>(info + 4 + unwind_codes_size(info))
        : nullptr;
}

uint8_t unwind_version(const byte *info) {
    return info[0] & 7;
}

uint8_t frame_register(const byte *info) {
    return info[3] & 0x0F;
}

const byte *unwind_info(DWORD64 module, const RUNTIME_FUNCTION *function) {
    return reinterpret_cast<const byte *>(module) + function->UnwindData;
}

const RUNTIME_FUNCTION *lookup_function(const void *code, DWORD64 &module) {
    return RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(code), &module, nullptr);
}

// ---------------------------------------------------------------- the engine's pak code ------------------------------

struct PakCode {
    byte *wrapper_lock_return = nullptr;
    const byte *wrapper_lock_slot = nullptr;
    uint8_t pak_list_critical_offset = 0;
    uint8_t pak_files_offset = 0;
    byte *mount = nullptr;
    byte *create_pak_file_handle = nullptr;
    byte *delete_pak_file = nullptr; // FPakFile's scalar deleting destructor
    byte *unmount_delete_return = nullptr;
    uint32_t sync_handles_offset = 0;
    uint32_t async_handles_offset = 0;
};

const byte *rel32_target(const byte *rel32) {
    return rel32 + 4 + *reinterpret_cast<const int32_t *>(rel32);
}

uint32_t read_u32(const byte *at) {
    return *reinterpret_cast<const uint32_t *>(at);
}

// Why the code wasn't found: it's looked for before there's a console to log to
const char *g_not_found = nullptr;

bool not_found(const char *why) {
    g_not_found = why;
    return false;
}

// The search wrapper (FPakPlatformFile::FindFileInPakFiles) gives the lock and the list; the rest is compiled with it,
// so it's looked for nearby. funchook moves a hooked function's first 5 bytes, which must be prologue (never a jump
// target), so each hooked function's prologue is matched too. False, with the reason in g_not_found, otherwise.
bool find_pak_code(byte *exe, size_t size, PakCode &code) {
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
        "7437",             // je     (empty list)
        exe,
        size);
    if (!wrapper) {
        return not_found("the FindFileInPakFiles wrapper wasn't found");
    }
    code.wrapper_lock_slot = rel32_target(wrapper + 0x23);
    code.wrapper_lock_return = wrapper + 0x27;
    code.pak_list_critical_offset = wrapper[0x05];
    code.pak_files_offset = static_cast<uint8_t>(wrapper[0x2A] - 8);

    byte *near_from = std::max(wrapper - 0x40000, exe);
    const size_t near_size = std::min<size_t>(0x80000, exe + size - near_from);
    code.mount = find_function(
        "FPakPlatformFile_Mount",
        "488bc4"            // mov    rax,rsp
        "44894018"          // mov    [rax+18h],r8d
        "48894808"          // mov    [rax+8],rcx
        "55534157"          // push   rbp; push rbx; push r15
        "488d68??"          // lea    rbp,[rax-xx]
        "4881ec????????"    // sub    rsp,xx
        "48897010"          // mov    [rax+10h],rsi
        "4533c0"            // xor    r8d,r8d
        "488978e0"          // mov    [rax-20h],rdi
        "498bf1"            // mov    rsi,r9
        "4c8960d8"          // mov    [rax-28h],r12
        "488bf9"            // mov    rdi,rcx                        (this)
        "488b4908",         // mov    rcx,[rcx+8]                    (the lower level platform file)
        near_from,
        near_size);
    code.create_pak_file_handle = find_function(
        "FPakPlatformFile_CreatePakFileHandle",
        "4c8bdc574881ec90000000488b05????????4833c44889442470488b410849895b0849896b10498be9",
        near_from,
        near_size);
    byte *unmount = find_function(
        "FPakPlatformFile_Unmount",
        "40535557415441554883ec30833d????????004c8be2488be97422488b1d",
        near_from,
        near_size);
    if (!code.mount || !code.create_pak_file_handle || !unmount) {
        return not_found(!code.mount ? "Mount wasn't found"
                         : !unmount  ? "Unmount wasn't found"
                                     : "CreatePakFileHandle wasn't found");
    }

    // Unmount reads both handle counts before deleting (only checked in development builds), giving their offsets
    byte *counts = find_function(
        "FPakPlatformFile_Unmount handle counts",
        "f0440fb1a9????0000" // lock cmpxchg [rcx+async count],r13d
        "????????????"
        "f0440fb1a9????0000", // lock cmpxchg [rcx+sync count],r13d
        unmount,
        0x200);
    byte *delete_call = find_function(
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
    if (!counts || !delete_call) {
        return not_found("Unmount isn't as expected");
    }
    code.async_handles_offset = read_u32(counts + 5);
    code.sync_handles_offset = read_u32(counts + 20);
    code.unmount_delete_return = delete_call + 32;
    code.delete_pak_file = const_cast<byte *>(rel32_target(delete_call + 28));

    // CreatePakFileHandle counts its handle up: lock inc [rsi+sync count]
    const byte *count_up = find_function("FPakPlatformFile_CreatePakFileHandle count", "f0ff86????0000",
                                         code.create_pak_file_handle, 0x400);
    const bool destructor_matches = find_function(
        "FPakFile scalar deleting destructor",
        "48895c2408"        // mov    [rsp+8],rbx
        "4889742410"        // mov    [rsp+10h],rsi
        "57"                // push   rdi
        "4883ec20"          // sub    rsp,20h
        "488bd9"            // mov    rbx,rcx
        "8bf2",             // mov    esi,edx                        (the delete flag)
        code.delete_pak_file,
        20);
    if (!count_up || read_u32(count_up + 3) != code.sync_handles_offset || !destructor_matches) {
        return not_found(destructor_matches ? "CreatePakFileHandle's handle count isn't as expected"
                                            : "FPakFile's destructor isn't as expected");
    }
    return true;
}

// ---------------------------------------------------------------- readers --------------------------------------------

constexpr uint64_t kNotReading = 0;
// A handle destructor: the engine's handle counts drop before the destructor is done, so it holds back every pak
constexpr uint64_t kAnyPakEpoch = 1;

OwnLine<uint64_t> g_current_epoch{2};

// A reader on this thread whose return address points at its stub, outermost first
struct Tracked {
    void **slot;
    byte *stub;
    uint64_t epoch;
};

constexpr int kMaxTracked = 64;

// One per thread, on its own cache line, so readers on different threads never write to shared memory
struct alignas(64) ReaderSlot {
    std::atomic<uint64_t> epoch{kNotReading};
    std::atomic<bool> owned{true};
    ReaderSlot *next = nullptr;
    std::atomic<const Tracked *> tracked{nullptr};
    std::atomic<const int *> tracked_count{nullptr};
};

// Slots are reused by later threads but never freed, so the list can be walked without a lock
std::atomic<ReaderSlot *> g_reader_slots{nullptr};

struct ThreadSlot {
    ReaderSlot *slot = nullptr;

    // Cleared too, so hooked code that still runs on this thread afterwards claims a new slot instead of sharing one
    ~ThreadSlot() {
        if (slot) {
            slot->tracked_count.store(nullptr);
            slot->epoch.store(kNotReading);
            slot->owned.store(false, std::memory_order_release);
            slot = nullptr;
        }
    }
};

thread_local ThreadSlot g_this_thread;

ReaderSlot *claim_slot() {
    for (ReaderSlot *slot = g_reader_slots.load(std::memory_order_acquire); slot; slot = slot->next) {
        bool owned = false;
        if (!slot->owned.load(std::memory_order_relaxed) &&
            slot->owned.compare_exchange_strong(owned, true, std::memory_order_acquire)) {
            return slot;
        }
    }

    auto *slot = new ReaderSlot;
    slot->next = g_reader_slots.load(std::memory_order_relaxed);
    while (!g_reader_slots.compare_exchange_weak(
        slot->next,
        slot,
        std::memory_order_release,
        std::memory_order_relaxed)) {
    }
    return slot;
}

uint64_t oldest_reader_epoch() {
    uint64_t oldest = UINT64_MAX;
    for (ReaderSlot *slot = g_reader_slots.load(std::memory_order_acquire); slot; slot = slot->next) {
        const uint64_t epoch = slot->epoch.load();
        if (epoch != kNotReading && epoch < oldest) {
            oldest = epoch;
        }
    }
    return oldest;
}

thread_local Tracked g_tracked[kMaxTracked];
thread_local int g_tracked_count = 0;
thread_local int g_destructors_running = 0;

uint64_t thread_epoch() {
    if (g_destructors_running) {
        return kAnyPakEpoch;
    }
    return g_tracked_count ? g_tracked[0].epoch : kNotReading;
}

// ---------------------------------------------------------------- unmounted paks -------------------------------------

void *(*FPakFile_Delete)(void *pak_file, uint32_t flags);

// Cleared when a reader can't be tracked: Unmount's deletes then run right away again, as without the fix
std::atomic<bool> g_tracking{true};

// Set when the game's crash reporting starts, before every reader's real return address is put back
std::atomic<bool> g_returns_restored{false};

byte *g_exe = nullptr;
PakCode g_code;
bool g_found = false;

// Learned at the first Mount (or the wrapper's first call, if Mount ran first); until then nothing is deferred
std::atomic<CRITICAL_SECTION *> g_pak_list_lock{nullptr};

struct UnmountedPak {
    void *pak_file;
    uint32_t flags;
    uint64_t epoch;
};

std::mutex g_unmounted_lock;
std::vector<UnmountedPak> g_unmounted;

OwnLine<size_t> g_unmounted_count{0};

// A reader that started after this epoch began can't have any unmounted pak in its copy
OwnLine<uint64_t> g_newest_unmounted_epoch{0};

// Release work is queued once until it starts, however many threads ask for it
PTP_WORK g_release_work;
OwnLine<bool> g_release_queued{false};

// Async handles aren't hooked, so a pak whose last async handle closes is picked up by this
PTP_TIMER g_release_timer;

// Set once the game exits or reports a crash, when paks are no longer deleted
std::atomic<bool> g_exiting{false};

// While this thread deletes paks for the release work, which exit mustn't wait for
thread_local bool g_releasing = false;

void request_release() {
    if (!g_release_queued.value.exchange(true)) {
        SubmitThreadpoolWork(g_release_work);
    }
}

// Publishes this thread's epoch after its readers changed. A reader's is stored before it takes the pak lock, which
// Unmount takes before removing a pak, and a destructor's before the engine's lock dec of the count, which orders it.
// Either the delete hook's count sees this reader done, or this sees the unmounted pak and asks for a release.
void publish(uint64_t before) {
    ReaderSlot *&slot = g_this_thread.slot;
    if (!slot) {
        slot = claim_slot();
        slot->tracked.store(g_tracked);
        slot->tracked_count.store(&g_tracked_count);
    }
    const uint64_t after = thread_epoch();
    if (after == before) {
        return;
    }
    slot->epoch.store(after);

    const bool released = before != kNotReading && (after == kNotReading || after > before);
    if (released && g_unmounted_count.value.load() != 0 && before <= g_newest_unmounted_epoch.value.load()) {
        request_release();
    }
}

int32_t open_handles(void *pak_file, uint32_t offset) {
    return InterlockedOr(reinterpret_cast<volatile LONG *>(static_cast<byte *>(pak_file) + offset), 0);
}

bool has_handles(const UnmountedPak &pak) {
    return open_handles(pak.pak_file, g_code.sync_handles_offset) != 0 ||
        open_handles(pak.pak_file, g_code.async_handles_offset) != 0;
}

// Needs g_unmounted_lock held. The counts are read before and after the readers: either order alone misses a
// destructor counting down after the readers were read, or a reader opening a handle after the counts were read.
void take_released(std::vector<UnmountedPak> &released) {
    std::vector<bool> without_handles;
    without_handles.reserve(g_unmounted.size());
    for (const UnmountedPak &pak : g_unmounted) {
        without_handles.push_back(!has_handles(pak));
    }

    const uint64_t oldest_reader = oldest_reader_epoch();
    size_t kept = 0;
    for (size_t i = 0; i < g_unmounted.size(); i++) {
        const UnmountedPak pak = g_unmounted[i];
        if (without_handles[i] && pak.epoch < oldest_reader && !has_handles(pak)) {
            released.push_back(pak);
        } else {
            g_unmounted[kept] = pak;
            kept++;
        }
    }
    g_unmounted.resize(kept);
}

// On a thread-pool thread: a pak's destructor waits for its signature-check thread, which would stall a game thread
void CALLBACK release_paks(PTP_CALLBACK_INSTANCE, void *, PTP_WORK) {
    // Cleared before the scan: a thread asking from here on queues another round, which sees what it published
    g_release_queued.value.store(false);
    if (g_exiting.load()) {
        return;
    }

    std::vector<UnmountedPak> released;
    {
        std::lock_guard<std::mutex> guard(g_unmounted_lock);
        take_released(released);
    }
    if (released.empty()) {
        return;
    }
    g_unmounted_count.value.fetch_sub(released.size());
    g_releasing = true;
    for (const UnmountedPak &pak : released) {
        FPakFile_Delete(pak.pak_file, pak.flags);
    }
    g_releasing = false;
}

// Only decides how soon a waiting pak is deleted, never whether it can be
void CALLBACK release_tick(PTP_CALLBACK_INSTANCE, void *, PTP_TIMER) {
    if (g_unmounted_count.value.load() != 0 && !g_exiting.load()) {
        request_release();
    }
}

// Unmount holds PakListCritical here, with the pak already out of the list, so no later reader can copy it. Its file
// stays open until the delete runs, so replacing the .pak meanwhile fails with a sharing violation.
void delete_when_released(void *pak_file, uint32_t flags) {
    {
        std::lock_guard<std::mutex> guard(g_unmounted_lock);
        const uint64_t epoch = g_current_epoch.value.fetch_add(1);
        g_unmounted.push_back({pak_file, flags, epoch});
        g_newest_unmounted_epoch.value.store(epoch);
    }
    g_unmounted_count.value.fetch_add(1);
    request_release();
}

// Only Unmount's delete is postponed; Mount also deletes a pak that failed to mount, which no reader has seen
__declspec(noinline) void *FPakFile_Delete_Hook(void *pak_file, uint32_t flags) {
    if (_ReturnAddress() != g_code.unmount_delete_return || !g_tracking.load() || !g_pak_list_lock.load()) {
        return FPakFile_Delete(pak_file, flags);
    }
    delete_when_released(pak_file, flags);

    // A scalar deleting destructor returns its object; Unmount ignores it
    return pak_file;
}

// A reader that isn't tracked could hold any pak unmounted after it started. The paks already waiting can't be in its
// copy, so they're still deleted once their readers return
void stop_tracking(const char *why) {
    if (g_tracking.exchange(false)) {
        printf("Pak list race fix: %s, so unmounted paks are deleted right away again, as without the fix\n", why);
    }
}

std::string describe(const void *address) {
    void *module = nullptr;
    char path[MAX_PATH] = "?";
    if (RtlPcToFileHeader(const_cast<void *>(address), &module) && module) {
        GetModuleFileNameA(static_cast<HMODULE>(module), path, MAX_PATH);
    }
    const char *name = strrchr(path, '\\');
    char text[MAX_PATH + 32];
    snprintf(text, sizeof(text), "%s+%llX", name ? name + 1 : path,
             static_cast<unsigned long long>(static_cast<const byte *>(address) - static_cast<const byte *>(module)));
    return text;
}

// ---------------------------------------------------------------- exit -----------------------------------------------

// The CRT's exit destroys the exe's statics while other threads run, and a pak's destructor needs some of them (the
// signature check's lock), so once exit starts no pak is deleted
void (*g_crt_exit)(int);
void (*g_crt_cexit)();

void stop_releasing() {
    g_exiting.store(true);
    if (!g_releasing) {
        WaitForThreadpoolWorkCallbacks(g_release_work, FALSE);
    }
}

void crt_exit_hook(int status) {
    stop_releasing();
    g_crt_exit(status);
}

void crt_cexit_hook() {
    stop_releasing();
    g_crt_cexit();
}

void **import_slot(byte *module, const char *function, bool crt_only) {
    void **found = nullptr;
    for_each_import(module, [&](const char *dll, const char *name, void **slot) {
        const bool crt = _strnicmp(dll, "api-ms-win-crt-runtime", 22) == 0 || _stricmp(dll, "ucrtbase.dll") == 0;
        if ((crt || !crt_only) && strcmp(name, function) == 0) {
            found = slot;
        }
    });
    return found;
}

std::mutex g_redirect_lock;

template <typename Function>
void redirect(void **slot, Function hook, Function *original) {
    std::lock_guard<std::mutex> guard(g_redirect_lock);
    DWORD protection;
    VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &protection);
    *original = reinterpret_cast<Function>(*slot);
    _ReadWriteBarrier();
    *slot = reinterpret_cast<void *>(hook);
    VirtualProtect(slot, sizeof(void *), protection, &protection);
}

bool hook_exit(byte *module) {
    void **exit_slot = import_slot(module, "exit", true);
    void **cexit_slot = import_slot(module, "_cexit", true);
    if (!exit_slot || !cexit_slot) {
        return false;
    }
    redirect(exit_slot, &crt_exit_hook, &g_crt_exit);
    redirect(cexit_slot, &crt_cexit_hook, &g_crt_cexit);
    return true;
}

// ---------------------------------------------------------------- handle destructors ---------------------------------

using HandleDestructor = void *(*)(void *handle, uint32_t flags);

// One hook per handle class (the EGS exe has four), each calling its class's own destructor
constexpr size_t kHandleClasses = 8;
HandleDestructor g_handle_destructors[kHandleClasses];

template <size_t Class>
void *handle_destructor_hook(void *handle, uint32_t flags) {
    const uint64_t before = thread_epoch();
    g_destructors_running++;
    publish(before);
    void *result = g_handle_destructors[Class](handle, flags);
    g_destructors_running--;
    publish(kAnyPakEpoch);
    return result;
}

template <size_t... Classes>
constexpr std::array<HandleDestructor, kHandleClasses> handle_destructor_hooks(std::index_sequence<Classes...>) {
    return {&handle_destructor_hook<Classes>...};
}

constexpr std::array<HandleDestructor, kHandleClasses> kHandleDestructorHooks =
    handle_destructor_hooks(std::make_index_sequence<kHandleClasses>());

void *(*CreatePakFileHandle)(void *pak_platform_file, const wchar_t *filename, void *pak_file, const void *entry);

std::mutex g_handle_classes_lock;
std::vector<void **> g_handle_vtables;

// A handle is destroyed through slot 0 of its class's vtable, its scalar deleting destructor. A class is hooked before
// CreatePakFileHandle returns its first handle, so none of its handles can be destroyed unhooked.
void hook_handle_destructor(void **vtable) {
    std::unique_lock<std::mutex> guard(g_handle_classes_lock);
    if (std::find(g_handle_vtables.begin(), g_handle_vtables.end(), vtable) != g_handle_vtables.end()) {
        return;
    }
    const size_t index = g_handle_vtables.size();
    g_handle_vtables.push_back(vtable);
    if (index >= kHandleClasses) {
        stop_tracking("there are more handle classes than expected");
        return;
    }
    redirect(&vtable[0], kHandleDestructorHooks[index], &g_handle_destructors[index]);
    guard.unlock();
    printf("Pak list race fix: handle destructor %s hooked through its vtable %s\n",
           describe(reinterpret_cast<const void *>(g_handle_destructors[index])).c_str(), describe(vtable).c_str());
}

void *CreatePakFileHandle_Hook(void *pak_platform_file, const wchar_t *filename, void *pak_file, const void *entry) {
    void *handle = CreatePakFileHandle(pak_platform_file, filename, pak_file, entry);
    if (handle) {
        hook_handle_destructor(*static_cast<void ***>(handle));
    }
    return handle;
}

// ---------------------------------------------------------------- return stubs ---------------------------------------

// A stub per return address ends the reader, then jumps there. Its unwind data is a copy of that function's, without
// its prologue size, so unwinding through the stub restores that function's frame as anywhere in its body, and without
// its exception handlers, which would see an address outside their code and pick the wrong state. Walkers look a return
// address up one byte early, so a stub's entry starts a little before its code, which doesn't start with a jump (that
// would read as an epilogue).
constexpr size_t kStubCodeOffset = 0x10;
constexpr size_t kStubCodeEnd = 0x0D;
constexpr size_t kStubThunk = 0x10;
constexpr size_t kStubReturnTo = 0x18;
constexpr size_t kStubCodeSize = 0x20;
constexpr size_t kReturnStubSize = 0x400;
constexpr size_t kStubsPerRegion = 1024;
constexpr size_t kRegionSize = kStubsPerRegion * kReturnStubSize;
constexpr size_t kMaxRegions = 16;

struct StubRegion {
    byte *memory = nullptr;
    size_t used = 0;
    RUNTIME_FUNCTION entries[kStubsPerRegion];
    void *table = nullptr;
};

using AddGrowableFunctionTable = DWORD(NTAPI *)(PVOID *, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR);
using GrowFunctionTable = VOID(NTAPI *)(PVOID, DWORD);
AddGrowableFunctionTable g_add_function_table;
GrowFunctionTable g_grow_function_table;

std::shared_mutex g_stubs_lock;
std::unordered_map<const byte *, byte *> g_stubs;
StubRegion *g_regions[kMaxRegions];
std::atomic<size_t> g_region_count{0};

bool is_stub(const void *address) {
    const size_t count = g_region_count.load(std::memory_order_acquire);
    for (size_t i = 0; i < count; i++) {
        const byte *memory = g_regions[i]->memory;
        if (address >= memory && address < memory + kRegionSize) {
            return true;
        }
    }
    return false;
}

// Needs g_stubs_lock held exclusively
StubRegion *current_region() {
    const size_t count = g_region_count.load(std::memory_order_relaxed);
    if (count && g_regions[count - 1]->used < kStubsPerRegion) {
        return g_regions[count - 1];
    }
    if (count == kMaxRegions) {
        return nullptr;
    }
    auto *memory = static_cast<byte *>(VirtualAlloc(nullptr, kRegionSize, MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_EXECUTE_READWRITE));
    if (!memory) {
        return nullptr;
    }
    auto *region = new StubRegion;
    region->memory = memory;
    g_regions[count] = region;
    g_region_count.store(count + 1, std::memory_order_release);
    return region;
}

DWORD region_offset(const StubRegion &region, const byte *at) {
    return static_cast<DWORD>(at - region.memory);
}

bool copy_unwind_info(DWORD64 module, const RUNTIME_FUNCTION *function, const StubRegion &region, byte *to,
                      const byte *end, const RUNTIME_FUNCTION &stub) {
    for (int depth = 0; depth < 8; depth++) {
        const byte *from = unwind_info(module, function);
        const size_t codes = unwind_codes_size(from);
        const RUNTIME_FUNCTION *continues = chained_entry(from);
        const size_t size = 4 + codes + (continues ? sizeof(RUNTIME_FUNCTION) : 0);
        // Version 2 places epilogs from the function's end, which the stub doesn't have
        if (unwind_version(from) != 1 || to + size > end) {
            return false;
        }
        memcpy(to, from, 4 + codes);
        to[0] = static_cast<byte>(unwind_version(from) | (continues ? UNW_FLAG_CHAININFO << 3 : 0));
        to[1] = 0;
        if (!continues) {
            return true;
        }
        auto *link = reinterpret_cast<RUNTIME_FUNCTION *>(to + 4 + codes);
        link->BeginAddress = stub.BeginAddress;
        link->EndAddress = stub.EndAddress;
        link->UnwindData = region_offset(region, to + size);
        function = continues;
        to += size;
    }
    return false;
}

byte *stub_for(const byte *return_to) {
    {
        std::shared_lock<std::shared_mutex> guard(g_stubs_lock);
        auto found = g_stubs.find(return_to);
        if (found != g_stubs.end()) {
            return found->second;
        }
    }

    std::unique_lock<std::shared_mutex> guard(g_stubs_lock);
    auto found = g_stubs.find(return_to);
    if (found != g_stubs.end()) {
        return found->second;
    }
    DWORD64 module = 0;
    const RUNTIME_FUNCTION *function = lookup_function(return_to, module);
    StubRegion *region = function ? current_region() : nullptr;
    if (!region) {
        return nullptr;
    }

    byte *entry = region->memory + region->used * kReturnStubSize;
    byte *code = entry + kStubCodeOffset;
    RUNTIME_FUNCTION &registered = region->entries[region->used];
    registered.BeginAddress = region_offset(*region, entry);
    registered.EndAddress = region_offset(*region, code + kStubCodeEnd);
    registered.UnwindData = region_offset(*region, code + kStubCodeSize);
    if (!copy_unwind_info(module, function, *region, code + kStubCodeSize, entry + kReturnStubSize, registered)) {
        return nullptr;
    }
    const void *thunk = reinterpret_cast<const void *>(&pak_return_thunk);
    const byte instructions[] = {
        0xFF, 0x15, 0x0A, 0x00, 0x00, 0x00, // call [rip+0Ah]          (pak_return_thunk, at +10h)
        0x90,                               // nop                     (so the jump isn't read as an epilogue)
        0xFF, 0x25, 0x0B, 0x00, 0x00, 0x00, // jmp  [rip+0Bh]          (the return address, at +18h)
    };
    memset(entry, 0xCC, kStubCodeOffset + kStubThunk);
    memcpy(code, instructions, sizeof(instructions));
    memcpy(code + kStubThunk, &thunk, sizeof(thunk));
    memcpy(code + kStubReturnTo, &return_to, sizeof(return_to));
    FlushInstructionCache(GetCurrentProcess(), entry, kStubCodeOffset + kStubCodeSize);

    region->used++;
    if (!region->table) {
        const auto start = reinterpret_cast<ULONG_PTR>(region->memory);
        if (g_add_function_table(&region->table, region->entries, 1, kStubsPerRegion, start, start + kRegionSize)) {
            region->table = nullptr;
            region->used--;
            return nullptr;
        }
    } else {
        g_grow_function_table(region->table, static_cast<DWORD>(region->used));
    }
    g_stubs.emplace(return_to, code);
    guard.unlock();
    printf("Pak list race fix: readers returning to %s are redirected through a stub\n", describe(return_to).c_str());
    return code;
}

// ---------------------------------------------------------------- tracking readers -----------------------------------

void(WINAPI *g_enter_critical_section)(LPCRITICAL_SECTION);

std::shared_mutex g_lock_calls_lock;
std::unordered_set<const byte *> g_lock_calls;

const byte *function_start(const byte *code) {
    DWORD64 module = 0;
    const RUNTIME_FUNCTION *function = lookup_function(code, module);
    if (!function) {
        return code;
    }
    while (const RUNTIME_FUNCTION *primary = chained_entry(unwind_info(module, function))) {
        function = primary;
    }
    return reinterpret_cast<const byte *>(module) + function->BeginAddress;
}

void note_lock_call(const byte *lock_call) {
    {
        std::shared_lock<std::shared_mutex> guard(g_lock_calls_lock);
        if (g_lock_calls.count(lock_call)) {
            return;
        }
    }
    {
        std::unique_lock<std::shared_mutex> guard(g_lock_calls_lock);
        if (!g_lock_calls.insert(lock_call).second) {
            return;
        }
    }
    printf("Pak list race fix: reader found, taking the pak lock at %s (in the function at %s)\n",
           describe(lock_call).c_str(), describe(function_start(lock_call)).c_str());
}

bool unwind(CONTEXT &context) {
    DWORD64 module = 0;
    PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(context.Rip, &module, nullptr);
    if (!function) {
        // A leaf function: the return address is on top of the stack
        context.Rip = *reinterpret_cast<DWORD64 *>(context.Rsp);
        context.Rsp += 8;
    } else {
        void *handler_data;
        DWORD64 establisher;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, module, context.Rip, function, &context, &handler_data, &establisher,
                         nullptr);
    }
    return context.Rip != 0;
}

// Readers at or below a live frame, or whose return no longer points at their stub, were unwound by an exception
void drop_dead_readers(void **floor) {
    int kept = 0;
    for (int i = 0; i < g_tracked_count; i++) {
        const Tracked tracked = g_tracked[i];
        if (tracked.slot > floor && *tracked.slot == tracked.stub) {
            g_tracked[kept] = tracked;
            kept++;
        }
    }
    g_tracked_count = kept;
}

// Without a frame pointer, a function's return address is a fixed distance above the stack pointer at each of its
// return addresses; 0 when that's not known yet, -1 when the function has a frame pointer (it may use alloca)
std::shared_mutex g_frames_lock;
std::unordered_map<const byte *, intptr_t> g_return_distances;

intptr_t return_distance(const byte *at) {
    std::shared_lock<std::shared_mutex> guard(g_frames_lock);
    auto found = g_return_distances.find(at);
    return found != g_return_distances.end() ? found->second : 0;
}

bool has_frame_pointer(const byte *at) {
    DWORD64 module = 0;
    const RUNTIME_FUNCTION *function = lookup_function(at, module);
    if (!function) {
        return true;
    }
    for (; function; function = chained_entry(unwind_info(module, function))) {
        if (frame_register(unwind_info(module, function))) {
            return true;
        }
    }
    return false;
}

// Each level's slot holds the return address the next one is found from; null when a distance isn't known, or the
// slot it gives doesn't hold a return address the unwinder knows
void **known_return_slot(void **slot, int frames_up) {
    for (int i = 0; i < frames_up && !is_stub(*slot); i++) {
        const intptr_t distance = return_distance(static_cast<const byte *>(*slot));
        if (distance <= 0) {
            return nullptr;
        }
        slot = reinterpret_cast<void **>(reinterpret_cast<byte *>(slot + 1) + distance);
        DWORD64 module = 0;
        if (!lookup_function(*slot, module)) {
            return nullptr;
        }
    }
    return slot;
}

void **unwound_return_slot(void **lock_call_return, int frames_up) {
    CONTEXT context;
    RtlCaptureContext(&context);
    while (context.Rsp <= reinterpret_cast<DWORD64>(lock_call_return)) {
        if (!unwind(context)) {
            return nullptr;
        }
    }
    void **slot = lock_call_return;
    for (int i = 0; i < frames_up && !is_stub(*slot); i++) {
        const auto *at = reinterpret_cast<const byte *>(context.Rip);
        const DWORD64 stack = context.Rsp;
        if (!unwind(context)) {
            return nullptr;
        }
        slot = reinterpret_cast<void **>(context.Rsp - 8);
        const intptr_t distance = has_frame_pointer(at) ? -1 : static_cast<intptr_t>(context.Rsp - 8 - stack);
        std::unique_lock<std::shared_mutex> guard(g_frames_lock);
        g_return_distances[at] = distance;
    }
    return slot;
}

// The reader is the function that called EnterCriticalSection, or the wrapper's caller, which gets the pak it found. A
// frame whose return already points at a stub is tracked already. A tail call leaves the caller's caller tracked,
// which only holds paks longer.
__declspec(noinline) void track_reader(void **lock_call_return) {
    const auto *lock_call = static_cast<const byte *>(*lock_call_return);
    const int frames_up = lock_call == g_code.wrapper_lock_return ? 2 : 1;
    void **slot = known_return_slot(lock_call_return, frames_up);
    if (!slot) {
        slot = unwound_return_slot(lock_call_return, frames_up);
    }
    if (!slot) {
        stop_tracking("a reader's stack couldn't be followed");
        return;
    }
    if (is_stub(*slot)) {
        return;
    }

    const uint64_t before = thread_epoch();
    drop_dead_readers(slot);
    byte *stub = g_tracked_count < kMaxTracked ? stub_for(static_cast<const byte *>(*slot)) : nullptr;
    if (stub) {
        note_lock_call(lock_call);
        g_tracked[g_tracked_count] = {slot, stub, g_current_epoch.value.load(std::memory_order_relaxed)};
        g_tracked_count++;
        void *return_to = *slot;
        *slot = stub;

        // A restore that started meanwhile may have scanned this thread before the stub was in; one of the two puts
        // the real return address back
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (g_returns_restored.load(std::memory_order_relaxed)) {
            *slot = return_to;
        }
    }
    publish(before);
    if (!stub) {
        stop_tracking(g_tracked_count == kMaxTracked ? "readers nest too deeply"
                                                     : "a reader's return couldn't be redirected");
    }
}

CRITICAL_SECTION *learn_pak_list_lock(CRITICAL_SECTION *section) {
    CRITICAL_SECTION *expected = nullptr;
    if (!g_pak_list_lock.compare_exchange_strong(expected, section)) {
        return expected;
    }
    const auto *pak_platform_file = reinterpret_cast<const byte *>(section) - g_code.pak_list_critical_offset;
    const auto mounted = *reinterpret_cast<const int32_t *>(pak_platform_file + g_code.pak_files_offset + 8);
    printf("Pak list race fix: found the pak list lock, with %d paks mounted\n", mounted);
    return section;
}

using MountFunction = bool (*)(void *pak_platform_file, const wchar_t *filename, uint32_t order, const wchar_t *path,
                               bool load_index);
MountFunction Mount;

// The list is empty until the first Mount, so a reader that ran before the lock was learned here held no pak
bool Mount_Hook(void *pak_platform_file, const wchar_t *filename, uint32_t order, const wchar_t *path,
                bool load_index) {
    if (!g_pak_list_lock.load(std::memory_order_relaxed)) {
        learn_pak_list_lock(reinterpret_cast<CRITICAL_SECTION *>(static_cast<byte *>(pak_platform_file) +
                                                                 g_code.pak_list_critical_offset));
    }
    return Mount(pak_platform_file, filename, order, path, load_index);
}

void WINAPI enter_critical_section_hook(LPCRITICAL_SECTION section) {
    CRITICAL_SECTION *pak_list_lock = g_pak_list_lock.load(std::memory_order_relaxed);
    if (!pak_list_lock && _ReturnAddress() == g_code.wrapper_lock_return) {
        pak_list_lock = learn_pak_list_lock(section);
    }
    if (section == pak_list_lock && g_tracking.load(std::memory_order_relaxed)) {
        track_reader(static_cast<void **>(_AddressOfReturnAddress()));
    }
    g_enter_critical_section(section);
}

// ---------------------------------------------------------------- crash reports --------------------------------------

// DbgHelp's StackWalk64 and debuggers reading a minidump don't see the stubs' unwind data, so before the game's crash
// reporting walks or dumps a stack, every reader's real return address is put back; nothing is tracked or freed after

void restore_thread_returns(const ReaderSlot *reader) {
    __try {
        const Tracked *tracked = reader->tracked.load();
        const int *count = reader->tracked_count.load();
        for (int i = 0; tracked && count && i < *count && i < kMaxTracked; i++) {
            void **slot = tracked[i].slot;
            byte *stub = tracked[i].stub;
            if (*slot == stub) {
                *slot = *reinterpret_cast<void **>(stub + kStubReturnTo);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void restore_returns() {
    if (g_returns_restored.exchange(true)) {
        return;
    }
    g_tracking.store(false);
    g_exiting.store(true);
    for (const ReaderSlot *reader = g_reader_slots.load(); reader; reader = reader->next) {
        restore_thread_returns(reader);
    }
    printf("Pak list race fix: the game is writing a crash report, so readers' return addresses are put back and the "
           "fix is off\n");
}

using MiniDumpWriteDumpFunction = BOOL(WINAPI *)(HANDLE, DWORD, HANDLE, int, void *, void *, void *);
using StackWalk64Function = BOOL(WINAPI *)(DWORD, HANDLE, HANDLE, void *, void *, void *, void *, void *, void *);
MiniDumpWriteDumpFunction g_minidump_write_dump;
StackWalk64Function g_stack_walk64;

BOOL WINAPI minidump_write_dump_hook(HANDLE process, DWORD process_id, HANDLE file, int type, void *exception,
                                     void *user_streams, void *callback) {
    restore_returns();
    return g_minidump_write_dump(process, process_id, file, type, exception, user_streams, callback);
}

BOOL WINAPI stack_walk64_hook(DWORD machine, HANDLE process, HANDLE thread, void *frame, void *context, void *read,
                              void *function_table, void *module_base, void *translate) {
    restore_returns();
    return g_stack_walk64(machine, process, thread, frame, context, read, function_table, module_base, translate);
}

// The game delay-loads DbgHelp; the first call through the delay-load thunk puts the function in the slot instead
void **dbghelp_slot(byte *module, const char *function) {
    void **found = import_slot(module, function, false);
    for_each_delay_import(module, [&](const char *, const char *name, void **slot) {
        if (strcmp(name, function) == 0) {
            found = slot;
        }
    });
    return found;
}

void hook_crash_reports(byte *module) {
    if (void **slot = dbghelp_slot(module, "MiniDumpWriteDump")) {
        redirect(slot, &minidump_write_dump_hook, &g_minidump_write_dump);
    }
    if (void **slot = dbghelp_slot(module, "StackWalk64")) {
        redirect(slot, &stack_walk64_hook, &g_stack_walk64);
    }
}

bool shadow_stacks_enforced() {
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy = {};
    return GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &policy, sizeof(policy)) &&
        policy.EnableUserShadowStack;
}

template <typename Function>
Function exported(HMODULE module, const char *name) {
    return reinterpret_cast<Function>(GetProcAddress(module, name));
}

void apply_fix() {
    // A return address that doesn't match the shadow stack's copy ends the process
    if (shadow_stacks_enforced()) {
        printf("Pak list race fix: shadow stacks are enforced, so return addresses can't be redirected "
               "- not applied\n");
        return;
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    g_add_function_table = exported<AddGrowableFunctionTable>(ntdll, "RtlAddGrowableFunctionTable");
    g_grow_function_table = exported<GrowFunctionTable>(ntdll, "RtlGrowFunctionTable");
    void **enter_slot = import_slot(g_exe, "EnterCriticalSection", false);
    if (!g_add_function_table || !g_grow_function_table ||
        reinterpret_cast<const byte *>(enter_slot) != g_code.wrapper_lock_slot) {
        printf("Pak list race fix: %s - not applied\n",
               g_add_function_table && g_grow_function_table ? "the pak lock isn't taken through the exe's import"
                                                              : "no growable function tables");
        return;
    }

    FPakFile_Delete = reinterpret_cast<decltype(FPakFile_Delete)>(g_code.delete_pak_file);
    CreatePakFileHandle = reinterpret_cast<decltype(CreatePakFileHandle)>(g_code.create_pak_file_handle);
    Mount = reinterpret_cast<MountFunction>(g_code.mount);
    g_release_work = CreateThreadpoolWork(release_paks, nullptr, nullptr);
    g_release_timer = CreateThreadpoolTimer(release_tick, nullptr, nullptr);
    if (!g_release_work || !g_release_timer) {
        printf("Pak list race fix: no thread-pool work - not applied\n");
        return;
    }

    redirect(enter_slot, &enter_critical_section_hook, &g_enter_critical_section);
    HookRequest requests[] = {
        {reinterpret_cast<void **>(&CreatePakFileHandle), reinterpret_cast<void *>(&CreatePakFileHandle_Hook)},
        {reinterpret_cast<void **>(&FPakFile_Delete), reinterpret_cast<void *>(&FPakFile_Delete_Hook)},
        {reinterpret_cast<void **>(&Mount), reinterpret_cast<void *>(&Mount_Hook)},
    };
    if (!setup_hook(requests, 3)) {
        g_tracking.store(false);
        decltype(g_enter_critical_section) hook;
        redirect(enter_slot, g_enter_critical_section, &hook);
        printf("Pak list race fix: hooks not installed - not applied\n");
        return;
    }
    hook_crash_reports(g_exe);

    // Relative due time, in 100 ns units
    FILETIME due;
    const int64_t first = -250LL * 10000;
    memcpy(&due, &first, sizeof(due));
    SetThreadpoolTimer(g_release_timer, &due, 250, 50);
    if (!hook_exit(g_exe)) {
        printf("Pak list race fix: the CRT's exit isn't imported, so paks are still deleted while the game exits\n");
    }
}

bool scan_exe() {
    return find_pak_code(g_exe, nt_headers(g_exe)->OptionalHeader.SizeOfImage, g_code);
}

} // namespace

extern "C" void pak_return_exit(void **stack) {
    const uint64_t before = thread_epoch();
    drop_dead_readers(stack - 1);
    publish(before);
}

void ScanForPakListRaceFix() {
    g_exe = reinterpret_cast<byte *>(GetModuleHandleW(nullptr));
    g_found = scan_exe();
}

void ApplyPakListRaceFix() {
    // An exe unpacked at its entry point only has its code by now
    if (!g_found) {
        g_found = scan_exe();
    }
    if (!g_found) {
        printf("Pak list race fix: %s - not applied\n", g_not_found);
    } else {
        apply_fix();
    }
}
