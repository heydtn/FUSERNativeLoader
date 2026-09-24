# FUSERNativeLoader

The FUSER mod loader (a `winhttp.dll` proxy, based on the community FuserSongLoader) with a minimal UE 4.24
reflection core (**fue**) and the **FuserNative** features built in: key/BPM on the HUD song items, Key Labels, real
song tabs, song search, crate-edit tabs, new-crate slot sizes, the mod settings rows, and free unlocks for custom and
event songs. Two build outputs:

| Output | What |
|---|---|
| `winhttp.dll` | the loader: pak-signature bypass for `*_P` paks, BPM range patch, fue, unlocks, FuserNative |
| `FUSERNativeMods_P.pak` (+ `.sig`) | FuserNative's cooked Blueprint assets (`/Game/Mods/FuserNative/`) |

## Requirements

- Windows, **Visual Studio 2022** (MSVC x64, C++20) and **CMake 3.20+** (e.g. from a Developer PowerShell).
- **Python 3** for the pak tool (standard library only).
- Optional, for `tools/derive_build.py`: `pefile`, `capstone`, `numpy`.

## Build

```powershell
.\build.ps1                          # out\Release\: winhttp.dll (+ .pdb), FUSERNativeMods_P.pak / .sig
.\build.ps1 -Configuration Debug     # out\Debug\: the diagnostic winhttp.dll, same pak
.\build.ps1 -Package                 # also out\FUSERNativeLoader-<version>.zip (+ -symbols.zip)
```

The **Debug** configuration is the diagnostic build (`FNL_DEBUG`): a console with the loader's tracing, the F6-F10
debug keys (F6 key/BPM self-test, F7 song probe, F8 crate-edit and settings dumps, F9 fue probe, F10 unlock state)
and the probes. Both configurations are optimised. The version comes from `VERSION`.

## Install for testing

```powershell
$env:FUSER_GAME_ROOT = '<folder containing Fuser\>'
.\install.ps1 [-Configuration Debug]   # keeps the previous winhttp.dll as winhttp.dll.fnl-backup
.\install.ps1 -Restore
```

Settings: `Fuser\Binaries\Win64\FuserNative.ini`; log: `Fuser\Binaries\Win64\FuserNative.log`.

## Layout

| Path | |
|---|---|
| `src/dllmain.cpp` | the loader (proxy exports, pak-signature bypass, BPM patches, legacy unlock-pak rename) |
| `src/fnl_entry.cpp` | `fnl_start`: fue, unlocks, FuserNative; the debug fue probe |
| `src/fue/` | the reflection core: objects, properties, ProcessEvent / tick / native hooks, per-build addresses |
| `src/unlocks.cpp` | custom and event song unlocks, patched into the live `DT_UnlocksSongs` at startup |
| `src/native/fusernative.cpp` | the FuserNative features |
| `src/debug/unlock_probe.cpp` | debug builds: unlock-state probe (F10) |
| `lib/` | funchook (prebuilt `funchook.lib` + header) |
| `assets/Content/` | the cooked assets packed into `FUSERNativeMods_P.pak` |
| `modkit/FuserModkit/` | the UE 4.24 editor project those assets are authored and cooked in |
| `docs/MOD_DEVELOPMENT.md` | a step-by-step tutorial for adding a new feature (assets, native code, settings, pak) |
| `package/README.md` | the player README (`{{VERSION}}` filled in by `build.ps1 -Package`) |
| `tools/fuser_pak_create.py` | pak + sig writer |
| `tools/derive_build.py` | derives fue's addresses for another FUSER executable (e.g. Steam) by static analysis |

## Supported executables

fue runs only on executables listed in `kBuilds` (`src/fue/fue.cpp`), selected by PE identity:

| Build | Exe | Status |
|---|---|--------|
| EGS v1.4.2 (engine CL 1310155) | `FuserEOS-Win64-Shipping.exe` | tested |
| EGS, later build (engine CL 1317808) | `FuserEOS-Win64-Shipping.exe` | tested |
| Steam (engine CL 1317755) | `Fuser-Win64-Shipping.exe` (SteamStub-wrapped) | tested |

Each entry holds 8 RVAs and prologue patterns, checked before anything is patched, and the globals are sanity-checked
at the first ProcessEvent: on any mismatch fue (and with it FuserNative and the unlocks) stays off, and the game runs
with the plain loader. To add a build, run
`python tools/derive_build.py --target <exe> --name "<name>" --ref <FuserEOS-Win64-Shipping.exe>` (or set
`FUSER_GAME_ROOT`) and paste the printed entry once every address is CONFIRMED. A SteamStub-wrapped exe has an
encrypted code section on disk: analyse an unpacked copy (e.g. from Steamless) as `--target` and pass the shipped exe
as `--identity`, so the entry matches the exe that actually runs. If the engine changelist differs from EGS's, the
tool will not report OVERALL confirmed; check that the engine functions fue relies on are unchanged before adding it.

## The cooked assets

`assets/Content/Mods/FuserNative/` holds the cooked `BPL_FuserNative` (the key/BPM call points, bound to native code
at runtime) and `WBP_FuserKeyBpm` (the key/BPM line widget). They are authored in `modkit/FuserModkit/` (a
Blueprint-only UE 4.24 project; File > Cook Content for Windows) and copied here from its
`Saved/Cooked/WindowsNoEditor/FuserModkit/Content/`. `docs/MOD_DEVELOPMENT.md` walks through the whole cycle.

## AI Usage Disclosure

AI/LLM was used heavily in the production of this loader.

## Licences

The loader is based on FuserSongLoader / FuserModDoorstop, MIT, (c) 2020 Mettra (`LICENSE.FuserSongLoader`).
funchook is GPLv2+ with a linking exception (see `lib/funchook.h`).
