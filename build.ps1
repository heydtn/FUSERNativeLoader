<#
.SYNOPSIS
    Builds FUSERNativeLoader: FUSERNativeLoader.dll and FUSERNativeMods_P.pak (+ .sig), and optionally the player package.

.DESCRIPTION
    Output goes to out\<Configuration>\:
      FUSERNativeLoader.dll, .pdb  the FuserModLoader mod (CMake, MSVC x64)
      FUSERMultiplayer.dll, .pdb   optional multiplayer client extension
      FUSERNativeMods_P.pak, .sig   the mod's cooked assets (assets\Content), packed by tools\fuser_pak_create.py
    -Configuration Debug builds the diagnostic FUSERNativeLoader.dll (FNL_DEBUG: a console with the loader's tracing, the
    F6-F10 debug keys and the probes); the pak is the same in both configurations.
    -Package also writes out\FUSERNativeLoader-<version>[-debug].zip, laid out as it goes into a FUSER install, with
    package\README.md and the licence; its symbols go into a separate -symbols.zip.

.PARAMETER Configuration
    Release (default) or Debug.
.PARAMETER Package
    Also build the player zip.
.PARAMETER Python
    Python 3 to run the pak tool. Default: py -3, python on PATH, or the newest %ProgramFiles%\Python3*\python.exe.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Configuration Debug
    .\build.ps1 -Package
#>
param(
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [switch]$Package,
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -TotalCount 1).Trim()
$buildDir = Join-Path $root "build\$Configuration"
$outDir = Join-Path $root "out\$Configuration"

function Find-Python {
    if ($Python) { return , @($Python) }
    if (Get-Command py -ErrorAction SilentlyContinue) { return , @('py', '-3') }
    if (Get-Command python -ErrorAction SilentlyContinue) { return , @('python') }
    $installed = Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Python3*\python.exe') -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($installed) { return , @($installed.FullName) }
    throw 'Python 3 not found: pass -Python <path to python.exe>.'
}

function Invoke-Checked([string]$what, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw 'CMake not found on PATH (Visual Studio ships one: use a Developer PowerShell).' }
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# ---- FUSERNativeLoader.dll: the diagnostic build differs only by FNL_DEBUG; both are optimised (MSVC Release config)
$debugFlag = if ($Configuration -eq 'Debug') { 'ON' } else { 'OFF' }
Invoke-Checked 'CMake configure' { cmake -S $root -B $buildDir -A x64 "-DFNL_DEBUG=$debugFlag" | Out-Host }
Invoke-Checked 'CMake build' { cmake --build $buildDir --config Release | Out-Host }
foreach ($f in 'FUSERNativeLoader.dll', 'FUSERNativeLoader.pdb', 'FUSERMultiplayer.dll', 'FUSERMultiplayer.pdb') { Copy-Item -LiteralPath (Join-Path $buildDir "Release\$f") -Destination $outDir -Force }

# ---- FUSERNativeMods_P.pak: every cooked file under assets\Content, mounted at ../../../Fuser/Content/
$py = Find-Python
$content = Join-Path $root 'assets\Content'
$files = Get-ChildItem -LiteralPath $content -Recurse -File | Sort-Object FullName | ForEach-Object { $_.FullName } # sorted: a reproducible pak
if (-not $files) { throw "No cooked assets under $content" }
$pak = Join-Path $outDir 'FUSERNativeMods_P.pak'
$pyArgs = @($py | Select-Object -Skip 1) + @((Join-Path $root 'tools\fuser_pak_create.py'), $pak, '--mount', '../../../Fuser/Content/', '--root', $content) + $files
Invoke-Checked 'fuser_pak_create.py' { & $py[0] @pyArgs | Out-Host }

# ---- player package
if ($Package) {
    $suffix = if ($Configuration -eq 'Debug') { '-debug' } else { '' }
    $name = "FUSERNativeLoader-$version$suffix"
    $stage = Join-Path $root "out\$name"
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    $modDir = Join-Path $stage 'Fuser\Binaries\Win64\mods\FUSERNativeLoader'
    $paks = Join-Path $stage 'Fuser\Content\Paks'
    New-Item -ItemType Directory -Path $modDir, $paks -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $outDir 'FUSERNativeLoader.dll'), (Join-Path $outDir 'FUSERMultiplayer.dll') -Destination $modDir
    Copy-Item -LiteralPath $pak, (Join-Path $outDir 'FUSERNativeMods_P.sig') -Destination $paks
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE.FuserSongLoader') -Destination $stage
    # FUSERMultiplayer.dll links libarchive (BSD-2) and zlib statically: their notices go with it
    Copy-Item -LiteralPath (Join-Path $root 'lib\libarchive\LICENSE.libarchive'), (Join-Path $root 'lib\libarchive\LICENSE.zlib') -Destination $stage
    (Get-Content -LiteralPath (Join-Path $root 'package\README.md') -Raw).Replace('{{VERSION}}', $version) |
        Set-Content -LiteralPath (Join-Path $stage 'README.md') -Encoding utf8
    $zip = Join-Path $root "out\$name.zip"
    $symZip = Join-Path $root "out\$name-symbols.zip"
    foreach ($z in $zip, $symZip) { if (Test-Path -LiteralPath $z) { Remove-Item -LiteralPath $z -Force } }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    Compress-Archive -LiteralPath (Join-Path $outDir 'FUSERNativeLoader.pdb'), (Join-Path $outDir 'FUSERMultiplayer.pdb') -DestinationPath $symZip
    Write-Host "package: $zip"
}

Get-ChildItem -LiteralPath $outDir -File | ForEach-Object { '{0,-26} {1,10}  {2}' -f $_.Name, $_.Length, (Get-FileHash -LiteralPath $_.FullName).Hash.Substring(0, 12) }
Write-Host "FUSERNativeLoader $version ($Configuration) -> $outDir"
