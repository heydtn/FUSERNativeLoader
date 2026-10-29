<#
.SYNOPSIS
    Installs a build from out\<Configuration>\ into a FUSER install, or uninstalls it.

.DESCRIPTION
    Copies FUSERNativeLoader.dll and optional FUSERMultiplayer.dll to Fuser\Binaries\Win64\mods\FUSERNativeLoader\, where
    FuserModLoader's winhttp.dll loads them, and FUSERNativeMods_P.pak / .sig to Fuser\Content\Paks\. The first install
    copies an existing Fuser\Binaries\Win64\FuserNative.ini into the mod folder so settings carry over. Refuses while the
    game is running, or while Fuser\Binaries\Win64\winhttp.dll is an older FUSERNativeLoader, which would run alongside it.

.PARAMETER GameRoot
    The folder that contains Fuser\ (default: %FUSER_GAME_ROOT%).
.PARAMETER Configuration
    Release (default) or Debug: which out\ folder to install.
.PARAMETER Uninstall
    Remove the mod's DLLs and FUSERNativeMods_P.pak / .sig. FuserNative.ini and FuserNative.log are kept.

.EXAMPLE
    $env:FUSER_GAME_ROOT = 'D:\Games\FUSER'
    .\install.ps1 -Configuration Debug
    .\install.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$GameRoot = $env:FUSER_GAME_ROOT,
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
if (-not $GameRoot) { throw 'Pass -GameRoot <folder containing Fuser\> or set FUSER_GAME_ROOT.' }
$win64 = Join-Path $GameRoot 'Fuser\Binaries\Win64'
$paks = Join-Path $GameRoot 'Fuser\Content\Paks'
if (-not (Test-Path -LiteralPath $win64) -or -not (Test-Path -LiteralPath $paks)) { throw "No FUSER install under '$GameRoot'." }
if (-not $WhatIfPreference -and (Get-Process -Name 'FuserEOS-Win64-Shipping', 'Fuser-Win64-Shipping' -ErrorAction SilentlyContinue)) { throw 'FUSER is running - close it first.' }

$modDir = Join-Path $win64 'mods\FUSERNativeLoader'
$modDlls = 'FUSERNativeLoader.dll', 'FUSERMultiplayer.dll' | ForEach-Object { Join-Path $modDir $_ }
$modPaks = 'FUSERNativeMods_P.pak', 'FUSERNativeMods_P.sig' | ForEach-Object { Join-Path $paks $_ }

if ($Uninstall) {
    foreach ($f in $modDlls + $modPaks) { if ((Test-Path -LiteralPath $f) -and $PSCmdlet.ShouldProcess($f, 'Remove')) { Remove-Item -LiteralPath $f -Force } }
    if (-not $WhatIfPreference) { Write-Host 'Uninstalled.' }
    return
}

$loader = Join-Path $win64 'winhttp.dll'
if (Test-Path -LiteralPath $loader) {
    if ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($loader)).Contains('fnl_start')) {
        throw "$loader is an older FUSERNativeLoader build: replace it with FuserModLoader's winhttp.dll first."
    }
} else {
    Write-Warning "No $loader - install FuserModLoader, which loads mods\FUSERNativeLoader."
}

$src = Join-Path $PSScriptRoot "out\$Configuration"
$inputs = @('FUSERNativeLoader.dll', 'FUSERMultiplayer.dll', 'FUSERNativeMods_P.pak', 'FUSERNativeMods_P.sig') | ForEach-Object { Join-Path $src $_ }
foreach ($f in $inputs) { if (-not (Test-Path -LiteralPath $f)) { throw "Missing $f - run .\build.ps1 -Configuration $Configuration first." } }

if ($PSCmdlet.ShouldProcess($modDir, 'Create')) { New-Item -ItemType Directory -Path $modDir -Force | Out-Null }
$oldSettings = Join-Path $win64 'FuserNative.ini'
$settings = Join-Path $modDir 'FuserNative.ini'
if ((Test-Path -LiteralPath $oldSettings) -and -not (Test-Path -LiteralPath $settings)) {
    if ($PSCmdlet.ShouldProcess($settings, 'Copy settings from Win64\FuserNative.ini')) { Copy-Item -LiteralPath $oldSettings -Destination $settings }
}
if ($PSCmdlet.ShouldProcess($modDir, "Install $Configuration FUSERNativeLoader.dll / FUSERMultiplayer.dll")) { Copy-Item -LiteralPath $inputs[0], $inputs[1] -Destination $modDir -Force }
if ($PSCmdlet.ShouldProcess($paks, 'Install FUSERNativeMods_P.pak / .sig')) { Copy-Item -LiteralPath $inputs[2], $inputs[3] -Destination $paks -Force }

if (Test-Path -LiteralPath (Join-Path $win64 'FUSERMultiplayer.dll')) {
    Write-Warning 'Win64\FUSERMultiplayer.dll is from an older install and is no longer used - it can be deleted.'
}
if (Test-Path -LiteralPath (Join-Path $win64 'dwmapi.dll')) {
    Write-Warning 'dwmapi.dll (UE4SS) is present: do not run UE4SS alongside FUSERNativeLoader - remove or rename it.'
}
if ($WhatIfPreference) { return }
$same = (Get-FileHash -LiteralPath $inputs[0]).Hash -eq (Get-FileHash -LiteralPath $modDlls[0]).Hash
Write-Host "Installed $Configuration build to $modDir (FUSERNativeLoader.dll hash match: $same)."
