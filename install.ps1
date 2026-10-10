<#
.SYNOPSIS
    Installs a build from out\<Configuration>\ into a FUSER install, or restores what was there before.

.DESCRIPTION
    Copies winhttp.dll and optional FUSERMultiplayer.dll to Fuser\Binaries\Win64\ and FUSERNativeMods_P.pak / .sig to Fuser\Content\Paks\. The first
    install keeps the game's previous winhttp.dll (e.g. the stock song loader) as winhttp.dll.fnl-backup; -Restore puts
    it back and removes the pak. Refuses while the game is running.

.PARAMETER GameRoot
    The folder that contains Fuser\ (default: %FUSER_GAME_ROOT%).
.PARAMETER Configuration
    Release (default) or Debug: which out\ folder to install.
.PARAMETER Restore
    Undo: restore the backed-up winhttp.dll and remove FUSERNativeMods_P.pak / .sig.

.EXAMPLE
    $env:FUSER_GAME_ROOT = 'D:\Games\FUSER'
    .\install.ps1 -Configuration Debug
    .\install.ps1 -Restore
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$GameRoot = $env:FUSER_GAME_ROOT,
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [switch]$Restore
)
$ErrorActionPreference = 'Stop'
if (-not $GameRoot) { throw 'Pass -GameRoot <folder containing Fuser\> or set FUSER_GAME_ROOT.' }
$win64 = Join-Path $GameRoot 'Fuser\Binaries\Win64'
$paks = Join-Path $GameRoot 'Fuser\Content\Paks'
if (-not (Test-Path -LiteralPath $win64) -or -not (Test-Path -LiteralPath $paks)) { throw "No FUSER install under '$GameRoot'." }
if (-not $WhatIfPreference -and (Get-Process -Name 'FuserEOS-Win64-Shipping', 'Fuser-Win64-Shipping' -ErrorAction SilentlyContinue)) { throw 'FUSER is running - close it first.' }

$dll = Join-Path $win64 'winhttp.dll'
$multiplayerDll = Join-Path $win64 'FUSERMultiplayer.dll'
$backup = Join-Path $win64 'winhttp.dll.fnl-backup'
$modPak = Join-Path $paks 'FUSERNativeMods_P.pak'
$modSig = Join-Path $paks 'FUSERNativeMods_P.sig'

if ($Restore) {
    if (Test-Path -LiteralPath $backup) {
        if ($PSCmdlet.ShouldProcess($dll, 'Restore from winhttp.dll.fnl-backup')) { Move-Item -LiteralPath $backup -Destination $dll -Force }
    } else {
        Write-Warning 'No winhttp.dll.fnl-backup: winhttp.dll left as it is.'
    }
    foreach ($f in $modPak, $modSig) { if ((Test-Path -LiteralPath $f) -and $PSCmdlet.ShouldProcess($f, 'Remove')) { Remove-Item -LiteralPath $f -Force } }
    if ((Test-Path -LiteralPath $multiplayerDll) -and $PSCmdlet.ShouldProcess($multiplayerDll, 'Remove')) { Remove-Item -LiteralPath $multiplayerDll -Force }
    if (-not $WhatIfPreference) { Write-Host 'Restored.' }
    return
}

$src = Join-Path $PSScriptRoot "out\$Configuration"
$inputs = @('winhttp.dll', 'FUSERMultiplayer.dll', 'FUSERNativeMods_P.pak', 'FUSERNativeMods_P.sig') | ForEach-Object { Join-Path $src $_ }
foreach ($f in $inputs) { if (-not (Test-Path -LiteralPath $f)) { throw "Missing $f - run .\build.ps1 -Configuration $Configuration first." } }

# keep the previous winhttp.dll once (a later install over our own build must not overwrite the backup)
if ((Test-Path -LiteralPath $dll) -and -not (Test-Path -LiteralPath $backup)) {
    if ($PSCmdlet.ShouldProcess($dll, 'Back up as winhttp.dll.fnl-backup')) { Copy-Item -LiteralPath $dll -Destination $backup }
}
if ($PSCmdlet.ShouldProcess($dll, "Install $Configuration winhttp.dll")) { Copy-Item -LiteralPath $inputs[0] -Destination $dll -Force }
if ($PSCmdlet.ShouldProcess($multiplayerDll, "Install $Configuration FUSERMultiplayer.dll")) { Copy-Item -LiteralPath $inputs[1] -Destination $multiplayerDll -Force }
if ($PSCmdlet.ShouldProcess($paks, 'Install FUSERNativeMods_P.pak / .sig')) { Copy-Item -LiteralPath $inputs[2], $inputs[3] -Destination $paks -Force }

if (Test-Path -LiteralPath (Join-Path $win64 'dwmapi.dll')) {
    Write-Warning 'dwmapi.dll (UE4SS) is present: do not run UE4SS alongside FUSERNativeLoader - remove or rename it.'
}
if ($WhatIfPreference) { return }
$same = (Get-FileHash -LiteralPath $inputs[0]).Hash -eq (Get-FileHash -LiteralPath $dll).Hash
Write-Host "Installed $Configuration build to $GameRoot (winhttp.dll hash match: $same)."
