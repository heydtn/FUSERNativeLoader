<#
.SYNOPSIS
    Builds the static libarchive (with zlib) that FUSERMultiplayer.dll links, into lib\libarchive\.

.DESCRIPTION
    FUSERMultiplayer.dll extracts community song archives (.zip, .rar 4 and 5) with libarchive. Like lib\funchook.lib, the built libraries are kept in lib\, so build.ps1 needs no network; run
    this only to rebuild or upgrade them.

    The sources are pinned by version and SHA256 (both checked against the digests GitHub publishes for the release
    assets, 2026-10-05). They are downloaded into build\deps\ and built with MSVC x64, /MD, Release. Only what reading
    ZIP and RAR needs is built: zlib for deflate. No crypto, xml, lzma, bzip2, zstd or lz4, and none of the bsdtar /
    bsdcpio / bsdcat / bsdunzip programs.

    Output in lib\libarchive\: archive.h, archive_entry.h, archive.lib, zlib.lib, and the two licences.
    Consumers define LIBARCHIVE_STATIC before including archive.h.

.EXAMPLE
    .\tools\build_libarchive.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$deps = Join-Path $root 'build\deps'
$out = Join-Path $root 'lib\libarchive'

$sources = @(
    @{ Name = 'zlib-1.3.2'; Url = 'https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz'
        Sha256 = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16' },
    @{ Name = 'libarchive-3.8.9'; Url = 'https://github.com/libarchive/libarchive/releases/download/v3.8.9/libarchive-3.8.9.tar.gz'
        Sha256 = 'f5a6539059cf5e597dbeda37bfa4874b1e8dea063c8d93bf85a2b44af90a5bd4' }
)

function Invoke-Checked([string]$what, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw 'CMake not found on PATH (Visual Studio ships one: use a Developer PowerShell).' }
New-Item -ItemType Directory -Path $deps, $out -Force | Out-Null

foreach ($s in $sources) {
    $tgz = Join-Path $deps "$($s.Name).tar.gz"
    if (-not (Test-Path -LiteralPath $tgz)) {
        Write-Host "downloading $($s.Url)"
        Invoke-WebRequest -Uri $s.Url -OutFile $tgz -UseBasicParsing
    }
    $hash = (Get-FileHash -LiteralPath $tgz -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $s.Sha256) { throw "$tgz has sha256 $hash, expected $($s.Sha256): delete it and run again" }
    $src = Join-Path $deps $s.Name
    if (-not (Test-Path -LiteralPath $src)) {
        Invoke-Checked "extract $($s.Name)" { & "$env:SystemRoot\System32\tar.exe" -xzf $tgz -C $deps }
    }
}

$prefix = Join-Path $deps 'install'
$zsrc = Join-Path $deps 'zlib-1.3.2'
$zbuild = Join-Path $deps 'zlib-build'
Invoke-Checked 'zlib configure' { cmake -S $zsrc -B $zbuild -A x64 -DZLIB_BUILD_SHARED=OFF -DZLIB_BUILD_TESTING=OFF `
        -DZLIB_INSTALL=ON "-DCMAKE_INSTALL_PREFIX=$prefix" | Out-Host }
Invoke-Checked 'zlib build' { cmake --build $zbuild --config Release --target install | Out-Host }
$zlib = Get-ChildItem -LiteralPath (Join-Path $prefix 'lib') -Filter '*.lib' | Where-Object { $_.Name -match '^(zs|zlibstatic)\.lib$' } | Select-Object -First 1
if (-not $zlib) { throw "no static zlib library in $prefix\lib" }

$asrc = Join-Path $deps 'libarchive-3.8.9'
$abuild = Join-Path $deps 'libarchive-build'
$off = 'MBEDTLS', 'NETTLE', 'OPENSSL', 'LIBB2', 'LZ4', 'LZO', 'LZMA', 'ZSTD', 'BZip2', 'LIBXML2', 'EXPAT', 'WIN32_XMLLITE',
'PCREPOSIX', 'PCRE2POSIX', 'LIBGCC', 'CNG', 'TAR', 'CPIO', 'CAT', 'UNZIP', 'XATTR', 'ACL', 'ICONV', 'TEST', 'INSTALL' | ForEach-Object { "-DENABLE_$_=OFF" }
# POSIX_REGEX_LIB=NONE: regex is only for bsdtar's -s option. CMake gets '/' paths.
$zinc = (Join-Path $prefix 'include') -replace '\\', '/'
$zlibPath = $zlib.FullName -replace '\\', '/'
Invoke-Checked 'libarchive configure' { cmake -S $asrc -B $abuild -A x64 -DBUILD_SHARED_LIBS=OFF -DPOSIX_REGEX_LIB=NONE `
        -DENABLE_ZLIB=ON "-DZLIB_INCLUDE_DIR=$zinc" "-DZLIB_LIBRARY=$zlibPath" @off | Out-Host }
Invoke-Checked 'libarchive build' { cmake --build $abuild --config Release --target archive_static | Out-Host }
$archive = Get-ChildItem -LiteralPath $abuild -Recurse -Filter '*.lib' | Where-Object { $_.Name -match '^archive(_static)?\.lib$' -and $_.FullName -match '\\Release\\' } | Select-Object -First 1
if (-not $archive) { throw "no archive library under $abuild" }

Copy-Item -LiteralPath (Join-Path $asrc 'libarchive\archive.h'), (Join-Path $asrc 'libarchive\archive_entry.h') -Destination $out -Force
Copy-Item -LiteralPath $archive.FullName -Destination (Join-Path $out 'archive.lib') -Force
Copy-Item -LiteralPath $zlib.FullName -Destination (Join-Path $out 'zlib.lib') -Force
Copy-Item -LiteralPath (Join-Path $asrc 'COPYING') -Destination (Join-Path $out 'LICENSE.libarchive') -Force
Copy-Item -LiteralPath (Join-Path $zsrc 'LICENSE') -Destination (Join-Path $out 'LICENSE.zlib') -Force
Get-ChildItem -LiteralPath $out | Format-Table Name, Length | Out-Host
