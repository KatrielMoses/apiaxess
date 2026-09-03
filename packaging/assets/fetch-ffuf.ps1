<#
.SYNOPSIS
    Acquires the bundled ffuf binary for one platform.

.DESCRIPTION
    Downloads the pinned official ffuf release archive named in ffuf.toml,
    verifies its SHA-256 against the release checksum, extracts the static
    binary into tools/ffuf/, copies the upstream MIT LICENSE, and writes an
    SBOM. On Linux it also verifies the binary is statically linked (no program
    interpreter / dynamic dependencies).

    ffuf is a static Go binary, so this is a pure drop-in — no runtime, no build.
    Mirrors fetch-chromium.ps1 / fetch-apk-tools.ps1 so Phase 12 installers
    assemble it the same way.
#>
[CmdletBinding()]
param(
    [ValidateSet("windows_x64", "linux_x64")]
    [string]$Platform = "windows_x64",
    [string]$OutputDirectory,
    [string]$CacheDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-ManifestField {
    param(
        [Parameter(Mandatory)] [string]$Section,
        [Parameter(Mandatory)] [string]$Field,
        [Parameter(Mandatory)] [string]$Manifest
    )
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*(?<body>.*?)(?=^\[|\z)'
    $sectionMatch = [regex]::Match($Manifest, $sectionPattern)
    if (-not $sectionMatch.Success) {
        throw "ffuf manifest section [$Section] is missing."
    }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) {
        throw "ffuf manifest field '$Field' is missing from [$Section]."
    }
    $fieldMatch.Groups["value"].Value
}

function Reset-OwnedDirectory {
    param([Parameter(Mandatory)] [string]$Path)
    $absolute = [System.IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $absolute) {
        Remove-Item -LiteralPath $absolute -Recurse -Force
    }
    New-Item -ItemType Directory -Path $absolute -Force | Out-Null
}

# Portable across Windows PowerShell 5.1 and PowerShell 7 (no GetRelativePath).
function Get-RelativePath {
    param([Parameter(Mandatory)] [string]$Base, [Parameter(Mandatory)] [string]$Full)
    $baseUri = New-Object System.Uri(($Base.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar))
    $fullUri = New-Object System.Uri($Full)
    ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($fullUri).ToString())) -replace '/', [System.IO.Path]::DirectorySeparatorChar
}

# BOM-less UTF-8 write, portable across Windows PowerShell 5.1 and PowerShell 7.
function Write-Utf8NoBom {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

# Verifies an ELF binary is statically linked (no PT_INTERP program header).
function Test-StaticElf {
    param([Parameter(Mandatory)] [string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x7f -or $bytes[1] -ne 0x45 -or $bytes[2] -ne 0x4c -or $bytes[3] -ne 0x46) {
        throw "ffuf Linux artifact is not an ELF binary."
    }
    $is64 = ($bytes[4] -eq 2)
    if (-not $is64) { throw "ffuf Linux artifact is not 64-bit." }
    $phoff = [System.BitConverter]::ToInt64($bytes, 0x20)
    $phentsize = [System.BitConverter]::ToUInt16($bytes, 0x36)
    $phnum = [System.BitConverter]::ToUInt16($bytes, 0x38)
    for ($i = 0; $i -lt $phnum; $i++) {
        $type = [System.BitConverter]::ToUInt32($bytes, [int]($phoff + $i * $phentsize))
        if ($type -eq 3) {
            # PT_INTERP: a dynamic loader is required -> not static.
            return $false
        }
    }
    $true
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$manifestPath = Join-Path $repositoryRoot "packaging/assets/ffuf.toml"
$manifest = Get-Content -LiteralPath $manifestPath -Raw

$version = [regex]::Match($manifest, '(?m)^version\s*=\s*"(?<value>[^"]+)"').Groups["value"].Value
$archive = Read-ManifestField -Section $Platform -Field "archive" -Manifest $manifest
$url = Read-ManifestField -Section $Platform -Field "url" -Manifest $manifest
$expectedHash = (Read-ManifestField -Section $Platform -Field "sha256" -Manifest $manifest).ToLowerInvariant()
$binary = Read-ManifestField -Section $Platform -Field "binary" -Manifest $manifest
if ($expectedHash -notmatch '^[0-9a-f]{64}$') {
    throw "ffuf manifest [$Platform] is not release-pinned."
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot "target/packaging/ffuf-$Platform"
}
if (-not $CacheDirectory) {
    $CacheDirectory = Join-Path $repositoryRoot "target/packaging-cache"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CacheDirectory = [System.IO.Path]::GetFullPath($CacheDirectory)
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null

$cacheArchive = Join-Path $CacheDirectory "ffuf-$version-$Platform-$archive"
$validCache = (Test-Path -LiteralPath $cacheArchive -PathType Leaf) -and ((Get-FileHash -LiteralPath $cacheArchive -Algorithm SHA256).Hash -ieq $expectedHash)
if (-not $validCache) {
    if (Test-Path -LiteralPath $cacheArchive) {
        Remove-Item -LiteralPath $cacheArchive -Force
    }
    Write-Host "Downloading ffuf $version ($Platform)..."
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $cacheArchive
}
$actualHash = (Get-FileHash -LiteralPath $cacheArchive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "ffuf archive hash mismatch. Expected $expectedHash; got $actualHash."
}

$extractDirectory = Join-Path $CacheDirectory "ffuf-$version-$Platform-extract"
Reset-OwnedDirectory -Path $extractDirectory
if ($archive.ToLowerInvariant().EndsWith(".zip")) {
    Expand-Archive -LiteralPath $cacheArchive -DestinationPath $extractDirectory -Force
}
else {
    & tar -xzf $cacheArchive -C $extractDirectory
    if ($LASTEXITCODE -ne 0) { throw "tar failed to extract $cacheArchive." }
}
$extractedBinary = Join-Path $extractDirectory $binary
if (-not (Test-Path -LiteralPath $extractedBinary -PathType Leaf)) {
    throw "ffuf archive did not contain $binary."
}

# The Linux binary must be a fully static ELF (CGO disabled): no dynamic loader.
if ($Platform -eq "linux_x64" -and -not (Test-StaticElf -Path $extractedBinary)) {
    throw "ffuf Linux binary is dynamically linked; a static (CGO_ENABLED=0) build is required."
}

Reset-OwnedDirectory -Path $OutputDirectory
Copy-Item -LiteralPath $extractedBinary -Destination (Join-Path $OutputDirectory $binary)
$license = Join-Path $extractDirectory "LICENSE"
if (Test-Path -LiteralPath $license -PathType Leaf) {
    Copy-Item -LiteralPath $license -Destination (Join-Path $OutputDirectory "LICENSE")
}
Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging/assets/ffuf-NOTICES.md") -Destination (Join-Path $OutputDirectory "APIaxess-NOTICES.md")

$files = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse |
        Where-Object { $_.Name -notin @("ffuf-sbom.json") } |
        ForEach-Object {
            [ordered]@{
                path   = Get-RelativePath -Base $OutputDirectory -Full $_.FullName
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                size   = $_.Length
            }
        }
)
$sbom = [ordered]@{
    schemaVersion = 1
    component     = "APIaxess bundled ffuf"
    source        = "ffuf-official-release"
    platform      = $Platform
    version       = $version
    archive       = $archive
    archiveSha256 = $expectedHash
    license       = "MIT"
    files         = $files
} | ConvertTo-Json -Depth 5
Write-Utf8NoBom -Path (Join-Path $OutputDirectory "ffuf-sbom.json") -Content $sbom

Write-Host "Verified ffuf $version ($Platform) at $OutputDirectory"
