<#
.SYNOPSIS
    Builds the bundled, trimmed OpenJDK runtime for one platform.

.DESCRIPTION
    Downloads the pinned Eclipse Temurin JDK named in java-runtime.toml,
    verifies its SHA-256, and runs that JDK's own jlink to produce a trimmed
    runtime image containing only the modules apktool and jadx need. The image
    ships with the legal/ notices jlink emits (unmodified-upstream posture) and
    an SBOM.

    jlink cannot cross-compile: run this on Windows with -Platform windows_x64
    and on Linux with -Platform linux_x64. Mirrors fetch-chromium.ps1 so the
    Phase 12 installers assemble every bundled runtime the same way.
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
        throw "java-runtime manifest section [$Section] is missing."
    }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) {
        throw "java-runtime manifest field '$Field' is missing from [$Section]."
    }
    $fieldMatch.Groups["value"].Value
}

function Read-TopLevelArray {
    param(
        [Parameter(Mandatory)] [string]$Field,
        [Parameter(Mandatory)] [string]$Manifest
    )
    # Top-level arrays live above the first [section]. Restrict the search so a
    # same-named per-platform value can never be picked up by accident.
    $preamble = [regex]::Match($Manifest, '(?ms)\A(?<body>.*?)(?=^\[)').Groups["body"].Value
    $arrayPattern = '(?ms)^' + [regex]::Escape($Field) + '\s*=\s*\[(?<body>.*?)\]'
    $arrayMatch = [regex]::Match($preamble, $arrayPattern)
    if (-not $arrayMatch.Success) {
        throw "java-runtime manifest array '$Field' is missing."
    }
    [regex]::Matches($arrayMatch.Groups["body"].Value, '"(?<value>[^"]+)"') |
        ForEach-Object { $_.Groups["value"].Value }
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

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$manifestPath = Join-Path $repositoryRoot "packaging/assets/java-runtime.toml"
$manifest = Get-Content -LiteralPath $manifestPath -Raw

$release = [regex]::Match($manifest, '(?m)^release\s*=\s*"(?<value>[^"]+)"').Groups["value"].Value
$archive = Read-ManifestField -Section $Platform -Field "archive" -Manifest $manifest
$url = Read-ManifestField -Section $Platform -Field "url" -Manifest $manifest
$expectedHash = (Read-ManifestField -Section $Platform -Field "sha256" -Manifest $manifest).ToLowerInvariant()
if ($expectedHash -notmatch '^[0-9a-f]{64}$') {
    throw "java-runtime manifest [$Platform] is not release-pinned."
}
$modules = @(Read-TopLevelArray -Field "modules" -Manifest $manifest)
$jlinkFlags = @(Read-TopLevelArray -Field "jlink_flags" -Manifest $manifest)
if ($modules.Count -eq 0) {
    throw "java-runtime manifest lists no modules."
}

# jlink cannot cross-compile; refuse a Linux image on Windows and vice versa so
# a broken cross-built runtime never reaches an installer. `$IsWindows` only
# exists in PowerShell 7+, so fall back to the host OS on Windows PowerShell 5.1.
$isWindowsPlatform = ($Platform -eq "windows_x64")
$runningOnWindows = if (Test-Path Variable:\IsWindows) { $IsWindows } else { $true }
if ($isWindowsPlatform -ne $runningOnWindows) {
    throw "jlink cannot cross-compile: build $Platform on its own operating system."
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot "target/packaging/java-runtime-$Platform"
}
if (-not $CacheDirectory) {
    $CacheDirectory = Join-Path $repositoryRoot "target/packaging-cache"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CacheDirectory = [System.IO.Path]::GetFullPath($CacheDirectory)
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null

$cacheArchive = Join-Path $CacheDirectory "$Platform-$release-$archive"
$validCache = (Test-Path -LiteralPath $cacheArchive -PathType Leaf) -and ((Get-FileHash -LiteralPath $cacheArchive -Algorithm SHA256).Hash -ieq $expectedHash)
if (-not $validCache) {
    if (Test-Path -LiteralPath $cacheArchive) {
        Remove-Item -LiteralPath $cacheArchive -Force
    }
    Write-Host "Downloading Temurin $release ($Platform)..."
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $cacheArchive
}
$actualHash = (Get-FileHash -LiteralPath $cacheArchive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Temurin archive hash mismatch. Expected $expectedHash; got $actualHash."
}

$extractDirectory = Join-Path $CacheDirectory "$Platform-$release-jdk"
Reset-OwnedDirectory -Path $extractDirectory
if ($archive.ToLowerInvariant().EndsWith(".zip")) {
    Expand-Archive -LiteralPath $cacheArchive -DestinationPath $extractDirectory -Force
}
else {
    & tar -xzf $cacheArchive -C $extractDirectory
    if ($LASTEXITCODE -ne 0) { throw "tar failed to extract $cacheArchive." }
}
$jdkHome = Get-ChildItem -LiteralPath $extractDirectory -Directory | Select-Object -First 1
if ($null -eq $jdkHome) {
    throw "Temurin archive did not contain a top-level JDK directory."
}
$jlinkName = if ($isWindowsPlatform) { "jlink.exe" } else { "jlink" }
$jlink = Join-Path (Join-Path $jdkHome.FullName "bin") $jlinkName
if (-not (Test-Path -LiteralPath $jlink -PathType Leaf)) {
    throw "Temurin archive did not contain $jlinkName; a JRE was downloaded instead of a JDK."
}

Reset-OwnedDirectory -Path $OutputDirectory
# jlink requires the output directory to NOT exist.
Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
$jlinkArgs = @("--add-modules", ($modules -join ",")) + $jlinkFlags + @("--output", $OutputDirectory)
Write-Host "jlink: trimming $($modules.Count) modules into $OutputDirectory"
& $jlink @jlinkArgs
if ($LASTEXITCODE -ne 0) { throw "jlink failed with exit code $LASTEXITCODE." }

$binaryName = if ($isWindowsPlatform) { "java.exe" } else { "java" }
$javaBinary = Join-Path (Join-Path $OutputDirectory "bin") $binaryName
if (-not (Test-Path -LiteralPath $javaBinary -PathType Leaf)) {
    throw "Trimmed runtime is missing bin/$binaryName."
}

Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging/assets/java-runtime-NOTICES.md") -Destination (Join-Path $OutputDirectory "APIaxess-NOTICES.md")

$files = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse |
        Where-Object { $_.Name -notin @("java-runtime-sbom.json") } |
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
    component     = "APIaxess shared Java runtime"
    source        = "eclipse-temurin"
    platform      = $Platform
    release       = $release
    archive       = $archive
    archiveSha256 = $expectedHash
    license       = "GPL-2.0-with-classpath-exception"
    modules       = $modules
    jlinkFlags    = $jlinkFlags
    files         = $files
} | ConvertTo-Json -Depth 5
Write-Utf8NoBom -Path (Join-Path $OutputDirectory "java-runtime-sbom.json") -Content $sbom

Write-Host "Verified trimmed Temurin $release ($Platform) at $OutputDirectory"
