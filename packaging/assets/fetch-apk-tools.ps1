<#
.SYNOPSIS
    Acquires the bundled apktool jar and jadx distribution.

.DESCRIPTION
    Downloads the pinned apktool jar and jadx distribution named in
    apk-tools.toml, verifies their SHA-256, lays them out under
    tools/apktool/ and tools/jadx/, copies the upstream NOTICE/LICENSE files
    that travel with the payload, and writes an SBOM.

    The payload is platform-independent: apktool bundles its own per-OS native
    aapt/aapt2 inside its jar and jadx is pure Java. Both run through the shared
    trimmed OpenJDK runtime (see fetch-java-runtime.ps1). Mirrors
    fetch-chromium.ps1 so Phase 12 installers assemble it the same way.
#>
[CmdletBinding()]
param(
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
        throw "apk-tools manifest section [$Section] is missing."
    }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) {
        throw "apk-tools manifest field '$Field' is missing from [$Section]."
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

function Get-VerifiedArchive {
    param(
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$ExpectedHash,
        [Parameter(Mandatory)] [string]$CachePath,
        [Parameter(Mandatory)] [string]$Label
    )
    $validCache = (Test-Path -LiteralPath $CachePath -PathType Leaf) -and ((Get-FileHash -LiteralPath $CachePath -Algorithm SHA256).Hash -ieq $ExpectedHash)
    if (-not $validCache) {
        if (Test-Path -LiteralPath $CachePath) {
            Remove-Item -LiteralPath $CachePath -Force
        }
        Write-Host "Downloading $Label..."
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $CachePath
    }
    $actualHash = (Get-FileHash -LiteralPath $CachePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $ExpectedHash) {
        throw "$Label hash mismatch. Expected $ExpectedHash; got $actualHash."
    }
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$manifestPath = Join-Path $repositoryRoot "packaging/assets/apk-tools.toml"
$manifest = Get-Content -LiteralPath $manifestPath -Raw

$apktoolVersion = Read-ManifestField -Section "apktool" -Field "version" -Manifest $manifest
$apktoolUrl = Read-ManifestField -Section "apktool" -Field "url" -Manifest $manifest
$apktoolHash = (Read-ManifestField -Section "apktool" -Field "sha256" -Manifest $manifest).ToLowerInvariant()
$jadxVersion = Read-ManifestField -Section "jadx" -Field "version" -Manifest $manifest
$jadxUrl = Read-ManifestField -Section "jadx" -Field "url" -Manifest $manifest
$jadxHash = (Read-ManifestField -Section "jadx" -Field "sha256" -Manifest $manifest).ToLowerInvariant()
if ($apktoolHash -notmatch '^[0-9a-f]{64}$' -or $jadxHash -notmatch '^[0-9a-f]{64}$') {
    throw "apk-tools manifest is not release-pinned."
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot "target/packaging/apk-tools"
}
if (-not $CacheDirectory) {
    $CacheDirectory = Join-Path $repositoryRoot "target/packaging-cache"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CacheDirectory = [System.IO.Path]::GetFullPath($CacheDirectory)
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
Reset-OwnedDirectory -Path $OutputDirectory

# --- apktool: a single executable jar ---
$apktoolCache = Join-Path $CacheDirectory "apktool-$apktoolVersion.jar"
Get-VerifiedArchive -Url $apktoolUrl -ExpectedHash $apktoolHash -CachePath $apktoolCache -Label "apktool $apktoolVersion"
$apktoolDir = Join-Path $OutputDirectory "apktool"
New-Item -ItemType Directory -Path $apktoolDir -Force | Out-Null
Copy-Item -LiteralPath $apktoolCache -Destination (Join-Path $apktoolDir "apktool.jar")

# --- jadx: an extracted distribution (bin/ + lib/ + LICENSE) ---
$jadxCache = Join-Path $CacheDirectory "jadx-$jadxVersion.zip"
Get-VerifiedArchive -Url $jadxUrl -ExpectedHash $jadxHash -CachePath $jadxCache -Label "jadx $jadxVersion"
$jadxExtract = Join-Path $CacheDirectory "jadx-$jadxVersion-extract"
Reset-OwnedDirectory -Path $jadxExtract
Expand-Archive -LiteralPath $jadxCache -DestinationPath $jadxExtract -Force
# jadx zips extract directly to bin/ + lib/ (no wrapping directory); normalize
# either shape into tools/jadx.
$jadxRoot = if (Test-Path -LiteralPath (Join-Path $jadxExtract "lib")) {
    $jadxExtract
}
else {
    (Get-ChildItem -LiteralPath $jadxExtract -Directory | Select-Object -First 1).FullName
}
if ($null -eq $jadxRoot -or -not (Test-Path -LiteralPath (Join-Path $jadxRoot "lib"))) {
    throw "jadx archive did not contain a lib/ directory."
}
$allJar = Get-ChildItem -LiteralPath (Join-Path $jadxRoot "lib") -Filter "*-all.jar" | Select-Object -First 1
if ($null -eq $allJar) {
    throw "jadx distribution did not contain a *-all.jar classpath jar."
}
$jadxDir = Join-Path $OutputDirectory "jadx"
New-Item -ItemType Directory -Path $jadxDir -Force | Out-Null
Get-ChildItem -LiteralPath $jadxRoot | Copy-Item -Destination $jadxDir -Recurse -Force

Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging/assets/apk-tools-NOTICES.md") -Destination (Join-Path $OutputDirectory "APIaxess-NOTICES.md")

$files = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse |
        Where-Object { $_.Name -notin @("apk-tools-sbom.json") } |
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
    component     = "APIaxess bundled Android tools"
    components    = @(
        [ordered]@{ tool = "apktool"; version = $apktoolVersion; archiveSha256 = $apktoolHash; license = "Apache-2.0" }
        [ordered]@{ tool = "jadx"; version = $jadxVersion; archiveSha256 = $jadxHash; license = "Apache-2.0 AND mixed-distributed-dependency-notices" }
    )
    files         = $files
} | ConvertTo-Json -Depth 6
Write-Utf8NoBom -Path (Join-Path $OutputDirectory "apk-tools-sbom.json") -Content $sbom

Write-Host "Verified apktool $apktoolVersion + jadx $jadxVersion at $OutputDirectory"
