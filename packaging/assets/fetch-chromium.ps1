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
        throw "Chromium manifest section [$Section] is missing."
    }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) {
        throw "Chromium manifest field '$Field' is missing from [$Section]."
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

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$manifestPath = Join-Path $repositoryRoot "packaging\assets\chromium.toml"
$manifest = Get-Content -LiteralPath $manifestPath -Raw
$revision = Read-ManifestField -Section $Platform -Field "revision" -Manifest $manifest
$archive = Read-ManifestField -Section $Platform -Field "archive" -Manifest $manifest
$expectedHash = (Read-ManifestField -Section $Platform -Field "sha256" -Manifest $manifest).ToLowerInvariant()
if ($revision -notmatch '^\d+$' -or $expectedHash -notmatch '^[0-9a-f]{64}$') {
    throw "Chromium manifest [$Platform] is not release-pinned."
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot "target\packaging\chromium-$Platform"
}
if (-not $CacheDirectory) {
    $CacheDirectory = Join-Path $repositoryRoot "target\packaging-cache"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CacheDirectory = [System.IO.Path]::GetFullPath($CacheDirectory)
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null

$snapshotPlatform = if ($Platform -eq "windows_x64") { "Win_x64" } else { "Linux_x64" }
$cacheArchive = Join-Path $CacheDirectory "$Platform-$revision-$archive"
$snapshotUri = "https://commondatastorage.googleapis.com/chromium-browser-snapshots/$snapshotPlatform/$revision/$archive"
$validCache = (Test-Path -LiteralPath $cacheArchive -PathType Leaf) -and ((Get-FileHash -LiteralPath $cacheArchive -Algorithm SHA256).Hash -ieq $expectedHash)
if (-not $validCache) {
    if (Test-Path -LiteralPath $cacheArchive) {
        Remove-Item -LiteralPath $cacheArchive -Force
    }
    Write-Host "Downloading official Chromium snapshot $revision ($Platform)..."
    Invoke-WebRequest -UseBasicParsing -Uri $snapshotUri -OutFile $cacheArchive
}
$actualHash = (Get-FileHash -LiteralPath $cacheArchive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Chromium archive hash mismatch. Expected $expectedHash; got $actualHash."
}

$extractDirectory = Join-Path $CacheDirectory "$Platform-$revision-extract"
Reset-OwnedDirectory -Path $extractDirectory
Expand-Archive -LiteralPath $cacheArchive -DestinationPath $extractDirectory -Force
$payload = Get-ChildItem -LiteralPath $extractDirectory -Directory | Select-Object -First 1
if ($null -eq $payload) {
    throw "Chromium archive did not contain a top-level runtime directory."
}
$binaryName = if ($Platform -eq "windows_x64") { "chrome.exe" } else { "chrome" }
$binary = Join-Path $payload.FullName $binaryName
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Chromium archive did not contain $binaryName."
}

Reset-OwnedDirectory -Path $OutputDirectory
Get-ChildItem -LiteralPath $payload.FullName | Copy-Item -Destination $OutputDirectory -Recurse -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging\assets\chromium-NOTICES.md") -Destination (Join-Path $OutputDirectory "APIaxess-NOTICES.md")

$creditsPath = Join-Path $OutputDirectory "about-credits.html"
@"
<!doctype html>
<meta charset="utf-8">
<title>APIaxess Chromium credits pointer</title>
<p>This runtime is an unmodified official Chromium snapshot.</p>
<p>Open <code>chrome://credits/</code> in the bundled runtime for the
complete upstream component credits. The archive revision and SHA-256 are
recorded in <code>chromium-sbom.json</code>.</p>
"@ | Set-Content -LiteralPath $creditsPath -Encoding utf8

$files = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse |
        Where-Object { $_.Name -notin @("chromium-sbom.json") } |
        ForEach-Object {
            [ordered]@{
                path = [System.IO.Path]::GetRelativePath($OutputDirectory, $_.FullName)
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                size = $_.Length
            }
        }
)
[ordered]@{
    schemaVersion = 1
    component = "APIaxess bundled Chromium"
    source = "official-chromium-snapshots"
    platform = $Platform
    revision = $revision
    archive = $archive
    archiveSha256 = $expectedHash
    license = "BSD-3-Clause"
    files = $files
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory "chromium-sbom.json") -Encoding utf8NoBOM

Write-Host "Verified Chromium $revision ($Platform) at $OutputDirectory"
