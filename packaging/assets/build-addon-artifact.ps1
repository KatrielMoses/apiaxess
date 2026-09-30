[CmdletBinding()]
param(
    # The add-on to package.
    [Parameter(Mandatory)] [ValidateSet("analysis-runtime", "android-target")] [string]$Slug,
    [Parameter(Mandatory)] [ValidateSet("windows_x64", "linux_x64")] [string]$Platform,
    # The website tree the artifact is written into (served at https://apiaxess.dev/).
    [Parameter(Mandatory)] [string]$SiteRoot,
    # An already-assembled payload (the output of fetch-<slug>.ps1). When
    # omitted, fetch-<slug>.ps1 assembles a fresh one first.
    [string]$PayloadDirectory,
    # Passed through to fetch-<slug>.ps1 (download cache, the bundled JDK).
    [string]$CacheDirectory,
    [string]$JavaHome,
    # zstd level; 19 is slow to build but smallest to host and download.
    [ValidateRange(1, 22)] [int]$Level = 19
)

# Packages one optional add-on into the single artifact the app downloads:
#   <SiteRoot>/assets/<slug>/<version>/<slug>-<platform>.tar.zst
# plus <file>.sha256 and <file>.json (sizes), which update-asset-catalog.ps1
# turns into assets/index.json. The upstream parts (Google's sdkmanager
# packages, frida-server, ws-scrcpy, Node) are pulled here, on the build
# machine, from the pins in <slug>.toml; the app itself only ever downloads the
# finished artifact from apiaxess.dev.
#
# The archive holds the payload root's contents (emulator/, platform-tools/,
# avd/, ...). Anything a used emulator writes (userdata, snapshots, locks, adb
# keys) is left out, so even a payload that has been booted packs clean; the
# emulator recreates it on first boot. The app rewrites the AVD's absolute
# `path=` for its install location.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$catalogPlatform = @{ windows_x64 = "windows-x64"; linux_x64 = "linux-amd64" }[$Platform]

if (-not $PayloadDirectory) {
    $PayloadDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "apiaxess-$Slug-$Platform-$([guid]::NewGuid().ToString('N'))"
    $fetchArgs = @{ Platform = $Platform; OutputDirectory = $PayloadDirectory }
    if ($CacheDirectory) { $fetchArgs.CacheDirectory = $CacheDirectory }
    if ($JavaHome) { $fetchArgs.JavaHome = $JavaHome }
    & (Join-Path $PSScriptRoot "fetch-$Slug.ps1") @fetchArgs
}
$payload = [System.IO.Path]::GetFullPath($PayloadDirectory)
$versionFile = Join-Path $payload "$Slug-version.txt"
if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
    throw "$payload is not an assembled $Slug payload ($Slug-version.txt is missing)."
}
$version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
if ($version -notmatch '^[0-9A-Za-z.\-+]+$') {
    throw "Unexpected $Slug version '$version'."
}

# Runtime state a booted emulator leaves behind. Inside an AVD only its
# config.ini is part of the payload.
$rootStatePatterns = @("adbkey", "adbkey.pub", "userid", "emu-*", "modem-nv-ram-*", "*.bak", "*.lock", "apiaxess-asset.json")
function Test-Excluded {
    param([string]$Relative)
    $parts = $Relative -split '/'
    if ($parts.Count -eq 1) {
        foreach ($pattern in $rootStatePatterns) { if ($parts[0] -like $pattern) { return $true } }
    }
    # avd/<name>.avd/<anything but config.ini>
    if ($parts.Count -ge 3 -and $parts[0] -eq "avd" -and $parts[1] -like "*.avd") {
        return -not ($parts.Count -eq 3 -and $parts[2] -eq "config.ini")
    }
    return $false
}

$entries = New-Object System.Collections.Generic.List[string]
$installedSize = [long]0
foreach ($item in Get-ChildItem -LiteralPath $payload -Recurse -Force) {
    $relative = [System.IO.Path]::GetRelativePath($payload, $item.FullName).Replace('\', '/')
    if (Test-Excluded $relative) { continue }
    $entries.Add($relative)
    if (-not $item.PSIsContainer) { $installedSize += $item.Length }
}
if (-not ($entries | Where-Object { $_ -like "avd/*.ini" })) {
    throw "$payload has no AVD pointer (avd/*.ini); it is not a bootable $Slug."
}

$outputDirectory = Join-Path $SiteRoot "assets/$Slug/$version"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$name = "$Slug-$catalogPlatform.tar.zst"
$artifact = Join-Path $outputDirectory $name
$list = Join-Path ([System.IO.Path]::GetTempPath()) "apiaxess-$Slug-files.txt"
# LF, no BOM: both bsdtar (Windows' tar.exe) and GNU tar read it as-is.
[System.IO.File]::WriteAllText($list, (($entries -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
$tar = if ($IsWindows) { Join-Path $env:SystemRoot "System32\tar.exe" } else { "tar" }
foreach ($stale in @($artifact, "$artifact.tar")) {
    if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
}
$zstd = Get-Command zstd -ErrorAction SilentlyContinue
if ($zstd) {
    # Plain tar, then the zstd CLI: multithreaded at the chosen level.
    & $tar -cf "$artifact.tar" -C $payload --no-recursion -T $list
    if ($LASTEXITCODE -ne 0) { throw "tar failed ($LASTEXITCODE)." }
    & $zstd.Source -q -f -T0 "-$Level" --rm "$artifact.tar" -o $artifact
    if ($LASTEXITCODE -ne 0) { throw "zstd failed ($LASTEXITCODE)." }
} elseif ($IsWindows) {
    # Windows' own tar.exe (bsdtar) carries libzstd.
    & $tar --zstd --options "zstd:compression-level=$Level" -cf $artifact -C $payload --no-recursion -T $list
    if ($LASTEXITCODE -ne 0) { throw "tar --zstd failed ($LASTEXITCODE)." }
} else {
    throw "zstd is required to package add-ons on this platform (apt install zstd)."
}
Remove-Item -LiteralPath $list -Force

$hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
$size = (Get-Item -LiteralPath $artifact).Length
[System.IO.File]::WriteAllText("$artifact.sha256", "$hash  $name`n", [System.Text.Encoding]::ASCII)
$meta = [ordered]@{ slug = $Slug; version = $version; platform = $catalogPlatform; sha256 = $hash; size = $size; installed_size = $installedSize }
[System.IO.File]::WriteAllText("$artifact.json", (($meta | ConvertTo-Json) -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "$Slug $version ($catalogPlatform) -> $artifact"
Write-Host ("  {0:N1} MB download, {1:N1} MB installed, {2} entries" -f ($size / 1MB), ($installedSize / 1MB), $entries.Count)
Write-Host "  sha256 $hash"
