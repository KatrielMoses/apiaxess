[CmdletBinding()]
param(
    # SHA256SUMS produced by gen-checksums for the release being published.
    [Parameter(Mandatory)] [string]$Sums,
    # Also write the in-app updater's release manifest (served at
    # https://apiaxess.dev/releases/latest.json) to this path.
    [string]$LatestJson,
    # The directory holding the release files, for the manifest's sizes.
    [string]$Artifacts,
    # One line on what changed, shown in the app's update notice.
    [string]$Summary = "",
    # The oldest version that may update to this release in place.
    [string]$MinSupported = "0.1.0",
    # The release date (YYYY-MM-DD); today when omitted.
    [string]$Released = (Get-Date -Format "yyyy-MM-dd"),
    # The website the updater's assets and notes are served from.
    [string]$SiteBase = "https://apiaxess.dev"
)

# Points the Scoop manifest and the Chocolatey package at a release: version,
# asset URLs, and SHA-256 values all come from SHA256SUMS, so the manifests can
# only ever reference hashes that were published with the release. With
# -LatestJson it also writes the updater's latest.json from the same values, so
# the Download page, the package managers and the app can never disagree.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$releaseBase = "https://github.com/KatrielMoses/apiaxess/releases/download"
$entries = @{}
foreach ($line in Get-Content -LiteralPath $Sums) {
    if ($line -match '^(?<hash>[0-9a-f]{64})\s+\*?(?<name>\S+)$') {
        $entries[$Matches.name] = $Matches.hash
    }
}

function Get-Asset {
    param([Parameter(Mandatory)] [string]$Pattern)
    $names = @($entries.Keys | Where-Object { $_ -match $Pattern })
    if ($names.Count -ne 1) {
        throw "Expected exactly one asset matching '$Pattern' in $Sums; found $($names.Count)."
    }
    [pscustomobject]@{ Name = $names[0]; Hash = $entries[$names[0]]; Version = [regex]::Match($names[0], $Pattern).Groups["version"].Value }
}

$zip = Get-Asset '^APIaxess-(?<version>\d+\.\d+\.\d+)-windows-x64-portable\.zip$'
$msi = Get-Asset '^APIaxess-(?<version>\d+\.\d+\.\d+)-windows-x64\.msi$'
if ($zip.Version -ne $msi.Version) {
    throw "Portable zip ($($zip.Version)) and MSI ($($msi.Version)) versions differ."
}
$version = $msi.Version

$scoopPath = Join-Path $PSScriptRoot "scoop\apiaxess.json"
# Targeted replacements keep the manifest's formatting, so a release bump is a
# three-line diff. The autoupdate block uses $version placeholders and a hash
# object, so only the pinned URL and the literal hash string match.
$scoop = Get-Content -LiteralPath $scoopPath -Raw
$scoop = $scoop -replace '"version": "[^"]*"', "`"version`": `"$version`""
$scoop = $scoop -replace '"url": "[^"$]*-portable\.zip"', "`"url`": `"$releaseBase/v$version/$($zip.Name)`""
$scoop = $scoop -replace '"hash": "[0-9a-f]{64}"', "`"hash`": `"$($zip.Hash)`""
[System.IO.File]::WriteAllText($scoopPath, $scoop)

$nuspecPath = Join-Path $PSScriptRoot "chocolatey\apiaxess.nuspec"
$nuspec = Get-Content -LiteralPath $nuspecPath -Raw
$nuspec = $nuspec -replace '<version>[^<]*</version>', "<version>$version</version>"
$nuspec = $nuspec -replace '/releases/tag/v[^<]*</releaseNotes>', "/releases/tag/v$version</releaseNotes>"
[System.IO.File]::WriteAllText($nuspecPath, $nuspec)

$installPath = Join-Path $PSScriptRoot "chocolatey\tools\chocolateyinstall.ps1"
$install = Get-Content -LiteralPath $installPath -Raw
$install = $install -replace "url64bit(\s+)= '[^']*'", "url64bit`$1= '$releaseBase/v$version/$($msi.Name)'"
$install = $install -replace "checksum64(\s+)= '[^']*'", "checksum64`$1= '$($msi.Hash)'"
[System.IO.File]::WriteAllText($installPath, $install)

Write-Host "Scoop + Chocolatey manifests now point at v$version"
Write-Host "  $($zip.Name)  $($zip.Hash)"
Write-Host "  $($msi.Name)  $($msi.Hash)"

if ($LatestJson) {
    if (-not $Artifacts) {
        throw "-LatestJson needs -Artifacts (the directory holding the release files) for their sizes."
    }
    $deb = Get-Asset '^apiaxess_(?<version>\d+\.\d+\.\d+)_amd64\.deb$'
    if ($deb.Version -ne $version) {
        throw "The .deb ($($deb.Version)) and MSI ($version) versions differ."
    }
    function Get-ManifestAsset {
        param([Parameter(Mandatory)] $Asset)
        $file = Join-Path $Artifacts $Asset.Name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "$($Asset.Name) is listed in $Sums but is not in $Artifacts."
        }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $Asset.Hash) {
            throw "$($Asset.Name) in $Artifacts does not match $Sums."
        }
        [ordered]@{
            url = "$SiteBase/dl/$version/$($Asset.Name)"
            sha256 = $Asset.Hash
            size = (Get-Item -LiteralPath $file).Length
        }
    }
    $manifest = [ordered]@{
        version = $version
        released = $Released
        notes_url = "$SiteBase/release-notes#$version"
        summary = $Summary
        min_supported = $MinSupported
        assets = [ordered]@{
            "windows-x64-msi" = Get-ManifestAsset $msi
            "windows-x64-zip" = Get-ManifestAsset $zip
            "linux-amd64-deb" = Get-ManifestAsset $deb
        }
    }
    # LF, no BOM, trailing newline. The signature (cargo xtask sign-manifest)
    # covers these exact bytes, so sign after writing and never re-save it.
    $json = ($manifest | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($LatestJson), "$json`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Release manifest for v$version written to $LatestJson"
    Write-Host "  $($deb.Name)  $($deb.Hash)"
}
