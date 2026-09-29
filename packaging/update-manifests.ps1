[CmdletBinding()]
param(
    # SHA256SUMS produced by gen-checksums for the release being published.
    [Parameter(Mandatory)] [string]$Sums
)

# Points the Scoop manifest and the Chocolatey package at a release: version,
# asset URLs, and SHA-256 values all come from SHA256SUMS, so the manifests can
# only ever reference hashes that were published with the release.

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
