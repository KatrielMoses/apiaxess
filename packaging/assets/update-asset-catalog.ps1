[CmdletBinding()]
param(
    # The website tree build-addon-artifact.ps1 wrote into.
    [Parameter(Mandatory)] [string]$SiteRoot,
    # Pin the published version per add-on (slug=version). An add-on left out
    # publishes its most recently built version.
    [string[]]$Version = @(),
    # The site the artifact URLs are served from.
    [string]$SiteBase = "https://apiaxess.dev"
)

# Writes <SiteRoot>/assets/index.json, the catalog the app reads when the
# operator clicks Download, from the artifacts build-addon-artifact.ps1 wrote:
# URL, SHA-256, download size, and installed size per add-on and platform. Each
# artifact is re-hashed so the catalog can only name bytes that are really
# there. Sign the result afterwards (cargo xtask sign-manifest <key> index.json)
# once the release key exists; never re-save it after signing.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$descriptions = [ordered]@{
    "analysis-runtime" = @{ name = "Android analysis runtime"; purpose = "Dynamic APK analysis (emulator + Android image + frida-server)" }
    "android-target"   = @{ name = "Android target (drivable device)"; purpose = "In-app Android capture: a device you drive, log in to, and capture" }
}
$pinned = @{}
foreach ($pin in $Version) {
    $slug, $value = $pin -split '=', 2
    if (-not $descriptions.Contains($slug) -or -not $value) { throw "Bad -Version '$pin' (use slug=version)." }
    $pinned[$slug] = $value
}

$assets = [ordered]@{}
foreach ($slug in $descriptions.Keys) {
    $slugRoot = Join-Path $SiteRoot "assets/$slug"
    $metas = @(Get-ChildItem -LiteralPath $slugRoot -Recurse -Filter "*.tar.zst.json" -ErrorAction SilentlyContinue)
    if ($metas.Count -eq 0) { Write-Host "  ${slug}: no artifacts built; left out"; continue }
    $chosen = if ($pinned.ContainsKey($slug)) { $pinned[$slug] } else {
        $newest = $metas | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        (Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json).version
    }
    $platforms = [ordered]@{}
    foreach ($meta in $metas | Sort-Object Name) {
        $record = Get-Content -LiteralPath $meta.FullName -Raw | ConvertFrom-Json
        if ($record.version -ne $chosen) { continue }
        $artifact = $meta.FullName.Substring(0, $meta.FullName.Length - ".json".Length)
        $actual = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $record.sha256) { throw "$artifact does not match its recorded SHA-256; rebuild it." }
        $platforms[$record.platform] = [ordered]@{
            url = "$SiteBase/assets/$slug/$chosen/$([System.IO.Path]::GetFileName($artifact))"
            sha256 = $record.sha256
            size = [long]$record.size
            installed_size = [long]$record.installed_size
        }
    }
    if ($platforms.Count -eq 0) { throw "No $slug artifacts for version $chosen." }
    $assets[$slug] = [ordered]@{
        name = $descriptions[$slug].name
        purpose = $descriptions[$slug].purpose
        version = $chosen
        platforms = $platforms
    }
    Write-Host "  ${slug} ${chosen}: $(@($platforms.Keys) -join ', ')"
}

$index = Join-Path $SiteRoot "assets/index.json"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $index) | Out-Null
$json = ([ordered]@{ assets = $assets } | ConvertTo-Json -Depth 6) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($index), "$json`n", [System.Text.UTF8Encoding]::new($false))
Write-Host "Add-on catalog written to $index"
