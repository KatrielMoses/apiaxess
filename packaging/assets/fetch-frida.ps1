<#
.SYNOPSIS
    Acquires the bundled Frida artifacts: host frida-core devkit + device-side
    frida-server (Phase 11.4).

.DESCRIPTION
    Downloads the pinned frida-core devkit for one host platform (linked into the
    Rust backend when the `frida-embedded` feature is on) and the device-side
    frida-server for the requested Android ABIs (baked into the owned image),
    verifies every SHA-256 against frida.toml, extracts them into the bundled
    layout, ships the wxWindows license/notice, and emits an SBOM.

    Frida is wxWindows Licence 3.1 (static-link exception). Unmodified upstream.

    Mirrors fetch-ffuf.ps1 / fetch-java-runtime.ps1. Requires `tar` (for the
    .tar.xz devkit) and an xz decompressor (`xz`, `7z`, or python3 `lzma`) for
    the single-file .xz frida-server.
#>
[CmdletBinding()]
param(
    [ValidateSet("windows_x64", "linux_x64")]
    [string]$Platform = "windows_x64",
    [string[]]$Abis = @("android_x86_64", "android_arm64"),
    [string]$OutputDirectory,
    [string]$CacheDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-ManifestField {
    param([Parameter(Mandatory)] [string]$Section, [Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*(?<body>.*?)(?=^\[|\z)'
    $sectionMatch = [regex]::Match($Manifest, $sectionPattern)
    if (-not $sectionMatch.Success) { throw "frida manifest section [$Section] is missing." }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) { throw "frida manifest field '$Field' is missing from [$Section]." }
    $fieldMatch.Groups["value"].Value
}
function Reset-OwnedDirectory {
    param([Parameter(Mandatory)] [string]$Path)
    $absolute = [System.IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
    New-Item -ItemType Directory -Path $absolute -Force | Out-Null
}
function Get-RelativePath {
    param([Parameter(Mandatory)] [string]$Base, [Parameter(Mandatory)] [string]$Full)
    $baseUri = New-Object System.Uri(($Base.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar))
    ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri((New-Object System.Uri($Full))).ToString())) -replace '/', [System.IO.Path]::DirectorySeparatorChar
}
function Write-Utf8NoBom {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}
function Get-Verified {
    param([Parameter(Mandatory)] [string]$Url, [Parameter(Mandatory)] [string]$ExpectedHash, [Parameter(Mandatory)] [string]$CachePath, [Parameter(Mandatory)] [string]$Label)
    $valid = (Test-Path -LiteralPath $CachePath -PathType Leaf) -and ((Get-FileHash -LiteralPath $CachePath -Algorithm SHA256).Hash -ieq $ExpectedHash)
    if (-not $valid) {
        if (Test-Path -LiteralPath $CachePath) { Remove-Item -LiteralPath $CachePath -Force }
        Write-Host "Downloading $Label..."
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $CachePath
    }
    $actual = (Get-FileHash -LiteralPath $CachePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedHash) { throw "$Label hash mismatch. Expected $ExpectedHash; got $actual." }
}
function Expand-Xz {
    param([Parameter(Mandatory)] [string]$Source, [Parameter(Mandatory)] [string]$Destination)
    if (Get-Command xz -ErrorAction SilentlyContinue) {
        # Decompress straight to the destination through the raw process stream.
        # PowerShell 7 removed `Set-Content -Encoding Byte` (5.1-only), and piping
        # a native command's binary stdout through the PS pipeline corrupts it
        # (line/encoding translation). Copy the base stream to stay binary-safe on
        # both Windows PowerShell 5.1 and PowerShell 7.
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = "xz"
        $psi.ArgumentList.Add("-dc")
        $psi.ArgumentList.Add($Source)
        $psi.RedirectStandardOutput = $true
        $psi.UseShellExecute = $false
        $process = [System.Diagnostics.Process]::Start($psi)
        $fileStream = [System.IO.File]::Create($Destination)
        try {
            $process.StandardOutput.BaseStream.CopyTo($fileStream)
        }
        finally {
            $fileStream.Dispose()
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "xz failed to decompress $Source." }
    }
    elseif (Get-Command 7z.exe -ErrorAction SilentlyContinue) {
        # Frida publishes the server as a raw .xz, not a tar.xz archive.
        # Windows tar can only unpack the latter; 7-Zip handles the raw stream
        # and is the preferred Windows fallback where an xz binary is absent.
        $temporary = Join-Path ([System.IO.Path]::GetDirectoryName($Destination)) (".xz-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $temporary -Force | Out-Null
        try {
            & 7z.exe x -y ("-o" + $temporary) $Source | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "7z failed to decompress $Source." }
            $expanded = Join-Path $temporary ([System.IO.Path]::GetFileNameWithoutExtension($Source))
            if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
                throw "tar did not produce the expected xz member $expanded."
            }
            Move-Item -LiteralPath $expanded -Destination $Destination -Force
        }
        finally {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
        }
    }
    elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        & python3 -c "import lzma,sys; open(sys.argv[2],'wb').write(lzma.open(sys.argv[1]).read())" $Source $Destination
        if ($LASTEXITCODE -ne 0) { throw "python lzma failed to decompress $Source." }
    }
    else {
        throw "No xz decompressor found (need xz, 7z, or Python lzma) for $Source."
    }
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$manifest = Get-Content -LiteralPath (Join-Path $repositoryRoot "packaging/assets/frida.toml") -Raw
$version = [regex]::Match($manifest, '(?m)^version\s*=\s*"(?<value>[^"]+)"').Groups["value"].Value

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repositoryRoot "target/packaging/frida" }
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $repositoryRoot "target/packaging-cache" }
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CacheDirectory = [System.IO.Path]::GetFullPath($CacheDirectory)
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
Reset-OwnedDirectory -Path $OutputDirectory

# --- Host frida-core devkit ---
$devArchive = Read-ManifestField -Section "devkit.$Platform" -Field "archive" -Manifest $manifest
$devUrl = Read-ManifestField -Section "devkit.$Platform" -Field "url" -Manifest $manifest
$devHash = (Read-ManifestField -Section "devkit.$Platform" -Field "sha256" -Manifest $manifest).ToLowerInvariant()
$devInstall = Read-ManifestField -Section "devkit.$Platform" -Field "install_path" -Manifest $manifest
$devCache = Join-Path $CacheDirectory "frida-$version-$devArchive"
Get-Verified -Url $devUrl -ExpectedHash $devHash -CachePath $devCache -Label "frida-core devkit ($Platform)"
$devOut = Join-Path $OutputDirectory ($devInstall -replace '^frida/', '')
New-Item -ItemType Directory -Path $devOut -Force | Out-Null
& tar -xf $devCache -C $devOut
if ($LASTEXITCODE -ne 0) { throw "tar failed to extract the frida devkit." }

# --- Device-side frida-server per ABI ---
foreach ($abi in $Abis) {
    $srvArchive = Read-ManifestField -Section "server.$abi" -Field "archive" -Manifest $manifest
    $srvUrl = Read-ManifestField -Section "server.$abi" -Field "url" -Manifest $manifest
    $srvHash = (Read-ManifestField -Section "server.$abi" -Field "sha256" -Manifest $manifest).ToLowerInvariant()
    $srvInstall = Read-ManifestField -Section "server.$abi" -Field "install_path" -Manifest $manifest
    $srvCache = Join-Path $CacheDirectory "frida-$version-$srvArchive"
    Get-Verified -Url $srvUrl -ExpectedHash $srvHash -CachePath $srvCache -Label "frida-server ($abi)"
    $srvOut = Join-Path $OutputDirectory ($srvInstall -replace '^frida/', '')
    New-Item -ItemType Directory -Path (Split-Path -Parent $srvOut) -Force | Out-Null
    Expand-Xz -Source $srvCache -Destination $srvOut
}

Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging/assets/frida-NOTICES.md") -Destination (Join-Path $OutputDirectory "APIaxess-NOTICES.md")

$files = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse |
        Where-Object { $_.Name -notin @("frida-sbom.json") } |
        ForEach-Object {
            [ordered]@{ path = Get-RelativePath -Base $OutputDirectory -Full $_.FullName; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size = $_.Length }
        }
)
$sbom = [ordered]@{
    schemaVersion = 1
    component     = "APIaxess bundled Frida"
    source        = "frida-official-release"
    version       = $version
    hostPlatform  = $Platform
    abis          = $Abis
    license       = "wxWindows-3.1"
    files         = $files
} | ConvertTo-Json -Depth 6
Write-Utf8NoBom -Path (Join-Path $OutputDirectory "frida-sbom.json") -Content $sbom
Write-Host "Verified Frida $version (devkit=$Platform, servers=$($Abis -join ',')) at $OutputDirectory"
