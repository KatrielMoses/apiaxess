<#
.SYNOPSIS
    Assembles the bundled analysis runtime: SDK emulator engine + owned
    Android-10 AOSP image + owned AVD + device-side frida-server (Phase 11.5).

.DESCRIPTION
    Bootstraps the Android command-line tools, uses `sdkmanager` to install the
    pinned emulator, platform-tools, and the pure-AOSP `default` (NO GMS) API-29
    system image into the runtime root (which doubles as ANDROID_SDK_ROOT),
    creates the owned Android-10 AVD, stages the device-side frida-server data
    files, and emits the payload SBOM, notices, provenance, and version. This is
    the separate, optional ~2 GB dynamic-analysis payload — not the base install.

    Advanced image path: pass -SystemImage "system-images;android-<N>;default;
    x86_64" (or an Android-x86 image) to acquire a different public API level for
    your own use; the owned Android-10 `default` image is the verified default.

    sdkmanager verifies every package against Google's signed repository
    manifest. It is a Java application: pass -JavaHome, or the script uses the
    bundled Java runtime from Phase 11.1 if present.

    Boot-time provisioning (session CA install via -writable-system, agent load,
    and a clean baseline snapshot) is applied by the engine on first boot; the
    frida-server is staged here as a bundled data file pushed to the guest.
#>
[CmdletBinding()]
param(
    [ValidateSet("windows_x64", "linux_x64")]
    [string]$Platform = "windows_x64",
    [string]$SystemImage,
    [string]$JavaHome,
    [string]$OutputDirectory,
    [string]$CacheDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-ManifestField {
    param([Parameter(Mandatory)] [string]$Section, [Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*(?<body>.*?)(?=^\[|\z)'
    $sectionMatch = [regex]::Match($Manifest, $sectionPattern)
    if (-not $sectionMatch.Success) { throw "analysis-runtime manifest section [$Section] is missing." }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) { throw "analysis-runtime manifest field '$Field' is missing from [$Section]." }
    $fieldMatch.Groups["value"].Value
}
function Read-TopField {
    param([Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    $preamble = [regex]::Match($Manifest, '(?ms)\A(?<body>.*?)(?=^\[)').Groups["body"].Value
    [regex]::Match($preamble, '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"').Groups["value"].Value
}
function Write-Utf8NoBom {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$manifest = Get-Content -LiteralPath (Join-Path $repositoryRoot "packaging/assets/analysis-runtime.toml") -Raw
$payloadVersion = Read-TopField -Field "payload_version" -Manifest $manifest
$avdName = Read-TopField -Field "owned_avd_name" -Manifest $manifest
if (-not $SystemImage) { $SystemImage = Read-ManifestField -Section "sdk_packages" -Field "system_image" -Manifest $manifest }
$emulatorPkg = Read-ManifestField -Section "sdk_packages" -Field "emulator" -Manifest $manifest
$platformToolsPkg = Read-ManifestField -Section "sdk_packages" -Field "platform_tools" -Manifest $manifest
$cmdToolsUrl = Read-ManifestField -Section "cmdline_tools.$Platform" -Field "url" -Manifest $manifest

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repositoryRoot "target/packaging/analysis-runtime-$Platform" }
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $repositoryRoot "target/packaging-cache" }
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CacheDirectory = [System.IO.Path]::GetFullPath($CacheDirectory)
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null

# Resolve a Java runtime for sdkmanager (prefer the Phase 11.1 bundled runtime).
if (-not $JavaHome) {
    $candidate = Join-Path $repositoryRoot "target/packaging/java-runtime-$Platform"
    if (Test-Path -LiteralPath (Join-Path $candidate "bin")) { $JavaHome = $candidate }
}
if ($JavaHome) { $env:JAVA_HOME = [System.IO.Path]::GetFullPath($JavaHome) }
# Android's Windows wrappers invoke system commands such as `findstr` by name.
# Codex's shell can inherit a reduced PATH, so restore the canonical Windows
# system directory before invoking those wrappers. Windows-only: on Linux
# $env:SystemRoot is unset, and the SDK uses POSIX shell wrappers instead.
if ($env:SystemRoot) {
    $system32 = Join-Path $env:SystemRoot "System32"
    if ((Test-Path -LiteralPath $system32) -and -not (($env:PATH -split ';') -contains $system32)) {
        $env:PATH = "$system32;$env:PATH"
    }
}
# sdkmanager/avdmanager's .bat wrappers verify the JDK version by piping
# `java -version` through `findstr`. In a minimal-PATH host shell findstr may not
# resolve, which makes the check abort with a false "Java version 17 or higher is
# required" even though the bundled runtime is JDK 21. We control and pin that
# runtime, so the check is redundant — skip it deterministically.
$env:SKIP_JDK_VERSION_CHECK = "1"

# --- Bootstrap command-line tools ---
$cmdZip = Join-Path $CacheDirectory ([System.IO.Path]::GetFileName(($cmdToolsUrl -split '\?')[0]))
if (-not (Test-Path -LiteralPath $cmdZip)) {
    Write-Host "Downloading Android command-line tools ($Platform)..."
    Invoke-WebRequest -UseBasicParsing -Uri $cmdToolsUrl -OutFile $cmdZip
}
$sdkRoot = $OutputDirectory
if (Test-Path -LiteralPath $sdkRoot) { Remove-Item -LiteralPath $sdkRoot -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $sdkRoot "cmdline-tools") -Force | Out-Null
Expand-Archive -LiteralPath $cmdZip -DestinationPath (Join-Path $sdkRoot "cmdline-tools") -Force
# sdkmanager expects cmdline-tools/<version>/; normalize the extracted "cmdline-tools/" -> "latest".
$extracted = Join-Path $sdkRoot "cmdline-tools/cmdline-tools"
if (Test-Path -LiteralPath $extracted) { Move-Item -LiteralPath $extracted -Destination (Join-Path $sdkRoot "cmdline-tools/latest") }

$sdkmanager = Join-Path $sdkRoot ("cmdline-tools/latest/bin/sdkmanager" + $(if ($Platform -eq "windows_x64") { ".bat" } else { "" }))
if (-not (Test-Path -LiteralPath $sdkmanager)) { throw "sdkmanager not found at $sdkmanager." }

# --- Install the bundled engine + owned image (checksums verified by sdkmanager) ---
# `sdkmanager --licenses` is interactive (prompts y/N per license). Running this
# installer is the operator's act of provisioning Google's Android SDK emulator
# components, so accept the SDK licenses non-interactively; without piped input
# the prompt defaults to "no" and every package is skipped, leaving no emulator.
$licenseAcceptance = (("y" + [Environment]::NewLine) * 50)
$licenseAcceptance | & $sdkmanager "--sdk_root=$sdkRoot" --licenses
& $sdkmanager "--sdk_root=$sdkRoot" $emulatorPkg $platformToolsPkg $SystemImage
if ($LASTEXITCODE -ne 0) { throw "sdkmanager failed to install $emulatorPkg / $platformToolsPkg / $SystemImage." }

# --- Create the owned AVD under an install-local ANDROID_AVD_HOME ---
$avdHome = Join-Path $sdkRoot "avd"
New-Item -ItemType Directory -Path $avdHome -Force | Out-Null
$env:ANDROID_AVD_HOME = $avdHome
$env:ANDROID_SDK_ROOT = $sdkRoot
$avdmanager = Join-Path $sdkRoot ("cmdline-tools/latest/bin/avdmanager" + $(if ($Platform -eq "windows_x64") { ".bat" } else { "" }))
"no" | & $avdmanager create avd --force --name $avdName --package $SystemImage --device "pixel"
if ($LASTEXITCODE -ne 0) { throw "avdmanager failed to create the owned AVD." }

# --- Stage device-side frida-server (bundled data file pushed to the guest) ---
# The owned AOSP-10 image is x86_64. Fetch into the standard packaging cache
# when necessary, then take the ABI-qualified path emitted by fetch-frida.ps1.
$fridaRoot = Join-Path $repositoryRoot "target/packaging/frida"
$fridaSource = Join-Path $fridaRoot "frida-server/android-x86_64/frida-server"
if (-not (Test-Path -LiteralPath $fridaSource -PathType Leaf)) {
    & (Join-Path $repositoryRoot "packaging/assets/fetch-frida.ps1") `
        -Platform $Platform `
        -Abis @("android_x86_64") `
        -OutputDirectory $fridaRoot `
        -CacheDirectory $CacheDirectory
}
if (-not (Test-Path -LiteralPath $fridaSource -PathType Leaf)) {
    throw "Verified Android x86_64 frida-server was not staged at $fridaSource."
}
Copy-Item -LiteralPath $fridaSource -Destination (Join-Path $sdkRoot "frida-server") -Force

Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging/assets/analysis-runtime-NOTICES.md") -Destination (Join-Path $sdkRoot "APIaxess-NOTICES.md")

# --- Provenance + version + SBOM ---
$provenance = [ordered]@{
    schemaVersion = 1
    component     = "APIaxess analysis runtime"
    payloadVersion = $payloadVersion
    platform      = $Platform
    androidApiLevel = 29
    androidRelease = "10"
    imageVariant  = "default"
    containsGms   = $false
    systemImage   = $SystemImage
    ownedAvd      = $avdName
    source        = "android-sdk (google signed repository)"
    licenses      = @("Apache-2.0 (AOSP userspace)", "GPL-2.0 (Linux kernel)", "GPL-2.0 (QEMU emulator)")
}
Write-Utf8NoBom -Path (Join-Path $sdkRoot "analysis-runtime-provenance.json") -Content ($provenance | ConvertTo-Json -Depth 5)
Write-Utf8NoBom -Path (Join-Path $sdkRoot "analysis-runtime-version.txt") -Content $payloadVersion

$files = @(
    Get-ChildItem -LiteralPath $sdkRoot -File -Recurse |
        ForEach-Object {
            $rel = $_.FullName.Substring($sdkRoot.Length).TrimStart('\', '/')
            [ordered]@{ path = $rel; size = $_.Length }
        }
)
$sbom = [ordered]@{
    schemaVersion = 1
    component     = "APIaxess analysis runtime"
    payloadVersion = $payloadVersion
    platform      = $Platform
    systemImage   = $SystemImage
    fileCount     = $files.Count
    files         = $files
} | ConvertTo-Json -Depth 5
Write-Utf8NoBom -Path (Join-Path $sdkRoot "analysis-runtime-sbom.json") -Content $sbom

Write-Host "Assembled analysis runtime $payloadVersion ($Platform, $SystemImage) at $sdkRoot"
Write-Host "Boot-time provisioning (session CA, agent, baseline snapshot) is applied by the engine on first boot."
