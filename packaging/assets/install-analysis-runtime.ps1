<#
.SYNOPSIS
    Fetches and installs the optional dynamic-analysis "analysis-runtime" payload
    into the location the installed product resolves.

.DESCRIPTION
    The analysis runtime (bundled QEMU/SDK emulator + owned Android-10 AOSP image
    + owned AVD + device-side frida-server) is the separate, optional ~2 GB
    payload that is deliberately NOT part of the base installer. The engine
    resolves it from `<install>\analysis-runtime` (Windows), or from
    `APIAXESS_ANALYSIS_RUNTIME` when set; a dynamic run without it reports the
    honest `sandbox.analysis-runtime-missing` diagnostic (Phase 12.1).

    This wraps `fetch-analysis-runtime.ps1` (which assembles + verifies the
    payload via Google's signed SDK repository) and stages the result at that
    resolved location, driving sdkmanager with the product's own bundled Java
    runtime so no host JDK is required. The per-user install tree
    (`%LocalAppData%\Programs\APIaxess`) is writable without elevation.

.EXAMPLE
    ./install-analysis-runtime.ps1
    Installs into the default per-user install tree's analysis-runtime\.

.EXAMPLE
    ./install-analysis-runtime.ps1 -Destination D:\apiaxess-runtime
    Installs into an explicit directory; set APIAXESS_ANALYSIS_RUNTIME to it.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot,
    [string]$Destination,
    [string]$SystemImage,
    [string]$CacheDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))

if (-not $InstallRoot) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\APIaxess"
}
if (-not $Destination) {
    $Destination = Join-Path $InstallRoot "analysis-runtime"
}
$Destination = [System.IO.Path]::GetFullPath($Destination)

# Prefer the product's own bundled Java runtime so sdkmanager needs no host JDK.
$bundledJavaHome = Join-Path $InstallRoot "runtime\java\windows"
$javaHomeArg = @{}
if (Test-Path -LiteralPath (Join-Path $bundledJavaHome "bin\java.exe") -PathType Leaf) {
    $javaHomeArg["JavaHome"] = $bundledJavaHome
}
$systemImageArg = @{}
if ($SystemImage) { $systemImageArg["SystemImage"] = $SystemImage }
$cacheArg = @{}
if ($CacheDirectory) { $cacheArg["CacheDirectory"] = $CacheDirectory }

Write-Host "Assembling the analysis runtime into $Destination (this is a large, one-time ~2 GB download)..."
& (Join-Path $PSScriptRoot "fetch-analysis-runtime.ps1") `
    -Platform "windows_x64" `
    -OutputDirectory $Destination `
    @javaHomeArg @systemImageArg @cacheArg

$emulator = Join-Path $Destination "emulator\emulator.exe"
if (-not (Test-Path -LiteralPath $emulator -PathType Leaf)) {
    throw "The analysis runtime did not assemble an emulator engine at $emulator."
}

$defaultResolved = Join-Path (Join-Path $env:LOCALAPPDATA "Programs\APIaxess") "analysis-runtime"
Write-Host "Analysis runtime installed at $Destination."
if ($Destination -ine $defaultResolved) {
    Write-Host "Set APIAXESS_ANALYSIS_RUNTIME to this path so the engine resolves it:"
    Write-Host "  setx APIAXESS_ANALYSIS_RUNTIME `"$Destination`""
}
else {
    Write-Host "The installed engine resolves it automatically; dynamic analysis is now enabled."
}
