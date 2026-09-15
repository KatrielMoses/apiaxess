<#
.SYNOPSIS
    Fetches and installs the optional GUI Android target add-on into the location
    the installed product resolves.

.DESCRIPTION
    The GUI Android target (slim no-GApps root-capable AOSP x86_64 emulator +
    system image + owned AVD + staged client APK + device-side frida-server + the
    engine-read manifest) is the separate, optional add-on that is deliberately
    NOT part of the base installer. The engine resolves it from
    `<install>\android-target` (Windows), or from `APIAXESS_ANDROID_TARGET` when
    set; launching a GUI target without it reports the honest
    `sandbox.android-target-missing` diagnostic.

    This wraps `fetch-android-target.ps1` (which assembles + verifies the payload
    via Google's signed SDK repository and stages this repo's client APK +
    frida-server) and stages the result at that resolved location, driving
    sdkmanager with the product's own bundled Java runtime so no host JDK is
    required. The per-user install tree (`%LocalAppData%\Programs\APIaxess`) is
    writable without elevation.

.EXAMPLE
    ./install-android-target.ps1
    Installs into the default per-user install tree's android-target\.

.EXAMPLE
    ./install-android-target.ps1 -Destination D:\apiaxess-android-target
    Installs into an explicit directory; set APIAXESS_ANDROID_TARGET to it.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot,
    [string]$Destination,
    [string]$SystemImage,
    [string]$CacheDirectory,
    [string]$ClientApk
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))

if (-not $InstallRoot) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\APIaxess"
}
if (-not $Destination) {
    $Destination = Join-Path $InstallRoot "android-target"
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
$clientApkArg = @{}
if ($ClientApk) { $clientApkArg["ClientApk"] = $ClientApk }

Write-Host "Assembling the GUI Android target into $Destination (a large, one-time download)..."
& (Join-Path $PSScriptRoot "fetch-android-target.ps1") `
    -Platform "windows_x64" `
    -OutputDirectory $Destination `
    @javaHomeArg @systemImageArg @cacheArg @clientApkArg

$emulator = Join-Path $Destination "emulator\emulator.exe"
if (-not (Test-Path -LiteralPath $emulator -PathType Leaf)) {
    throw "The GUI Android target did not assemble an emulator engine at $emulator."
}

$defaultResolved = Join-Path (Join-Path $env:LOCALAPPDATA "Programs\APIaxess") "android-target"
Write-Host "GUI Android target installed at $Destination."
if ($Destination -ine $defaultResolved) {
    Write-Host "Set APIAXESS_ANDROID_TARGET to this path so the engine resolves it:"
    Write-Host "  setx APIAXESS_ANDROID_TARGET `"$Destination`""
}
else {
    Write-Host "The installed engine resolves it automatically; launching a GUI Android target is now enabled."
}
