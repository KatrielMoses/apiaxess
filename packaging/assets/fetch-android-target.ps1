<#
.SYNOPSIS
    Assembles the GUI Android target add-on: slim no-GApps root-capable AOSP
    x86_64 emulator engine + system image + owned AVD + staged client APK +
    device-side frida-server, plus the engine-read manifest (Phase D1).

.DESCRIPTION
    Bootstraps the Android command-line tools, uses `sdkmanager` to install the
    pinned emulator, platform-tools, and the pure-AOSP `default` (NO GMS, so
    `adb root` works) system image into the add-on root (which doubles as
    ANDROID_SDK_ROOT), creates the owned AVD with the manifest's RAM floor, stages
    this repository's client APK and the device-side frida-server as first-boot
    provisioning artifacts, and emits the engine-read manifest
    (android-target-manifest.json) plus the SBOM, notices, provenance, and
    version. This is the separate, optional add-on — not the base install.

    Provisioning is NOT baked here: the session CA, frida-server, and client APK
    are installed on first boot by the engine's existing C2/C5 flow. This script
    only stages the artifacts and records what first-boot provisioning will do.

    sdkmanager verifies every package against Google's signed repository
    manifest. It is a Java application: pass -JavaHome, or the script uses the
    bundled Java runtime from Phase 11.1 if present.
#>
[CmdletBinding()]
param(
    [ValidateSet("windows_x64", "linux_x64")]
    [string]$Platform = "windows_x64",
    [string]$SystemImage,
    [string]$JavaHome,
    [string]$OutputDirectory,
    [string]$CacheDirectory,
    [string]$ClientApk,
    [switch]$SkipStreaming
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-ManifestField {
    param([Parameter(Mandatory)] [string]$Section, [Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*(?<body>.*?)(?=^\[|\z)'
    $sectionMatch = [regex]::Match($Manifest, $sectionPattern)
    if (-not $sectionMatch.Success) { throw "android-target manifest section [$Section] is missing." }
    $fieldPattern = '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"'
    $fieldMatch = [regex]::Match($sectionMatch.Groups["body"].Value, $fieldPattern)
    if (-not $fieldMatch.Success) { throw "android-target manifest field '$Field' is missing from [$Section]." }
    $fieldMatch.Groups["value"].Value
}
function Read-TopField {
    param([Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    $preamble = [regex]::Match($Manifest, '(?ms)\A(?<body>.*?)(?=^\[)').Groups["body"].Value
    [regex]::Match($preamble, '(?m)^' + [regex]::Escape($Field) + '\s*=\s*"(?<value>[^"]+)"').Groups["value"].Value
}
function Read-TopNumber {
    param([Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    [int]([regex]::Match($Manifest, '(?m)^' + [regex]::Escape($Field) + '\s*=\s*(?<value>\d+)').Groups["value"].Value)
}
function Read-SectionNumber {
    param([Parameter(Mandatory)] [string]$Section, [Parameter(Mandatory)] [string]$Field, [Parameter(Mandatory)] [string]$Manifest)
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*(?<body>.*?)(?=^\[|\z)'
    $body = [regex]::Match($Manifest, $sectionPattern).Groups["body"].Value
    [int]([regex]::Match($body, '(?m)^' + [regex]::Escape($Field) + '\s*=\s*(?<value>\d+)').Groups["value"].Value)
}
function Write-Utf8NoBom {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$manifest = Get-Content -LiteralPath (Join-Path $repositoryRoot "packaging/assets/android-target.toml") -Raw
$payloadVersion = Read-TopField -Field "payload_version" -Manifest $manifest
$addonId = Read-TopField -Field "addon_id" -Manifest $manifest
$avdName = Read-TopField -Field "owned_avd_name" -Manifest $manifest
$apiLevel = Read-TopNumber -Field "android_api_level" -Manifest $manifest
$androidRelease = Read-TopField -Field "android_release" -Manifest $manifest
$ramMib = Read-SectionNumber -Section "runtime" -Field "ram_mib" -Manifest $manifest
$wsScrcpyPort = Read-SectionNumber -Section "runtime" -Field "ws_scrcpy_port" -Manifest $manifest
if (-not $SystemImage) { $SystemImage = Read-ManifestField -Section "sdk_packages" -Field "system_image" -Manifest $manifest }
$emulatorPkg = Read-ManifestField -Section "sdk_packages" -Field "emulator" -Manifest $manifest
$platformToolsPkg = Read-ManifestField -Section "sdk_packages" -Field "platform_tools" -Manifest $manifest
$cmdToolsUrl = Read-ManifestField -Section "cmdline_tools.$Platform" -Field "url" -Manifest $manifest
if (-not $ClientApk) { $ClientApk = Join-Path $repositoryRoot (Read-ManifestField -Section "artifacts" -Field "client_apk" -Manifest $manifest) }
# Streaming (Phase D2): pinned Node + upstream ws-scrcpy (by commit SHA), staged into the payload.
$streamBasePath = Read-ManifestField -Section "streaming" -Field "base_path" -Manifest $manifest
$streamNodeDir = Read-ManifestField -Section "streaming" -Field "node_dir" -Manifest $manifest
$streamWsDir = Read-ManifestField -Section "streaming" -Field "ws_scrcpy_dir" -Manifest $manifest
$streamWsEntry = Read-ManifestField -Section "streaming" -Field "ws_scrcpy_entry" -Manifest $manifest
$nodeUrl = Read-ManifestField -Section "streaming.node.$Platform" -Field "url" -Manifest $manifest
$wsScrcpyRepo = Read-ManifestField -Section "streaming.ws_scrcpy" -Field "repo" -Manifest $manifest
$wsScrcpyRef = Read-ManifestField -Section "streaming.ws_scrcpy" -Field "git_ref" -Manifest $manifest
# Build-config features compiled out of ws-scrcpy (comma-separated), e.g. the ADB
# shell, whose node-pty dependency cannot install on Windows under current Node.
$wsScrcpyExcluded = @((Read-ManifestField -Section "streaming.ws_scrcpy" -Field "excluded_features" -Manifest $manifest) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# A slim GUI target the user drives: cold boot each session for reliability, but
# userdata (installed APK + completed logins) persists across boots. NOT -wipe-data
# and NOT a quickboot snapshot (a killed run's qcow2 can poison later boots).
$emulatorArgs = @("-no-window", "-no-audio", "-no-boot-anim", "-no-metrics", "-no-snapshot", "-gpu", "swiftshader_indirect")
# The device serial is emulator-<consolePort>; 5556 avoids the analysis runtime's 5554.
$consolePort = 5556

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repositoryRoot "target/packaging/android-target-$Platform" }
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
if ($env:SystemRoot) {
    $system32 = Join-Path $env:SystemRoot "System32"
    if ((Test-Path -LiteralPath $system32) -and -not (($env:PATH -split ';') -contains $system32)) {
        $env:PATH = "$system32;$env:PATH"
    }
}
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
$extracted = Join-Path $sdkRoot "cmdline-tools/cmdline-tools"
if (Test-Path -LiteralPath $extracted) { Move-Item -LiteralPath $extracted -Destination (Join-Path $sdkRoot "cmdline-tools/latest") }

$sdkmanager = Join-Path $sdkRoot ("cmdline-tools/latest/bin/sdkmanager" + $(if ($Platform -eq "windows_x64") { ".bat" } else { "" }))
if (-not (Test-Path -LiteralPath $sdkmanager)) { throw "sdkmanager not found at $sdkmanager." }

# --- Install the slim engine + no-GApps image (checksums verified by sdkmanager) ---
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

# Raise the AVD's RAM to the manifest floor so a GUI target the user drives is
# responsive (avdmanager defaults are low). Append/replace hw.ramSize in config.ini.
$avdConfig = Join-Path $avdHome "$avdName.avd/config.ini"
if (Test-Path -LiteralPath $avdConfig) {
    $config = [System.Collections.Generic.List[string]](Get-Content -LiteralPath $avdConfig)
    $config = $config | Where-Object { $_ -notmatch '^(hw\.ramSize|hw\.keyboard|showDeviceFrame)\s*=' }
    $config += "hw.ramSize=$ramMib"
    $config += "hw.keyboard=yes"          # let the operator type into the target in D2
    $config += "showDeviceFrame=no"
    Write-Utf8NoBom -Path $avdConfig -Content (($config -join [Environment]::NewLine) + [Environment]::NewLine)
}

# --- Stage device-side frida-server (bundled data file pushed to the guest) ---
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

# --- Stage the first-party client APK as a first-boot provisioning artifact ---
$artifactsDir = Join-Path $sdkRoot "artifacts"
New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
$clientApkRel = "artifacts/apiaxess-client.apk"
$clientApkStaged = $false
if (Test-Path -LiteralPath $ClientApk -PathType Leaf) {
    Copy-Item -LiteralPath $ClientApk -Destination (Join-Path $sdkRoot $clientApkRel) -Force
    $clientApkStaged = $true
}
else {
    Write-Warning "Client APK not found at $ClientApk; the add-on will assemble without it. First-boot provisioning reports android-target.client-apk-missing until it is staged at <root>/$clientApkRel (build apps/android and re-run, or pass -ClientApk)."
}

# --- Stage the screen-streaming components (Phase D2): Node + ws-scrcpy ---
# The drivable target is its screen, so a stream that fails to build is a build
# failure: the script stops non-zero rather than shipping a stream-less add-on.
# Only an explicit -SkipStreaming assembles without it (the engine then reports
# sandbox.android-stream-unavailable). ws-scrcpy binds loopback only and is
# reverse-proxied by the engine behind the workbench gate; it is never directly
# reachable (see the loopback patch below, and the smoke test that proves it).
$streamingStaged = $false
if (-not $SkipStreaming) {
    try {
        $nodeRoot = Join-Path $sdkRoot "node"
        if (Test-Path -LiteralPath $nodeRoot) { Remove-Item -LiteralPath $nodeRoot -Recurse -Force }
        New-Item -ItemType Directory -Path $nodeRoot -Force | Out-Null
        $nodeArchive = Join-Path $CacheDirectory ([System.IO.Path]::GetFileName(($nodeUrl -split '\?')[0]))
        if (-not (Test-Path -LiteralPath $nodeArchive)) {
            Write-Host "Downloading Node runtime for ws-scrcpy ($Platform)..."
            try { Invoke-WebRequest -UseBasicParsing -Uri $nodeUrl -OutFile $nodeArchive } catch { Remove-Item -LiteralPath $nodeArchive -ErrorAction SilentlyContinue; throw "downloading the Node runtime from $nodeUrl failed ($($_.Exception.Message))." }
        }
        $nodeExtract = Join-Path $CacheDirectory "node-extract-$Platform"
        if (Test-Path -LiteralPath $nodeExtract) { Remove-Item -LiteralPath $nodeExtract -Recurse -Force }
        New-Item -ItemType Directory -Path $nodeExtract -Force | Out-Null
        if ($Platform -eq "windows_x64") {
            Expand-Archive -LiteralPath $nodeArchive -DestinationPath $nodeExtract -Force
        }
        else {
            & tar -xJf $nodeArchive -C $nodeExtract
            if ($LASTEXITCODE -ne 0) { throw "tar failed to extract the Node runtime." }
        }
        # Flatten the single node-v<ver>-<plat> directory into <root>/node/.
        $nodeInner = Get-ChildItem -LiteralPath $nodeExtract -Directory | Select-Object -First 1
        Get-ChildItem -LiteralPath $nodeInner.FullName -Force | ForEach-Object {
            Move-Item -LiteralPath $_.FullName -Destination $nodeRoot
        }
        # node[.exe] lives at the node root on Windows, under bin/ on Linux.
        if ($Platform -eq "windows_x64") {
            $nodeExe = Join-Path $nodeRoot "node.exe"
            $npmCmd = Join-Path $nodeRoot "npm.cmd"
            $streamNodeDirEmit = "node"
        }
        else {
            $nodeExe = Join-Path $nodeRoot "bin/node"
            $npmCmd = Join-Path $nodeRoot "bin/npm"
            $streamNodeDirEmit = "node/bin"
        }
        if (-not (Test-Path -LiteralPath $nodeExe)) { throw "Node executable not found at $nodeExe after staging." }

        # Fetch pinned ws-scrcpy (GitHub archive of the ref) and build dist.
        $wsRoot = Join-Path $sdkRoot $streamWsDir
        if (Test-Path -LiteralPath $wsRoot) { Remove-Item -LiteralPath $wsRoot -Recurse -Force }
        $wsZip = Join-Path $CacheDirectory ("ws-scrcpy-$wsScrcpyRef.zip")
        if (-not (Test-Path -LiteralPath $wsZip)) {
            # GitHub's archive path differs by ref kind: a 40-hex commit SHA is
            # /archive/<sha>.zip, whereas a tag is /archive/refs/tags/<tag>.zip. The
            # pin is a commit SHA (base-path support landed on master after v0.8.1),
            # so route on the ref shape rather than assuming a tag.
            $archivePath = if ($wsScrcpyRef -match '^[0-9a-fA-F]{40}$') { "archive/$wsScrcpyRef.zip" } else { "archive/refs/tags/$wsScrcpyRef.zip" }
            $archiveUrl = "$($wsScrcpyRepo.TrimEnd('/'))/$archivePath"
            Write-Host "Downloading pinned ws-scrcpy ($wsScrcpyRef)..."
            try { Invoke-WebRequest -UseBasicParsing -Uri $archiveUrl -OutFile $wsZip } catch { Remove-Item -LiteralPath $wsZip -ErrorAction SilentlyContinue; throw "downloading ws-scrcpy $wsScrcpyRef from $archiveUrl failed ($($_.Exception.Message))." }
        }
        $wsExtract = Join-Path $CacheDirectory "ws-scrcpy-extract"
        if (Test-Path -LiteralPath $wsExtract) { Remove-Item -LiteralPath $wsExtract -Recurse -Force }
        Expand-Archive -LiteralPath $wsZip -DestinationPath $wsExtract -Force
        $wsInner = Get-ChildItem -LiteralPath $wsExtract -Directory | Select-Object -First 1
        Move-Item -LiteralPath $wsInner.FullName -Destination $wsRoot

        # APIaxess adaptations of upstream ws-scrcpy, applied to every fresh copy so no
        # assembly depends on a hand-patched add-on:
        # 1. Build config: compile out the excluded features (the ADB shell, and with
        #    it node-pty) and serve under the engine's reverse-proxy base path.
        $buildConfig = [ordered]@{ PATHNAME = $streamBasePath }
        foreach ($feature in $wsScrcpyExcluded) { $buildConfig[$feature] = $false }
        Write-Utf8NoBom -Path (Join-Path $wsRoot "build.config.override.json") -Content ($buildConfig | ConvertTo-Json)
        # 2. Listen on loopback, on the port the engine chooses. Upstream binds every
        #    interface on its config port and has no auth, so unpatched it would let
        #    anyone on the network view and drive the device around the engine's gate.
        $httpServerSource = Join-Path $wsRoot "src/server/services/HttpServer.ts"
        $listenAnchor = "server.listen(port, () => {"
        $httpServer = Get-Content -LiteralPath $httpServerSource -Raw
        if (-not $httpServer.Contains($listenAnchor)) {
            throw "ws-scrcpy $wsScrcpyRef no longer contains '$listenAnchor' in src/server/services/HttpServer.ts; the loopback-bind patch must be updated for this pin."
        }
        $httpServer = $httpServer.Replace($listenAnchor, "server.listen(Number(process.env.WS_SCRCPY_PORT) || port, process.env.WS_SCRCPY_HOST || '127.0.0.1', () => {")
        Write-Utf8NoBom -Path $httpServerSource -Content $httpServer

        # Build the distributable server bundle with the bundled Node's npm.
        Push-Location $wsRoot
        try {
            $env:PATH = "$([System.IO.Path]::GetDirectoryName($nodeExe))$([System.IO.Path]::PathSeparator)$env:PATH"
            # --ignore-scripts: the only install scripts are node-pty's native build
            # (it fails on Windows with `spawn EINVAL` under Node >= 20.12, and the
            # shell it serves is compiled out above) and the iOS/appium setup, which
            # the Android target does not use.
            & $npmCmd ci --ignore-scripts
            if ($LASTEXITCODE -ne 0) { throw "npm ci failed for ws-scrcpy (exit $LASTEXITCODE)." }
            & $npmCmd run dist
            if ($LASTEXITCODE -ne 0) { throw "npm run dist failed for ws-scrcpy (exit $LASTEXITCODE)." }
        }
        finally {
            Pop-Location
        }
        $wsEntryPath = Join-Path $wsRoot $streamWsEntry
        if (-not (Test-Path -LiteralPath $wsEntryPath)) {
            throw "ws-scrcpy build did not produce $streamWsEntry."
        }
        if ((Get-Content -LiteralPath $wsEntryPath -Raw).Contains("node-pty")) {
            throw "ws-scrcpy build still references node-pty; the excluded features ($($wsScrcpyExcluded -join ', ')) did not take effect."
        }

        # Smoke test the built server exactly as the engine runs it: it must serve
        # under the base path (and not at the root) and listen on loopback only.
        $smokePort = 18000 + (Get-Random -Maximum 1000)
        $smokeInfo = New-Object System.Diagnostics.ProcessStartInfo
        $smokeInfo.FileName = $nodeExe
        $smokeInfo.Arguments = "`"$wsEntryPath`""
        $smokeInfo.WorkingDirectory = $wsRoot
        $smokeInfo.UseShellExecute = $false
        $smokeInfo.RedirectStandardOutput = $true
        $smokeInfo.RedirectStandardError = $true
        $smokeInfo.Environment["WS_SCRCPY_HOST"] = "127.0.0.1"
        $smokeInfo.Environment["WS_SCRCPY_PORT"] = "$smokePort"
        $smokeInfo.Environment["WS_SCRCPY_PATHNAME"] = $streamBasePath
        $smokeInfo.Environment["ADB"] = Join-Path $sdkRoot ("platform-tools/" + $(if ($Platform -eq "windows_x64") { "adb.exe" } else { "adb" }))
        $smoke = [System.Diagnostics.Process]::Start($smokeInfo)
        try {
            $served = $null
            for ($attempt = 0; $attempt -lt 60 -and -not $smoke.HasExited; $attempt++) {
                Start-Sleep -Milliseconds 500
                try {
                    $served = (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$smokePort$streamBasePath" -TimeoutSec 5).StatusCode
                    break
                }
                catch { }
            }
            if ($served -ne 200) {
                $output = if ($smoke.HasExited) { $smoke.StandardError.ReadToEnd() + $smoke.StandardOutput.ReadToEnd() } else { "" }
                throw "the built ws-scrcpy did not serve $streamBasePath on 127.0.0.1:$smokePort (status: $served). $output"
            }
            $rootStatus = try { (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$smokePort/" -TimeoutSec 5).StatusCode } catch { [int]$_.Exception.Response.StatusCode }
            if ($rootStatus -eq 200) {
                throw "the built ws-scrcpy also serves at the root, not only under $streamBasePath; the base path did not take effect."
            }
            if ($Platform -eq "windows_x64") {
                $exposed = @(Get-NetTCPConnection -LocalPort $smokePort -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notin @("127.0.0.1", "::1") })
                if ($exposed.Count -gt 0) {
                    throw "the built ws-scrcpy listens on $($exposed[0].LocalAddress):$smokePort, not loopback only; the loopback-bind patch did not take effect."
                }
            }
        }
        finally {
            if (-not $smoke.HasExited) { $smoke.Kill($true) }
            $smoke.Dispose()
        }
        $streamingStaged = $true
        Write-Host "Staged ws-scrcpy ($wsScrcpyRef) on Node runtime: serves $streamBasePath on loopback (smoke-tested)."
    }
    catch {
        throw "Android target streaming could not be staged: $($_.Exception.Message) The drivable target needs its screen stream, so this assembly is a failure. Fix the cause and re-run, or pass -SkipStreaming to deliberately assemble a target without a screen."
    }
}

Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging/assets/android-target-NOTICES.md") -Destination (Join-Path $sdkRoot "APIaxess-NOTICES.md")

# --- Engine-read runtime manifest (Phase D1) ---
# The engine's add-on resolver reads this verbatim to boot the AVD headless and run
# first-boot C2/C5 provisioning. Keys are camelCase to match the other emitted JSON.
$engineManifest = [ordered]@{
    schemaVersion   = 1
    addonId         = $addonId
    product         = "APIaxess GUI Android target"
    payloadVersion  = $payloadVersion
    androidApiLevel = $apiLevel
    androidRelease  = $androidRelease
    imageVariant    = "default"
    containsGms     = $false
    avdName         = $avdName
    systemImage     = $SystemImage
    emulatorDir     = "emulator"
    platformToolsDir = "platform-tools"
    avdDir          = "avd"
    consolePort     = $consolePort
    ramMib          = $ramMib
    wsScrcpyPort    = $wsScrcpyPort
    emulatorArgs    = $emulatorArgs
    provisioning    = [ordered]@{
        installClientApk = $true
        installSessionCa = $true
        startFridaServer = $true
    }
    artifacts       = [ordered]@{
        clientApk   = $clientApkRel
        fridaServer = "frida-server"
    }
}
# The streaming block is present only when ws-scrcpy + Node were staged; absent, the
# engine reports sandbox.android-stream-unavailable and the target still captures.
if ($streamingStaged) {
    $engineManifest["streaming"] = [ordered]@{
        nodeDir      = $streamNodeDirEmit
        wsScrcpyDir  = $streamWsDir
        wsScrcpyEntry = $streamWsEntry
        basePath     = $streamBasePath
    }
}
Write-Utf8NoBom -Path (Join-Path $sdkRoot "android-target-manifest.json") -Content ($engineManifest | ConvertTo-Json -Depth 6)

# --- Provenance + version + SBOM ---
$provenance = [ordered]@{
    schemaVersion   = 1
    component       = "APIaxess GUI Android target"
    addonId         = $addonId
    payloadVersion  = $payloadVersion
    platform        = $Platform
    androidApiLevel = $apiLevel
    androidRelease  = $androidRelease
    imageVariant    = "default"
    containsGms     = $false
    systemImage     = $SystemImage
    ownedAvd        = $avdName
    clientApkStaged = $clientApkStaged
    streamingStaged = $streamingStaged
    source          = "android-sdk (google signed repository); client APK + frida-server from this repository; ws-scrcpy + Node from upstream"
    licenses        = @("Apache-2.0 (AOSP userspace)", "GPL-2.0 (Linux kernel)", "GPL-2.0 (QEMU emulator)", "wxWindows-3.1 (frida-server)", "first-party (APIaxess client APK)", "MIT (ws-scrcpy)", "MIT (Node.js)")
}
Write-Utf8NoBom -Path (Join-Path $sdkRoot "android-target-provenance.json") -Content ($provenance | ConvertTo-Json -Depth 5)
Write-Utf8NoBom -Path (Join-Path $sdkRoot "android-target-version.txt") -Content $payloadVersion

$files = @(
    Get-ChildItem -LiteralPath $sdkRoot -File -Recurse |
        ForEach-Object {
            $rel = $_.FullName.Substring($sdkRoot.Length).TrimStart('\', '/')
            [ordered]@{ path = $rel; size = $_.Length }
        }
)
$sbom = [ordered]@{
    schemaVersion  = 1
    component      = "APIaxess GUI Android target"
    addonId        = $addonId
    payloadVersion = $payloadVersion
    platform       = $Platform
    systemImage    = $SystemImage
    fileCount      = $files.Count
    files          = $files
} | ConvertTo-Json -Depth 5
Write-Utf8NoBom -Path (Join-Path $sdkRoot "android-target-sbom.json") -Content $sbom

Write-Host "Assembled GUI Android target $payloadVersion ($Platform, $SystemImage) at $sdkRoot"
Write-Host "First-boot provisioning (client APK, live session CA, frida-server, pairing) is applied by the engine via C2/C5 on launch."
