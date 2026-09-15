[CmdletBinding()]
param(
    [ValidateSet("x64")]
    [string]$Architecture = "x64",
    [string]$NodeVersion = "24.19.0",
    [string]$NodeArchiveSha256 = "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73",
    [string]$PnpmVersion = "11.19.0",
    [string]$WixVersion = "4.0.6",
    [string]$ChromiumRuntimeDirectory,
    [string]$OutputDirectory,
    [switch]$SkipApplicationBuild,
    [switch]$BundleFrida
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = "false"

function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(ValueFromRemainingArguments)] [string[]]$ArgumentList
    )
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($ArgumentList -join ' ')"
    }
}

function Reset-OwnedDirectory {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$AllowedRoot
    )
    $absolutePath = [System.IO.Path]::GetFullPath($Path)
    $absoluteRoot = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $absolutePath.StartsWith($absoluteRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to reset packaging directory outside ${absoluteRoot}: $absolutePath"
    }
    if (Test-Path -LiteralPath $absolutePath) {
        Remove-Item -LiteralPath $absolutePath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $absolutePath -Force | Out-Null
}

function Get-DeterministicGuid {
    param([Parameter(Mandatory)] [string]$Seed)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
    }
    finally {
        $sha256.Dispose()
    }
    $bytes = [byte[]]::new(16)
    [Array]::Copy($digest, $bytes, 16)
    $bytes[7] = [byte](($bytes[7] -band 0x0f) -bor 0x50)
    $bytes[8] = [byte](($bytes[8] -band 0x3f) -bor 0x80)
    ([Guid]::new($bytes)).ToString("D").ToUpperInvariant()
}

function Get-StableId {
    param(
        [Parameter(Mandatory)] [string]$Prefix,
        [Parameter(Mandatory)] [string]$Value
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    }
    finally {
        $sha256.Dispose()
    }
    $hex = [Convert]::ToHexString($digest).Substring(0, 24).ToLowerInvariant()
    "${Prefix}_${hex}"
}

function Get-LatestProductSourceWriteTime {
    param([Parameter(Mandatory)] [string]$RepositoryRoot)

    # Deliberately restrict this to authored product inputs. Generated output,
    # dependency directories, and prior artifacts must never make a valid
    # release binary look stale.
    $roots = @(
        (Join-Path $RepositoryRoot "apps\engine"),
        (Join-Path $RepositoryRoot "apps\desktop"),
        (Join-Path $RepositoryRoot "crates"),
        (Join-Path $RepositoryRoot "plugins"),
        (Join-Path $RepositoryRoot "contracts")
    )
    $files = foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root -PathType Container) {
            Get-ChildItem -LiteralPath $root -Recurse -File |
                Where-Object {
                    $_.FullName -notmatch '[\\/]node_modules[\\/]' -and
                    $_.FullName -notmatch '[\\/]dist[\\/]' -and
                    $_.Extension -in @('.rs', '.toml', '.json', '.ts', '.tsx', '.css', '.html', '.proto')
                }
        }
    }
    $files += Get-Item -LiteralPath (Join-Path $RepositoryRoot "Cargo.toml"), (Join-Path $RepositoryRoot "Cargo.lock") -ErrorAction SilentlyContinue
    $latest = $files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -eq $latest) {
        throw "Could not determine the newest authored product source file."
    }
    return $latest
}

function Assert-ReleaseBinaryFreshness {
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string[]]$BinaryPaths
    )

    $newestSource = Get-LatestProductSourceWriteTime -RepositoryRoot $RepositoryRoot
    $stale = @()
    foreach ($binaryPath in $BinaryPaths) {
        if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
            $stale += "$binaryPath (missing)"
            continue
        }
        $binary = Get-Item -LiteralPath $binaryPath
        if ($binary.LastWriteTimeUtc -lt $newestSource.LastWriteTimeUtc) {
            $stale += "$binaryPath (built $($binary.LastWriteTimeUtc.ToString('o')); source $($newestSource.FullName) changed $($newestSource.LastWriteTimeUtc.ToString('o')))"
        }
    }
    if ($stale.Count -gt 0) {
        throw "Refusing to package stale release binaries. Rebuild without -SkipApplicationBuild, then retry. $($stale -join '; ')"
    }
    return $newestSource
}

function Write-WixPayloadFragment {
    param(
        [Parameter(Mandatory)] [string]$StageDirectory,
        [Parameter(Mandatory)] [string]$Destination
    )
    $stage = [System.IO.Path]::GetFullPath($StageDirectory)
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.Xml.XmlWriter]::Create($Destination, $settings)
    $namespace = "http://wixtoolset.org/schemas/v4/wxs"
    $componentIds = [System.Collections.Generic.List[string]]::new()

    function Write-DirectoryContents {
        param(
            [Parameter(Mandatory)] [System.Xml.XmlWriter]$Xml,
            [Parameter(Mandatory)] [System.IO.DirectoryInfo]$Directory,
            [Parameter(Mandatory)] [AllowEmptyString()] [string]$RelativeDirectory,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Components
        )

        foreach ($file in @($Directory.GetFiles() | Sort-Object Name)) {
            $relativeFile = if ($RelativeDirectory) { "$RelativeDirectory\$($file.Name)" } else { $file.Name }
            $componentId = Get-StableId -Prefix "cmp" -Value $relativeFile.ToLowerInvariant()
            $fileId = if ($relativeFile -ieq "bin\apiaxess-desktop.exe") { "ApplicationExecutable" } else { Get-StableId -Prefix "fil" -Value $relativeFile.ToLowerInvariant() }
            $Components.Add($componentId)

            $Xml.WriteStartElement("Component", $namespace)
            $Xml.WriteAttributeString("Id", $componentId)
            $Xml.WriteAttributeString("Guid", "*")
            $Xml.WriteStartElement("File", $namespace)
            $Xml.WriteAttributeString("Id", $fileId)
            $Xml.WriteAttributeString("Source", "!(bindpath.Stage)\$relativeFile")
            $Xml.WriteAttributeString("KeyPath", "yes")
            if ($relativeFile -ieq "bin\apiaxess-desktop.exe") {
                $Xml.WriteStartElement("Shortcut", $namespace)
                $Xml.WriteAttributeString("Id", "StartMenuShortcut")
                $Xml.WriteAttributeString("Directory", "ApplicationProgramsFolder")
                $Xml.WriteAttributeString("Name", "APIaxess")
                $Xml.WriteAttributeString("Description", "Launch the APIaxess local workbench")
                $Xml.WriteAttributeString("WorkingDirectory", "INSTALLFOLDER")
                # The desktop shell embeds the app icon; the Start Menu shortcut
                # uses the same mark (Icon element defined in Product.wxs).
                $Xml.WriteAttributeString("Icon", "AppIcon.exe")
                $Xml.WriteEndElement()
            }
            $Xml.WriteEndElement()
            if ($relativeFile -ieq "bin\apiaxess-desktop.exe") {
                $Xml.WriteStartElement("RemoveFolder", $namespace)
                $Xml.WriteAttributeString("Id", "RemoveApplicationProgramsFolder")
                $Xml.WriteAttributeString("Directory", "ApplicationProgramsFolder")
                $Xml.WriteAttributeString("On", "uninstall")
                $Xml.WriteEndElement()
            }
            $Xml.WriteEndElement()
        }

        foreach ($child in @($Directory.GetDirectories() | Sort-Object Name)) {
            $childRelative = if ($RelativeDirectory) { "$RelativeDirectory\$($child.Name)" } else { $child.Name }
            $Xml.WriteStartElement("Directory", $namespace)
            $Xml.WriteAttributeString("Id", (Get-StableId -Prefix "dir" -Value $childRelative.ToLowerInvariant()))
            $Xml.WriteAttributeString("Name", $child.Name)
            Write-DirectoryContents -Xml $Xml -Directory $child -RelativeDirectory $childRelative -Components $Components
            $Xml.WriteEndElement()
        }
    }

    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement("Wix", $namespace)
        $writer.WriteStartElement("Fragment", $namespace)
        $writer.WriteStartElement("DirectoryRef", $namespace)
        $writer.WriteAttributeString("Id", "INSTALLFOLDER")
        Write-DirectoryContents -Xml $writer -Directory ([System.IO.DirectoryInfo]::new($stage)) -RelativeDirectory "" -Components $componentIds
        $writer.WriteEndElement()
        $writer.WriteEndElement()

        $writer.WriteStartElement("Fragment", $namespace)
        $writer.WriteStartElement("ComponentGroup", $namespace)
        $writer.WriteAttributeString("Id", "ApplicationFiles")
        foreach ($componentId in $componentIds) {
            $writer.WriteStartElement("ComponentRef", $namespace)
            $writer.WriteAttributeString("Id", $componentId)
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally {
        $writer.Dispose()
    }
}

if (-not $IsWindows) {
    throw "The MSI build must run on Windows."
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$targetRoot = Join-Path $repositoryRoot "target\packaging\windows-$Architecture"
$stageRoot = Join-Path $targetRoot "stage"
$intermediateRoot = Join-Path $targetRoot "wix-intermediate"
$toolRoot = Join-Path $repositoryRoot "target\packaging-tools"
$cacheRoot = Join-Path $repositoryRoot "target\packaging-cache"
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot "artifacts\windows"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$cargoManifest = Get-Content -LiteralPath (Join-Path $repositoryRoot "Cargo.toml") -Raw
$versionMatch = [regex]::Match($cargoManifest, '(?ms)^\[workspace\.package\].*?^version\s*=\s*"(?<version>\d+\.\d+\.\d+)"')
if (-not $versionMatch.Success) {
    throw "Could not read the workspace package version from Cargo.toml."
}
$productVersion = $versionMatch.Groups["version"].Value
$productCode = Get-DeterministicGuid -Seed "apiaxess/windows-msi/$Architecture/$productVersion"

# The Frida host-side components are staged early when building the linked
# `frida-embedded` product variant, because the release cargo build below must
# link the pinned devkit. `fetch-frida.ps1` verifies and lays out the devkit +
# device-side server under target\packaging\frida.
$fridaRuntimeDirectory = $null
if ($BundleFrida) {
    $fridaRuntimeDirectory = Join-Path $targetRoot "frida"
    & (Join-Path $repositoryRoot "packaging\assets\fetch-frida.ps1") `
        -Platform "windows_x64" `
        -OutputDirectory $fridaRuntimeDirectory `
        -CacheDirectory $cacheRoot
    $fridaDevkit = Join-Path $fridaRuntimeDirectory "devkit\windows-x86_64"
    if (-not (Test-Path -LiteralPath (Join-Path $fridaDevkit "frida-core.lib") -PathType Leaf)) {
        throw "The bundled Frida devkit is missing frida-core.lib at $fridaDevkit."
    }
    if (-not $env:LIBCLANG_PATH) {
        throw "Building the frida-embedded variant requires libclang: set LIBCLANG_PATH to an LLVM bin directory (frida-sys runs bindgen)."
    }
    # Point frida-sys's bindgen at the devkit header and the crate build script
    # (crates\sandbox\build.rs) at the devkit for the link search.
    $env:APIAXESS_FRIDA_DEVKIT = $fridaDevkit
    $env:BINDGEN_EXTRA_CLANG_ARGS = "-I$($fridaDevkit -replace '\\','/')"
}

if (-not $SkipApplicationBuild) {
    $nodeCommand = Get-Command "node" -CommandType Application -ErrorAction Stop
    $vite = Join-Path $repositoryRoot "apps\gui\node_modules\vite\bin\vite.js"
    if (-not (Test-Path -LiteralPath $vite -PathType Leaf)) {
        throw "GUI dependencies are missing. Run 'pnpm install --frozen-lockfile' before building the MSI."
    }
    Push-Location (Join-Path $repositoryRoot "apps\gui")
    try {
        Invoke-Checked $nodeCommand.Source $vite "build"
    }
    finally {
        Pop-Location
    }
    Push-Location $repositoryRoot
    try {
        if ($BundleFrida) {
            Invoke-Checked "cargo" "build" "--release" "-p" "apiaxess" "--features" "frida-embedded"
        }
        else {
            Invoke-Checked "cargo" "build" "--release" "-p" "apiaxess"
        }
        # The native desktop shell (Tauri) that gives the GUI its own window.
        Invoke-Checked "cargo" "build" "--release" "-p" "apiaxess-desktop"
    }
    finally {
        Pop-Location
    }

    # Cargo deliberately preserves an output's original timestamp when an
    # incremental build proves that binary is already current.  The packaging
    # freshness gate below compares the two packaged binaries with the newest
    # workspace source, so a desktop shell unaffected by a newer engine change
    # would otherwise make every full package build fail as "stale".  A
    # successful cargo invocation is the authoritative dependency check; mark
    # both requested product outputs at that point.  This is intentionally
    # inside the non-skip path: prebuilt binaries still fail the guard.
    $applicationBuildStamp = [DateTime]::UtcNow
    foreach ($applicationOutput in @(
        (Join-Path $repositoryRoot "target\\release\\apiaxess.exe"),
        (Join-Path $repositoryRoot "target\\release\\apiaxess-desktop.exe")
    )) {
        if (Test-Path -LiteralPath $applicationOutput -PathType Leaf) {
            (Get-Item -LiteralPath $applicationOutput).LastWriteTimeUtc = $applicationBuildStamp
        }
    }
}

$engine = Join-Path $repositoryRoot "target\release\apiaxess.exe"
$desktop = Join-Path $repositoryRoot "target\release\apiaxess-desktop.exe"
$gui = Join-Path $repositoryRoot "apps\gui\dist"
if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) {
    throw "Release engine is missing at $engine. Build it first or omit -SkipApplicationBuild."
}
if (-not (Test-Path -LiteralPath $desktop -PathType Leaf)) {
    throw "Release desktop shell is missing at $desktop. Build it first or omit -SkipApplicationBuild."
}
if (-not (Test-Path -LiteralPath (Join-Path $gui "index.html") -PathType Leaf)) {
    throw "Built GUI is missing at $gui. Build it first or omit -SkipApplicationBuild."
}
$newestProductSource = Assert-ReleaseBinaryFreshness -RepositoryRoot $repositoryRoot -BinaryPaths @($engine, $desktop)

Reset-OwnedDirectory -Path $stageRoot -AllowedRoot (Join-Path $repositoryRoot "target")
Reset-OwnedDirectory -Path $intermediateRoot -AllowedRoot (Join-Path $repositoryRoot "target")
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

$stageBin = Join-Path $stageRoot "bin"
$stageGui = Join-Path $stageRoot "share\apiaxess\gui"
$stageRuntime = Join-Path $stageRoot "runtime"
New-Item -ItemType Directory -Path $stageBin, $stageGui, $stageRuntime -Force | Out-Null
Copy-Item -LiteralPath $engine -Destination (Join-Path $stageBin "apiaxess.exe")
# The native desktop shell is the double-click entry point; the Start Menu
# shortcut targets it (see Write-DirectoryContents) and it spawns the engine.
Copy-Item -LiteralPath $desktop -Destination (Join-Path $stageBin "apiaxess-desktop.exe")
# The WebView2 Evergreen Bootstrapper ships beside the desktop shell, which runs
# it install-if-missing so the app never opens to a blank window.
$webview2Directory = Join-Path $targetRoot "webview2"
& (Join-Path $repositoryRoot "packaging\assets\fetch-webview2.ps1") -OutputDirectory $webview2Directory
$webview2Bootstrapper = Join-Path $webview2Directory "MicrosoftEdgeWebview2Setup.exe"
if (-not (Test-Path -LiteralPath $webview2Bootstrapper -PathType Leaf)) {
    throw "The verified WebView2 bootstrapper is missing at $webview2Bootstrapper."
}
Copy-Item -LiteralPath $webview2Bootstrapper -Destination (Join-Path $stageBin "MicrosoftEdgeWebview2Setup.exe")
Copy-Item -Path (Join-Path $gui "*") -Destination $stageGui -Recurse -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot "README.md") -Destination (Join-Path $stageRoot "README.md")

if (-not $ChromiumRuntimeDirectory) {
    $ChromiumRuntimeDirectory = Join-Path $targetRoot "chromium-runtime"
    & (Join-Path $repositoryRoot "packaging\assets\fetch-chromium.ps1") `
        -Platform "windows_x64" `
        -OutputDirectory $ChromiumRuntimeDirectory `
        -CacheDirectory $cacheRoot
}
$chromiumBinary = Join-Path $ChromiumRuntimeDirectory "chrome.exe"
if (-not (Test-Path -LiteralPath $chromiumBinary -PathType Leaf)) {
    throw "Verified Chromium runtime is missing chrome.exe at $chromiumBinary."
}
foreach ($requiredChromiumFile in @("APIaxess-NOTICES.md", "about-credits.html", "chromium-sbom.json")) {
    if (-not (Test-Path -LiteralPath (Join-Path $ChromiumRuntimeDirectory $requiredChromiumFile) -PathType Leaf)) {
        throw "Verified Chromium runtime is missing its release record $requiredChromiumFile."
    }
}
$stageChromium = Join-Path $stageRuntime "chromium"
Copy-Item -LiteralPath $ChromiumRuntimeDirectory -Destination $stageChromium -Recurse -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot "packaging\assets\chromium-NOTICES.md") -Destination (Join-Path $stageChromium "APIaxess-NOTICES.md")
$chromiumSbom = Get-Content -LiteralPath (Join-Path $ChromiumRuntimeDirectory "chromium-sbom.json") -Raw | ConvertFrom-Json

# --- Bundled Java runtime (Phase 11.1): the one shared, trimmed OpenJDK ---
# Staged at runtime\java\windows so plugins/targets/apk/src/bundled.rs resolves
# <install>\runtime\java\windows\bin\java.exe from the installed apiaxess.exe.
$javaRuntimeDirectory = Join-Path $targetRoot "java-runtime"
& (Join-Path $repositoryRoot "packaging\assets\fetch-java-runtime.ps1") `
    -Platform "windows_x64" `
    -OutputDirectory $javaRuntimeDirectory `
    -CacheDirectory $cacheRoot
$javaBinary = Join-Path $javaRuntimeDirectory "bin\java.exe"
if (-not (Test-Path -LiteralPath $javaBinary -PathType Leaf)) {
    throw "Bundled Java runtime is missing bin\java.exe at $javaRuntimeDirectory."
}
$stageJavaParent = Join-Path $stageRuntime "java"
New-Item -ItemType Directory -Path $stageJavaParent -Force | Out-Null
Copy-Item -LiteralPath $javaRuntimeDirectory -Destination (Join-Path $stageJavaParent "windows") -Recurse -Force
$javaSbom = Get-Content -LiteralPath (Join-Path $javaRuntimeDirectory "java-runtime-sbom.json") -Raw | ConvertFrom-Json

# --- Bundled apktool + jadx (Phase 11.1) ---
# Staged at tools\apktool\apktool.jar and tools\jadx\lib\*-all.jar.
$stageTools = Join-Path $stageRoot "tools"
New-Item -ItemType Directory -Path $stageTools -Force | Out-Null
$apkToolsDirectory = Join-Path $targetRoot "apk-tools"
& (Join-Path $repositoryRoot "packaging\assets\fetch-apk-tools.ps1") `
    -OutputDirectory $apkToolsDirectory `
    -CacheDirectory $cacheRoot
$apktoolJar = Join-Path $apkToolsDirectory "apktool\apktool.jar"
if (-not (Test-Path -LiteralPath $apktoolJar -PathType Leaf)) {
    throw "Bundled apktool is missing apktool.jar at $apkToolsDirectory."
}
# Copy apktool/, jadx/, and the shared NOTICES + SBOM into tools\.
Get-ChildItem -LiteralPath $apkToolsDirectory | Copy-Item -Destination $stageTools -Recurse -Force
$stagedJadxAllJar = Get-ChildItem -LiteralPath (Join-Path $stageTools "jadx\lib") -Filter "*-all.jar" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name.ToLowerInvariant() -like "*jadx*" } | Select-Object -First 1
if ($null -eq $stagedJadxAllJar) {
    throw "Bundled jadx is missing a jadx *-all.jar under tools\jadx\lib."
}
$apkToolsSbom = Get-Content -LiteralPath (Join-Path $apkToolsDirectory "apk-tools-sbom.json") -Raw | ConvertFrom-Json

# --- Bundled ffuf (Phase 11.2): static discovery binary ---
# Staged at tools\ffuf\ffuf.exe for crates/workbench-proxy/src/bundled.rs.
$ffufRuntimeDirectory = Join-Path $targetRoot "ffuf-runtime"
& (Join-Path $repositoryRoot "packaging\assets\fetch-ffuf.ps1") `
    -Platform "windows_x64" `
    -OutputDirectory $ffufRuntimeDirectory `
    -CacheDirectory $cacheRoot
$ffufBinary = Join-Path $ffufRuntimeDirectory "ffuf.exe"
if (-not (Test-Path -LiteralPath $ffufBinary -PathType Leaf)) {
    throw "Bundled ffuf is missing ffuf.exe at $ffufRuntimeDirectory."
}
Copy-Item -LiteralPath $ffufRuntimeDirectory -Destination (Join-Path $stageTools "ffuf") -Recurse -Force
$ffufSbom = Get-Content -LiteralPath (Join-Path $ffufRuntimeDirectory "ffuf-sbom.json") -Raw | ConvertFrom-Json

# --- Bundled Frida host components (only the frida-embedded variant) ---
# Not resolved from a runtime install path (the devkit is a build/link input and
# the device-side server ships inside the analysis-runtime image), but staged for
# provenance and the wxWindows notice when the linked variant is shipped.
$fridaSbom = $null
if ($BundleFrida) {
    if (-not $fridaRuntimeDirectory -or -not (Test-Path -LiteralPath $fridaRuntimeDirectory -PathType Container)) {
        throw "Frida bundling was requested but the fetched Frida runtime is missing."
    }
    Copy-Item -LiteralPath $fridaRuntimeDirectory -Destination (Join-Path $stageRoot "frida") -Recurse -Force
    $fridaSbomPath = Join-Path $fridaRuntimeDirectory "frida-sbom.json"
    if (Test-Path -LiteralPath $fridaSbomPath -PathType Leaf) {
        $fridaSbom = Get-Content -LiteralPath $fridaSbomPath -Raw | ConvertFrom-Json
    }
}

$nodeArchiveName = "node-v$NodeVersion-win-$Architecture.zip"
$nodeArchive = Join-Path $cacheRoot $nodeArchiveName
$nodeUri = "https://nodejs.org/dist/v$NodeVersion/$nodeArchiveName"
$archiveValid = (Test-Path -LiteralPath $nodeArchive -PathType Leaf) -and ((Get-FileHash -LiteralPath $nodeArchive -Algorithm SHA256).Hash -ieq $NodeArchiveSha256)
if (-not $archiveValid) {
    if (Test-Path -LiteralPath $nodeArchive) {
        Remove-Item -LiteralPath $nodeArchive -Force
    }
    Write-Host "Downloading hash-pinned Node.js $NodeVersion runtime..."
    Invoke-WebRequest -UseBasicParsing -Uri $nodeUri -OutFile $nodeArchive
}
$actualNodeHash = (Get-FileHash -LiteralPath $nodeArchive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualNodeHash -ne $NodeArchiveSha256.ToLowerInvariant()) {
    throw "Node.js archive hash mismatch. Expected $NodeArchiveSha256; got $actualNodeHash."
}

$nodeExtractRoot = Join-Path $targetRoot "node-extract"
Reset-OwnedDirectory -Path $nodeExtractRoot -AllowedRoot (Join-Path $repositoryRoot "target")
Expand-Archive -LiteralPath $nodeArchive -DestinationPath $nodeExtractRoot -Force
$extractedNode = Join-Path $nodeExtractRoot "node-v$NodeVersion-win-$Architecture"
$stageNode = Join-Path $stageRuntime "node"
Move-Item -LiteralPath $extractedNode -Destination $stageNode

$corepack = Join-Path $stageNode "corepack.cmd"
if (-not (Test-Path -LiteralPath $corepack -PathType Leaf)) {
    throw "The official Node.js archive does not contain Corepack at $corepack."
}
$previousCorepackHome = $env:COREPACK_HOME
$previousCorepackNetwork = $env:COREPACK_ENABLE_NETWORK
try {
    $env:COREPACK_HOME = Join-Path $stageNode "corepack-cache"
    $env:COREPACK_ENABLE_NETWORK = "1"
    Invoke-Checked $corepack "enable" "--install-directory" $stageNode
    Invoke-Checked $corepack "install" "--global" "pnpm@$PnpmVersion"
}
finally {
    $env:COREPACK_HOME = $previousCorepackHome
    $env:COREPACK_ENABLE_NETWORK = $previousCorepackNetwork
}

$runtimeLayout = [ordered]@{
    schemaVersion = 2
    node = "runtime/node/node.exe"
    nodeVersion = $NodeVersion
    nodeArchiveSha256 = $NodeArchiveSha256.ToLowerInvariant()
    pnpm = "runtime/node/pnpm.cmd"
    pnpmVersion = $PnpmVersion
    corepackHome = "runtime/node/corepack-cache"
    chromium = "runtime/chromium/chrome.exe"
    chromiumSource = "official-chromium-snapshots"
    java = "runtime/java/windows/bin/java.exe"
    javaRelease = $javaSbom.release
    apktool = "tools/apktool/apktool.jar"
    jadx = "tools/jadx/lib/$($stagedJadxAllJar.Name)"
    ffuf = "tools/ffuf/ffuf.exe"
    ffufVersion = $ffufSbom.version
    frida = $(if ($BundleFrida) { "frida/devkit/windows-x86_64" } else { $null })
    analysisRuntime = "analysis-runtime (separate optional download; APIAXESS_ANALYSIS_RUNTIME overrides)"
    desktop = "bin/apiaxess-desktop.exe"
    webview2Bootstrapper = "bin/MicrosoftEdgeWebview2Setup.exe"
}
$runtimeLayout | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stageRoot "runtime-layout.json") -Encoding utf8NoBOM

$wixDirectory = Join-Path $toolRoot "wix-$WixVersion"
$wix = Join-Path $wixDirectory "wix.exe"
if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) {
    New-Item -ItemType Directory -Path $wixDirectory -Force | Out-Null
    Invoke-Checked "dotnet" "tool" "install" "wix" "--tool-path" $wixDirectory "--version" $WixVersion
}
$reportedWixVersion = (& $wix --version).Trim()
if ($LASTEXITCODE -ne 0 -or -not $reportedWixVersion.StartsWith($WixVersion, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Expected WiX $WixVersion at $wix; found '$reportedWixVersion'."
}

# The branded wizard (Product.wxs references WixUI_Minimal) needs the WiX UI
# extension. Add it version-pinned so `wix build -ext` below resolves it.
Invoke-Checked $wix "extension" "add" "WixToolset.UI.wixext/$WixVersion"

$payloadFragment = Join-Path $targetRoot "Payload.wxs"
Write-WixPayloadFragment -StageDirectory $stageRoot -Destination $payloadFragment
$msiName = "APIaxess-$productVersion-windows-$Architecture.msi"
$msiPath = Join-Path $OutputDirectory $msiName
if (Test-Path -LiteralPath $msiPath) {
    Remove-Item -LiteralPath $msiPath -Force
}

$licenseRtf = Join-Path $PSScriptRoot "License.rtf"
if (-not (Test-Path -LiteralPath $licenseRtf -PathType Leaf)) {
    throw "The installer license is missing at $licenseRtf."
}
# Branded wizard graphics (identity-kit mark) referenced by Product.wxs as the
# WixUIBannerBmp / WixUIDialogBmp variables. Regenerate with
# scratchpad gen-installer-bmps if the mark changes.
$bannerBmp = Join-Path $PSScriptRoot "banner.bmp"
$dialogBmp = Join-Path $PSScriptRoot "dialog.bmp"
foreach ($brandBmp in @($bannerBmp, $dialogBmp)) {
    if (-not (Test-Path -LiteralPath $brandBmp -PathType Leaf)) {
        throw "The branded installer bitmap is missing at $brandBmp."
    }
}
Invoke-Checked $wix "build" (Join-Path $PSScriptRoot "Product.wxs") $payloadFragment "-arch" $Architecture "-ext" "WixToolset.UI.wixext" "-d" "ProductVersion=$productVersion" "-d" "ProductCode=$productCode" "-d" "LicenseRtf=$licenseRtf" "-d" "BannerBmp=$bannerBmp" "-d" "DialogBmp=$dialogBmp" "-bindpath" "Stage=$stageRoot" "-intermediateFolder" $intermediateRoot "-pdbtype" "none" "-out" $msiPath

$msiHash = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
"$msiHash  $msiName" | Set-Content -LiteralPath "$msiPath.sha256" -Encoding ascii
$buildManifest = [ordered]@{
    schemaVersion = 1
    product = "APIaxess"
    productVersion = $productVersion
    productCode = $productCode
    architecture = $Architecture
    wixVersion = $reportedWixVersion
    nodeVersion = $NodeVersion
    nodeArchiveSha256 = $NodeArchiveSha256.ToLowerInvariant()
    pnpmVersion = $PnpmVersion
    chromiumRevision = $chromiumSbom.revision
    chromiumArchiveSha256 = $chromiumSbom.archiveSha256
    bundledTools = [ordered]@{
        javaRelease = $javaSbom.release
        javaArchiveSha256 = $javaSbom.archiveSha256
        apktool = @($apkToolsSbom.components | Where-Object { $_.tool -eq "apktool" } | Select-Object -First 1).version
        jadx = @($apkToolsSbom.components | Where-Object { $_.tool -eq "jadx" } | Select-Object -First 1).version
        ffufVersion = $ffufSbom.version
        ffufArchiveSha256 = $ffufSbom.archiveSha256
        fridaVersion = $(if ($fridaSbom) { $fridaSbom.version } else { $null })
        fridaBundled = [bool]$BundleFrida
    }
    analysisRuntimeBundled = $false
    desktopShell = "tauri"
    webview2Bootstrapper = [ordered]@{
        bundled = $true
        source = "microsoft-evergreen-bootstrapper"
        signature = "authenticode-microsoft"
    }
    msi = $msiName
    msiSha256 = $msiHash
    productSourceCutoffUtc = $newestProductSource.LastWriteTimeUtc.ToString("o")
    engineSha256 = (Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant()
    desktopSha256 = (Get-FileHash -LiteralPath $desktop -Algorithm SHA256).Hash.ToLowerInvariant()
}
$buildManifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory "APIaxess-$productVersion-windows-$Architecture.build.json") -Encoding utf8NoBOM

Write-Host "Built $msiPath"
Write-Output $msiPath
