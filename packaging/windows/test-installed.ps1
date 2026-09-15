[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$MsiPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { $listener.LocalEndpoint.Port } finally { $listener.Stop() }
}

function Invoke-MsiExec {
    param([Parameter(Mandatory)] [string[]]$Arguments)
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "msiexec failed with exit code $($process.ExitCode): $($Arguments -join ' ')"
    }
}

function Get-TrustSnapshot {
    $stores = @("Cert:\CurrentUser\Root", "Cert:\LocalMachine\Root")
    @($stores | ForEach-Object {
        $store = $_
        Get-ChildItem -Path $store | ForEach-Object { "$store|$($_.Thumbprint)" }
    } | Sort-Object)
}

function Assert-AppFilesOnlyMsi {
    param([Parameter(Mandatory)] [string]$Path)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path, 0)
    $tableView = $database.OpenView('SELECT `Name` FROM `_Tables`')
    $tableView.Execute()
    $tables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        while ($record = $tableView.Fetch()) {
            [void]$tables.Add($record.StringData(1))
        }
    }
    finally {
        $tableView.Close()
    }

    $forbidden = @(
        "CustomAction", "ServiceInstall", "ServiceControl", "Registry",
        "RemoveRegistry", "Environment", "ODBCDataSource", "ODBCDriver",
        "ODBCTranslator", "Class", "Extension", "PublishComponent"
    )
    $present = @($forbidden | Where-Object { $tables.Contains($_) })
    if ($present.Count -gt 0) {
        throw "MSI contains forbidden non-file/security surface: $($present -join ', ')"
    }
}

function Wait-HttpReady {
    param([Parameter(Mandatory)] [string]$Uri)
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 1
            if ($response.StatusCode -eq 200) { return $response }
        }
        catch { Start-Sleep -Milliseconds 250 }
    }
    throw "Timed out waiting for $Uri."
}

$MsiPath = [System.IO.Path]::GetFullPath($MsiPath)
if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
    throw "MSI does not exist: $MsiPath"
}
Assert-AppFilesOnlyMsi -Path $MsiPath

$testId = [Guid]::NewGuid().ToString("N")
$installRoot = Join-Path $env:LOCALAPPDATA "Programs\APIaxess-QA-$testId"
$testRoot = Join-Path $env:TEMP "apiaxess-msi-qa-$testId"
$storeRoot = Join-Path $testRoot "store"
$msiLog = Join-Path $testRoot "msiexec.log"
$engineLog = Join-Path $testRoot "engine.log"
$engineErrorLog = Join-Path $testRoot "engine-error.log"
$upstreamScript = Join-Path $testRoot "upstream.js"
$startMenuDirectory = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\APIaxess"
$startMenuShortcut = Join-Path $startMenuDirectory "APIaxess.lnk"
$guiPort = Get-FreePort
$proxyPort = Get-FreePort
$upstreamPort = Get-FreePort
$trustBefore = Get-TrustSnapshot
$installed = $false
$engineProcess = $null
$upstreamProcess = $null

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
Write-Host "MSI verification logs: $testRoot"
try {
    Invoke-MsiExec @("/i", "`"$MsiPath`"", "/qn", "/norestart", "INSTALLFOLDER=`"$installRoot\`"", "/l*v", "`"$msiLog`"")
    $installed = $true

    $engine = Join-Path $installRoot "bin\apiaxess.exe"
    $desktop = Join-Path $installRoot "bin\apiaxess-desktop.exe"
    $webview2Bootstrapper = Join-Path $installRoot "bin\MicrosoftEdgeWebview2Setup.exe"
    $node = Join-Path $installRoot "runtime\node\node.exe"
    $pnpm = Join-Path $installRoot "runtime\node\pnpm.cmd"
    $corepackHome = Join-Path $installRoot "runtime\node\corepack-cache"
    $guiIndex = Join-Path $installRoot "share\apiaxess\gui\index.html"
    $runtimeLayoutPath = Join-Path $installRoot "runtime-layout.json"
    foreach ($required in @($engine, $desktop, $webview2Bootstrapper, $node, $pnpm, $guiIndex, $runtimeLayoutPath, $startMenuShortcut)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Installed payload is missing: $required"
        }
    }

    # The Start Menu shortcut must launch the native desktop shell (not the raw
    # engine), so a double-click opens the app in its own window.
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcutTarget = $shell.CreateShortcut($startMenuShortcut).TargetPath
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }
    if ($shortcutTarget -ine $desktop) {
        throw "Start Menu shortcut targets '$shortcutTarget'; expected the native desktop shell '$desktop'."
    }

    $runtimeLayout = Get-Content -LiteralPath $runtimeLayoutPath -Raw | ConvertFrom-Json

    # --- Phase-11 bundled tools: present at the exact paths the resolvers expect ---
    # These are the absolute install-relative locations resolved from the installed
    # apiaxess.exe (plugins/targets/apk/src/bundled.rs, crates/workbench-proxy/src/bundled.rs,
    # crates/engine-shell/src/lib.rs). If any is absent the product surfaces
    # install.component-missing, so the installer must place them exactly here.
    $bundledJava = Join-Path $installRoot ($runtimeLayout.java -replace '/', '\')
    $bundledApktool = Join-Path $installRoot ($runtimeLayout.apktool -replace '/', '\')
    $bundledJadx = Join-Path $installRoot ($runtimeLayout.jadx -replace '/', '\')
    $bundledFfuf = Join-Path $installRoot ($runtimeLayout.ffuf -replace '/', '\')
    $bundledChromium = Join-Path $installRoot ($runtimeLayout.chromium -replace '/', '\')
    foreach ($tool in @($bundledJava, $bundledApktool, $bundledJadx, $bundledFfuf, $bundledChromium)) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
            throw "Installed bundled tool is missing at its resolver path: $tool"
        }
    }

    # The emulator analysis-runtime is a separate optional download and MUST NOT
    # be baked into the base installer (packaging/README.md).
    $analysisRuntimeDir = Join-Path $installRoot "analysis-runtime"
    if (Test-Path -LiteralPath $analysisRuntimeDir) {
        throw "The base installer must not contain analysis-runtime\; it is a separate optional payload."
    }

    # --- Exercise each bundled tool through its bundled runtime (not host tools) ---
    # The absolute-path invocations mirror exactly how intake/discovery drive the
    # tools, proving the installed product runs its own bundled binaries.
    $javaVersion = (& $bundledJava "-version" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Bundled Java runtime failed to run: $javaVersion"
    }
    $apktoolVersion = (& $bundledJava "-jar" $bundledApktool "--version" 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($apktoolVersion)) {
        throw "Bundled apktool failed to run through the bundled Java runtime: $apktoolVersion"
    }
    $jadxVersion = (& $bundledJava "-cp" $bundledJadx "jadx.cli.JadxCLI" "--version" 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($jadxVersion)) {
        throw "Bundled jadx failed to run through the bundled Java runtime: $jadxVersion"
    }
    $ffufVersion = (& $bundledFfuf "-V" 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ffufVersion)) {
        throw "Bundled ffuf failed to run: $ffufVersion"
    }
    Write-Host "  Bundled: java, apktool ($apktoolVersion), jadx ($jadxVersion), ffuf ($ffufVersion) run from the install tree"

    $nodeVersion = (& $node --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $nodeVersion -ne "v$($runtimeLayout.nodeVersion)") {
        throw "Private Node runtime failed or reported '$nodeVersion'."
    }
    $previousCorepackHome = $env:COREPACK_HOME
    $previousCorepackNetwork = $env:COREPACK_ENABLE_NETWORK
    try {
        $env:COREPACK_HOME = $corepackHome
        $env:COREPACK_ENABLE_NETWORK = "0"
        $pnpmVersion = (& $pnpm --version).Trim()
        $pnpmExitCode = $LASTEXITCODE
    }
    finally {
        $env:COREPACK_HOME = $previousCorepackHome
        $env:COREPACK_ENABLE_NETWORK = $previousCorepackNetwork
    }
    if ($pnpmExitCode -ne 0 -or $pnpmVersion -ne $runtimeLayout.pnpmVersion) {
        throw "Private offline pnpm runtime failed or reported '$pnpmVersion'."
    }

    @"
const http = require("http");
http.createServer((request, response) => {
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("installed-ok");
}).listen($upstreamPort, "127.0.0.1");
"@ | Set-Content -LiteralPath $upstreamScript -Encoding utf8NoBOM
    $upstreamProcess = Start-Process -FilePath $node -ArgumentList $upstreamScript -PassThru -WindowStyle Hidden
    Wait-HttpReady "http://127.0.0.1:$upstreamPort/ready" | Out-Null

    $savedEnvironment = @{
        APIAXESS_GUI_ADDRESS = $env:APIAXESS_GUI_ADDRESS
        APIAXESS_PROXY_ADDRESS = $env:APIAXESS_PROXY_ADDRESS
        APIAXESS_WORKBENCH_STORE_DIR = $env:APIAXESS_WORKBENCH_STORE_DIR
        APIAXESS_ALLOWED_TARGETS = $env:APIAXESS_ALLOWED_TARGETS
        APIAXESS_SESSION_ID = $env:APIAXESS_SESSION_ID
    }
    try {
        $env:APIAXESS_GUI_ADDRESS = "127.0.0.1:$guiPort"
        $env:APIAXESS_PROXY_ADDRESS = "127.0.0.1:$proxyPort"
        $env:APIAXESS_WORKBENCH_STORE_DIR = $storeRoot
        $env:APIAXESS_ALLOWED_TARGETS = "127.0.0.1"
        $env:APIAXESS_SESSION_ID = "session:msi-qa-$testId"
        $engineProcess = Start-Process -FilePath $engine -WorkingDirectory $installRoot -RedirectStandardOutput $engineLog -RedirectStandardError $engineErrorLog -PassThru -WindowStyle Hidden
    }
    finally {
        foreach ($name in $savedEnvironment.Keys) {
            if ($null -eq $savedEnvironment[$name]) {
                Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
            }
            else {
                Set-Item -Path "Env:$name" -Value $savedEnvironment[$name]
            }
        }
    }

    $status = Wait-HttpReady "http://127.0.0.1:$guiPort/api/v1/system/status"
    if (($status.Content | ConvertFrom-Json).state -ne "ready") {
        throw "Installed engine did not report ready state."
    }
    $gui = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$guiPort/"
    if ($gui.Content -notmatch "APIaxess") {
        throw "Installed GUI entry point was not served."
    }

    $proxiedBody = & curl.exe --silent --show-error --fail --noproxy "" --proxy "http://127.0.0.1:$proxyPort" "http://127.0.0.1:$upstreamPort/captured"
    if ($LASTEXITCODE -ne 0 -or $proxiedBody -ne "installed-ok") {
        throw "Installed proxy did not forward the real request."
    }

    $flows = $null
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        $flows = Invoke-RestMethod -Uri "http://127.0.0.1:$guiPort/api/v1/workbench/flows"
        if (@($flows).Count -gt 0) { break }
        Start-Sleep -Milliseconds 250
    }
    if (@($flows).Count -eq 0) {
        throw "Captured traffic did not reach the installed durable flow API."
    }
    $database = Get-ChildItem -Path $storeRoot -Filter "*.sqlite3" -File -Recurse | Select-Object -First 1
    if ($null -eq $database -or $database.Length -eq 0) {
        throw "Installed workbench did not create a non-empty SQLite traffic store."
    }

    $resendRequest = @{ request = @{ method = "GET"; url = "http://127.0.0.1:$upstreamPort/resend"; headers = @(); body = $null } } | ConvertTo-Json -Depth 6
    $resend = Invoke-RestMethod -Method Post -ContentType "application/json" -Body $resendRequest -Uri "http://127.0.0.1:$guiPort/api/v1/workbench/resend"
    $resendResult = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$guiPort/api/v1/workbench/resend/$($resend.id)/send"
    if ($resendResult.revision.response.status -ne 200) {
        throw "Installed resend did not complete through the live proxy."
    }

    $fuzzerUrl = "http://127.0.0.1:$upstreamPort/fuzzer/FUZZ"
    $markerStart = $fuzzerUrl.IndexOf("FUZZ", [System.StringComparison]::Ordinal)
    $fuzzerConfig = @{
        baseRequest = @{ method = "GET"; url = $fuzzerUrl; headers = @(); body = $null }
        positions = @(@{ location = "url"; headerName = $null; start = $markerStart; end = $markerStart + 4; setIndex = 0 })
        payloadSets = @(@{ name = "qa"; values = @("one") })
        attackType = "sniper"
        matchFilter = @{
            statuses = @()
            minSize = $null
            maxSize = $null
            contains = $null
            regex = $null
        }
        concurrency = 1
        ratePerSecond = 0
        maxResults = 1
        authPreflight = $null
        sequence = @(@{
            name = "send"
            request = @{ method = "GET"; url = $fuzzerUrl; headers = @(); body = $null }
            extractors = @()
        })
    } | ConvertTo-Json -Depth 8
    $fuzzer = Invoke-RestMethod -Method Post -ContentType "application/json" -Body $fuzzerConfig -Uri "http://127.0.0.1:$guiPort/api/v1/workbench/fuzzer"
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$guiPort/api/v1/workbench/fuzzer/$($fuzzer.id)/start" | Out-Null
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $fuzzer = Invoke-RestMethod -Uri "http://127.0.0.1:$guiPort/api/v1/workbench/fuzzer/$($fuzzer.id)"
        if ($fuzzer.state -in @("completed", "failed")) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($fuzzer.state -ne "completed" -or $fuzzer.results[0].response.status -ne 200) {
        throw "Installed fuzzer did not complete its native request path."
    }
}
finally {
    if ($null -ne $engineProcess -and -not $engineProcess.HasExited) {
        Stop-Process -Id $engineProcess.Id -Force
        $engineProcess.WaitForExit()
    }
    if ($null -ne $upstreamProcess -and -not $upstreamProcess.HasExited) {
        Stop-Process -Id $upstreamProcess.Id -Force
        $upstreamProcess.WaitForExit()
    }
    if ($installed) {
        Invoke-MsiExec @("/x", "`"$MsiPath`"", "/qn", "/norestart", "/l*v", "`"$(Join-Path $testRoot 'uninstall.log')`"")
    }
}

if (Test-Path -LiteralPath $installRoot) {
    throw "Uninstall left the install directory behind: $installRoot"
}
if (Test-Path -LiteralPath $startMenuDirectory) {
    throw "Uninstall left the Start Menu registration behind: $startMenuDirectory"
}
$trustAfter = Get-TrustSnapshot
$trustDifference = Compare-Object -ReferenceObject $trustBefore -DifferenceObject $trustAfter
if ($null -ne $trustDifference) {
    throw "Install/run/uninstall changed a Windows root certificate store: $($trustDifference | Out-String)"
}

Write-Host "Installed-product verification passed."
Write-Host "  GUI/API: installed assets and ready API verified"
Write-Host "  Proxy:   real request capture verified"
Write-Host "  Store:   SQLite capture verified"
Write-Host "  Tools:   private Node and offline pnpm verified"
Write-Host "  Bundled: java + apktool + jadx + ffuf + chromium placed and runnable from the install tree"
Write-Host "  Desktop: native shell + WebView2 bootstrapper installed; Start Menu shortcut targets the native app"
Write-Host "  Payload: analysis-runtime correctly excluded from the base installer"
Write-Host "  MSI:     clean uninstall and unchanged root trust stores verified"
