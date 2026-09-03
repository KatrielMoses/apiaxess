<#
.SYNOPSIS
    Acquires the Microsoft Edge WebView2 Evergreen Bootstrapper (~2 MB).

.DESCRIPTION
    Downloads the official Evergreen Bootstrapper stub and verifies it is a valid
    Microsoft-Authenticode-signed executable. The bootstrapper is deliberately
    "evergreen" (Microsoft updates it in place), so it has no stable published
    SHA-256 to pin; the trust anchor is the Microsoft code signature instead. The
    native desktop shell runs it install-if-missing so a machine that shipped
    without the WebView2 runtime never opens to a blank window.

    Windows-only: the bootstrapper is a Windows executable. On Linux the webview
    dependency is WebKitGTK, declared as a .deb dependency instead.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$Url = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Utf8NoBom {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repositoryRoot "target/packaging/webview2" }
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { Remove-Item -LiteralPath $OutputDirectory -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$bootstrapper = Join-Path $OutputDirectory "MicrosoftEdgeWebview2Setup.exe"
Write-Host "Downloading the WebView2 Evergreen Bootstrapper..."
Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $bootstrapper

if (-not (Test-Path -LiteralPath $bootstrapper -PathType Leaf) -or (Get-Item -LiteralPath $bootstrapper).Length -lt 512000) {
    throw "The WebView2 bootstrapper download is missing or implausibly small."
}

# The evergreen stub has no stable hash; verify the Microsoft Authenticode
# signature as the integrity anchor.
$signature = Get-AuthenticodeSignature -LiteralPath $bootstrapper
if ($signature.Status -ne "Valid") {
    throw "The WebView2 bootstrapper Authenticode signature is not valid: $($signature.Status)."
}
$subject = $signature.SignerCertificate.Subject
if ($subject -notmatch "Microsoft Corporation") {
    throw "The WebView2 bootstrapper is not signed by Microsoft Corporation: $subject."
}

$hash = (Get-FileHash -LiteralPath $bootstrapper -Algorithm SHA256).Hash.ToLowerInvariant()
$sbom = [ordered]@{
    schemaVersion = 1
    component     = "Microsoft Edge WebView2 Evergreen Bootstrapper"
    source        = $Url
    signature     = "Authenticode (Microsoft Corporation)"
    signerSubject = $subject
    observedSha256 = $hash
    note          = "Evergreen stub; Microsoft updates it in place, so the trust anchor is the code signature, not a pinned hash."
} | ConvertTo-Json -Depth 4
Write-Utf8NoBom -Path (Join-Path $OutputDirectory "webview2-sbom.json") -Content $sbom

Write-Host "Verified Microsoft-signed WebView2 bootstrapper at $bootstrapper"
