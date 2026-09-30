$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/KatrielMoses/apiaxess/releases/download/v0.1.0/APIaxess-0.1.0-windows-x64.msi'
  checksum64     = 'edfa4f71836f917241b6b81c76dde5a5b3236ff3ab4c5745f00b56cdfc079c03'
  checksumType64 = 'sha256'
  softwareName   = 'APIaxess'
  # Per-user MSI: installs to %LOCALAPPDATA%\Programs\APIaxess of the user
  # running choco. Silent mode skips the finish-page "Launch APIaxess" action.
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs

# Tell the in-app updater this copy is Chocolatey's, so it shows
# `choco upgrade apiaxess` rather than running an MSI update itself.
$installChannel = Join-Path $env:LOCALAPPDATA 'Programs\APIaxess\install-channel'
if (Test-Path -LiteralPath (Split-Path -Parent $installChannel)) {
  Set-Content -LiteralPath $installChannel -Value 'chocolatey' -NoNewline -Encoding ascii
}
