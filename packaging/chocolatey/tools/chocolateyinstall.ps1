$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/KatrielMoses/apiaxess/releases/download/v0.1.0/APIaxess-0.1.0-windows-x64.msi'
  checksum64     = '0000000000000000000000000000000000000000000000000000000000000000'
  checksumType64 = 'sha256'
  softwareName   = 'APIaxess'
  # Per-user MSI: installs to %LOCALAPPDATA%\Programs\APIaxess of the user
  # running choco. Silent mode skips the finish-page "Launch APIaxess" action.
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
