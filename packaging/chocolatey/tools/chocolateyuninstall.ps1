$ErrorActionPreference = 'Stop'

[array]$keys = Get-UninstallRegistryKey -SoftwareName 'APIaxess'

if ($keys.Count -eq 1) {
  $keys | ForEach-Object {
    $packageArgs = @{
      packageName    = $env:ChocolateyPackageName
      fileType       = 'msi'
      silentArgs     = "$($_.PSChildName) /qn /norestart"
      file           = ''
      validExitCodes = @(0, 3010, 1605, 1614, 1641)
    }
    Uninstall-ChocolateyPackage @packageArgs
  }
}
elseif ($keys.Count -eq 0) {
  Write-Warning "$env:ChocolateyPackageName has already been uninstalled by other means."
}
else {
  Write-Warning "$($keys.Count) matches found; not uninstalling to avoid removing the wrong software:"
  $keys | ForEach-Object { Write-Warning "- $($_.DisplayName)" }
}
