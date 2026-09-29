[CmdletBinding()]
param(
    # Directory holding the release assets (MSI, portable zip, .deb). SHA256SUMS
    # is written into the same directory.
    [Parameter(Mandatory)] [string]$Directory
)

# Writes SHA256SUMS in the GNU coreutils format ("<hash>  <file>", LF endings),
# so Linux users can run `sha256sum -c SHA256SUMS` and Windows users can compare
# against `Get-FileHash <file> -Algorithm SHA256`. Mirrors gen-checksums.sh.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = [System.IO.Path]::GetFullPath($Directory)
[string[]]$names = @(Get-ChildItem -LiteralPath $root -File |
    Where-Object { $_.Extension -in ".msi", ".zip", ".deb" } |
    ForEach-Object Name)
if ($names.Count -eq 0) {
    throw "No release assets (*.msi, *.zip, *.deb) found in $root."
}
# Byte order, matching `LC_ALL=C sort` in gen-checksums.sh.
[System.Array]::Sort($names, [System.StringComparer]::Ordinal)

$lines = foreach ($name in $names) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name"
}
$sumsPath = Join-Path $root "SHA256SUMS"
[System.IO.File]::WriteAllText($sumsPath, (($lines -join "`n") + "`n"), [System.Text.Encoding]::ASCII)
Get-Content -LiteralPath $sumsPath
