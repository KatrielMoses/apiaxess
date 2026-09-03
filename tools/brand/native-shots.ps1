<#
.SYNOPSIS
  Resizes the APIaxess native window through a range of dimensions and captures
  the real window — chrome included — at each one.

.DESCRIPTION
  The web sweep in `ui-shots.mjs` proves the layout; this proves the layout
  survives inside the Tauri window, where the viewport is the window's client
  area and the operator changes it by dragging an edge rather than by emulating
  a viewport. Frames land in testers/assets/<Stamp>/.

  The shell is launched with WebView2 remote debugging on, so `native-drive.mjs`
  can walk the app's surfaces over CDP between resizes. That is a test affordance
  only: nothing in the shipped app enables it.

.EXAMPLE
  pwsh -File tools/brand/native-shots.ps1 -Stamp 2026-09-02_1320
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Stamp,
  [string]$Exe = "target/release/apiaxess-desktop.exe",
  [int]$DebugPort = 9222,
  # width,height pairs covering the same range the web sweep does, from the
  # window's minimum up to a large desktop.
  [string[]]$Sizes = @("1920,1080", "1440,900", "1280,800", "1024,768", "820,900", "640,900", "480,860"),
  [string]$Label = "native",
  [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hgt, bool repaint);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$outDir = Join-Path $root "testers/assets/$Stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$exePath = Join-Path $root $Exe
if (-not (Test-Path $exePath)) { throw "not built: $exePath" }

$env:APIAXESS_LAUNCH_MODE = "desktop"
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$DebugPort"

Write-Output "launching $exePath"
$proc = Start-Process -FilePath $exePath -PassThru

# The shell starts the engine before it builds the window, so the handle can
# take a few seconds to exist.
$handle = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  $proc.Refresh()
  if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $handle = $proc.MainWindowHandle; break }
}
if ($handle -eq [IntPtr]::Zero) { throw "the APIaxess window never appeared" }
Write-Output "window handle $handle"

[void][Win]::ShowWindow($handle, 9)   # SW_RESTORE
[void][Win]::SetForegroundWindow($handle)
Start-Sleep -Seconds 3

foreach ($size in $Sizes) {
  $parts = $size.Split(",")
  $w = [int]$parts[0]
  $h = [int]$parts[1]

  [void][Win]::MoveWindow($handle, 60, 40, $w, $h, $true)
  Start-Sleep -Milliseconds 900
  [void][Win]::SetForegroundWindow($handle)
  Start-Sleep -Milliseconds 600

  $rect = New-Object Win+RECT
  [void][Win]::GetWindowRect($handle, [ref]$rect)
  $rw = $rect.Right - $rect.Left
  $rh = $rect.Bottom - $rect.Top

  $bitmap = New-Object System.Drawing.Bitmap($rw, $rh)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
  $path = Join-Path $outDir "$Label`_$($w)x$($h).png"
  $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $graphics.Dispose()
  $bitmap.Dispose()

  Write-Output "captured ${w}x${h} (window ${rw}x${rh}) -> $path"
}

if ($KeepRunning) {
  Write-Output "left running as pid $($proc.Id); debug port $DebugPort"
} else {
  Stop-Process -Id $proc.Id -Force
  Write-Output "stopped pid $($proc.Id)"
}
