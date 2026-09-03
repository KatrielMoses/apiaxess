<#
.SYNOPSIS
  Resizes or screenshots the main window of a running process, by pid.

.DESCRIPTION
  The small Win32 half of the native responsive sweep. `native-drive.mjs` owns
  the loop and switches views over CDP; this does the two things only the OS can
  do — move/resize a real window, and capture it with its chrome.

.EXAMPLE
  pwsh -File tools/brand/native-window.ps1 -Action resize -ProcessId 1234 -Width 1440 -Height 900
  pwsh -File tools/brand/native-window.ps1 -Action capture -ProcessId 1234 -Path out.png
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidateSet("resize", "capture")][string]$Action,
  # `$Pid` is a read-only automatic variable in PowerShell.
  [Parameter(Mandatory = $true)][int]$ProcessId,
  [int]$Width,
  [int]$Height,
  [string]$Path
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeWin {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hgt, bool repaint);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

$proc = Get-Process -Id $ProcessId
$handle = $proc.MainWindowHandle
if ($handle -eq [IntPtr]::Zero) { throw "process $ProcessId has no main window" }

if ($Action -eq "resize") {
  [void][NativeWin]::MoveWindow($handle, 60, 40, $Width, $Height, $true)
  Start-Sleep -Milliseconds 350
  [void][NativeWin]::SetForegroundWindow($handle)
  Write-Output "resized to ${Width}x${Height}"
  return
}

[void][NativeWin]::SetForegroundWindow($handle)
Start-Sleep -Milliseconds 250
$rect = New-Object NativeWin+RECT
[void][NativeWin]::GetWindowRect($handle, [ref]$rect)
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
$bitmap = New-Object System.Drawing.Bitmap($w, $h)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
$bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()
Write-Output "captured ${w}x${h} -> $Path"
