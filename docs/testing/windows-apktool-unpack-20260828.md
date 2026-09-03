# Windows Feeder apktool unpack measurement

The Feeder 2.22.0 APK (`fixtures/capstone/feeder-2.22.0-4050.apk`, 63,130,759
bytes) was decoded into new NTFS directories on 2026-08-28 with apktool 2.9.3.
The production argument shape was measured independently of APIaxess static
analysis:

```text
apktool d --force --output <new-directory> feeder-2.22.0-4050.apk
```

The first run completed in 31.926 seconds and produced 18,250 files totaling
216,917,181 bytes. A second exploratory run with `--no-debug-info` completed in
98.086 seconds and produced the same file count and 182,082,711 bytes. The large
variance confirms Windows filesystem/host contention, but neither run approached
the existing 300-second deadline. Removing debug information did not demonstrate
a speed improvement and is not used by the product.

The failed release-QA artifact recorded `apktool unpack: exceeded 300s deadline`.
The installed `C:\Windows\apktool.bat` ends with a conditional `pause` whenever
`%CMDCMDLINE%` contains `/c`. Windows launches batch tools through that command
processor form. APIaxess now gives all `.bat`/`.cmd` external tools an explicit
non-interactive command context, preventing a completed tool from waiting at a
wrapper prompt. The 300-second hard bound remains unchanged. The external-tool
runner emits a heartbeat every 30 seconds with elapsed and deadline seconds so a
long invocation remains legible.

This is an orchestration fix; APIaxess still invokes the upstream apktool and
does not duplicate its decoder. A fresh product run must use a new intake root
to verify the boundary rather than reopening an existing normalized artifact.

