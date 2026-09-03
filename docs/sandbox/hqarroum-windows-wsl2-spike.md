# HQarroum emulator spike — Windows 11 / WSL2

**Date:** 2026-08-19  
**Image:** `halimqarroum/docker-android:api-33`  
**Pulled digest:** `sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95`

## Headline

The rooted, headless, KVM-accelerated HQarroum emulator runs locally on this
Windows 11/WSL2/Docker Desktop machine. The local capstone did not complete
with the supplied `PlayRoom.apk`: installation failed because the file is a
base APK that declares required ABI/density splits, while no split APKs were
available. This is an APK fixture limitation, not an HQarroum/KVM/root failure.

## Evidence

| Gate | Result | Evidence |
|---|---|---|
| Windows/CPU | Pass | `Win32_OperatingSystem`: Windows 11 Pro, build 26200. CPU: 12th Gen Intel Core i5-12450H. Registry compatibility metadata says Windows 10, but Win32 and `systeminfo` identify Windows 11. |
| Hypervisor/WHPX | Pass | `systeminfo` reports a hypervisor detected; Android `emulator-check.exe accel` reports `WHPX ... is installed and usable`. Optional-feature state could not be queried without elevation. |
| WSL2 | Pass | Ubuntu default version 2; kernel `6.18.33.2-microsoft-standard-WSL2`. |
| WSL `/dev/kvm` | Pass after permission fix | Initially `root:kvm` mode 660 and inaccessible. Added user `katriel` to `kvm` through the WSL root account and restarted Ubuntu; `/dev/kvm` then became readable/writable. `/etc/wsl.conf` did not require editing. |
| Docker Desktop | Pass | Docker Desktop 4.52.0, Engine 29.0.1, Linux/amd64, WSL2 kernel backend. The Docker CLI run was from Windows PowerShell; after the WSL restart, the Ubuntu shell did not have the Docker CLI on PATH. |
| Image pull | Pass | Pull completed with the digest above. |
| HQarroum boot | Pass | Base run booted in about 104 seconds. `EXTRA_FLAGS=-writable-system` run logged `Boot completed in 92241 ms`. |
| KVM vs TCG | Pass — KVM | The live QEMU process held `/dev/kvm`, `anon_inode:kvm-vm`, and four `anon_inode:kvm-vcpu:*` descriptors. Container `emulator -accel-check` reported `KVM (version 12) is installed and usable`. |
| Loopback ADB | Pass | `adb connect 127.0.0.1:5555` attached as `device`; Docker port mapping was `5555/tcp -> 127.0.0.1:5555`. |
| Root/debuggable | Pass | `ro.build.type=userdebug`; `ro.debuggable=1`; `adb root` restarted adbd as root and `id` reported `uid=0(root)`. |
| Base remount | Fail | Without extra flags, `adb remount` exited 10; AVB/overlay remount errors were reported and the CA directory remained read-only. |
| Writable-system variant | Pass | With `EXTRA_FLAGS=-writable-system`, `adb remount` succeeded but required reboot. After reboot, `adb root` followed by a second `adb remount` produced an `rw` overlay on `/system`; writing/removing a probe file under `/system/etc/security/cacerts/` succeeded. |
| APK capstone install | Blocked by fixture | `adb install -r -d target/PlayRoom.apk` failed with `INSTALL_FAILED_MISSING_SPLIT`. The manifest declares `android:requiredSplitTypes="base__abi,base__density"`; only the base APK was supplied. |

## Exact run configuration

Base:

```text
docker run --detach --rm --name apiaxess-hqarroum-spike \
  --device /dev/kvm \
  --publish 127.0.0.1:5555:5555 \
  halimqarroum/docker-android@sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95
```

Writable-system retry added:

```text
--env EXTRA_FLAGS=-writable-system
```

The named spike container was stopped and removed. The image remains pulled;
no unrelated Docker containers were changed.

## Capstone boundary

The capstone could not reach API traffic, CA injection, pinning bypass, or
dynamic model writes because the supplied APK could not be installed. The
APIaxess APK intake runner also reports a missing `jadx` tool in this checkout.
No APK split reconstruction or license/anti-tamper bypass was attempted.

For a definitive local capstone run, provide either a universal APK or the
complete base/config/ABI/density split set, plus `jadx` for static intake. The
HQarroum runtime itself is locally viable; remote-offload is not required for
this emulator/KVM/root capability.
