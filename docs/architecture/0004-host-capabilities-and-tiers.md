# ADR 0004: Host capabilities and dynamic tiers

**Status:** accepted at structural level

## Supported hosts

Linux is primary. Windows receives native static analysis and workbench support.
The packaging goals are `.deb`/APT for Linux and MSI or native `.exe` installer
for Windows. macOS is out of scope.

## Capability model

Features declare required and optional capability IDs before planning work. The
host-capability service in `crates/host-capabilities` evaluates those declarations
and returns supported, degraded, or unavailable with human-readable evidence and
remediation. OS names are observations, not capability checks.

Examples of future capability IDs include native KVM acceleration, nested
virtualization, WSL2 integration, Docker availability, Android image availability,
privileged packet operations, and remote sandbox reachability. IDs and result
types are defined with the data/contracts work, not in 0.1.

No caller may interpret “detector returned nothing” as support. Unknown and probe
failure are explicit non-supported states. Capability evidence is included in job
provenance so degraded results cannot be mistaken for full-tier results.

## Rungs

1. **Full:** Linux host with KVM and the local dynamic prerequisites.
2. **Offloaded:** any supported local host using a reachable Linux sandbox host;
   results and the authoritative project remain local.
3. **Windows/WSL2:** supported integration with explicitly reported limitations.
4. **Static/workbench:** Linux or Windows without dynamic prerequisites.

Selection is capability-driven rather than hard-coded by OS. A missing rung does
not break static analysis or the workbench. The planner exposes the chosen rung,
missing requirements, and available fallback before executing.

