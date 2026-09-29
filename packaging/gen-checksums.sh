#!/usr/bin/env bash
# Writes SHA256SUMS for the release assets (*.msi, *.zip, *.deb) in a directory,
# in the GNU coreutils format so users can run `sha256sum -c SHA256SUMS`.
# Mirrors gen-checksums.ps1.
#
#   bash packaging/gen-checksums.sh <release-directory>
set -euo pipefail

directory="${1:?usage: gen-checksums.sh <release-directory>}"
cd "$directory"

shopt -s nullglob
assets=(*.msi *.zip *.deb)
if [ "${#assets[@]}" -eq 0 ]; then
    echo "No release assets (*.msi, *.zip, *.deb) found in $directory." >&2
    exit 1
fi

# Format each line explicitly: some sha256sum builds (Git Bash) default to
# binary mode and emit "<hash> *<file>".
printf '%s\n' "${assets[@]}" | LC_ALL=C sort | while IFS= read -r asset; do
    printf '%s  %s\n' "$(sha256sum "$asset" | cut -d' ' -f1)" "$asset"
done > SHA256SUMS
cat SHA256SUMS
