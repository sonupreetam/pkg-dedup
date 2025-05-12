#!/bin/bash

# Script: Correlate SBOM vs Filesystem Digests
# Requirements: grep, sort, uniq, comm

SBOMS=(
  "amazonlinux_2"
  "gitlab_gitlab-ce_latest"
  "nginx_alpine"
  "node_18"
  "python_3.11"
)

SBOM_DIR="sbom_scans"
FS_DIR="fs_digests"
OUT_DIR="correlation_outputs"
mkdir -p "$OUT_DIR"

for SAFE_NAME in "${SBOMS[@]}"; do
  echo "\n[+] Correlating: $SAFE_NAME"

  SBOM_FILE="$SBOM_DIR/${SAFE_NAME}-sbom.json"
  FS_DIGEST_FILE="$FS_DIR/${SAFE_NAME}-sha256.txt"
  SBOM_DIGESTS="$OUT_DIR/$SAFE_NAME-sbom-digests.txt"
  FS_DIGESTS="$OUT_DIR/$SAFE_NAME-fs-digests.txt"

   echo "Extract SHA256 from SBOM"
  grep -o '[a-f0-9]\{64\}' "$SBOM_FILE" | sort | uniq > "$SBOM_DIGESTS"

  echo "Extract SHA256 from actual filesystem"
  cut -d ' ' -f 1 "$FS_DIGEST_FILE" | sort | uniq > "$FS_DIGESTS"

  echo "Comparing SBOM and filesystem digests..."
  comm -23 "$SBOM_DIGESTS" "$FS_DIGESTS" > "$OUT_DIR/$SAFE_NAME-deleted-in-fs.txt"
  comm -13 "$SBOM_DIGESTS" "$FS_DIGESTS" > "$OUT_DIR/$SAFE_NAME-orphaned-in-fs.txt"

  echo "[✔] Output written to:"
  echo "    - Deleted in FS:   $OUT_DIR/$SAFE_NAME-deleted-in-fs.txt"
  echo "    - Orphaned in FS:  $OUT_DIR/$SAFE_NAME-orphaned-in-fs.txt"
done

echo -e "\n Correlation completed for all SBOMs. Output in $OUT_DIR/"