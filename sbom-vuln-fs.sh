#!/bin/bash

# SBOM + CVE Scanning + Filesystem Digest Extraction
# Requirements: syft, grype, docker, jq, tar, sha256sum, find

# List of target container images across ecosystems
IMAGES=(
  # --- Debian-based base images ---
  "apache/devlake"          # Debian-based, Node.js + Go
  "mlflow/mlflow:latest"    # Python-based, built on Debian or Ubuntu
  "node:20"                 # Debian-based Node.js runtime

  # --- Alpine-based ---
  "ghost:latest"            # Alpine-based Node.js CMS
  "python:3.12-alpine"      # Python + Alpine
  "golang:1.22-alpine"      # Go + Alpine (small + statically compiled)

  # --- RPM-based ---
  "bitnami/spring-cloud-dataflow:latest"  # Java (Spring), uses RPM-based OS
  "redhat/ubi8:latest"      # Universal Base Image (RPM/Red Hat base)

  # --- Java / Maven Ecosystem ---
  "openjdk:21"              # Pure Java base, useful for Maven-based apps
  "bitnami/tomcat:latest"   # Java web app stack using Maven dependencies

  # --- Go Modules Ecosystem ---
  "influxdb:latest"         # Go-based, statically linked, common CVEs
  "prom/prometheus:latest"  # Pure Go, great for upstream Go CVE tracking

  # --- Python Ecosystem ---
  "python:3.12"             # CPython, good PyPI base
  "mlflow/mlflow:latest"    # Already included, data science toolchain
  "jupyter/scipy-notebook"  # Python-heavy image with scientific libs (e.g., numpy, pandas)

  # --- Node.js Ecosystem ---
  "airbyte/airbyte-server:latest"  # Complex Node + Java stack
  "strapi/strapi:latest"          # Node.js headless CMS with real npm deps

  # --- Multi-ecosystem / Complex stacks ---
  "airbyte/airbyte-webapp:latest" # Complementary UI for Airbyte server
)


OUTDIR="sbom_scans"
FSDIR_ROOT="fs_digests"
mkdir -p "$OUTDIR" "$FSDIR_ROOT"

for IMAGE in "${IMAGES[@]}"; do
    TAG_SAFE=$(echo "$IMAGE" | tr '/:' '_')
    echo -e "\n[+] Processing image: $IMAGE"

    # Step 1: Pull the image
    echo "[1] Pulling image..."
    docker pull "$IMAGE"

    # Step 2: Generate SBOM
    echo "[2] Generating SBOM..."
    syft "$IMAGE" -o json > "$OUTDIR/${TAG_SAFE}-sbom.json"

    # Step 3: Run Grype for vulnerability scan
    echo "[3] Running vulnerability scan..."
    grype sbom:"$OUTDIR/${TAG_SAFE}-sbom.json" -o json > "$OUTDIR/${TAG_SAFE}-vulns.json"

    # Step 4: Export container filesystem and generate digests
    echo "[4] Exporting filesystem and generating digests..."
    CID=$(docker create "$IMAGE")
    FSDIR="$FSDIR_ROOT/fs-$TAG_SAFE"
    DIGEST_FILE="$FSDIR_ROOT/$TAG_SAFE-sha256.txt"
    mkdir -p "$FSDIR"
    docker export "$CID" | tar -C "$FSDIR" -xf -
    docker rm "$CID"
    find "$FSDIR" -type f -exec sha256sum {} \; > "$DIGEST_FILE"

    echo "[✔] SBOM, CVE scan, and file digests completed for $IMAGE"
done

echo -e "\n All images processed. Results saved in $OUTDIR and $FSDIR_ROOT."
