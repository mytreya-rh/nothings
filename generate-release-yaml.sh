#!/usr/bin/env bash
# Generate a Konflux Release YAML with RHSA CVE notes by comparing from/to images.
# Fixed CVE IDs come from compare-cves.sh (stdlib Brew backports, sustaining-fork
# release notes and upstream base, then the Red Hat portal HTTP 200 filter).
# Writes a YAML file only — does not apply.
#
# Usage (single component):
#   ./generate-release-yaml.sh \
#     --component cert-manager-istio-csr-1-20 \
#     --snapshot cert-manager-istio-csr-1-20-20260928-100256-000 \
#     --from-image registry.redhat.io/...@sha256:OLD \
#     --to-image   quay.io/...@sha256:NEW \
#     --output cert-manager-istio-csr-1-20-1.yaml
#
# Usage (multi-component, e.g. jetstack + acmesolver — repeat --pair):
#   ./generate-release-yaml.sh \
#     --release-name jetstack-cert-manager-1-20-1-release-4 \
#     --release-plan jetstack-cert-manager-prod-1-20 \
#     --snapshot jetstack-cert-manager-1-20-20260928-100257-000 \
#     --pair jetstack-cert-manager-1-20=registry...@old,quay...@new \
#     --pair jetstack-cert-manager-acmesolver-1-20=registry...@old,quay...@new \
#     --include-packages \
#     --output jcm.yaml
#
# Env:
#   COMPARE_CVES_SH  path to compare-cves.sh (default: ~/compare-cves.sh).
#                    Each pair is compared by that script. With --include-packages,
#                    package names are read from the old-image Trivy report it copies out.

set -euo pipefail

usage() {
  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

RELEASE_NAME=""
RELEASE_PLAN=""
SNAPSHOT=""
NAMESPACE="cert-manager-oape-tenant"
SEVERITY="Important"
TYPE="RHSA"
OUTPUT=""
INCLUDE_PACKAGES=0
# pairs: "component|from|to"
declare -a PAIRS=()

# Convenience single-component flags (appended as one pair)
COMPONENT=""
FROM_IMAGE=""
TO_IMAGE=""

# Normalize --flag=value into --flag value (so --output=foo.yaml keeps hyphens).
# Use longest %% so --pair=comp=from,to keeps the value after the first '='.
normalize_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --*=*)
      normalize_args+=("${1%%=*}" "${1#*=}")
      shift
      ;;
    *)
      normalize_args+=("$1")
      shift
      ;;
  esac
done
set -- "${normalize_args[@]}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-name) RELEASE_NAME="$2"; shift 2 ;;
    --release-plan) RELEASE_PLAN="$2"; shift 2 ;;
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --type) TYPE="$2"; shift 2 ;;
    --output|-o)
      OUTPUT="$2"
      # Guard: people sometimes type pair-style name=... for -o by mistake
      if [[ "$OUTPUT" == *"="* && "$OUTPUT" != *"/"* ]]; then
        echo "WARNING: --output contains '=': $OUTPUT" >&2
        echo "         (did you mean hyphens? e.g. jetstack-cert-manager-1-17-2.yaml)" >&2
        OUTPUT="${OUTPUT/=/-}"
        echo "         using: $OUTPUT" >&2
      fi
      shift 2
      ;;
    --include-packages) INCLUDE_PACKAGES=1; shift ;;
    --component) COMPONENT="$2"; shift 2 ;;
    --from-image) FROM_IMAGE="$2"; shift 2 ;;
    --to-image) TO_IMAGE="$2"; shift 2 ;;
    --pair)
      # format: component=fromImage,toImage
      raw="$2"; shift 2
      comp="${raw%%=*}"
      rest="${raw#*=}"
      from="${rest%%,*}"
      to="${rest#*,}"
      if [[ -z "$comp" || -z "$from" || -z "$to" || "$from" == "$to" ]]; then
        echo "ERROR: --pair expects component=fromImage,toImage" >&2
        exit 1
      fi
      PAIRS+=("${comp}|${from}|${to}")
      ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown arg: $1" >&2; usage 1 ;;
  esac
done

if [[ -n "$COMPONENT" ]]; then
  if [[ -z "$FROM_IMAGE" || -z "$TO_IMAGE" ]]; then
    echo "ERROR: --component requires --from-image and --to-image" >&2
    usage 1
  fi
  PAIRS+=("${COMPONENT}|${FROM_IMAGE}|${TO_IMAGE}")
fi

if [[ ${#PAIRS[@]} -eq 0 ]]; then
  echo "ERROR: provide --component/--from-image/--to-image and/or --pair" >&2
  usage 1
fi
if [[ -z "$SNAPSHOT" ]]; then
  echo "ERROR: --snapshot is required" >&2
  usage 1
fi

# Defaults derived from first component
FIRST_COMP="${PAIRS[0]%%|*}"
if [[ -z "$RELEASE_PLAN" ]]; then
  # cert-manager-istio-csr-1-20 -> cert-manager-istio-csr-prod-1-20
  # jetstack-cert-manager-1-20 -> jetstack-cert-manager-prod-1-20
  # cert-manager-operator-1-20 -> cert-manager-operator-prod-1-20
  if [[ "$FIRST_COMP" =~ ^(.+)-([0-9]+-[0-9]+)$ ]]; then
    RELEASE_PLAN="${BASH_REMATCH[1]}-prod-${BASH_REMATCH[2]}"
  else
    RELEASE_PLAN="${FIRST_COMP}-prod"
  fi
fi
if [[ -z "$RELEASE_NAME" ]]; then
  # strip trailing stream digits for a tidy name, append -release
  RELEASE_NAME="${FIRST_COMP}-release"
fi
if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${RELEASE_NAME}.yaml"
fi

COMPARE_CVES_SH="${COMPARE_CVES_SH:-$HOME/compare-cves.sh}"
if [[ ! -x "$COMPARE_CVES_SH" ]]; then
  echo "ERROR: $COMPARE_CVES_SH is not executable" >&2
  exit 1
fi
if [[ "$INCLUDE_PACKAGES" -eq 1 ]]; then
  command -v jq >/dev/null || { echo "ERROR: jq is required for --include-packages" >&2; exit 1; }
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Returns newline-separated fixed CVE IDs (Red Hat filtered) on stdout.
# Side-effect: writes $WORKDIR/${safe}_old.json for package lookup.
# The compare-cves report goes to stderr so it is not mixed into the ID list.
scan_fixed_cves() {
  local component="$1"
  local from_img="$2"
  local to_img="$3"
  local safe dest
  safe="$(echo "$component" | tr '/:' '__')"
  dest="$WORKDIR/${safe}_compare"
  mkdir -p "$dest"

  echo "Comparing images for $component ..." >&2
  COMPARE_CVES_RESULT_DIR="$dest" "$COMPARE_CVES_SH" "$from_img" "$to_img" >&2

  cp -f "$dest/old.json" "$WORKDIR/${safe}_old.json"

  if [[ ! -s "$dest/fixed-cves.txt" ]]; then
    echo "WARNING: no Red Hat-tracked fixed CVEs for $component" >&2
    return 0
  fi

  cat "$dest/fixed-cves.txt"
}

# Packages for a CVE from the OLD scan of a component (PkgName unique).
packages_for_cve() {
  local safe="$1"
  local cve="$2"
  jq -r --arg cve "$cve" '
    .Results[]? | .Vulnerabilities[]? |
    select(.VulnerabilityID == $cve) | .PkgName
  ' "$WORKDIR/${safe}_old.json" | sort -u | grep -v '^$' || true
}

# Build CVE entries as a YAML fragment under temporary file.
CVE_YAML="$WORKDIR/cves.yaml"
: > "$CVE_YAML"
echo "cves:" > "$CVE_YAML"

TOTAL=0
for pair in "${PAIRS[@]}"; do
  IFS='|' read -r comp from to <<< "$pair"
  safe="$(echo "$comp" | tr '/:' '__')"

  scan_fixed_cves "$comp" "$from" "$to" > "$WORKDIR/${safe}_fixed.txt"
  mapfile -t FIXED < "$WORKDIR/${safe}_fixed.txt"
  if [[ ${#FIXED[@]} -eq 0 || -z "${FIXED[0]:-}" ]]; then
    continue
  fi

  for cve in "${FIXED[@]}"; do
    [[ -z "$cve" ]] && continue
    TOTAL=$((TOTAL + 1))
    {
      echo "  - key: ${cve}"
      echo "    component: ${comp}"
      if [[ "$INCLUDE_PACKAGES" -eq 1 ]]; then
        mapfile -t PKGS < <(packages_for_cve "$safe" "$cve")
        if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]:-}" ]]; then
          echo "    packages:"
          for p in "${PKGS[@]}"; do
            [[ -z "$p" ]] && continue
            echo "      - ${p}"
          done
        fi
      fi
    } >> "$CVE_YAML"
  done
done

if [[ "$TOTAL" -eq 0 ]]; then
  echo "ERROR: no fixed Red Hat CVEs found across all pairs; refusing to write empty Release" >&2
  exit 1
fi

# Assemble Release YAML
{
  cat <<EOF
apiVersion: appstudio.redhat.com/v1alpha1
kind: Release
metadata:
  name: ${RELEASE_NAME}
  namespace: ${NAMESPACE}
spec:
  releasePlan: ${RELEASE_PLAN}
  snapshot: ${SNAPSHOT}
  data:
    releaseNotes:
      type: ${TYPE}
      severity: ${SEVERITY}
EOF
  # indent cves block under releaseNotes (CVE_YAML starts with "cves:")
  sed 's/^/      /' "$CVE_YAML"
} > "$OUTPUT"

echo
echo "Wrote $OUTPUT ($TOTAL CVE entries)"
echo "  releasePlan: $RELEASE_PLAN"
echo "  snapshot:    $SNAPSHOT"
echo "  review before: oc apply -f $OUTPUT"
