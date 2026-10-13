#!/usr/bin/env bash
# Split a combined operator+bundle Konflux Snapshot YAML into two single-component
# Snapshot YAMLs (operator-only and bundle-only). Writes files only — does not apply.
#
# Usage:
#   ./split-operator-snapshot.sh --base-snapshot ~/cmo_base.yaml
#   ./split-operator-snapshot.sh --base-snapshot ~/cmo_base.yaml \
#       --operator-snapshot-name cert-manager-operator-1-17 \
#       --bundle-snapshot-name cert-manager-operator-bundle-1-17 \
#       --outdir .
#
# Component names are auto-detected from spec.components[].name (must contain
# "operator" vs "bundle"). Override with --operator-component / --bundle-component.

set -euo pipefail

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

BASE_SNAPSHOT=""
OUTDIR="."
OPERATOR_SNAPSHOT_NAME=""
BUNDLE_SNAPSHOT_NAME=""
OPERATOR_COMPONENT=""
BUNDLE_COMPONENT=""
NAMESPACE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-snapshot) BASE_SNAPSHOT="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --operator-snapshot-name) OPERATOR_SNAPSHOT_NAME="$2"; shift 2 ;;
    --bundle-snapshot-name) BUNDLE_SNAPSHOT_NAME="$2"; shift 2 ;;
    --operator-component) OPERATOR_COMPONENT="$2"; shift 2 ;;
    --bundle-component) BUNDLE_COMPONENT="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown arg: $1" >&2; usage 1 ;;
  esac
done

if [[ -z "$BASE_SNAPSHOT" || ! -f "$BASE_SNAPSHOT" ]]; then
  echo "ERROR: --base-snapshot FILE is required and must exist" >&2
  usage 1
fi

command -v yq >/dev/null || { echo "ERROR: yq (mikefarah v4) is required" >&2; exit 1; }

mkdir -p "$OUTDIR"

mapfile -t COMPS < <(yq -r '.spec.components[].name' "$BASE_SNAPSHOT")
if [[ ${#COMPS[@]} -lt 1 ]]; then
  echo "ERROR: no components found in $BASE_SNAPSHOT" >&2
  exit 1
fi

if [[ -z "$OPERATOR_COMPONENT" ]]; then
  for c in "${COMPS[@]}"; do
    [[ "$c" == *bundle* ]] && continue
    if [[ "$c" == *operator* ]]; then
      OPERATOR_COMPONENT="$c"
      break
    fi
  done
fi
if [[ -z "$BUNDLE_COMPONENT" ]]; then
  for c in "${COMPS[@]}"; do
    if [[ "$c" == *bundle* ]]; then
      BUNDLE_COMPONENT="$c"
      break
    fi
  done
fi

if [[ -z "$OPERATOR_COMPONENT" || -z "$BUNDLE_COMPONENT" ]]; then
  echo "ERROR: could not detect operator/bundle components from: ${COMPS[*]}" >&2
  echo "       pass --operator-component and --bundle-component explicitly" >&2
  exit 1
fi

APP="$(yq -r '.spec.application // .metadata.labels."appstudio.openshift.io/application" // ""' "$BASE_SNAPSHOT")"
NS_FROM_FILE="$(yq -r '.metadata.namespace // "cert-manager-oape-tenant"' "$BASE_SNAPSHOT")"
NAMESPACE="${NAMESPACE:-$NS_FROM_FILE}"

OPERATOR_SNAPSHOT_NAME="${OPERATOR_SNAPSHOT_NAME:-${OPERATOR_COMPONENT}}"
BUNDLE_SNAPSHOT_NAME="${BUNDLE_SNAPSHOT_NAME:-${BUNDLE_COMPONENT}}"

OPERATOR_OUT="${OUTDIR}/${OPERATOR_SNAPSHOT_NAME}.yaml"
BUNDLE_OUT="${OUTDIR}/${BUNDLE_SNAPSHOT_NAME}.yaml"

emit_single() {
  local component="$1"
  local snap_name="$2"
  local outfile="$3"

  # Clone base, strip cluster-managed fields, keep only the selected component.
  yq eval "
    del(.metadata.uid, .metadata.resourceVersion, .metadata.generation,
        .metadata.creationTimestamp, .metadata.managedFields, .metadata.ownerReferences,
        .status) |
    .metadata.name = \"${snap_name}\" |
    .metadata.namespace = \"${NAMESPACE}\" |
    .metadata.labels.\"appstudio.openshift.io/application\" = \"${APP}\" |
    .metadata.labels.\"appstudio.openshift.io/component\" = \"${component}\" |
    .metadata.labels.\"test.appstudio.openshift.io/type\" = \"component\" |
    .spec.application = \"${APP}\" |
    .spec.artifacts = (.spec.artifacts // {}) |
    .spec.components |= map(select(.name == \"${component}\"))
  " "$BASE_SNAPSHOT" > "$outfile"

  local img digest url_no_digest
  img="$(yq -r ".spec.components[] | select(.name == \"${component}\") | .containerImage" "$BASE_SNAPSHOT")"
  if [[ "$img" == *"@"* ]]; then
    digest="${img##*@}"
    url_no_digest="${img%@*}"
    yq eval -i "
      .metadata.annotations.\"test.appstudio.openshift.io/result-image-digest\" = \"${digest}\" |
      .metadata.annotations.\"test.appstudio.openshift.io/result-image-url\" = \"${url_no_digest}\"
    " "$outfile"
  fi

  echo "Wrote $outfile (component=$component)"
}

emit_single "$OPERATOR_COMPONENT" "$OPERATOR_SNAPSHOT_NAME" "$OPERATOR_OUT"
emit_single "$BUNDLE_COMPONENT" "$BUNDLE_SNAPSHOT_NAME" "$BUNDLE_OUT"

echo
echo "Done. Review YAMLs before applying:"
echo "  $OPERATOR_OUT"
echo "  $BUNDLE_OUT"
