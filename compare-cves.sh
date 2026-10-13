#!/usr/bin/env bash
set -euo pipefail

# Usage: ./compare-cves.sh <old-image> <new-image>
#
# Go stdlib CVEs that Trivy still reports after a rebuild are treated as fixed
# when every new-image binary Trivy flags was built with a Red Hat golang NVR
# whose Brew changelog lists that CVE, and the old image was not already covered.
# Trivy compares only the upstream Go version (v1.24.13) and drops the
# "(Red Hat 1.24.13-N.el9)" suffix, so the changelog check is what sees the backport.

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <old-image> <new-image>"
    exit 1
fi

OLD_IMAGE="$1"
NEW_IMAGE="$2"

# Check dependencies
for cmd in trivy jq comm curl go podman python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd is not installed."
        exit 1
    fi
done

trivy_version=$(trivy --version | awk '/^Version:/{print $2; exit}')
if [[ -z "$trivy_version" ]]; then
    echo "Error: could not read the trivy version."
    exit 1
fi
if ! printf '%s\n' "$trivy_version" | awk -F. -v min="0.75.0" '
    BEGIN { split(min, need, ".") }
    {
        split($0, got, ".")
        for (i = 1; i <= 3; i++) {
            g = got[i] + 0
            n = need[i] + 0
            if (g > n) exit 0
            if (g < n) exit 1
        }
        exit 0
    }
'; then
    echo "Error: trivy ${trivy_version} is older than 0.75.0."
    echo "Older Trivy drops every Go stdlib CVE for binaries built with Red Hat Go."
    exit 1
fi

case "$(uname -m)" in
    x86_64) GOARCH=amd64 ;;
    aarch64|arm64) GOARCH=arm64 ;;
    ppc64le) GOARCH=ppc64le ;;
    s390x) GOARCH=s390x ;;
    *)
        echo "Error: unsupported architecture $(uname -m)"
        exit 1
        ;;
esac
PLATFORM="linux/${GOARCH}"

# Temporary directory for scan results
WORK_DIR=$(mktemp -d)
PODMAN_CID=""
cleanup() {
    if [[ -n "${PODMAN_CID}" ]]; then
        podman rm -f "$PODMAN_CID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${WORK_DIR:-}" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

OLD_REPORT="$WORK_DIR/old.json"
NEW_REPORT="$WORK_DIR/new.json"

OLD_CVES="$WORK_DIR/old-cves.txt"
NEW_CVES="$WORK_DIR/new-cves.txt"

FIXED_CVES="$WORK_DIR/fixed-cves.txt"
ADDED_CVES="$WORK_DIR/added-cves.txt"
REMAINING_CVES="$WORK_DIR/remaining-cves.txt"
SKIPPED_CVES="$WORK_DIR/skipped-cves.txt"
OLD_STDLIB="$WORK_DIR/old-stdlib.tsv"
NEW_STDLIB="$WORK_DIR/new-stdlib.tsv"
OLD_NVR="$WORK_DIR/old-nvr.tsv"
NEW_NVR="$WORK_DIR/new-nvr.tsv"
BACKPORT_FIXED="$WORK_DIR/backport-fixed.txt"
EVIDENCE="$WORK_DIR/backport-evidence.txt"

# Keep only IDs that resolve on the Red Hat CVE portal.
# CVEs not accessible at https://access.redhat.com/security/cve/<id> must not be
# listed in release notes.
filter_redhat_accessible_cves() {
    local input_file="$1"
    local kept_file="$2"
    local skipped_file="$3"
    local status_file="$WORK_DIR/rh-cve-status.txt"
    local jobs="${RH_CVE_CHECK_JOBS:-15}"

    : > "$kept_file"
    : > "$skipped_file"
    : > "$status_file"

    if [[ ! -s "$input_file" ]]; then
        return 0
    fi

    echo "Checking Red Hat CVE accessibility for $(wc -l < "$input_file") fixed CVE(s)..."

    check_one() {
        local cve="$1"
        local code
        code=$(curl -sS -o /dev/null -w '%{http_code}' -L --max-time 20 \
            "https://access.redhat.com/security/cve/${cve}" || echo "000")
        echo "${code} ${cve}"
    }
    export -f check_one

    # shellcheck disable=SC2016
    xargs -P "$jobs" -I{} bash -c 'check_one "$@"' _ {} < "$input_file" \
        | LC_ALL=C sort > "$status_file"

    while read -r code cve; do
        [[ -z "${cve:-}" ]] && continue
        if [[ "$code" == "200" ]]; then
            echo "$cve" >> "$kept_file"
        else
            echo "$cve" >> "$skipped_file"
        fi
    done < "$status_file"

    LC_ALL=C sort -u -o "$kept_file" "$kept_file"
    LC_ALL=C sort -u -o "$skipped_file" "$skipped_file"
}

stdlib_findings() {
    local report="$1"
    local out="$2"
    jq -r '
        .Results[]?
        | .Target as $target
        | .Vulnerabilities[]?
        | select(.PkgName == "stdlib" and .VulnerabilityID != null and $target != null and $target != "")
        | [$target, .VulnerabilityID]
        | @tsv
    ' "$report" | LC_ALL=C sort -u > "$out"
}

# Copy each binary Trivy flagged for stdlib and record the Red Hat golang NVR
# embedded by the toolchain: go1.24.13 (Red Hat 1.24.13-12.el9).
collect_stdlib_nvrs() {
    local image="$1"
    local findings="$2"
    local out_tsv="$3"
    local dest="$4"
    local path container_path outfile line rel status nvr

    : > "$out_tsv"
    if [[ ! -s "$findings" ]]; then
        return 0
    fi

    mkdir -p "$dest"
    echo "Reading Go build info from ${image}..."
    PODMAN_CID=$(podman create --platform "$PLATFORM" "$image")

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        container_path="${path#./}"
        [[ "$container_path" == /* ]] || container_path="/${container_path}"
        outfile="${dest}/$(printf '%s' "$container_path" | tr '/' '_')"
        status="unreadable"
        nvr="-"
        if podman cp "${PODMAN_CID}:${container_path}" "$outfile" >/dev/null 2>&1; then
            line=$(go version -m "$outfile" 2>/dev/null | awk 'NR==1 { print; exit }' || true)
            # Stored in a variable so the ")" inside the group is not the end of [[ ]].
            local rh_re='\(Red Hat ([^)]+)\)'
            if [[ "$line" =~ $rh_re ]]; then
                rel="${BASH_REMATCH[1]}"
                if [[ "$rel" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z._+]+$ ]]; then
                    status="ok"
                    nvr="golang-${rel}"
                else
                    echo "Warning: unrecognized Red Hat Go version '${rel}' in ${path}" >&2
                fi
            elif [[ -n "$line" ]]; then
                status="no-redhat"
            else
                echo "Warning: could not read Go build info for ${path} in ${image}" >&2
            fi
        else
            echo "Warning: could not copy ${container_path} from ${image}" >&2
        fi
        printf '%s\t%s\t%s\n' "$path" "$status" "$nvr" >> "$out_tsv"
    done < <(cut -f1 "$findings" | LC_ALL=C sort -u)

    podman rm -f "$PODMAN_CID" >/dev/null
    PODMAN_CID=""
}

fetch_changelog() {
    local nvr="$1"
    local out="$2"
    python3 - "$nvr" "$out" <<'PY'
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

nvr, out = sys.argv[1], sys.argv[2]
hub = "https://brewhub.engineering.redhat.com/brewhub"


def call(method, params):
    body = (
        '<?xml version="1.0"?>'
        "<methodCall>"
        f"<methodName>{method}</methodName>"
        f"<params>{params}</params>"
        "</methodCall>"
    ).encode()
    req = urllib.request.Request(
        hub, data=body, headers={"Content-Type": "text/xml"}
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            payload = resp.read()
    except Exception as exc:
        raise SystemExit(f"Brew request failed for {nvr}: {exc}")
    root = ET.fromstring(payload)
    fault = root.find("fault")
    if fault is not None:
        text = " ".join("".join(fault.itertext()).split())
        raise SystemExit(f"Brew fault for {nvr}: {text[:400]}")
    return root


root = call("getBuild", f"<param><value><string>{nvr}</string></value></param>")
build_id = None
for member in root.iter("member"):
    if member.findtext("name") != "build_id":
        continue
    value = member.find("value")
    if value is not None and value.find("int") is not None:
        build_id = value.findtext("int")
        break
if not build_id:
    raise SystemExit(f"Brew has no build for {nvr}")

root = call(
    "getChangelogEntries",
    f"<param><value><int>{build_id}</int></value></param>",
)
cves = set()
for member in root.iter("member"):
    if member.findtext("name") != "text":
        continue
    value = member.find("value")
    text = "" if value is None else "".join(value.itertext())
    cves.update(re.findall(r"CVE-[0-9]{4}-[0-9]+", text))

with open(out, "w", encoding="utf-8") as handle:
    for cve in sorted(cves):
        handle.write(cve + "\n")
print(f"{nvr}: Brew build {build_id}, {len(cves)} changelog CVE(s)")
PY
}

fetch_all_changelogs() {
    local nvr safe
    mkdir -p "$WORK_DIR/changelogs"
    while IFS= read -r nvr; do
        [[ -z "$nvr" || "$nvr" == "-" ]] && continue
        safe=$(printf '%s' "$nvr" | tr '/:' '_')
        echo "Fetching Brew changelog for ${nvr}..."
        fetch_changelog "$nvr" "$WORK_DIR/changelogs/${safe}.cves"
    done < <(cut -f3 "$OLD_NVR" "$NEW_NVR" | LC_ALL=C sort -u)
}

classify_backports() {
    python3 - \
        "$OLD_REPORT" "$NEW_REPORT" \
        "$OLD_NVR" "$NEW_NVR" \
        "$WORK_DIR/changelogs" \
        "$BACKPORT_FIXED" "$EVIDENCE" <<'PY'
import json
import sys
from collections import defaultdict
from pathlib import Path

(
    old_report,
    new_report,
    old_nvr_path,
    new_nvr_path,
    changelog_dir,
    fixed_path,
    evidence_path,
) = sys.argv[1:]


def stdlib_map(report_path):
    with open(report_path, encoding="utf-8") as handle:
        data = json.load(handle)
    by_cve = defaultdict(set)
    non_stdlib = set()
    for result in data.get("Results") or []:
        target = result.get("Target") or ""
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID")
            if not cve:
                continue
            if vuln.get("PkgName") == "stdlib" and target:
                by_cve[cve].add(target)
            else:
                non_stdlib.add(cve)
    return by_cve, non_stdlib


def load_nvr(path):
    info = {}
    file_path = Path(path)
    if not file_path.exists():
        return info
    for line in file_path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        target, status, nvr = parts
        info[target] = (status, nvr)
    return info


def changelog_name(nvr):
    return nvr.replace("/", "_").replace(":", "_") + ".cves"


def load_changelogs(nvrs):
    logs = {}
    directory = Path(changelog_dir)
    for nvr in sorted(nvrs):
        file_path = directory / changelog_name(nvr)
        if not file_path.exists():
            raise SystemExit(f"Missing Brew changelog for {nvr}")
        logs[nvr] = {
            line for line in file_path.read_text(encoding="utf-8").splitlines() if line
        }
    return logs


def covered(cve, paths, nvrs, logs):
    """True only when every flagged binary was built with an NVR that lists cve."""
    if not paths:
        return False
    for target in paths:
        status, nvr = nvrs.get(target, ("missing", "-"))
        if status != "ok":
            return False
        if cve not in logs.get(nvr, ()):
            return False
    return True


def format_binaries(targets, nvrs):
    if not targets:
        return ["  (none)"]
    lines = []
    for target in sorted(targets):
        status, nvr = nvrs.get(target, ("missing", "-"))
        if status == "ok":
            shown = nvr
        elif status == "no-redhat":
            shown = "no Red Hat golang NVR"
        else:
            shown = f"unreadable ({status})"
        lines.append(f"  {target}  {shown}")
    return lines


old_stdlib, _old_non = stdlib_map(old_report)
new_stdlib, new_non = stdlib_map(new_report)
old_nvrs = load_nvr(old_nvr_path)
new_nvrs = load_nvr(new_nvr_path)
needed = {
    nvr
    for status, nvr in list(old_nvrs.values()) + list(new_nvrs.values())
    if status == "ok" and nvr != "-"
}
logs = load_changelogs(needed)

fixed = []
for cve in sorted(old_stdlib):
    new_paths = new_stdlib.get(cve, set())
    # Trivy already dropped it. The ordinary set diff records that fix.
    if not new_paths:
        continue
    # The same ID is still present on a non-stdlib package in the new image.
    if cve in new_non:
        continue
    if covered(cve, new_paths, new_nvrs, logs) and not covered(
        cve, old_stdlib[cve], old_nvrs, logs
    ):
        fixed.append(cve)

with open(fixed_path, "w", encoding="utf-8") as handle:
    for cve in fixed:
        handle.write(cve + "\n")

old_targets = {target for paths in old_stdlib.values() for target in paths}
new_targets = {target for paths in new_stdlib.values() for target in paths}
evidence = [
    "A stdlib CVE is counted as fixed when every new-image binary Trivy still",
    "flags for it was compiled with a Red Hat golang NVR whose Brew changelog",
    "lists that CVE, and the old image was not already covered the same way.",
    "A binary that cannot be read, or that has no Red Hat NVR, keeps the CVE",
    "in Remaining.",
    "",
    "Old image Go binaries:",
    *format_binaries(old_targets, old_nvrs),
    "",
    "New image Go binaries:",
    *format_binaries(new_targets, new_nvrs),
    "",
    "Stdlib CVEs newly covered by the new image's Red Hat golang changelog:",
]
if fixed:
    evidence.extend(fixed)
else:
    evidence.append("(none)")
evidence.append("")
with open(evidence_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(evidence))
PY
}

TRIVY_DB="${HOME}/.cache/trivy/db"
if [[ ! -s "$TRIVY_DB/trivy.db" ]]; then
    echo "Error: Trivy vulnerability database not found at ${TRIVY_DB}/trivy.db"
    echo "Run: trivy image --download-db-only"
    exit 1
fi
mkdir -p "$WORK_DIR/trivy-cache"
ln -s "$TRIVY_DB" "$WORK_DIR/trivy-cache/db"

echo "Platform: ${PLATFORM}"
echo "Trivy:    ${trivy_version}"

# Scan both images using Trivy. The private cache dir forces a fresh binary
# analysis so a previous scan cannot reuse a malformed Red Hat Go version.
echo "Scanning old image: $OLD_IMAGE"

trivy image \
    --cache-dir "$WORK_DIR/trivy-cache" \
    --skip-db-update \
    --platform "$PLATFORM" \
    --scanners vuln \
    --format json \
    --output "$OLD_REPORT" \
    "$OLD_IMAGE"

echo "Scanning new image: $NEW_IMAGE"

trivy image \
    --cache-dir "$WORK_DIR/trivy-cache" \
    --skip-db-update \
    --platform "$PLATFORM" \
    --scanners vuln \
    --format json \
    --output "$NEW_REPORT" \
    "$NEW_IMAGE"

stdlib_findings "$OLD_REPORT" "$OLD_STDLIB"
stdlib_findings "$NEW_REPORT" "$NEW_STDLIB"
collect_stdlib_nvrs "$OLD_IMAGE" "$OLD_STDLIB" "$OLD_NVR" "$WORK_DIR/old-bins"
collect_stdlib_nvrs "$NEW_IMAGE" "$NEW_STDLIB" "$NEW_NVR" "$WORK_DIR/new-bins"
fetch_all_changelogs
classify_backports

# Extract unique vulnerability IDs from both reports
jq -r '
    .Results[]?.Vulnerabilities[]?
    | .VulnerabilityID
    | select(. != null)
' "$OLD_REPORT" | LC_ALL=C sort -u > "$OLD_CVES"

jq -r '
    .Results[]?.Vulnerabilities[]?
    | .VulnerabilityID
    | select(. != null)
' "$NEW_REPORT" | LC_ALL=C sort -u > "$NEW_CVES"

# Trivy totals, before backport IDs are taken out of the new-image set.
OLD_COUNT=$(wc -l < "$OLD_CVES")
NEW_COUNT=$(wc -l < "$NEW_CVES")

# Drop stdlib CVEs the new binaries contain via a Red Hat backport. Trivy still
# lists them because the upstream Go version did not change.
if [[ -s "$BACKPORT_FIXED" ]]; then
    comm -23 "$NEW_CVES" "$BACKPORT_FIXED" > "$WORK_DIR/new-cves-adjusted.txt"
    mv "$WORK_DIR/new-cves-adjusted.txt" "$NEW_CVES"
fi

# CVEs found in old image but not in new image
comm -23 "$OLD_CVES" "$NEW_CVES" > "$FIXED_CVES"

# CVEs found in new image but not in old image
comm -13 "$OLD_CVES" "$NEW_CVES" > "$ADDED_CVES"

# CVEs present in both images
comm -12 "$OLD_CVES" "$NEW_CVES" > "$REMAINING_CVES"

# Drop fixed CVEs that are not published on access.redhat.com
FIXED_CVES_RAW="$WORK_DIR/fixed-cves-raw.txt"
mv "$FIXED_CVES" "$FIXED_CVES_RAW"
filter_redhat_accessible_cves "$FIXED_CVES_RAW" "$FIXED_CVES" "$SKIPPED_CVES"

# Count vulnerabilities. OLD_COUNT and NEW_COUNT are the Trivy totals.
FIXED_COUNT=$(wc -l < "$FIXED_CVES")
ADDED_COUNT=$(wc -l < "$ADDED_CVES")
REMAINING_COUNT=$(wc -l < "$REMAINING_CVES")
SKIPPED_COUNT=$(wc -l < "$SKIPPED_CVES")
FIXED_RAW_COUNT=$(wc -l < "$FIXED_CVES_RAW")
BACKPORT_COUNT=$(wc -l < "$BACKPORT_FIXED")

# Display results
echo ""
echo "========================================"
echo "           CVE COMPARISON"
echo "========================================"

echo "Old image: $OLD_IMAGE"
echo "New image: $NEW_IMAGE"
echo "Platform:  $PLATFORM"
echo ""

echo "CVEs in old image : $OLD_COUNT"
echo "CVEs in new image : $NEW_COUNT"
echo "Fixed CVEs (raw)  : $FIXED_RAW_COUNT"
echo "Fixed CVEs (RH)   : $FIXED_COUNT"
echo "Stdlib backports  : $BACKPORT_COUNT"
echo "Skipped (no RH)   : $SKIPPED_COUNT"
echo "New CVEs          : $ADDED_COUNT"
echo "Remaining CVEs    : $REMAINING_COUNT"

echo ""
echo "========================================"
echo "     STDLIB BACKPORT EVIDENCE"
echo "========================================"
echo ""
cat "$EVIDENCE"
echo ""

echo "========================================"
echo "            FIXED CVEs"
echo "========================================"
echo "(Only CVEs accessible at https://access.redhat.com/security/cve/<id>)"
echo ""

if [[ -s "$FIXED_CVES" ]]; then
    cat "$FIXED_CVES"
else
    echo "No fixed CVEs found."
fi

if [[ -s "$SKIPPED_CVES" ]]; then
    echo ""
    echo "========================================"
    echo "   SKIPPED FIXED CVEs (not on RH portal)"
    echo "========================================"
    cat "$SKIPPED_CVES"
fi

echo ""
echo "========================================"
echo "             NEW CVEs"
echo "========================================"

if [[ -s "$ADDED_CVES" ]]; then
    cat "$ADDED_CVES"
else
    echo "No new CVEs found."
fi

echo ""
echo "========================================"
echo "           REMAINING CVEs"
echo "========================================"

if [[ -s "$REMAINING_CVES" ]]; then
    cat "$REMAINING_CVES"
else
    echo "No remaining CVEs found."
fi

echo ""
echo "========================================"
echo "         COMPARISON COMPLETE"
echo "========================================"
