#!/usr/bin/env bash
set -euo pipefail

# Usage: ./compare-cves.sh <old-image> <new-image>
#
# Go stdlib CVEs that Trivy still reports after a rebuild are treated as fixed
# when every new-image binary Trivy flags was built with a Red Hat golang NVR
# whose Brew changelog lists that CVE, and the old image was not already covered.
# Trivy compares only the upstream Go version (v1.24.13) and drops the
# "(Red Hat 1.24.13-N.el9)" suffix, so the changelog check is what sees the backport.
#
# Module CVEs fixed by an openshift-sustaining replace are credited from that
# fork's GitHub releases and from the upstream base the fork is cut from.
# Trivy records the fork path, which has no Go vulnerability entries, so a
# CVE that disappeared with the upstream module path stays fixed only when
# the cumulative <base>-sec.1 .. sec.N notes name it, or the fork base is at
# least the upstream fixed version Trivy recorded. The rest stay in Remaining.

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

# Gobinary paths from the Trivy report, plus any stdlib finding path.
gobinary_targets() {
    local report="$1"
    local findings="$2"
    {
        jq -r '
            .Results[]?
            | select(.Type == "gobinary" and .Target != null and .Target != "")
            | .Target
        ' "$report"
        if [[ -s "$findings" ]]; then
            cut -f1 "$findings"
        fi
    } | sed '/^$/d' | LC_ALL=C sort -u
}

# Copy each Go binary and record the Red Hat golang NVR from the first line of
# go version -m: go1.24.13 (Red Hat 1.24.13-12.el9). The full build info is
# kept so replace directives can be read later.
collect_stdlib_nvrs() {
    local image="$1"
    local report="$2"
    local findings="$3"
    local out_tsv="$4"
    local dest="$5"
    local mod_dir="$6"
    local path container_path flat outfile modfile line rel status nvr
    # Stored in a variable so the ")" inside the group is not the end of [[ ]].
    local rh_re='\(Red Hat ([^)]+)\)'

    mkdir -p "$dest" "$mod_dir"
    : > "$out_tsv"
    : > "$mod_dir/index.tsv"

    local targets
    targets=$(gobinary_targets "$report" "$findings")
    if [[ -z "$targets" ]]; then
        return 0
    fi

    echo "Reading Go build info from ${image}..."
    PODMAN_CID=$(podman create --platform "$PLATFORM" "$image")

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        container_path="${path#./}"
        [[ "$container_path" == /* ]] || container_path="/${container_path}"
        flat=$(printf '%s' "$container_path" | tr '/' '_')
        outfile="${dest}/${flat}"
        modfile="${mod_dir}/${flat}.mod"
        status="unreadable"
        nvr="-"
        if ! podman cp "${PODMAN_CID}:${container_path}" "$outfile" >/dev/null 2>&1; then
            echo "Error: could not copy ${container_path} from ${image}" >&2
            exit 1
        fi
        if ! go version -m "$outfile" > "$modfile" 2>"${modfile}.err"; then
            echo "Error: could not read Go build info for ${path} in ${image}" >&2
            cat "${modfile}.err" >&2
            exit 1
        fi
        if [[ ! -s "$modfile" ]]; then
            echo "Error: empty Go build info for ${path} in ${image}" >&2
            exit 1
        fi
        line=$(awk 'NR==1 { print; exit }' "$modfile")
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
        fi
        printf '%s\t%s\t%s\n' "$path" "$status" "$nvr" >> "$out_tsv"
        printf '%s\t%s\n' "$path" "$modfile" >> "$mod_dir/index.tsv"
    done < <(gobinary_targets "$report" "$findings")

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

# Credit CVEs named by openshift-sustaining <base>-sec.N release notes, and
# list CVEs that Trivy dropped only because the upstream module path changed.
classify_sustaining() {
    python3 - \
        "$OLD_REPORT" "$NEW_REPORT" \
        "$OLD_MOD_INDEX" "$NEW_MOD_INDEX" \
        "$WORK_DIR/sustaining-cache" \
        "$SUSTAINING_FIXED" "$SUSTAINING_HIDDEN" "$SUSTAINING_EVIDENCE" <<'PY'
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

(
    old_report,
    new_report,
    old_index_path,
    new_index_path,
    cache_dir,
    fixed_path,
    hidden_path,
    evidence_path,
) = sys.argv[1:]

CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]+")
SEC_RE = re.compile(r"^(.+)-sec\.([0-9]+)$")
FORK_RE = re.compile(r"^github\.com/openshift-sustaining/([^/]+)$")
release_cache = {}


def github_json(url):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "compare-cves",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise SystemExit(f"GitHub request failed for {url}: HTTP {exc.code} {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"GitHub request failed for {url}: {exc.reason}")


def fetch_releases(repo):
    if repo in release_cache:
        return release_cache[repo]
    found = []
    page = 1
    while page <= 20:
        url = (
            "https://api.github.com/repos/openshift-sustaining/"
            f"{repo}/releases?per_page=100&page={page}"
        )
        batch = github_json(url)
        if not isinstance(batch, list):
            raise SystemExit(f"Unexpected GitHub releases response for {repo}")
        found.extend(batch)
        if len(batch) < 100:
            release_cache[repo] = found
            return found
        page += 1
    raise SystemExit(f"Too many GitHub release pages for {repo}")


def compare_status(repo, earlier, pinned):
    base = urllib.parse.quote(earlier, safe=".-")
    head = urllib.parse.quote(pinned, safe=".-")
    url = (
        "https://api.github.com/repos/openshift-sustaining/"
        f"{repo}/compare/{base}...{head}"
    )
    status = github_json(url).get("status")
    if status not in ("ahead", "identical"):
        raise SystemExit(
            f"{earlier} is not an ancestor of {pinned} in "
            f"openshift-sustaining/{repo} (status {status})"
        )


def cves_for_version(repo, version):
    match = SEC_RE.fullmatch(version)
    if not match:
        raise SystemExit(f"Not a sustaining security tag: {repo} {version}")
    base, number = match.group(1), int(match.group(2))
    if number < 1:
        raise SystemExit(f"Not a sustaining security tag: {repo} {version}")
    cache = Path(cache_dir) / f"{repo}_{version}.cves"
    if cache.exists():
        return {line for line in cache.read_text(encoding="utf-8").splitlines() if line}
    by_tag = {}
    for release in fetch_releases(repo):
        tag = release.get("tag_name") or ""
        if tag:
            by_tag[tag] = release
    cves = set()
    for index in range(1, number + 1):
        tag = f"{base}-sec.{index}"
        release = by_tag.get(tag)
        if release is None:
            raise SystemExit(
                f"Missing GitHub release {tag} in openshift-sustaining/{repo}"
            )
        if index < number:
            compare_status(repo, tag, version)
        text = f"{release.get('name') or ''}\n{release.get('body') or ''}"
        named = set(CVE_RE.findall(text))
        if not named:
            raise SystemExit(
                f"GitHub release {tag} in openshift-sustaining/{repo} names no CVE"
            )
        cves.update(named)
    cache.write_text("".join(cve + "\n" for cve in sorted(cves)), encoding="utf-8")
    print(
        f"openshift-sustaining/{repo} {version}: "
        f"{len(cves)} release-note CVE(s)",
        flush=True,
    )
    return cves


def parse_buildinfo(text):
    deps = {}
    pending = None
    for raw in text.splitlines():
        if not raw.startswith("\t"):
            pending = None
            continue
        parts = raw.split("\t")
        kind = parts[1] if len(parts) > 1 else ""
        if kind == "dep" and len(parts) >= 4:
            pending = parts[2]
            deps.setdefault(pending, None)
            continue
        if kind == "=>" and pending and len(parts) >= 4:
            repo_match = FORK_RE.fullmatch(parts[2])
            sec_match = SEC_RE.fullmatch(parts[3])
            if repo_match and sec_match:
                deps[pending] = (repo_match.group(1), parts[3])
            pending = None
            continue
        pending = None
    return deps


def load_binaries(index_path):
    binaries = {}
    file_path = Path(index_path)
    if not file_path.exists():
        return binaries
    for line in file_path.read_text(encoding="utf-8").splitlines():
        target, modfile = line.split("\t", 1)
        binaries[target] = parse_buildinfo(Path(modfile).read_text(encoding="utf-8"))
    return binaries


def covered_cves(binaries, module, cve_sets):
    holders = [deps for deps in binaries.values() if module in deps]
    if not holders or any(deps[module] is None for deps in holders):
        return set()
    sets = [cve_sets[deps[module]] for deps in holders]
    return set.intersection(*sets)


def fully_replaced(binaries, module):
    holders = [deps for deps in binaries.values() if module in deps]
    if not holders:
        return False
    return all(deps[module] is not None for deps in holders)


def parse_semver(version):
    """Return (major, minor, patch, prerelease) or None."""
    text = version.strip()
    if text.startswith("v") or text.startswith("V"):
        text = text[1:]
    text = text.split("+", 1)[0]
    if "-" in text:
        main, pre = text.split("-", 1)
    else:
        main, pre = text, None
    parts = main.split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    nums = [int(part) for part in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2], pre)


def cmp_semver(left, right):
    """Compare two versions. 1, 0, or -1. None if either is not semver."""
    parsed_left, parsed_right = parse_semver(left), parse_semver(right)
    if parsed_left is None or parsed_right is None:
        return None
    for left_num, right_num in zip(parsed_left[:3], parsed_right[:3]):
        if left_num != right_num:
            return -1 if left_num < right_num else 1
    pre_left, pre_right = parsed_left[3], parsed_right[3]
    if pre_left is None and pre_right is None:
        return 0
    if pre_left is None:
        return 1
    if pre_right is None:
        return -1

    def ident(part):
        return (0, int(part)) if part.isdigit() else (1, part)

    left_ids = [ident(part) for part in pre_left.split(".") if part]
    right_ids = [ident(part) for part in pre_right.split(".") if part]
    if left_ids != right_ids:
        return -1 if left_ids < right_ids else 1
    return 0


def base_covers_fix(base, fixed_field):
    """True when base is at least the upstream fix recorded by Trivy.

    One fixed version means every greater-or-equal release contains the fix.
    Several versions are the first patched release of each minor line.
    """
    versions = [part.strip() for part in (fixed_field or "").split(",") if part.strip()]
    if not versions:
        return False
    parsed = []
    for version in versions:
        parsed_version = parse_semver(version)
        if parsed_version is None:
            return False
        parsed.append((version, parsed_version))
    base_parsed = parse_semver(base)
    if base_parsed is None:
        return False
    same_line = [
        version
        for version, parsed_version in parsed
        if parsed_version[0] == base_parsed[0] and parsed_version[1] == base_parsed[1]
    ]
    if same_line:
        required = same_line[0]
        for version in same_line[1:]:
            if cmp_semver(version, required) > 0:
                required = version
        return cmp_semver(base, required) >= 0
    highest = parsed[0][0]
    for version, _parsed_version in parsed[1:]:
        if cmp_semver(version, highest) > 0:
            highest = version
    return cmp_semver(base, highest) >= 0


def fork_bases(binaries, module):
    """Bases of every sustaining replace of module, or None if any copy is upstream."""
    bases = []
    seen = False
    for deps in binaries.values():
        if module not in deps:
            continue
        seen = True
        repl = deps[module]
        if repl is None:
            return None
        match = SEC_RE.fullmatch(repl[1])
        if not match:
            return None
        bases.append(match.group(1))
    if not seen:
        return None
    return bases


def report_ids(report_path):
    with open(report_path, encoding="utf-8") as handle:
        data = json.load(handle)
    ids = set()
    by_pkg = defaultdict(set)
    fixes = defaultdict(set)
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID")
            if not cve:
                continue
            ids.add(cve)
            pkg = vuln.get("PkgName") or ""
            if pkg:
                by_pkg[cve].add(pkg)
                fixes[(cve, pkg)].add(vuln.get("FixedVersion") or "")
    return ids, by_pkg, fixes


def write_ids(path, ids):
    with open(path, "w", encoding="utf-8") as handle:
        for cve in sorted(ids):
            handle.write(cve + "\n")


def format_replaces(binaries, cve_sets):
    if not binaries:
        return ["  (none)"]
    lines = []
    for target in sorted(binaries):
        replaces = [
            (orig, repl)
            for orig, repl in binaries[target].items()
            if repl is not None
        ]
        if not replaces:
            lines.append(f"  {target}  (no sustaining replace)")
            continue
        for orig, (repo, version) in sorted(replaces):
            named = " ".join(sorted(cve_sets[(repo, version)]))
            lines.append(
                f"  {target}  {orig} => github.com/openshift-sustaining/{repo} {version}"
            )
            lines.append(f"    {named}")
    return lines


Path(cache_dir).mkdir(parents=True, exist_ok=True)
old_bins = load_binaries(old_index_path)
new_bins = load_binaries(new_index_path)
needed = {
    repl
    for binaries in (old_bins, new_bins)
    for deps in binaries.values()
    for repl in deps.values()
    if repl is not None
}
cve_sets = {(repo, version): cves_for_version(repo, version) for repo, version in sorted(needed)}

modules = {
    orig
    for binaries in (old_bins, new_bins)
    for deps in binaries.values()
    for orig, repl in deps.items()
    if repl is not None
}
new_ids, _new_pkgs, _new_fixes = report_ids(new_report)
old_ids, old_pkgs, old_fixes = report_ids(old_report)
newly = set()
fixed = set()
left_reported = set()
for module in sorted(modules):
    if not any(module in deps for deps in old_bins.values()):
        continue
    gained = covered_cves(new_bins, module, cve_sets) - covered_cves(old_bins, module, cve_sets)
    old_fork = any(
        deps[module] is not None for deps in old_bins.values() if module in deps
    )
    for cve in gained:
        newly.add(cve)
        if cve in new_ids:
            left_reported.add(cve)
        elif cve in old_ids or old_fork:
            fixed.add(cve)
def base_fixes(cve, pkg):
    bases = fork_bases(new_bins, pkg)
    recorded = old_fixes.get((cve, pkg), set())
    if bases is None or not recorded:
        return False
    return all(
        fixed_field and all(base_covers_fix(base, fixed_field) for base in bases)
        for fixed_field in recorded
    )


hidden = set()
base_fixed = set()
for cve, pkgs in old_pkgs.items():
    if cve in new_ids or cve in fixed or not pkgs:
        continue
    if not all(fully_replaced(new_bins, pkg) for pkg in pkgs):
        continue
    if all(base_fixes(cve, pkg) for pkg in pkgs):
        base_fixed.add(cve)
    else:
        hidden.add(cve)
fixed.update(base_fixed)
newly.update(base_fixed)

write_ids(fixed_path, fixed)
write_ids(hidden_path, hidden)
evidence = [
    "A sustaining replace credits a CVE when every new-image binary that",
    "depends on the original module uses an openshift-sustaining",
    "<base>-sec.N tag, and either the GitHub releases from sec.1 through",
    "sec.N name that CVE or <base> is at least the upstream fixed version",
    "Trivy recorded. Earlier tags must be ancestors of the pinned tag, and",
    "the old image must not already be covered. A CVE that Trivy drops only",
    "because the module path changed stays in Remaining when the fork base",
    "is older than that upstream fix and the notes do not name it. A CVE",
    "still reported on another package is left in place.",
    "",
    "Old image sustaining replaces:",
    *format_replaces(old_bins, cve_sets),
    "",
    "New image sustaining replaces:",
    *format_replaces(new_bins, cve_sets),
    "",
    "Sustaining CVEs newly covered:",
]
evidence.extend(sorted(newly) if newly else ["(none)"])
evidence.extend([
    "",
    "Sustaining CVEs still reported on the new image:",
])
evidence.extend(sorted(left_reported) if left_reported else ["(none)"])
evidence.extend([
    "",
    "Sustaining CVEs kept in Remaining because the fork base is older than the upstream fix:",
])
evidence.extend(sorted(hidden) if hidden else ["(none)"])
evidence.append("")
Path(evidence_path).write_text("\n".join(evidence), encoding="utf-8")
PY
}

run_compare() {
    if [[ $# -ne 2 ]]; then
        echo "Usage: $0 <old-image> <new-image>"
        exit 1
    fi

    OLD_IMAGE="$1"
    NEW_IMAGE="$2"

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
    OLD_MOD_INDEX="$WORK_DIR/old-mods/index.tsv"
    NEW_MOD_INDEX="$WORK_DIR/new-mods/index.tsv"
    BACKPORT_FIXED="$WORK_DIR/backport-fixed.txt"
    EVIDENCE="$WORK_DIR/backport-evidence.txt"
    SUSTAINING_FIXED="$WORK_DIR/sustaining-fixed.txt"
    SUSTAINING_HIDDEN="$WORK_DIR/sustaining-hidden.txt"
    SUSTAINING_EVIDENCE="$WORK_DIR/sustaining-evidence.txt"

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
collect_stdlib_nvrs "$OLD_IMAGE" "$OLD_REPORT" "$OLD_STDLIB" "$OLD_NVR" "$WORK_DIR/old-bins" "$WORK_DIR/old-mods"
collect_stdlib_nvrs "$NEW_IMAGE" "$NEW_REPORT" "$NEW_STDLIB" "$NEW_NVR" "$WORK_DIR/new-bins" "$WORK_DIR/new-mods"
fetch_all_changelogs
classify_backports
classify_sustaining

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

# CVEs Trivy dropped because the module path changed to a sustaining fork,
# and that the fork release notes do not name, are still present.
if [[ -s "$SUSTAINING_HIDDEN" ]]; then
    cat "$NEW_CVES" "$SUSTAINING_HIDDEN" | LC_ALL=C sort -u > "$WORK_DIR/new-cves-hidden.txt"
    mv "$WORK_DIR/new-cves-hidden.txt" "$NEW_CVES"
fi

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

# Fork-only fixes are absent from both Trivy reports when both images already
# use a sustaining replace. Named CVEs that Trivy did report are already in
# FIXED_CVES from the set diff.
cat "$FIXED_CVES" "$SUSTAINING_FIXED" | LC_ALL=C sort -u > "$WORK_DIR/fixed-with-sustaining.txt"
mv "$WORK_DIR/fixed-with-sustaining.txt" "$FIXED_CVES"

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
SUSTAINING_COUNT=$(wc -l < "$SUSTAINING_FIXED")

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
echo "Sustaining backports: $SUSTAINING_COUNT"
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
echo "   SUSTAINING BACKPORT EVIDENCE"
echo "========================================"
echo ""
cat "$SUSTAINING_EVIDENCE"
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

# Optional machine-readable copy for callers such as generate-release-yaml.sh.
# The EXIT trap deletes WORK_DIR, so this must happen before run_compare returns.
if [[ -n "${COMPARE_CVES_RESULT_DIR:-}" ]]; then
    mkdir -p "$COMPARE_CVES_RESULT_DIR"
    cp -f "$FIXED_CVES" "$COMPARE_CVES_RESULT_DIR/fixed-cves.txt"
    cp -f "$OLD_REPORT" "$COMPARE_CVES_RESULT_DIR/old.json"
fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    run_compare "$@"
fi
