#!/usr/bin/env bash
# Install NullBound's launcher dependencies on Linux.
#
# Distro packages are preferred where they are unambiguous. Portable Go tools
# are kept below the project-local, ignored .nullbound-tools directory. Official
# GitHub release archives are the fallback when a Go build is unavailable.

set -Eeuo pipefail

CHECK_ONLY=0
FORCE=0
SKIP_NMAP=0
PERSIST_PATH=1

usage() {
    cat <<'EOF'
Usage: bash ./scripts/setup-tools.sh [options]

Options:
  --check-only       Report missing tools without installing anything
  --force            Reinstall tools even when a healthy executable is found
  --skip-nmap        Do not install Nmap
  --no-persist-path  Do not add the local tool directories to ~/.profile
  -h, --help         Show this help
EOF
}

while (($#)); do
    case "$1" in
        --check-only) CHECK_ONLY=1 ;;
        --force) FORCE=1 ;;
        --skip-nmap) SKIP_NMAP=1 ;;
        --no-persist-path) PERSIST_PATH=0 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'This bootstrapper targets Linux. Use setup-tools.ps1 on Windows.\n' >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
DEFINITIONS_PATH="$PROJECT_ROOT/recon_modules/definitions.json"
TOOLS_ROOT="$PROJECT_ROOT/.nullbound-tools"
BIN_DIR="$TOOLS_ROOT/bin"
PACKAGES_DIR="$TOOLS_ROOT/packages"
DOWNLOADS_DIR="$TOOLS_ROOT/downloads"
NMAP_PREFIX="$TOOLS_ROOT/nmap"

TOOLS=(subfinder dnsx nmap httpx gau tlsx)
declare -A GO_PACKAGES=(
    [subfinder]='github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
    [dnsx]='github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
    [httpx]='github.com/projectdiscovery/httpx/cmd/httpx@latest'
    [gau]='github.com/lc/gau/v2/cmd/gau@latest'
    [tlsx]='github.com/projectdiscovery/tlsx/cmd/tlsx@latest'
)
declare -A GITHUB_REPOSITORIES=(
    [subfinder]='projectdiscovery/subfinder'
    [dnsx]='projectdiscovery/dnsx'
    [httpx]='projectdiscovery/httpx'
    [gau]='lc/gau'
    [tlsx]='projectdiscovery/tlsx'
)
declare -A CONFIGURED_PATHS=()

step() {
    printf '\n\033[36m==> %s\033[0m\n' "$1"
}

warn() {
    printf '\033[33mWARNING: %s\033[0m\n' "$1" >&2
}

if [[ ! -f "$DEFINITIONS_PATH" ]]; then
    printf 'Cannot find NullBound module definitions at %s\n' "$DEFINITIONS_PATH" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    while IFS=$'\t' read -r module_bin module_path; do
        [[ -n "$module_bin" ]] && CONFIGURED_PATHS["$module_bin"]="$module_path"
    done < <(
        python3 - "$DEFINITIONS_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    catalog = json.load(stream)
for module in catalog.get("modules", []):
    print(f"{module.get('bin', '')}\t{module.get('path', '')}")
PY
    )
fi

version_arguments() {
    case "$1" in
        nmap|gau) printf '%s\n' '--version' ;;
        *) printf '%s\n' '-version' ;;
    esac
}

version_pattern() {
    case "$1" in
        nmap) printf '%s\n' 'Nmap version' ;;
        subfinder) printf '%s\n' 'subfinder' ;;
        dnsx) printf '%s\n' 'dnsx' ;;
        httpx) printf '%s\n' 'httpx' ;;
        gau) printf '%s\n' '(gau|v[0-9]+\.)' ;;
        tlsx) printf '%s\n' 'tlsx' ;;
    esac
}

healthy_executable() {
    local name="$1"
    local executable="$2"
    local argument output status pattern
    [[ -f "$executable" && -x "$executable" ]] || return 1
    argument="$(version_arguments "$name")"
    pattern="$(version_pattern "$name")"
    set +e
    if command -v timeout >/dev/null 2>&1; then
        output="$(timeout 15 "$executable" "$argument" 2>&1)"
        status=$?
    else
        output="$("$executable" "$argument" 2>&1)"
        status=$?
    fi
    set -e
    [[ $status -eq 0 ]] && grep -Eqi "$pattern" <<<"$output"
}

find_tool() {
    local name="$1"
    local configured="${CONFIGURED_PATHS[$name]:-}"
    local candidate
    for candidate in \
        "$BIN_DIR/$name" \
        "$NMAP_PREFIX/bin/$name" \
        "$PROJECT_ROOT/$configured"; do
        if [[ -n "$candidate" ]] && healthy_executable "$name" "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    candidate="$(command -v "$name" 2>/dev/null || true)"
    if [[ -n "$candidate" ]] && healthy_executable "$name" "$candidate"; then
        printf '%s\n' "$candidate"
        return 0
    fi
    return 1
}

step 'Checking NullBound module executables'
missing=()
for tool in "${TOOLS[@]}"; do
    if path="$(find_tool "$tool")"; then
        printf '\033[32m[FOUND]\033[0m   %-10s %s\n' "$tool" "$path"
    else
        printf '\033[33m[MISSING]\033[0m %-10s\n' "$tool"
        missing+=("$tool")
    fi
done

if ((CHECK_ONLY)); then
    if ((${#missing[@]})); then
        printf '\nMissing: %s\n' "${missing[*]}" >&2
        exit 1
    fi
    printf '\nAll NullBound module executables are available.\n'
    exit 0
fi

mkdir -p -- "$BIN_DIR" "$PACKAGES_DIR" "$DOWNLOADS_DIR"
export PATH="$BIN_DIR:$NMAP_PREFIX/bin:$PATH"

PACKAGE_MANAGER=''
if command -v apt-get >/dev/null 2>&1; then
    PACKAGE_MANAGER='apt'
elif command -v dnf >/dev/null 2>&1; then
    PACKAGE_MANAGER='dnf'
elif command -v yum >/dev/null 2>&1; then
    PACKAGE_MANAGER='yum'
elif command -v pacman >/dev/null 2>&1; then
    PACKAGE_MANAGER='pacman'
fi

ROOT_COMMAND=()
if ((EUID != 0)); then
    if command -v sudo >/dev/null 2>&1; then
        ROOT_COMMAND=(sudo)
    else
        warn 'sudo is unavailable; system-package installation will be skipped.'
    fi
fi

APT_UPDATED=0
manager_install() {
    (($#)) || return 0
    [[ -n "$PACKAGE_MANAGER" ]] || return 1
    if ((EUID != 0)) && ((${#ROOT_COMMAND[@]} == 0)); then
        return 1
    fi
    case "$PACKAGE_MANAGER" in
        apt)
            if ((APT_UPDATED == 0)); then
                "${ROOT_COMMAND[@]}" apt-get update || return 1
                APT_UPDATED=1
            fi
            "${ROOT_COMMAND[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf) "${ROOT_COMMAND[@]}" dnf install -y "$@" ;;
        yum) "${ROOT_COMMAND[@]}" yum install -y "$@" ;;
        pacman) "${ROOT_COMMAND[@]}" pacman -Sy --needed --noconfirm "$@" ;;
    esac
}

manager_has_package() {
    local package="$1"
    # The distro package called httpx is commonly the unrelated Python HTTP
    # client. Never accept it as ProjectDiscovery httpx.
    [[ "$package" != 'httpx' && "$package" != 'gau' ]] || return 1
    case "$PACKAGE_MANAGER" in
        apt) apt-cache show "$package" >/dev/null 2>&1 ;;
        dnf) dnf --quiet info "$package" >/dev/null 2>&1 ;;
        yum) yum --quiet info "$package" >/dev/null 2>&1 ;;
        pacman) pacman -Si "$package" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

install_prerequisites() {
    local packages=()
    case "$PACKAGE_MANAGER" in
        apt) packages=(ca-certificates curl git golang-go openssl python3 tar unzip) ;;
        dnf|yum) packages=(ca-certificates curl git golang openssl python3 tar unzip) ;;
        pacman) packages=(ca-certificates curl git go openssl python tar unzip) ;;
        *) warn 'No apt, dnf/yum, or pacman installation was found.'; return 1 ;;
    esac
    step "Installing prerequisites with $PACKAGE_MANAGER"
    manager_install "${packages[@]}"
}

if ! install_prerequisites; then
    warn 'Could not install all prerequisites; continuing with what is already available.'
fi

install_from_go() {
    local name="$1"
    local package="${GO_PACKAGES[$name]:-}"
    [[ -n "$package" ]] || return 1
    command -v go >/dev/null 2>&1 || return 1
    step "Installing $name with Go"
    GOBIN="$BIN_DIR" go install "$package"
    healthy_executable "$name" "$BIN_DIR/$name"
}

github_architecture() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s\n' 'amd64' ;;
        aarch64|arm64) printf '%s\n' 'arm64' ;;
        armv7l|armv7) printf '%s\n' 'armv7' ;;
        *) return 1 ;;
    esac
}

install_from_github_release() {
    local name="$1"
    local repository="${GITHUB_REPOSITORIES[$name]:-}"
    local architecture release_json archive_name archive_url checksum_url
    local archive_path checksum_path expected actual staging executable
    [[ -n "$repository" ]] || return 1
    command -v curl >/dev/null 2>&1 || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    architecture="$(github_architecture)" || return 1
    release_json="$DOWNLOADS_DIR/$name-release.json"
    step "Installing $name from $repository release"
    curl -fsSL \
        -H 'Accept: application/vnd.github+json' \
        -H 'User-Agent: NullBound-tool-bootstrap' \
        "https://api.github.com/repos/$repository/releases/latest" \
        -o "$release_json"

    mapfile -t release_asset < <(
        python3 - "$release_json" "$architecture" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    release = json.load(stream)
architecture = sys.argv[2].lower()
archives = []
checksum_url = ""
for asset in release.get("assets", []):
    name = asset.get("name", "")
    lowered = name.lower()
    if re.search(r"(checksums?|sha256sums?)(\.txt)?$", lowered):
        checksum_url = asset.get("browser_download_url", "")
    if (
        "linux" in lowered
        and architecture in lowered
        and (lowered.endswith(".zip") or lowered.endswith(".tar.gz"))
        and "checksum" not in lowered
        and "sha256" not in lowered
    ):
        archives.append(asset)
if not archives:
    raise SystemExit("no matching Linux release archive")
asset = archives[0]
print(asset["name"])
print(asset["browser_download_url"])
print(checksum_url)
PY
    )
    ((${#release_asset[@]} >= 2)) || return 1
    archive_name="${release_asset[0]}"
    archive_url="${release_asset[1]}"
    checksum_url="${release_asset[2]:-}"
    archive_path="$DOWNLOADS_DIR/$archive_name"
    curl -fL "$archive_url" -o "$archive_path"

    if [[ -n "$checksum_url" ]]; then
        checksum_path="$DOWNLOADS_DIR/$name-checksums.txt"
        curl -fsSL "$checksum_url" -o "$checksum_path"
        expected="$(python3 - "$checksum_path" "$archive_name" <<'PY'
import re
import sys

archive = sys.argv[2]
with open(sys.argv[1], encoding="utf-8", errors="replace") as stream:
    for line in stream:
        match = re.match(r"^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", line)
        if match and match.group(2) == archive:
            print(match.group(1).lower())
            break
PY
)"
        if [[ -n "$expected" ]]; then
            if command -v sha256sum >/dev/null 2>&1; then
                actual="$(sha256sum "$archive_path" | awk '{print $1}')"
            else
                actual="$(openssl dgst -sha256 "$archive_path" | awk '{print $NF}')"
            fi
            [[ "$actual" == "$expected" ]] || {
                warn "SHA256 mismatch for $archive_name"
                return 1
            }
        else
            warn "Published checksums did not contain $archive_name; relying on HTTPS."
        fi
    else
        warn "$repository did not publish a checksum list; relying on HTTPS."
    fi

    staging="$(mktemp -d "$PACKAGES_DIR/$name.XXXXXX")"
    case "$archive_name" in
        *.zip) unzip -q "$archive_path" -d "$staging" ;;
        *.tar.gz) tar -xzf "$archive_path" -C "$staging" ;;
        *) return 1 ;;
    esac
    executable="$(find "$staging" -type f -name "$name" -print -quit)"
    [[ -n "$executable" ]] || { warn "$archive_name did not contain $name"; return 1; }
    install -m 0755 "$executable" "$BIN_DIR/$name"
    rm -r -- "$staging"
    healthy_executable "$name" "$BIN_DIR/$name"
}

install_nmap_from_source() {
    local source_dir jobs
    command -v git >/dev/null 2>&1 || return 1
    case "$PACKAGE_MANAGER" in
        apt) manager_install build-essential libpcap-dev libssl-dev ;;
        dnf|yum) manager_install gcc gcc-c++ make libpcap-devel openssl-devel ;;
        pacman) manager_install base-devel libpcap ;;
        *) return 1 ;;
    esac || return 1
    source_dir="$(mktemp -d "$PACKAGES_DIR/nmap-source.XXXXXX")"
    step 'Building Nmap from its upstream Git repository'
    git clone --depth 1 https://github.com/nmap/nmap.git "$source_dir"
    (
        cd "$source_dir"
        ./configure --prefix="$NMAP_PREFIX"
        jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')"
        make -j "$jobs"
        make install
    )
    rm -r -- "$source_dir"
    healthy_executable nmap "$NMAP_PREFIX/bin/nmap"
}

failed=()
for tool in "${TOOLS[@]}"; do
    if ((FORCE == 0)) && find_tool "$tool" >/dev/null; then
        continue
    fi
    if [[ "$tool" == 'nmap' && $SKIP_NMAP -eq 1 ]]; then
        warn 'Nmap is missing but was skipped.'
        continue
    fi

    installed=0
    if manager_has_package "$tool"; then
        step "Installing $tool with $PACKAGE_MANAGER"
        if manager_install "$tool" && find_tool "$tool" >/dev/null; then
            installed=1
        else
            warn "$PACKAGE_MANAGER did not provide a compatible $tool executable."
        fi
    fi
    if ((installed == 0)) && [[ "$tool" != 'nmap' ]]; then
        if install_from_go "$tool" || install_from_github_release "$tool"; then
            installed=1
        fi
    fi
    if ((installed == 0)) && [[ "$tool" == 'nmap' ]]; then
        if install_nmap_from_source; then
            installed=1
        fi
    fi
    if ((installed == 0)); then
        failed+=("$tool")
        warn "Could not install $tool; continuing with the remaining tools."
    fi
done

if ((PERSIST_PATH)); then
    profile_path="${NULLBOUND_SHELL_PROFILE:-$HOME/.profile}"
    path_line="export PATH=\"$BIN_DIR:$NMAP_PREFIX/bin:\$PATH\" # NullBound tools"
    if [[ ! -f "$profile_path" ]] || ! grep -Fqx "$path_line" "$profile_path"; then
        printf '\n%s\n' "$path_line" >> "$profile_path"
    fi
fi

step 'Final tool status'
final_missing=()
for tool in "${TOOLS[@]}"; do
    if path="$(find_tool "$tool")"; then
        printf '\033[32m[READY]\033[0m   %-10s %s\n' "$tool" "$path"
    else
        printf '\033[31m[MISSING]\033[0m %-10s\n' "$tool"
        final_missing+=("$tool")
    fi
done

if ((PERSIST_PATH)); then
    printf '\nThe local tool directories were added to %s.\n' "$profile_path"
    printf 'Run: source %q\n' "$profile_path"
fi
printf 'Flatpak was not used: these scanners have no suitable official Flatpak packages.\n'

if ((${#final_missing[@]})); then
    printf 'Some required executables are still missing: %s\n' "${final_missing[*]}" >&2
    exit 1
fi
