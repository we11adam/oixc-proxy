#!/bin/sh
set -eu

repository=${OIXC_REPOSITORY:-we11adam/oixc-proxy}
release=${OIXC_VERSION:-latest}
install_dir=${OIXC_INSTALL_DIR:-/usr/local/bin}
release_base=${OIXC_RELEASE_BASE_URL:-}
github_token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
restart=false
service_target=
nodelist_url=

usage() {
    cat <<'EOF'
Usage: install.sh [--version VERSION] [--install-dir DIR]
                  [--restart [--service-target TARGET] [--nodelist-url URL]]

Download a published oixc-proxy binary for the current macOS or Linux host,
verify it against the release SHA256SUMS file, and atomically install it.

Options:
  --version VERSION   Install a release tag such as v0.8.0 (default: latest)
  --install-dir DIR   Install directory (default: /usr/local/bin)
  --restart           Upgrade an existing launchd or systemd service, with rollback
  --service-target    macOS: gui/<uid>/io.oixc.proxy (default), or system/<label>
                      Linux: user/oixc-proxy.service (default), or system/<unit>
  --nodelist-url URL   Listening HTTP origin (default: http://127.0.0.1:6173)
  -h, --help          Show this help

Environment:
  OIXC_REPOSITORY        GitHub owner/repository (default: we11adam/oixc-proxy)
  OIXC_VERSION           Same as --version
  OIXC_INSTALL_DIR       Same as --install-dir
  OIXC_RELEASE_BASE_URL  Override the release download directory (for mirrors)
  GH_TOKEN/GITHUB_TOKEN  Read-only token used by gh for private release assets

By default the script installs only the binary. --restart requires an
existing running service and uses curl and lsof for local verification.
EOF
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || die "--version requires a value"
            release=$2
            shift 2
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || die "--install-dir requires a value"
            install_dir=$2
            shift 2
            ;;
        --restart)
            restart=true
            shift
            ;;
        --service-target|--nodelist-url)
            [ "$#" -ge 2 ] && [ -n "$2" ] || die "$1 requires a value"
            case "$1" in
                --service-target) service_target=$2 ;;
                --nodelist-url) nodelist_url=$2 ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

owner=${repository%%/*}
name=${repository#*/}
[ "$owner" != "$repository" ] || die "OIXC_REPOSITORY must be owner/repository"
[ -n "$owner" ] && [ -n "$name" ] || die "OIXC_REPOSITORY must be owner/repository"
case "$name" in
    */*) die "OIXC_REPOSITORY must contain exactly one slash" ;;
esac
case "$repository" in
    *[!A-Za-z0-9._/-]*) die "OIXC_REPOSITORY contains unsupported characters" ;;
esac
case "$install_dir" in
    /*) ;;
    *) die "install directory must be an absolute path" ;;
esac

os=$(uname -s)
arch=$(uname -m)
if [ "$restart" = true ]; then
    nodelist_url=${nodelist_url:-http://127.0.0.1:6173}
    # Require a numeric HTTP origin with an explicit port. Listener ownership
    # is checked before making any request to it.
    printf '%s\n' "$nodelist_url" | LC_ALL=C awk '
        NR == 1 && /^http:\/\/([0-9.]+|\[[[:xdigit:]:.]+\]):[0-9]+$/ {
            port = $0
            sub(/^.*:/, "", port)
            valid = port > 0 && port <= 65535
        }
        END { exit !(NR == 1 && valid) }
    ' || die "--nodelist-url requires a numeric HTTP address and port"
    case "$os" in
        Darwin) service_target=${service_target:-gui/$(id -u)/io.oixc.proxy} ;;
        Linux) service_target=${service_target:-user/oixc-proxy.service} ;;
        *) die "--restart requires launchd or systemd" ;;
    esac
    case "$service_target" in
        *[!A-Za-z0-9_./@:-]*) die "invalid service target" ;;
    esac
    service_unit=${service_target#*/}
    service_scope=${service_target%%/*}
    case "$os:$service_target" in
        Darwin:gui/"$(id -u)"/?*)
            service_unit=${service_unit#*/}
            ;;
        Darwin:system/?*|Linux:user/?*.service|Linux:system/?*.service) ;;
        *) die "service target does not match this platform and user" ;;
    esac
    case "$service_unit" in
        -*|*/*) die "invalid service name" ;;
    esac
    command -v curl >/dev/null 2>&1 || die "--restart requires curl"
    command -v lsof >/dev/null 2>&1 || die "--restart requires lsof"
elif [ -n "$service_target$nodelist_url" ]; then
    die "--service-target and --nodelist-url require --restart"
fi
case "$os" in
    Darwin) os_target=apple-darwin ;;
    Linux) os_target=unknown-linux-musl ;;
    *) die "unsupported operating system: $os" ;;
esac
case "$arch" in
    x86_64|amd64) arch_target=x86_64 ;;
    arm64|aarch64) arch_target=aarch64 ;;
    *) die "unsupported architecture: $arch" ;;
esac

target=${arch_target}-${os_target}
asset=oixc-proxy-${target}.tar.gz
if [ "$release" != latest ]; then
    case "$release" in
        *[!A-Za-z0-9.+-]*) die "version contains unsupported characters" ;;
    esac
    case "$release" in
        v*) release_tag=$release ;;
        *) release_tag=v$release ;;
    esac
fi
if [ -n "$release_base" ]; then
    base=${release_base%/}
elif [ "$release" = latest ]; then
    base=https://github.com/${repository}/releases/latest/download
else
    base=https://github.com/${repository}/releases/download/${release_tag}
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/oixc-proxy-install.XXXXXX")
stage=
rollback=false
cleanup() {
    result=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ "$rollback" = true ]; then
        result=1
        rollback_service
    fi
    if [ -n "$stage" ]; then
        install_cmd rm -f "$stage/new" "$stage/backup" "$stage/restore" &&
            install_cmd rmdir "$stage" || result=1
    fi
    rm -rf "$tmp_dir"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
    url=$1
    output=$2
    if command -v curl >/dev/null 2>&1; then
        case "$url" in
            https://*) curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$output" ;;
            *) curl -fsSL "$url" -o "$output" ;;
        esac
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$output" "$url"
    else
        die "curl or wget is required"
    fi
}

archive=$tmp_dir/$asset
checksums=$tmp_dir/SHA256SUMS
use_gh=false
if [ -z "$release_base" ] && command -v gh >/dev/null 2>&1; then
    if [ -n "$github_token" ] || gh auth status --hostname github.com >/dev/null 2>&1; then
        use_gh=true
    fi
fi
if [ "$use_gh" = true ]; then
    if [ -n "$github_token" ]; then
        GH_TOKEN=$github_token
        export GH_TOKEN
    fi
    if [ "$release" = latest ]; then
        gh release download --repo "$repository" \
            --pattern "$asset" --pattern SHA256SUMS --dir "$tmp_dir"
    else
        gh release download "$release_tag" --repo "$repository" \
            --pattern "$asset" --pattern SHA256SUMS --dir "$tmp_dir"
    fi
else
    download "$base/$asset" "$archive" || die "download failed; private repositories require gh authenticated by login or token"
    download "$base/SHA256SUMS" "$checksums" || die "download failed; private repositories require gh authenticated by login or token"
fi

expected=$(awk -v file="$asset" '$2 == file || $2 == ("*" file) { print $1; exit }' "$checksums")
[ -n "$expected" ] || die "$asset is missing from SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$archive" | awk '{ print $1 }')
else
    die "sha256sum or shasum is required"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $asset"

entries=$(tar -tzf "$archive")
[ "$entries" = oixc-proxy ] || die "release archive has unexpected contents"
extract_dir=$tmp_dir/extracted
mkdir "$extract_dir"
tar -xzf "$archive" -C "$extract_dir"
binary=$extract_dir/oixc-proxy
[ -f "$binary" ] && [ ! -L "$binary" ] || die "release archive does not contain a regular binary"
chmod 0755 "$binary"

reported=$("$binary" version)
case "$reported" in
    "oixc-proxy "*" (commit "*) ;;
    *) die "downloaded binary did not report an oixc-proxy version" ;;
esac
if [ "$release" != latest ]; then
    expected_version=${release_tag#v}
    case "$reported" in
        "oixc-proxy $expected_version ("*) ;;
        *) die "downloaded binary version does not match $release_tag: $reported" ;;
    esac
fi

destination=$install_dir/oixc-proxy
parent=$(dirname "$install_dir")
install_sudo=false
if [ "$(id -u)" -ne 0 ] && [ ! -w "$install_dir" ] &&
    { [ -e "$install_dir" ] || [ ! -w "$parent" ]; }; then
    command -v sudo >/dev/null 2>&1 || die "$install_dir is not writable and sudo is unavailable"
    install_sudo=true
fi

install_cmd() {
    if [ "$install_sudo" = true ]; then sudo "$@"; else "$@"; fi
}

service_cmd() {
    if [ "$service_scope" = system ] && [ "$(id -u)" -ne 0 ]; then
        sudo "$@"
    else
        "$@"
    fi
}

systemd() {
    if [ "$service_scope" = user ]; then
        systemctl --user "$@" "$service_unit"
    else
        service_cmd systemctl "$@" "$service_unit"
    fi
}

launchd_value() {
    # Only accept the job's top-level scalar, never nested service properties.
    service_cmd launchctl print "$service_target" 2>/dev/null |
        awk -v prefix="$1 = " 'index($0, "\t" prefix) == 1 {
            print substr($0, 2 + length(prefix)); exit
        }'
}

service_pid() {
    if [ "$os" = Darwin ]; then
        pid=$(launchd_value pid)
    else
        pid=$(systemd show --property=MainPID --value 2>/dev/null) || return 1
    fi
    case "$pid" in
        ''|0|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "$pid"
}

listeners() {
    service_cmd lsof -nP -a -p "$1" -iTCP -sTCP:LISTEN -Fn 2>/dev/null |
        LC_ALL=C awk '/^n/ { print substr($0, 2) }' | LC_ALL=C sort -u
}

endpoints_healthy() {
    probe_listeners=$(listeners "$1")
    printf '%s\n' "$probe_listeners" | awk -v address="${nodelist_url#http://}" '
        BEGIN { port = address; sub(/^.*:/, "", port) }
        $0 == address ||
            ($0 == ("*:" port) && (address == ("127.0.0.1:" port) || address == ("[::1]:" port))) {
            found = 1
        }
        END { exit !found }
    ' || return 1
    [ "$probe_listeners" = "$old_listeners" ] || return 1
    health=$(curl -q --noproxy '*' --max-time 2 -s -o /dev/null -w '%{http_code}' \
        "$nodelist_url/healthz") && [ "$health" = 204 ] || return 1
    provider=$(curl -q --noproxy '*' --max-time 2 -s -o /dev/null -w '%{http_code}' \
        "$nodelist_url/surge-proxies.conf?all=1") && [ "$provider" = 200 ] || return 1
    [ "$(service_pid || :)" = "$1" ]
}

restart_service() {
    stopped_pid=$1
    deadline=$(( $(date +%s) + 60 ))
    if [ "$os" = Darwin ]; then
        if [ -n "$stopped_pid" ]; then
            service_cmd launchctl kill SIGTERM "$service_target" || return 1
            while service_cmd kill -0 "$stopped_pid" 2>/dev/null; do
                [ "$(date +%s)" -lt "$deadline" ] || return 1
                sleep 1
            done
        fi
        # Give KeepAlive a chance to start the job. kickstart without -k
        # also handles jobs without KeepAlive and never kills a running job.
        if ! service_pid >/dev/null; then
            service_cmd launchctl kickstart -p "$service_target" >/dev/null || return 1
        fi
    else
        systemd restart --no-block || return 1
    fi
    while [ "$(date +%s)" -lt "$deadline" ]; do
        new_pid=$(service_pid || :)
        if [ -n "$new_pid" ] && [ "$new_pid" != "$stopped_pid" ] &&
            endpoints_healthy "$new_pid"; then
            if [ "$os" = Darwin ] || [ "$destination" -ef "/proc/$new_pid/exe" ] ||
                { [ "$service_scope" = system ] &&
                    service_cmd test "$destination" -ef "/proc/$new_pid/exe"; }; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}

rollback_service() {
    echo "install.sh: upgrade failed, restoring $destination.previous" >&2
    if ! install_cmd cp -p "$destination.previous" "$stage/restore" ||
        ! install_cmd mv -f "$stage/restore" "$destination"; then
        echo "install.sh: rollback could not restore the binary. Backup: $destination.previous" >&2
        return
    fi
    rollback_pid=$(service_pid || :)
    if [ "$rollback_pid" = "$old_pid" ] && [ "$restart_sent" = false ] &&
        endpoints_healthy "$old_pid"; then
        echo "install.sh: restored the binary and verified the original service (PID $old_pid)" >&2
    elif restart_service "$rollback_pid"; then
        echo "install.sh: previous version restored and verified (PID $new_pid)" >&2
    else
        echo "install.sh: previous binary restored, but service recovery could not be verified" >&2
    fi
}

if [ "$restart" = true ]; then
    [ -f "$destination" ] && [ ! -L "$destination" ] && [ -x "$destination" ] ||
        die "--restart requires an installed executable at $destination"
    old_pid=$(service_pid) || die "$service_target is not running"
    if [ "$os" = Darwin ]; then
        program=$(launchd_value program)
        [ -n "$program" ] && [ "$program" -ef "$destination" ] ||
            die "$service_target does not use $destination"
    else
        service_cmd test "$destination" -ef "/proc/$old_pid/exe" ||
            die "$service_target does not run the current binary at $destination"
        signal=$(systemd show --property=KillSignal --value)
        case "$signal" in
            15|SIGTERM|2|SIGINT) ;;
            *) die "$service_target must stop with SIGTERM or SIGINT for graceful upgrade" ;;
        esac
    fi
    old_listeners=$(listeners "$old_pid")
    endpoints_healthy "$old_pid" ||
        die "the running service does not own a healthy nodelist at $nodelist_url"
fi

install_cmd mkdir -p "$install_dir"
lock=$install_dir/.oixc-proxy-install.lock
install_cmd mkdir -m 700 "$lock" ||
    die "could not acquire $lock (another install may be running)"
stage=$lock
[ ! -d "$destination" ] || die "binary destination is a directory"
install_cmd cp "$binary" "$stage/new"
install_cmd chmod 0755 "$stage/new"
install_cmd cmp -s "$binary" "$stage/new" ||
    die "staged binary does not match the verified release"
if [ "$restart" = true ]; then
    [ "$(service_pid || :)" = "$old_pid" ] || die "service changed during preflight"
    [ ! -d "$destination.previous" ] || die "backup destination is a directory"
    install_cmd cp -p "$destination" "$stage/backup"
    install_cmd mv -f "$stage/backup" "$destination.previous"
    restart_sent=false
    rollback=true
fi
install_cmd mv -f "$stage/new" "$destination"
installed=$("$destination" version)
[ "$installed" = "$reported" ] || die "installed binary reported a different version"
if [ "$restart" = true ]; then
    restart_sent=true
    restart_service "$old_pid" || die "$service_target did not become healthy"
    rollback=false
    echo "Updated $service_target to $installed at $destination (PID $old_pid → $new_pid)"
else
    echo "Installed $installed at $destination"
    echo "See DEPLOY.md for service setup and updates."
fi
