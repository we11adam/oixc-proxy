#!/bin/sh
set -eu

repository=${OIXC_REPOSITORY:-we11adam/oixc-proxy}
release=${OIXC_VERSION:-latest}
install_dir=${OIXC_INSTALL_DIR:-/usr/local/bin}
release_base=${OIXC_RELEASE_BASE_URL:-}
github_token=${GH_TOKEN:-${GITHUB_TOKEN:-}}

usage() {
    cat <<'EOF'
Usage: install.sh [--version VERSION] [--install-dir DIR]

Download a published oixc-proxy binary for the current macOS or Linux host,
verify it against the release SHA256SUMS file, and atomically install it.

Options:
  --version VERSION   Install a release tag such as v0.1.0 (default: latest)
  --install-dir DIR   Install directory (default: /usr/local/bin)
  -h, --help          Show this help

Environment:
  OIXC_REPOSITORY        GitHub owner/repository (default: we11adam/oixc-proxy)
  OIXC_VERSION           Same as --version
  OIXC_INSTALL_DIR       Same as --install-dir
  OIXC_RELEASE_BASE_URL  Override the release download directory (for mirrors)
  GH_TOKEN/GITHUB_TOKEN  Read-only token used by gh for private release assets

The script installs only the binary. It does not create configuration files,
install a service definition, or restart an existing service.
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
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

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
if [ "$release" != latest ]; then
    expected_version=${release_tag#v}
    case "$reported" in
        "oixc-proxy $expected_version ("*) ;;
        *) die "downloaded binary version does not match $release_tag: $reported" ;;
    esac
fi

destination=$install_dir/oixc-proxy
temporary=$install_dir/.oixc-proxy-install.$$
parent=$(dirname "$install_dir")
if [ "$(id -u)" -eq 0 ] || [ -w "$install_dir" ] || { [ ! -e "$install_dir" ] && [ -w "$parent" ]; }; then
    mkdir -p "$install_dir"
    cp "$binary" "$temporary"
    chmod 0755 "$temporary"
    mv -f "$temporary" "$destination"
else
    command -v sudo >/dev/null 2>&1 || die "$install_dir is not writable and sudo is unavailable"
    sudo mkdir -p "$install_dir"
    sudo cp "$binary" "$temporary"
    sudo chmod 0755 "$temporary"
    sudo mv -f "$temporary" "$destination"
fi

installed=$("$destination" version)
echo "Installed $installed at $destination"
echo "No service was created or restarted. See DEPLOY.md for service setup and updates."
