#!/bin/sh
# Rebuild vendor/rustls as published rustls plus vendor/rustls-ech-outer-alpn.patch.
#
#   scripts/vendor-rustls.sh check            vendored tree equals published source + patch
#   scripts/vendor-rustls.sh outdated         fail if a newer rustls 0.23.x is published
#   scripts/vendor-rustls.sh update [VERSION] regenerate from VERSION (default: newest 0.23.x)
#
# Sources are fetched through cargo, so registry mirrors configured for cargo apply.
set -eu

rust_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
vendored="$rust_root/vendor/rustls"
patch_file="$rust_root/vendor/rustls-ech-outer-alpn.patch"
series=0.23
work=$(mktemp -d "${TMPDIR:-/tmp}/oixc-vendor-rustls.XXXXXX")

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

usage() {
    echo "usage: $0 check | outdated | update [VERSION]" >&2
    exit 2
}

vendored_version() {
    awk -F '"' '/^version = / { print $2; exit }' "$vendored/Cargo.toml"
}

# Resolve a rustls requirement in a throwaway package outside this workspace.
resolve() {
    probe="$work/probe-$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"
    mkdir -p "$probe/src"
    : > "$probe/src/lib.rs"
    cat > "$probe/Cargo.toml" <<EOF
[package]
name = "vendor-rustls-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
rustls = { version = "$1", default-features = false, features = ["std"] }
EOF
    cargo generate-lockfile --quiet --manifest-path "$probe/Cargo.toml"
    id=$(cd "$probe" && cargo pkgid --quiet rustls)
    printf '%s\n' "${id##*[@#]}"
}

latest_version() {
    resolve "$series"
}

# Print the directory of the published crate source for an exact version.
fetch_source() {
    resolve "=$1" > /dev/null
    probe="$work/probe-$(printf '%s' "=$1" | tr -c 'A-Za-z0-9' '_')"
    cargo fetch --quiet --manifest-path "$probe/Cargo.toml"
    manifest=$(cargo metadata --quiet --format-version 1 --manifest-path "$probe/Cargo.toml" |
        grep -o "\"manifest_path\":\"[^\"]*/rustls-$1/Cargo.toml\"" | head -n 1 |
        sed -e 's/^"manifest_path":"//' -e 's/"$//')
    [ -n "$manifest" ] || { echo "rustls $1 source not found" >&2; exit 1; }
    dirname -- "$manifest"
}

# Copy published sources without packaging metadata, benches or examples.
build_tree() {
    source=$(fetch_source "$1")
    mkdir -p "$2"
    for entry in build.rs Cargo.toml LICENSE-APACHE LICENSE-ISC LICENSE-MIT README.md src; do
        cp -R "$source/$entry" "$2/"
    done
    # A rejected hunk fails here; offset hunks only leave backups to discard.
    (cd "$2" && patch --quiet --forward -p1 < "$patch_file")
    find "$2" -name '*.orig' -type f -exec rm -f {} +
}

command=${1:-}
case "$command" in
    check)
        [ $# -eq 1 ] || usage
        version=$(vendored_version)
        build_tree "$version" "$work/expected"
        if ! diff -r "$work/expected" "$vendored"; then
            echo "vendor/rustls differs from rustls $version + $(basename "$patch_file")" >&2
            exit 1
        fi
        echo "vendor/rustls matches rustls $version + $(basename "$patch_file")"
        ;;
    outdated)
        [ $# -eq 1 ] || usage
        version=$(vendored_version)
        latest=$(latest_version)
        if [ "$latest" != "$version" ]; then
            echo "rustls $latest is published; vendor/rustls is $version" >&2
            echo "run scripts/vendor-rustls.sh update and review upstream advisories" >&2
            exit 1
        fi
        echo "vendor/rustls $version is the newest rustls $series.x"
        ;;
    update)
        [ $# -le 2 ] || usage
        version=${2:-$(latest_version)}
        build_tree "$version" "$work/rustls"
        rm -rf "$vendored"
        mv "$work/rustls" "$vendored"
        echo "vendor/rustls regenerated from rustls $version; run cargo update -p rustls and the ECH checks"
        ;;
    *)
        usage
        ;;
esac
