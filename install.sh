#!/bin/sh
# Install falconnet and put it on PATH.
#
#   curl -fsSL https://github.com/FalconTechDev/falconnet/releases/latest/download/install.sh | sh
#
# Nothing here needs root: the binary goes under your home directory, and the
# PATH line is added to your own shell's startup file. Set FALCONNET_DIR to
# install somewhere else.

set -eu

REPO="FalconTechDev/falconnet"
BIN="falconnet"
DIR="${FALCONNET_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required and was not found"
}

# ── which build ──────────────────────────────────────────────────────────────

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux)  os_part="unknown-linux-gnu" ;;
    Darwin) os_part="apple-darwin" ;;
    *)      die "no build for $os — clone the repository and 'cargo build --release'" ;;
esac

case "$arch" in
    x86_64|amd64)  arch_part="x86_64" ;;
    aarch64|arm64) arch_part="aarch64" ;;
    *)             die "no build for $arch — clone the repository and 'cargo build --release'" ;;
esac

target="${arch_part}-${os_part}"

# ── fetch ────────────────────────────────────────────────────────────────────

need tar
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
else
    die "neither curl nor wget is available"
fi

tag="${FALCONNET_VERSION:-latest}"
if [ "$tag" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$tag"
fi

tmp=$(mktemp -d)
# Leave nothing behind, including when the download fails halfway.
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading falconnet for $target…"
archive="falconnet-${tag}-${target}.tar.gz"
if [ "$tag" = "latest" ]; then
    # The latest-download URL has no version in it, so ask the API for the tag
    # rather than guessing at the file name.
    tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" /dev/stdout 2>/dev/null \
        | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$tag" ] || die "could not work out the latest version — set FALCONNET_VERSION"
    archive="falconnet-${tag}-${target}.tar.gz"
fi

fetch "$base/$archive" "$tmp/$archive" || die "no release archive at $base/$archive"

# Verify what arrived, when there is something to verify it against.
if fetch "$base/$archive.sha256" "$tmp/$archive.sha256" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
        expected=$(cut -d' ' -f1 < "$tmp/$archive.sha256")
        actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        expected=$(cut -d' ' -f1 < "$tmp/$archive.sha256")
        actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
    fi
    if [ -n "${expected:-}" ] && [ "$expected" != "${actual:-}" ]; then
        die "checksum mismatch — the download is not what the release published"
    fi
fi

tar xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$DIR"
install -m 0755 "$tmp/falconnet-${tag}-${target}/$BIN" "$DIR/$BIN" 2>/dev/null \
    || { cp "$tmp/falconnet-${tag}-${target}/$BIN" "$DIR/$BIN" && chmod 0755 "$DIR/$BIN"; }

say "Installed $DIR/$BIN"

# ── PATH ─────────────────────────────────────────────────────────────────────

case ":$PATH:" in
    *":$DIR:"*)
        say "$DIR is already on your PATH."
        say "Run: $BIN --help"
        exit 0
        ;;
esac

# Add the line once, to the file the user's own shell actually reads.
line="export PATH=\"$DIR:\$PATH\""
case "${SHELL##*/}" in
    zsh)  rc="$HOME/.zshrc" ;;
    bash) [ -f "$HOME/.bashrc" ] && rc="$HOME/.bashrc" || rc="$HOME/.bash_profile" ;;
    fish)
        mkdir -p "$HOME/.config/fish"
        rc="$HOME/.config/fish/config.fish"
        line="fish_add_path $DIR"
        ;;
    *)    rc="$HOME/.profile" ;;
esac

if [ -f "$rc" ] && grep -Fq "$DIR" "$rc"; then
    say "$rc already mentions $DIR."
else
    printf '\n# added by the falconnet installer\n%s\n' "$line" >> "$rc"
    say "Added $DIR to your PATH in $rc"
fi

say ""
say "Open a new terminal, or run:  . $rc"
say "Then:  $BIN --help"
