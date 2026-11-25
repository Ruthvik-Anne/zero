#!/bin/sh
# Zero Unix installer (T-INST-03; INST-03, INST-04, INST-05).
#
# Installs one already-downloaded executable after verifying its SHA-256. POSIX
# sh only: it runs under dash, ash, and the macOS system shell. It needs no
# Node and no other runtime.
#
# This installer never escalates privileges. A prefix that needs administrator
# rights is refused with guidance instead of failing with a raw permission
# error.
#
# Exit codes: 0 installed or already installed; 2 bad usage; 3 refused (lock,
# checksum, conflict, permissions); 4 missing tool or I/O failure.
set -eu
umask 022

PROG=zero-unix-install
PREFIX=
ARTIFACT=
NAME=zero
SHA256=
FORCE=0
UNINSTALL=0
NO_PATH=0
UPDATE_PATH=0

LOCK=
LOCK_HELD=0
TMP_FILE=
STTY_INITIAL=
CLEANED=0

say() {
    printf '%s\n' "$*"
}

warn() {
    printf '%s\n' "$*" >&2
}

die() {
    warn "$PROG: $*"
    exit 4
}

refuse() {
    warn "$PROG: $*"
    exit 3
}

usage_error() {
    warn "$PROG: $*"
    warn "run '$PROG --help' for the flags"
    exit 2
}

usage() {
    cat <<'USAGE'
usage: sh installer/unix.sh [options]

Install or remove one Zero executable without administrator rights.

options:
  --prefix DIR     install root; the binary goes to DIR/bin (default
                   $HOME/.local). Must be an absolute path this user can write.
  --file PATH      artifact to install (required unless --uninstall)
  --name NAME      installed file name (default: zero)
  --sha256 HEX     expected SHA-256 of --file, 64 lowercase hex (required)
  --force          replace an existing binary that has different content
  --uninstall      remove the installed binary and the lock; keep user data
  --no-path        do not print PATH guidance and never edit a shell profile
  --update-path    append the PATH line to ~/.profile (or ~/.zshrc for zsh)
  --help           print this help

safety:
  the checksum is verified before anything is written, the install is staged
  and renamed atomically, a lock directory refuses concurrent installs, and
  INT/TERM/EXIT traps clean the temporary file and the lock. Nothing is ever
  prompted: the installer runs the same way without a TTY. The terminal state
  is restored only if it changed.

exit codes: 0 ok, 2 usage, 3 refused, 4 missing tool or I/O failure
USAGE
}

cleanup() {
    if [ "$CLEANED" -eq 1 ]; then
        return 0
    fi
    CLEANED=1
    if [ -n "$TMP_FILE" ] && [ -e "$TMP_FILE" ]; then
        rm -f "$TMP_FILE" 2>/dev/null || true
        TMP_FILE=
    fi
    if [ -n "$STTY_INITIAL" ]; then
        CURRENT_STTY=$(stty -g 2>/dev/null || true)
        if [ "$CURRENT_STTY" != "$STTY_INITIAL" ]; then
            stty sane 2>/dev/null || true
        fi
    fi
    if [ "$LOCK_HELD" -eq 1 ]; then
        rm -f "$LOCK/pid" 2>/dev/null || true
        rmdir "$LOCK" 2>/dev/null || true
        LOCK_HELD=0
    fi
    return 0
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

acquire_lock() {
    if mkdir "$LOCK" 2>/dev/null; then
        printf '%s\n' "$$" >"$LOCK/pid" || die "could not write the install lock at $LOCK"
        LOCK_HELD=1
        return 0
    fi
    OWNER=
    if [ -f "$LOCK/pid" ]; then
        OWNER=$(cat "$LOCK/pid" 2>/dev/null || true)
    fi
    case "$OWNER" in
        '' | *[!0-9]*) OWNER= ;;
    esac
    if [ -n "$OWNER" ] && kill -0 "$OWNER" 2>/dev/null; then
        refuse "another install is already running for $PREFIX (pid $OWNER); wait for it, or remove $LOCK"
    fi
    say "removing a stale install lock at $LOCK"
    rm -f "$LOCK/pid" 2>/dev/null || true
    rmdir "$LOCK" 2>/dev/null || refuse "could not clear the stale install lock at $LOCK"
    if mkdir "$LOCK" 2>/dev/null; then
        printf '%s\n' "$$" >"$LOCK/pid" || die "could not write the install lock at $LOCK"
        LOCK_HELD=1
        return 0
    fi
    refuse "another install took the lock for $PREFIX"
}

ensure_user_writable() {
    PROBE=$PREFIX
    while [ ! -e "$PROBE" ]; do
        PARENT=$(dirname "$PROBE")
        if [ "$PARENT" = "$PROBE" ]; then
            break
        fi
        PROBE=$PARENT
    done
    if [ -d "$PROBE" ] && [ -w "$PROBE" ]; then
        return 0
    fi
    refuse "refusing to install into $INSTALL_DIR: that location needs administrator rights; choose a user prefix such as '$HOME/.local', or create the directory with the right owner first"
}

compute_sha256() {
    HASH_INPUT=$1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$HASH_INPUT" | cut -d ' ' -f 1
        return 0
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$HASH_INPUT" | cut -d ' ' -f 1
        return 0
    fi
    return 1
}

print_path_guidance() {
    if [ "$NO_PATH" -eq 1 ]; then
        return 0
    fi
    say ""
    say "PATH: add this line to your shell profile:"
    say "  export PATH=\"$INSTALL_DIR:\$PATH\""
    if [ "$UPDATE_PATH" -eq 1 ]; then
        PROFILE=$HOME/.profile
        case "${SHELL:-}" in
            *zsh*) PROFILE=$HOME/.zshrc ;;
        esac
        PATH_LINE="export PATH=\"$INSTALL_DIR:\$PATH\""
        if [ -f "$PROFILE" ] && grep -F "$PATH_LINE" "$PROFILE" >/dev/null 2>&1; then
            say "the PATH line is already present in $PROFILE"
        else
            printf '\n# Added by the zero installer\n%s\n' "$PATH_LINE" >>"$PROFILE" || die "could not write $PROFILE"
            say "appended the PATH line to $PROFILE"
        fi
    else
        say "no shell profile was edited; pass --update-path to append that line"
    fi
    say "then run: export PATH=\"$INSTALL_DIR:\$PATH\""
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || usage_error "--prefix needs a directory"
            PREFIX=$2
            shift 2
            ;;
        --prefix=*)
            PREFIX=${1#*=}
            shift
            ;;
        --file)
            [ $# -ge 2 ] || usage_error "--file needs a path"
            ARTIFACT=$2
            shift 2
            ;;
        --file=*)
            ARTIFACT=${1#*=}
            shift
            ;;
        --name)
            [ $# -ge 2 ] || usage_error "--name needs a value"
            NAME=$2
            shift 2
            ;;
        --name=*)
            NAME=${1#*=}
            shift
            ;;
        --sha256)
            [ $# -ge 2 ] || usage_error "--sha256 needs a digest"
            SHA256=$2
            shift 2
            ;;
        --sha256=*)
            SHA256=${1#*=}
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --no-path)
            NO_PATH=1
            shift
            ;;
        --update-path)
            UPDATE_PATH=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        -h)
            usage
            exit 0
            ;;
        *)
            usage_error "unknown option '$1'"
            ;;
    esac
done

if [ -z "${HOME:-}" ]; then
    die "HOME is not set; pass --prefix explicitly"
fi
if [ -z "$PREFIX" ]; then
    PREFIX=$HOME/.local
fi
while [ "$PREFIX" != "/" ] && [ "${PREFIX%/}" != "$PREFIX" ]; do
    PREFIX=${PREFIX%/}
done
case "$PREFIX" in
    /*) ;;
    *) usage_error "--prefix must be an absolute path" ;;
esac
if [ "$PREFIX" = "/" ]; then
    refuse "refusing to install into the filesystem root; choose a user prefix such as '$HOME/.local'"
fi
case "$NAME" in
    '' | . | .. | */*)
        usage_error "--name must be a plain file name"
        ;;
esac
if [ "$NO_PATH" -eq 1 ] && [ "$UPDATE_PATH" -eq 1 ]; then
    usage_error "--no-path and --update-path cannot be combined"
fi

INSTALL_DIR=$PREFIX/bin
TARGET=$INSTALL_DIR/$NAME
LOCK=$PREFIX/.zero-install.lock

if [ "$UNINSTALL" -eq 1 ]; then
    if [ ! -e "$PREFIX" ]; then
        say "nothing to uninstall: $PREFIX does not exist"
        exit 0
    fi
    acquire_lock
    if [ -e "$TARGET" ]; then
        rm -f "$TARGET" || die "could not remove $TARGET"
        say "removed $TARGET"
    else
        say "not installed: $TARGET"
    fi
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    say ""
    say "Kept: user data and configuration. Nothing under the Zero data directories was touched."
    say "Reinstall with --file and --sha256 when needed."
    exit 0
fi

if [ -z "$ARTIFACT" ]; then
    usage_error "--file is required to install"
fi
case "$SHA256" in
    '' | *[!0-9a-f]*)
        usage_error "--sha256 must be 64 lowercase hex characters"
        ;;
esac
if [ ${#SHA256} -ne 64 ]; then
    usage_error "--sha256 must be 64 lowercase hex characters"
fi

HAVE_TTY=0
if [ -t 0 ]; then
    HAVE_TTY=1
    STTY_INITIAL=$(stty -g 2>/dev/null || true)
fi

if [ ! -f "$ARTIFACT" ]; then
    die "artifact not found: $ARTIFACT"
fi
if [ ! -r "$ARTIFACT" ]; then
    die "artifact is not readable: $ARTIFACT"
fi

ACTUAL=$(compute_sha256 "$ARTIFACT") || die "neither sha256sum nor shasum is available to verify the checksum"
if [ "$ACTUAL" != "$SHA256" ]; then
    warn "$PROG: checksum mismatch for $ARTIFACT"
    warn "  expected $SHA256"
    warn "  actual   $ACTUAL"
    refuse "refusing to install an artifact that does not match --sha256"
fi

ensure_user_writable
mkdir -p "$INSTALL_DIR" 2>/dev/null || refuse "cannot create $INSTALL_DIR without administrator rights; choose a user prefix with --prefix"
if [ ! -w "$INSTALL_DIR" ]; then
    refuse "cannot write to $INSTALL_DIR; choose a user prefix with --prefix"
fi
acquire_lock

if [ -e "$TARGET" ]; then
    EXISTING=$(compute_sha256 "$TARGET" || true)
    if [ "$EXISTING" = "$SHA256" ]; then
        chmod 755 "$TARGET" 2>/dev/null || true
        say "already installed: $TARGET (identical sha256)"
        print_path_guidance
        say ""
        say "mode: non-interactive (no prompts were shown)"
        exit 0
    fi
    if [ "$FORCE" -ne 1 ]; then
        refuse "$TARGET already exists with different content; pass --force to replace it"
    fi
    say "replacing $TARGET (--force)"
fi

TMP_FILE=$INSTALL_DIR/.$NAME.tmp.$$
cp "$ARTIFACT" "$TMP_FILE" || die "could not copy $ARTIFACT to $TMP_FILE"
chmod 755 "$TMP_FILE" || die "could not make $TMP_FILE executable"
COPIED=$(compute_sha256 "$TMP_FILE") || die "could not verify the staged copy"
if [ "$COPIED" != "$SHA256" ]; then
    die "the staged copy does not match --sha256"
fi
mv -f "$TMP_FILE" "$TARGET" || die "could not move the staged binary into place"
TMP_FILE=

say "installed $TARGET"
if [ "$HAVE_TTY" -eq 1 ]; then
    say "mode: interactive terminal; no prompts were needed"
else
    say "mode: non-interactive (stdin is not a TTY); no prompts were shown"
fi
print_path_guidance
say ""
say "verify: $TARGET --version"
exit 0
