#!/bin/bash
# Install trusted code root-owned and keep request/response state user-owned.

set -euo pipefail
ORIGINAL_PATH="$PATH"
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

if [[ "$EUID" -eq 0 ]]; then
    echo "Error: run this script as your normal user; it invokes sudo narrowly." >&2
    exit 1
fi
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: the hardened installer only runs on macOS." >&2
    exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tools/privileged_tools.sh
source "$SOURCE_ROOT/tools/privileged_tools.sh"
load_privileged_tool_paths
PRODUCT_ROOT="/Library/Application Support/GrokBotIMessage"
USER_ROOT="$PRODUCT_ROOT/users/$UID"
CODE_ROOT="$USER_ROOT/libexec"
CONFIG_ROOT="$USER_ROOT/config"
BRIDGE_ROOT="${GROKBOT_IMESSAGE_BRIDGE:-$HOME/Library/Application Support/GrokBotIMessage}"
PLIST_TEMPLATE="$SOURCE_ROOT/com.jeffhuber.grokbot-imessage.plist.template"
PLIST_DEST="$HOME/Library/LaunchAgents/com.jeffhuber.grokbot-imessage.plist"
LABEL="com.jeffhuber.grokbot-imessage"
WATCH_PLIST_TEMPLATE="$SOURCE_ROOT/com.jeffhuber.grokbot-imessage-watch.plist.template"
WATCH_LABEL="com.jeffhuber.grokbot-imessage-watch"
WATCH_PLIST_DEST="$HOME/Library/LaunchAgents/$WATCH_LABEL.plist"
LEGACY_LABEL="com.user.cowork-imessage"
LEGACY_PLIST="$HOME/Library/LaunchAgents/$LEGACY_LABEL.plist"
LEGACY_WRAPPER="$CODE_ROOT/bin/cowork-imessage-helper"
LEGACY_MIGRATOR="$SOURCE_ROOT/tools/migrate_legacy_launchagent.py"
PYTHON_SELECTOR="$SOURCE_ROOT/tools/select_python.sh"
ALLOWLIST="$CONFIG_ROOT/allowed_chats.txt"
GATE_JSON="$CONFIG_ROOT/gate.json"
CONTACT_REFS_PY="$CODE_ROOT/bin/contact_refs.py"
GATE_CLIENT_PY="$CODE_ROOT/bin/gate_client.py"
CONFIGURE_GATE="$SOURCE_ROOT/tools/configure_gate.py"
CONFIGURE_GATE_INSTALLED="$CODE_ROOT/tools/configure_gate.py"
GATE_URL_INPUT="${IMESSAGE_GATE_URL:-}"
GATE_TOKEN_FILE="${IMESSAGE_GATE_TOKEN_FILE:-}"
GATE_TOKEN_INPUT=""
CURRENT_USER="$(id -un)"
# Root-owned 0700 build area: the setuid wrapper is compiled, signed, and
# installed as root, never from a directory a user process could write to.
BUILD_ROOT="$USER_ROOT/build"

if [[ ! -f "$PYTHON_SELECTOR" || -L "$PYTHON_SELECTOR" ]]; then
    echo "Error: missing regular Python selector: $PYTHON_SELECTOR" >&2
    exit 1
fi
# shellcheck source=tools/select_python.sh
source "$PYTHON_SELECTOR"

require_safe_runtime_entry() {
    local path="$1"
    local kind="$2"
    if [[ -L "$path" ]]; then
        echo "Error: refusing symlinked runtime path: $path" >&2
        exit 1
    fi
    if [[ -e "$path" && "$kind" == "directory" && ! -d "$path" ]]; then
        echo "Error: expected a runtime directory: $path" >&2
        exit 1
    fi
    if [[ -e "$path" && "$kind" == "file" && ! -f "$path" ]]; then
        echo "Error: expected a regular runtime file: $path" >&2
        exit 1
    fi
}

for cmd in clang codesign launchctl sudo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command not found: $cmd" >&2
        exit 1
    fi
done
if ! xcode-select -p >/dev/null 2>&1; then
    echo "Error: install Xcode Command Line Tools with xcode-select --install" >&2
    exit 1
fi
if ! PYTHON3_PATH="$(find_supported_python 1)"; then
    echo "Error: hardened mode requires a trusted Python 3.9 or newer" >&2
    echo "with dir_fd support. Its file and parents must be root-owned and protected." >&2
    echo "IMESSAGE_PYTHON, when set, must be an absolute trusted path." >&2
    exit 1
fi
if ! hardened_python_is_trusted "$PYTHON3_PATH"; then
    echo "Error: hardened mode requires a root-owned Python interpreter" >&2
    echo "whose file and parent directories are not symlinks or group/world-writable." >&2
    echo "Use /usr/bin/python3, provide a trusted IMESSAGE_PYTHON path, or run ./install.sh." >&2
    exit 1
fi
# The setuid wrapper execs the real interpreter, not the /usr/bin/python3 xcrun
# shim, so no per-user xcrun state sits between it and Python.
REAL_PYTHON="$(env -u DEVELOPER_DIR "$PYTHON3_PATH" -I -c \
    'import os, sys; print(os.path.realpath(sys.executable))')"
if [[ "$REAL_PYTHON" != /* ]] || ! hardened_python_is_trusted "$REAL_PYTHON"; then
    echo "Error: could not resolve a trusted real Python interpreter behind $PYTHON3_PATH" >&2
    exit 1
fi

for path in \
    "$SOURCE_ROOT/bin/helper.py" \
    "$SOURCE_ROOT/bin/send_gate.py" \
    "$SOURCE_ROOT/bin/contact_refs.py" \
    "$SOURCE_ROOT/bin/gate_client.py" \
    "$SOURCE_ROOT/bin/imessage_helper.c" \
    "$SOURCE_ROOT/contacts/gate.json.template" \
    "$CONFIGURE_GATE" \
    "$SOURCE_ROOT/bin/confirm_imessage_send.m" \
    "$SOURCE_ROOT/tools/doctor.py" \
    "$SOURCE_ROOT/tools/configure_allowlist.py" \
    "$PYTHON_SELECTOR" \
    "$LEGACY_MIGRATOR" \
    "$SOURCE_ROOT/contacts/blocked_chats.txt.template" \
    "$SOURCE_ROOT/contacts/allowed_chats.txt.template" \
    "$SOURCE_ROOT/install-skill.sh" \
    "$SOURCE_ROOT/tools/watch_tick.sh" \
    "$SOURCE_ROOT/tools/configure_watch_webhook.sh" \
    "$WATCH_PLIST_TEMPLATE" \
    "$PLIST_TEMPLATE"; do
    if [[ ! -f "$path" ]]; then
        echo "Error: missing source file: $path" >&2
        exit 1
    fi
done

# Approval gate (optional). IMESSAGE_GATE_URL names the gate origin; the helper
# token comes from IMESSAGE_GATE_TOKEN_FILE or a hidden prompt, and is passed to
# configure_gate.py on stdin only. Without IMESSAGE_GATE_URL, an existing gate
# section in gate.json is kept as-is.
if [[ -n "$GATE_URL_INPUT" ]]; then
    if [[ -n "$GATE_TOKEN_FILE" ]]; then
        if [[ -L "$GATE_TOKEN_FILE" || ! -f "$GATE_TOKEN_FILE" ]]; then
            echo "Error: IMESSAGE_GATE_TOKEN_FILE must be a regular file: $GATE_TOKEN_FILE" >&2
            exit 1
        fi
        IFS= read -r GATE_TOKEN_INPUT < "$GATE_TOKEN_FILE" || true
    elif [[ -t 0 ]]; then
        IFS= read -r -s -p "Approval gate helper token for $GATE_URL_INPUT (input hidden): " \
            GATE_TOKEN_INPUT
        echo >&2
    else
        echo "Error: set IMESSAGE_GATE_TOKEN_FILE or run interactively to enter the helper token." >&2
        exit 1
    fi
    if [[ -z "$GATE_TOKEN_INPUT" ]]; then
        echo "Error: empty approval gate helper token." >&2
        exit 1
    fi
fi

# Upgrading from the layout where gate.json carried a user-read ACL: its helper
# token and contact-ref key were readable by any process running as you, so
# both are rotated now. IMESSAGE_GATE_ROTATE=1 forces the same rotation.
ROTATE_SECRETS=0
if [[ "${IMESSAGE_GATE_ROTATE:-0}" == "1" ]]; then
    ROTATE_SECRETS=1
elif [[ -f "$GATE_JSON" ]] && /bin/ls -le "$GATE_JSON" 2>/dev/null | grep -q "allow read"; then
    ROTATE_SECRETS=1
fi
if [[ "$ROTATE_SECRETS" == "1" ]]; then
    echo "gate.json secrets will be rotated (new contact-ref key; a new helper token is required)."
    if [[ -z "$GATE_URL_INPUT" ]] && grep -q '"helper_token"' "$GATE_JSON" 2>/dev/null; then
        echo "Error: the old helper token was readable by your user. Ask for a new token on the" >&2
        echo "gate, then rerun with IMESSAGE_GATE_URL=... and IMESSAGE_GATE_TOKEN_FILE=<new token>." >&2
        exit 1
    fi
fi

for path in "$BRIDGE_ROOT/control" "$BRIDGE_ROOT/control/requests" \
    "$BRIDGE_ROOT/control/responses" "$BRIDGE_ROOT/contacts"; do
    require_safe_runtime_entry "$path" directory
done
for path in "$BRIDGE_ROOT/control/log.txt" \
    "$BRIDGE_ROOT/contacts/blocked_chats.txt" \
    "$BRIDGE_ROOT/contacts/read_policy.txt"; do
    require_safe_runtime_entry "$path" file
done
mkdir -p "$BRIDGE_ROOT/control/requests" "$BRIDGE_ROOT/control/responses" \
    "$BRIDGE_ROOT/contacts"
BRIDGE_ROOT="$(cd "$BRIDGE_ROOT" && pwd -P)"
touch "$BRIDGE_ROOT/control/log.txt"
chmod 700 "$BRIDGE_ROOT" "$BRIDGE_ROOT/control" \
    "$BRIDGE_ROOT/control/requests" "$BRIDGE_ROOT/control/responses" \
    "$BRIDGE_ROOT/contacts"
chmod 600 "$BRIDGE_ROOT/control/log.txt"

if [[ ! -f "$BRIDGE_ROOT/contacts/blocked_chats.txt" ]]; then
    cp "$SOURCE_ROOT/contacts/blocked_chats.txt.template" \
        "$BRIDGE_ROOT/contacts/blocked_chats.txt"
fi
printf 'allowlist\n' > "$BRIDGE_ROOT/contacts/read_policy.txt"
chmod 600 "$BRIDGE_ROOT/contacts/blocked_chats.txt" \
    "$BRIDGE_ROOT/contacts/read_policy.txt"

echo "Requesting administrator access for the root-owned code and policy..."
sudo -v
sudo "$INSTALL_BIN" -d -o root -g wheel -m 755 \
    "$PRODUCT_ROOT" "$PRODUCT_ROOT/users" "$USER_ROOT" "$CODE_ROOT" \
    "$CODE_ROOT/bin" "$CODE_ROOT/tools" "$CONFIG_ROOT"
if [[ -L "$ALLOWLIST" ]]; then
    echo "Error: hardened allowlist must not be a symlink: $ALLOWLIST" >&2
    exit 1
fi
if [[ ! -e "$ALLOWLIST" ]]; then
    sudo "$INSTALL_BIN" -o root -g wheel -m 600 \
        "$SOURCE_ROOT/contacts/allowed_chats.txt.template" "$ALLOWLIST"
fi
if ! "$PYTHON3_PATH" - "$ALLOWLIST" <<'PYCHECK'; then
import os
import stat
import sys

metadata = os.lstat(sys.argv[1])
valid = stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
valid = valid and not metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
raise SystemExit(0 if valid else 1)
PYCHECK
    echo "Error: existing hardened allowlist is not a protected root-owned file." >&2
    exit 1
fi
if ! sudo "$CHMOD_BIN" -N "$ALLOWLIST" 2>/dev/null; then
    echo "  no existing ACL to clear"
fi
sudo "$CHMOD_BIN" +a "user:$CURRENT_USER allow read" "$ALLOWLIST"

if [[ -L "$GATE_JSON" ]]; then
    echo "Error: hardened gate config must not be a symlink: $GATE_JSON" >&2
    exit 1
fi
# Only run root-owned copies as root: stage both files into the code root first.
sudo "$INSTALL_BIN" -o root -g wheel -m 444 \
    "$SOURCE_ROOT/bin/gate_client.py" "$GATE_CLIENT_PY"
sudo "$INSTALL_BIN" -o root -g wheel -m 444 \
    "$CONFIGURE_GATE" "$CONFIGURE_GATE_INSTALLED"
CONFIGURE_ARGS=(--gate-json "$GATE_JSON")
if [[ "$ROTATE_SECRETS" == "1" ]]; then
    CONFIGURE_ARGS+=(--rotate-hmac-key)
fi
if [[ -n "$GATE_URL_INPUT" ]]; then
    CONFIGURE_ARGS+=(--gate-url "$GATE_URL_INPUT" --token-stdin)
    if [[ "$ROTATE_SECRETS" == "1" ]]; then
        CONFIGURE_ARGS+=(--require-new-token)
    fi
    printf '%s\n' "$GATE_TOKEN_INPUT" | sudo "$PYTHON3_PATH" -I "$CONFIGURE_GATE_INSTALLED" \
        "${CONFIGURE_ARGS[@]}"
    GATE_TOKEN_INPUT=""
else
    sudo "$PYTHON3_PATH" -I "$CONFIGURE_GATE_INSTALLED" "${CONFIGURE_ARGS[@]}"
fi
if [[ -e "$GATE_JSON" ]]; then
    sudo "$CHOWN_BIN" root:wheel "$GATE_JSON"
    sudo "$CHMOD_BIN" 600 "$GATE_JSON"
fi
if ! "$PYTHON3_PATH" - "$GATE_JSON" <<'PYCHECK'; then
import os
import stat
import sys

metadata = os.lstat(sys.argv[1])
valid = stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
valid = valid and not metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
raise SystemExit(0 if valid else 1)
PYCHECK
    echo "Error: existing hardened gate.json is not a protected root-owned file." >&2
    exit 1
fi
# gate.json holds the helper token and contact-ref HMAC key. It stays root-only
# (0600, no user ACL): the setuid wrapper reads it and passes it to the worker
# on a pipe, so no process running as the user can read it.
if ! sudo "$CHMOD_BIN" -N "$GATE_JSON" 2>/dev/null; then
    echo "  no existing ACL to clear on gate.json"
fi

# Stage every trusted source root-owned first; the binaries are built from
# these copies, so what runs is exactly what was installed.
for name in helper.py send_gate.py contact_refs.py gate_client.py \
    imessage_helper.c confirm_imessage_send.m; do
    sudo "$INSTALL_BIN" -o root -g wheel -m 444 \
        "$SOURCE_ROOT/bin/$name" "$CODE_ROOT/bin/$name"
done

sudo "$RM_BIN" -rf "$BUILD_ROOT"
sudo "$INSTALL_BIN" -d -o root -g wheel -m 700 "$BUILD_ROOT"
sudo "$CLANG_BIN" -Wall -Wextra -Werror -fobjc-arc \
    -framework AppKit -framework Foundation \
    -o "$BUILD_ROOT/grokbot-imessage-confirm" "$CODE_ROOT/bin/confirm_imessage_send.m"
sudo "$CLANG_BIN" -Wall -Wextra -Werror -O2 \
    -DHELPER_SCRIPT="\"$CODE_ROOT/bin/helper.py\"" \
    -DSEND_GATE_SCRIPT="\"$CODE_ROOT/bin/send_gate.py\"" \
    -DCONFIRM_HELPER="\"$CODE_ROOT/bin/grokbot-imessage-confirm\"" \
    -DBRIDGE_ROOT="\"$BRIDGE_ROOT\"" \
    -DPYTHON_INTERPRETER="\"$REAL_PYTHON\"" \
    -DEXPECTED_CODE_UID=0 \
    -DEXPECTED_USER_UID="$UID" \
    -DREAD_POLICY_MODE='"allowlist"' \
    -DREAD_ALLOWLIST_PATH="\"$ALLOWLIST\"" \
    -DIMESSAGE_GATE_PATH="\"$GATE_JSON\"" \
    -DCONTACT_REFS_SCRIPT="\"$CONTACT_REFS_PY\"" \
    -DGATE_CLIENT_SCRIPT="\"$GATE_CLIENT_PY\"" \
    -DGATE_SECRETS_VIA_FD=1 \
    -DREQUIRE_ROOT_POLICY=1 \
    -DHELPER_DISPLAY_NAME='"grokbot-imessage-helper"' \
    -DHOST_DISPLAY_NAME='"Grok Bot"' \
    -o "$BUILD_ROOT/grokbot-imessage-helper" \
    "$CODE_ROOT/bin/imessage_helper.c"

# Signed as root too. A non-ad-hoc CODESIGN_IDENTITY must be usable by root.
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
SIGN_ARGS=(--force --sign "$CODESIGN_IDENTITY" --options runtime)
if [[ "$CODESIGN_IDENTITY" != "-" ]]; then
    SIGN_ARGS+=(--timestamp)
fi
sudo "$CODESIGN_BIN" "${SIGN_ARGS[@]}" "$BUILD_ROOT/grokbot-imessage-helper"
sudo "$CODESIGN_BIN" "${SIGN_ARGS[@]}" "$BUILD_ROOT/grokbot-imessage-confirm"

# Clear the setuid bit on the old wrapper's inode before replacing it, so a
# hard link someone made to it can't keep a setuid copy alive.
WRAPPER_DEST="$CODE_ROOT/bin/grokbot-imessage-helper"
if [[ -f "$WRAPPER_DEST" && ! -L "$WRAPPER_DEST" ]]; then
    sudo "$CHMOD_BIN" 0555 "$WRAPPER_DEST"
fi
# setuid root: only to read the root-only gate.json before irrevocably
# dropping to the invoking user (see GATE_SECRETS_VIA_FD in imessage_helper.c).
sudo "$INSTALL_BIN" -o root -g wheel -m 4555 \
    "$BUILD_ROOT/grokbot-imessage-helper" "$WRAPPER_DEST"
sudo "$INSTALL_BIN" -o root -g wheel -m 555 \
    "$BUILD_ROOT/grokbot-imessage-confirm" "$CODE_ROOT/bin/grokbot-imessage-confirm"
sudo "$RM_BIN" -rf "$BUILD_ROOT"
sudo "$INSTALL_BIN" -o root -g wheel -m 555 \
    "$SOURCE_ROOT/tools/doctor.py" "$CODE_ROOT/tools/doctor.py"
sudo "$INSTALL_BIN" -o root -g wheel -m 555 \
    "$SOURCE_ROOT/tools/configure_allowlist.py" "$CODE_ROOT/tools/configure_allowlist.py"
sudo "$INSTALL_BIN" -o root -g wheel -m 555 \
    "$SOURCE_ROOT/tools/watch_tick.sh" "$CODE_ROOT/tools/watch_tick.sh"
sudo "$INSTALL_BIN" -o root -g wheel -m 555 \
    "$SOURCE_ROOT/tools/configure_watch_webhook.sh" "$CODE_ROOT/tools/configure_watch_webhook.sh"

mkdir -p "$(dirname "$PLIST_DEST")"
render_plist() {
    "$PYTHON3_PATH" - "$CODE_ROOT" "$BRIDGE_ROOT" "$1" "$2" <<'PYGEN'
import sys
import xml.etree.ElementTree as ET

code_root, bridge_root, destination, template = sys.argv[1:]
tree = ET.parse(template)
for element in tree.getroot().iter("string"):
    if element.text:
        element.text = element.text.replace("{{CODE_ROOT}}", code_root)
        element.text = element.text.replace("{{BRIDGE_ROOT}}", bridge_root)
tree.write(destination, encoding="UTF-8", xml_declaration=True)
PYGEN
    chmod 644 "$1"
}
render_plist "$PLIST_DEST" "$PLIST_TEMPLATE"
render_plist "$WATCH_PLIST_DEST" "$WATCH_PLIST_TEMPLATE"

if [[ -e "$LEGACY_PLIST" || -L "$LEGACY_PLIST" ]]; then
    if "$PYTHON3_PATH" "$LEGACY_MIGRATOR" \
        --plist "$LEGACY_PLIST" \
        --program "$LEGACY_WRAPPER" \
        --watch "$BRIDGE_ROOT/control/requests"; then
        if launchctl print "gui/$UID/$LEGACY_LABEL" >/dev/null 2>&1; then
            launchctl bootout "gui/$UID/$LEGACY_LABEL"
        fi
        rm -f "$LEGACY_PLIST"
        echo "  migrated this Grok install from legacy label $LEGACY_LABEL"
    else
        echo "  retained legacy $LEGACY_LABEL because it belongs to another install"
    fi
elif launchctl print "gui/$UID/$LEGACY_LABEL" >/dev/null 2>&1; then
    echo "  legacy $LEGACY_LABEL is loaded without a verifiable plist; left untouched"
fi

if launchctl print "gui/$UID/$LABEL" >/dev/null 2>&1; then
    launchctl bootout "gui/$UID/$LABEL"
fi
launchctl bootstrap "gui/$UID" "$PLIST_DEST"
launchctl enable "gui/$UID/$LABEL"
# Watch trigger: no-op until a webhook is saved with configure_watch_webhook.sh.
if launchctl print "gui/$UID/$WATCH_LABEL" >/dev/null 2>&1; then
    launchctl bootout "gui/$UID/$WATCH_LABEL"
fi
launchctl bootstrap "gui/$UID" "$WATCH_PLIST_DEST"
launchctl enable "gui/$UID/$WATCH_LABEL"
PATH="$ORIGINAL_PATH" "$SOURCE_ROOT/install-skill.sh"

cat <<EOF

Hardened install complete.

Trusted code (root-owned): $CODE_ROOT
Runtime bridge (user-owned): $BRIDGE_ROOT
Read policy: root-owned allowlist (default-deny), or approval-gate grants
when gate.json names a gate (see "gate" in the doctor/status output).

To enable or change the approval gate (token is prompted, never echoed):
  IMESSAGE_GATE_URL=https://imessage-gate.example.ts.net ./install-hardened.sh

Without a gate, add an allowed contact before reading:
  "$PYTHON3_PATH" "$CODE_ROOT/tools/configure_allowlist.py" add +15551234567

Grant Full Disk Access to (remove and re-add it after every reinstall):
  $CODE_ROOT/bin/grokbot-imessage-helper

Optional, proactive watch (Grok Bot webhook routine), after creating the routine:
  "$CODE_ROOT/tools/configure_watch_webhook.sh"

Then verify:
  "$PYTHON3_PATH" "$CODE_ROOT/tools/doctor.py" --bridge "$BRIDGE_ROOT" --code-root "$CODE_ROOT"
EOF
