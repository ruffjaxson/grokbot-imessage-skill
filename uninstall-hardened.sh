#!/bin/bash
# Remove the hardened helper while preserving the user-owned runtime bridge.

set -euo pipefail
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tools/privileged_tools.sh
source "$SCRIPT_DIR/tools/privileged_tools.sh"
load_privileged_tool_paths

if [[ "$EUID" -eq 0 ]]; then
    echo "Error: run as your normal user; this script invokes sudo narrowly." >&2
    exit 1
fi

LABEL="com.jeffhuber.grokbot-imessage"
POWER_NAP_LABEL="com.jeffhuber.grokbot-imessage-power-nap.$UID"
POWER_NAP_PLIST_DEST="/Library/LaunchDaemons/$POWER_NAP_LABEL.plist"
POWER_NAP_STATE_DIR="/var/db/grokbot-imessage-power-nap/$UID"
SKILL_DEST="${GROK_HOME:-$HOME/.grok}/skills/imessage-grok-bot"
PRODUCT_ROOT="/Library/Application Support/GrokBotIMessage"
USER_ROOT="$PRODUCT_ROOT/users/$UID"
BRIDGE_ROOT="${GROKBOT_IMESSAGE_BRIDGE:-$HOME/Library/Application Support/GrokBotIMessage}"

for label in "$LABEL" "$LABEL-watch"; do
    if launchctl print "gui/$UID/$label" >/dev/null 2>&1; then
        launchctl bootout "gui/$UID/$label"
        echo "  launchd agent $label unloaded"
    fi
    plist="$HOME/Library/LaunchAgents/$label.plist"
    if [[ -f "$plist" ]]; then
        rm -f "$plist"
        echo "  removed $plist"
    fi
done
if sudo launchctl print "system/$POWER_NAP_LABEL" >/dev/null 2>&1; then
    sudo launchctl bootout system "$POWER_NAP_PLIST_DEST"
    echo "  launchd daemon $POWER_NAP_LABEL unloaded"
fi
if [[ -f "$POWER_NAP_PLIST_DEST" ]]; then
    sudo "$RM_BIN" -f "$POWER_NAP_PLIST_DEST"
    echo "  removed $POWER_NAP_PLIST_DEST"
fi
if [[ -d "$POWER_NAP_STATE_DIR" ]]; then
    state_file="$POWER_NAP_STATE_DIR/next_wake.epoch"
    if [[ -f "$state_file" ]]; then
        read -r epoch < "$state_file" || true
        if [[ "$epoch" =~ ^[0-9]+$ ]]; then
            fmt="$(date -r "$epoch" "+%m/%d/%y %H:%M:%S")"
            sudo "$PMSET_BIN" schedule cancel wake "$fmt" "$POWER_NAP_LABEL" 2>/dev/null || true
        fi
    fi
    sudo "$RM_BIN" -rf "$POWER_NAP_STATE_DIR"
    echo "  removed power nap state $POWER_NAP_STATE_DIR"
fi
if [[ -d "$SKILL_DEST" ]]; then
    rm -rf "$SKILL_DEST"
    echo "  removed Grok skill $SKILL_DEST"
fi
if [[ -d "$USER_ROOT" ]]; then
    # Clear the setuid bit first so hard links to the wrapper lose it too.
    wrapper="$USER_ROOT/libexec/bin/grokbot-imessage-helper"
    if [[ -f "$wrapper" && ! -L "$wrapper" ]]; then
        sudo "$CHMOD_BIN" 0555 "$wrapper"
    fi
    sudo "$RM_BIN" -rf "$USER_ROOT"
    echo "  removed root-owned helper $USER_ROOT"
    if sudo "$RMDIR_BIN" "$PRODUCT_ROOT/users" 2>/dev/null; then
        if ! sudo "$RMDIR_BIN" "$PRODUCT_ROOT" 2>/dev/null; then
            echo "  retained non-empty $PRODUCT_ROOT"
        fi
    fi
fi

cat <<EOF

Hardened helper uninstalled. Runtime data remains at:
  $BRIDGE_ROOT

Delete that directory only after reviewing any responses/logs you need.
Revoke grokbot-imessage-helper under Full Disk Access and Automation in
System Settings -> Privacy & Security.
EOF
