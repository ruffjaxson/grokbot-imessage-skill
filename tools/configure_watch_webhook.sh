#!/bin/bash
# Save (or remove) the Grok Bot routine webhook that watch_tick.sh triggers.
#
# Run as your normal user after creating a webhook routine in Grok Bot. Copy
# the routine's "POST to" URL and "key". The key is read with a hidden prompt
# (or from --key-file) and never echoed.
#
#   configure_watch_webhook.sh                    # prompts for URL and key
#   configure_watch_webhook.sh --url URL --key-file FILE [--min-interval 120]
#   configure_watch_webhook.sh --test             # send one trigger now
#   configure_watch_webhook.sh --disable          # stop triggering

set -euo pipefail
umask 077
PATH="/usr/bin:/bin"

BRIDGE="${GROKBOT_IMESSAGE_BRIDGE:-$HOME/Library/Application Support/GrokBotIMessage}"
WATCH_DIR="$BRIDGE/watch"
CONFIG="$WATCH_DIR/webhook.json"
CURL="${WATCH_TICK_CURL:-/usr/bin/curl}"

url=""
key_file=""
min_interval=120
action="configure"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) url="${2:?}"; shift 2 ;;
        --key-file) key_file="${2:?}"; shift 2 ;;
        --min-interval) min_interval="${2:?}"; shift 2 ;;
        --test) action="test"; shift ;;
        --disable) action="disable"; shift ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ -L "$WATCH_DIR" || -L "$CONFIG" ]]; then
    echo "Error: refusing symlinked $WATCH_DIR or $CONFIG" >&2
    exit 1
fi

if [[ "$action" == "disable" ]]; then
    rm -f "$CONFIG"
    echo "Watch webhook removed; watch_tick.sh will stop triggering."
    exit 0
fi

if [[ "$action" == "test" ]]; then
    [[ -f "$CONFIG" ]] || { echo "Error: no webhook configured" >&2; exit 1; }
    url="$(plutil -extract url raw -o - "$CONFIG")"
    key="$(plutil -extract key raw -o - "$CONFIG")"
    printf 'url = "%s"\nheader = "Authorization: Bearer %s"\n' "$url" "$key" |
        "$CURL" -q --silent --show-error --fail --max-time 15 --proto '=https' \
            --request POST --header 'Content-Type: application/json' \
            --data '{"event":"imessage_watch","test":true}' --config - > /dev/null
    echo "Test trigger sent. Check that the routine ran in Grok Bot."
    exit 0
fi

if [[ -z "$url" ]]; then
    [[ -t 0 ]] || { echo "Error: pass --url when not interactive" >&2; exit 2; }
    read -r -p "Routine webhook URL (\"POST to\"): " url
fi
if [[ -n "$key_file" ]]; then
    if [[ -L "$key_file" || ! -f "$key_file" ]]; then
        echo "Error: --key-file must be a regular file" >&2
        exit 1
    fi
    IFS= read -r key < "$key_file" || true
else
    [[ -t 0 ]] || { echo "Error: pass --key-file when not interactive" >&2; exit 2; }
    IFS= read -r -s -p "Routine webhook key (input hidden): " key
    echo >&2
fi

if [[ ! "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~%/-]*$ ]]; then
    echo "Error: the webhook URL must be an https:// URL" >&2
    exit 1
fi
if [[ ! "$key" =~ ^[A-Za-z0-9_.~+/=-]+$ || ${#key} -lt 16 || ${#key} -gt 512 ]]; then
    echo "Error: the webhook key doesn't look right (16-512 URL-safe characters)" >&2
    exit 1
fi
if [[ ! "$min_interval" =~ ^[0-9]+$ || "$min_interval" -lt 60 ]]; then
    echo "Error: --min-interval must be at least 60 seconds" >&2
    exit 1
fi

mkdir -p "$WATCH_DIR"
chmod 700 "$WATCH_DIR"
tmp="$(mktemp "$WATCH_DIR/.webhook.XXXXXX")"
printf '{"url": "%s", "key": "%s", "min_interval_seconds": %s}\n' "$url" "$key" "$min_interval" > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$CONFIG"
key=""
echo "Watch webhook saved to $CONFIG (key not shown)."
echo "Test it with: $0 --test"
