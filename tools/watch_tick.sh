#!/bin/bash
# Content-free watch trigger, run every 60 s by a user LaunchAgent (no FDA).
#
# 1. Drop a `watch_tick` request into the bridge and read the helper's reply,
#    which is only a count of new messages from watched contacts.
# 2. If the count is above zero, POST {"event":"imessage_watch"} to the Grok
#    Bot routine webhook in <bridge>/watch/webhook.json, at most once per
#    min_interval_seconds. The routine then calls `inbox` itself.
#
# Nothing about messages or people leaves this script: no counts, names, or
# text. With no webhook configured it exits immediately.
#
# Usage: watch_tick.sh <bridge-root>
# Test overrides: WATCH_TICK_CURL, WATCH_TICK_TIMEOUT_S.

set -euo pipefail
umask 077
PATH="/usr/bin:/bin"

BRIDGE="${1:?usage: watch_tick.sh <bridge-root>}"
WATCH_DIR="$BRIDGE/watch"
CONFIG="$WATCH_DIR/webhook.json"
STATE="$WATCH_DIR/trigger.state"
LOG="$WATCH_DIR/log.txt"
CURL="${WATCH_TICK_CURL:-/usr/bin/curl}"
TIMEOUT_S="${WATCH_TICK_TIMEOUT_S:-20}"

[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || exit 0
[[ -d "$WATCH_DIR" && ! -L "$WATCH_DIR" ]] || exit 0

log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$*" >> "$LOG"
    if [[ "$(stat -f %z "$LOG" 2>/dev/null || echo 0)" -gt 262144 ]]; then
        mv -f "$LOG" "$LOG.1"
    fi
}

json_field() {  # json_field <file> <key>
    plutil -extract "$2" raw -o - "$1" 2>/dev/null || true
}

url="$(json_field "$CONFIG" url)"
key="$(json_field "$CONFIG" key)"
min_interval="$(json_field "$CONFIG" min_interval_seconds)"
[[ "$min_interval" =~ ^[0-9]+$ ]] || min_interval=120
if [[ ! "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~%/-]*$ ]] ||
    [[ ! "$key" =~ ^[A-Za-z0-9_.~+/=-]+$ || ${#key} -lt 16 || ${#key} -gt 512 ]]; then
    log "webhook.json is invalid; not triggering"
    exit 0
fi

# 1. Ask the helper for the count.
id="watch-$(date +%s)-$$"
requests="$BRIDGE/control/requests"
response="$BRIDGE/control/responses/response-$id.json"
printf '{"id":"%s","action":"watch_tick","params":{}}' "$id" > "$requests/.request-$id.json.tmp"
mv "$requests/.request-$id.json.tmp" "$requests/request-$id.json"

count=""
deadline=$(( $(date +%s) + TIMEOUT_S ))
while [[ "$(date +%s)" -le "$deadline" ]]; do
    if [[ -f "$response" ]]; then
        if [[ "$(json_field "$response" ok)" == "true" ]]; then
            count="$(json_field "$response" new_count)"
        else
            log "watch_tick failed (gate unavailable or not configured)"
        fi
        rm -f "$response"
        break
    fi
    sleep 0.5
done
if [[ ! "$count" =~ ^[0-9]+$ ]]; then
    rm -f "$requests/request-$id.json"
    exit 0
fi

# 2. Debounced, content-free trigger.
now="$(date +%s)"
last_post=0
pending=0
if [[ -f "$STATE" && ! -L "$STATE" ]]; then
    read -r last_post pending < "$STATE" || true
    [[ "$last_post" =~ ^[0-9]+$ ]] || last_post=0
    [[ "$pending" =~ ^[01]$ ]] || pending=0
fi
if [[ "$count" -gt 0 ]]; then
    pending=1
fi
if [[ "$pending" -eq 1 && $(( now - last_post )) -ge "$min_interval" ]]; then
    # The key goes to curl on stdin (--config -), never on its command line.
    if printf 'url = "%s"\nheader = "Authorization: Bearer %s"\n' "$url" "$key" |
        "$CURL" -q --silent --show-error --fail --max-time 15 --proto '=https' \
            --request POST --header 'Content-Type: application/json' \
            --data '{"event":"imessage_watch"}' --config - > /dev/null 2>> "$LOG"; then
        last_post="$now"
        pending=0
        log "triggered routine"
    else
        log "webhook POST failed; will retry next tick"
    fi
fi
printf '%s %s\n' "$last_post" "$pending" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
