#!/bin/bash
# Scheduled sleep wake for the iMessage watch while the Mac sleeps on AC power.
#
# A root LaunchDaemon runs this script on a StartInterval and after pmset wakes
# the machine. When the Mac has been awake for longer than a short threshold,
# it exits immediately (the user LaunchAgent already ticks every 60 s). After
# a recent wake from sleep it runs watch_tick.sh once as the installing user,
# schedules the next pmset wake, and exits without holding any sleep assertions.
#
# On battery it cancels owned wake events and does nothing.
#
# Usage: power_nap_tick.sh
# Install fills POWER_NAP_* environment variables in the LaunchDaemon plist.

set -euo pipefail
umask 077
PATH="/usr/bin:/bin:/usr/sbin:/sbin"

OWNER="${POWER_NAP_OWNER:-com.jeffhuber.grokbot-imessage-power-nap}"
INTERVAL_S="${POWER_NAP_INTERVAL_S:-420}"
AWAKE_SKIP_S="${POWER_NAP_AWAKE_SKIP_S:-180}"
TARGET_USER="${POWER_NAP_TARGET_USER:?POWER_NAP_TARGET_USER required}"
TARGET_UID="${POWER_NAP_TARGET_UID:?POWER_NAP_TARGET_UID required}"
TARGET_HOME="${POWER_NAP_TARGET_HOME:?POWER_NAP_TARGET_HOME required}"
CODE_ROOT="${POWER_NAP_CODE_ROOT:?POWER_NAP_CODE_ROOT required}"
BRIDGE_ROOT="${POWER_NAP_BRIDGE_ROOT:?POWER_NAP_BRIDGE_ROOT required}"
STATE_DIR="${POWER_NAP_STATE_DIR:-/var/db/grokbot-imessage-power-nap}"
LOG="${POWER_NAP_LOG:-$STATE_DIR/log.txt}"
PMSET="${POWER_NAP_PMSET:-/usr/bin/pmset}"
DATE_BIN="${POWER_NAP_DATE:-/bin/date}"
SYSCTL="${POWER_NAP_SYSCTL:-/usr/sbin/sysctl}"
WATCH_TICK="$CODE_ROOT/tools/watch_tick.sh"
STATE_FILE="$STATE_DIR/next_wake.epoch"
MIN_TICK_GAP_S="${POWER_NAP_MIN_TICK_GAP_S:-90}"

mkdir -p "$STATE_DIR"
chown root:wheel "$STATE_DIR" 2>/dev/null || true
chmod 700 "$STATE_DIR" 2>/dev/null || true

log() {
    printf '[%s] %s\n' "$("$DATE_BIN" '+%Y-%m-%dT%H:%M:%S')" "$*" >> "$LOG"
    if [[ "$(stat -f %z "$LOG" 2>/dev/null || echo 0)" -gt 524288 ]]; then
        mv -f "$LOG" "$LOG.1"
    fi
}

on_ac_power() {
    "$PMSET" -g ps 2>/dev/null | tail -1 | grep -q "AC Power"
}

seconds_since_wake() {
    local wake_sec now
    wake_sec="$("$SYSCTL" -n kern.waketime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')"
    now="$("$DATE_BIN" +%s)"
    if [[ -z "$wake_sec" || ! "$wake_sec" =~ ^[0-9]+$ ]]; then
        echo 999999
        return
    fi
    echo "$(( now - wake_sec ))"
}

format_pmset_time() {
    "$DATE_BIN" -r "$1" "+%m/%d/%y %H:%M:%S"
}

cancel_scheduled_wake() {
    local epoch fmt raw
    if [[ -f "$STATE_FILE" ]]; then
        read -r epoch < "$STATE_FILE" || true
        if [[ "$epoch" =~ ^[0-9]+$ ]]; then
            fmt="$(format_pmset_time "$epoch")"
            "$PMSET" schedule cancel wake "$fmt" "$OWNER" 2>/dev/null || true
        fi
        rm -f "$STATE_FILE"
    fi
    while IFS= read -r line; do
        case "$line" in
            *" by '$OWNER'"*)
                raw="$(printf '%s' "$line" | sed -n 's/.*wake at \([0-9/]* [0-9:]*\).*/\1/p')"
                if [[ -n "$raw" ]]; then
                    fmt="$(printf '%s' "$raw" | awk '{
                        split($1, d, "/");
                        yr = d[3] % 100;
                        printf "%02d/%02d/%02d %s", d[1], d[2], yr, $2
                    }')"
                    "$PMSET" schedule cancel wake "$fmt" "$OWNER" 2>/dev/null || true
                fi
                ;;
        esac
    done < <("$PMSET" -g sched 2>/dev/null || true)
}

schedule_next_wake() {
    local now next fmt
    if ! on_ac_power; then
        cancel_scheduled_wake
        log "on battery; cancelled scheduled wakes"
        return 0
    fi
    cancel_scheduled_wake
    now="$("$DATE_BIN" +%s)"
    next="$(( now + INTERVAL_S ))"
    fmt="$(format_pmset_time "$next")"
    if ! "$PMSET" schedule wake "$fmt" "$OWNER" 2>>"$LOG"; then
        log "pmset schedule wake failed for $fmt"
        return 1
    fi
    printf '%s\n' "$next" > "$STATE_FILE"
    log "scheduled wake at $fmt (+${INTERVAL_S}s)"
}

should_run_tick() {
    local awake_s now last_tick gap
    awake_s="$(seconds_since_wake)"
    if [[ "$awake_s" -gt "$AWAKE_SKIP_S" ]]; then
        log "awake ${awake_s}s; leaving watch to the user LaunchAgent"
        return 1
    fi
    if [[ -f "$STATE_DIR/last_tick.epoch" ]]; then
        read -r last_tick < "$STATE_DIR/last_tick.epoch" || true
        now="$("$DATE_BIN" +%s)"
        if [[ "$last_tick" =~ ^[0-9]+$ ]]; then
            gap="$(( now - last_tick ))"
            if [[ "$gap" -lt "$MIN_TICK_GAP_S" ]]; then
                log "last tick ${gap}s ago; skipping duplicate"
                return 1
            fi
        fi
    fi
    return 0
}

run_watch_tick() {
    if [[ ! -x "$WATCH_TICK" ]]; then
        log "missing watch_tick.sh: $WATCH_TICK"
        return 1
    fi
    if [[ ! -d "$BRIDGE_ROOT" ]]; then
        log "missing bridge root: $BRIDGE_ROOT"
        return 1
    fi
    local start end elapsed
    start="$("$DATE_BIN" +%s)"
    log "running watch_tick for uid=$TARGET_UID bridge=$BRIDGE_ROOT"
    if ! /usr/bin/sudo -u "$TARGET_USER" \
        HOME="$TARGET_HOME" USER="$TARGET_USER" LOGNAME="$TARGET_USER" \
        /bin/bash "$WATCH_TICK" "$BRIDGE_ROOT" >>"$LOG" 2>&1; then
        log "watch_tick exited non-zero"
    fi
    end="$("$DATE_BIN" +%s)"
    elapsed="$(( end - start ))"
    printf '%s\n' "$end" > "$STATE_DIR/last_tick.epoch"
    log "watch_tick finished in ${elapsed}s"
}

main() {
    if ! on_ac_power; then
        cancel_scheduled_wake
        log "on battery; no wake scheduled"
        exit 0
    fi

    if should_run_tick; then
        run_watch_tick
    fi
    schedule_next_wake
}

main "$@"
