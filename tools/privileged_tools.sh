# Resolve macOS privileged-tool paths after PATH is trimmed.
# shellcheck shell=bash

_privileged_tool_path() {
    local name="$1"
    local path
    path="$(command -v "$name" || true)"
    if [[ -z "$path" || "$path" != /* ]]; then
        echo "Error: required command not found on PATH: $name" >&2
        return 1
    fi
    printf '%s\n' "$path"
}

load_privileged_tool_paths() {
    SUDO_BIN="$(_privileged_tool_path sudo)"
    INSTALL_BIN="$(_privileged_tool_path install)"
    CHOWN_BIN="$(_privileged_tool_path chown)"
    CHMOD_BIN="$(_privileged_tool_path chmod)"
    TEE_BIN="$(_privileged_tool_path tee)"
    RM_BIN="$(_privileged_tool_path rm)"
    RMDIR_BIN="$(_privileged_tool_path rmdir)"
}
