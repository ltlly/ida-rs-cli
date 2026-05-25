#!/usr/bin/env bash
# Install the ida-rs-cli skill into Claude Code and/or Codex CLI.
#
# Usage:
#   ./scripts/install-skill.sh              # install to both (symlink)
#   ./scripts/install-skill.sh --client codex
#   ./scripts/install-skill.sh --client claude-code
#   ./scripts/install-skill.sh --mode copy  # copy instead of symlink
#   ./scripts/install-skill.sh --uninstall  # remove installed skill

set -euo pipefail

SKILL_NAME="ida-rs-cli"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILL_SOURCE="$REPO_ROOT/skills/$SKILL_NAME"

# Defaults
MODE="symlink"
CLIENT="both"
UNINSTALL=false

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install the ida-rs-cli skill into Claude Code and/or Codex CLI.

Options:
  --client <codex|claude-code|both>   Target client (default: both)
  --mode <symlink|copy>               Install mode (default: symlink)
  --uninstall                         Remove the installed skill
  -h, --help                          Show this help

Paths:
  Claude Code: \${CLAUDE_CONFIG_DIR:-~/.claude}/skills/$SKILL_NAME
  Codex CLI:   \${CODEX_HOME:-~/.codex}/skills/$SKILL_NAME
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --client)
            CLIENT="$2"; shift 2 ;;
        --mode)
            MODE="$2"; shift 2 ;;
        --uninstall)
            UNINSTALL=true; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# Resolve target directories
claude_dir() {
    local base="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
    echo "$base/skills/$SKILL_NAME"
}

codex_dir() {
    local base="${CODEX_HOME:-$HOME/.codex}"
    echo "$base/skills/$SKILL_NAME"
}

get_targets() {
    case "$CLIENT" in
        both)       echo "codex claude-code" ;;
        codex)      echo "codex" ;;
        claude-code) echo "claude-code" ;;
        *) echo "Unknown client: $CLIENT" >&2; exit 1 ;;
    esac
}

dest_for_client() {
    case "$1" in
        codex)      codex_dir ;;
        claude-code) claude_dir ;;
    esac
}

# Uninstall
if $UNINSTALL; then
    for client in $(get_targets); do
        dest="$(dest_for_client "$client")"
        if [[ -e "$dest" || -L "$dest" ]]; then
            rm -rf "$dest"
            echo "Removed: $dest ($client)"
        else
            echo "Not installed: $dest ($client)"
        fi
    done
    exit 0
fi

# Verify source exists
if [[ ! -d "$SKILL_SOURCE" ]]; then
    echo "Error: Skill source not found at $SKILL_SOURCE" >&2
    exit 1
fi

# Install
for client in $(get_targets); do
    dest="$(dest_for_client "$client")"
    parent="$(dirname "$dest")"
    mkdir -p "$parent"

    # Remove existing
    if [[ -e "$dest" || -L "$dest" ]]; then
        rm -rf "$dest"
    fi

    if [[ "$MODE" == "symlink" ]]; then
        ln -s "$SKILL_SOURCE" "$dest"
        echo "Symlinked: $dest -> $SKILL_SOURCE ($client)"
    else
        cp -R "$SKILL_SOURCE" "$dest"
        echo "Copied: $SKILL_SOURCE -> $dest ($client)"
    fi
done

echo ""
echo "Done. Restart your agent session to pick up the new skill."
