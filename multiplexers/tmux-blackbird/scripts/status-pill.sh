#!/usr/bin/env sh
# Strictly read-only, zero-side-effect tmux status pill for Blackbird / mp-outpost.
#
# Invariants:
# - NEVER creates directories or files.
# - NEVER spawns daemons or makes network calls.
# - NEVER reads or prints secret material (root.key, device.key, credentials.bbm, *.mpkey).
# - Reads only passive presence/metadata markers under OUTPOST_STATE_DIR / .blackbird.

set -eu

OUTPOST_DIR="${OUTPOST_STATE_DIR:-}"
if [ -z "$OUTPOST_DIR" ]; then
  if [ -n "${XDG_CONFIG_HOME:-}" ]; then
    OUTPOST_DIR="$XDG_CONFIG_HOME/mp-outpost"
  else
    OUTPOST_DIR="${HOME:-/nonexistent}/.config/mp-outpost"
  fi
fi

BB_STATE_DIR="${BLACKBIRD_STATE_DIR:-}"
if [ -z "$BB_STATE_DIR" ]; then
  if [ -n "${XDG_STATE_HOME:-}" ]; then
    BB_STATE_DIR="$XDG_STATE_HOME/blackbird"
  else
    BB_STATE_DIR="${HOME:-/nonexistent}/.local/state/blackbird"
  fi
fi

# 1. Check passive Outpost daemon socket or cached status metadata (no writes, no exec).
outpost_tag=""
if [ -d "$OUTPOST_DIR" ]; then
  if [ -S "$OUTPOST_DIR/daemon.sock" ] || [ -S "${OUTPOST_RUNTIME_DIR:-/nonexistent}/daemon.sock" ]; then
    outpost_tag="mp:live"
  elif [ -f "$OUTPOST_DIR/default_device.bin" ]; then
    outpost_tag="mp:idle"
  fi
fi

# 2. Check passive workspace .blackbird/ marker or Blackbird session directory (read-only).
bb_tag=""
if [ -d ".blackbird" ]; then
  bb_tag="bb:ws"
elif [ -d "$BB_STATE_DIR" ]; then
  bb_tag="bb:ready"
fi

# Combine cleanly with zero secret or filesystem mutation.
if [ -n "$outpost_tag" ] && [ -n "$bb_tag" ]; then
  printf '[%s | %s]\n' "$bb_tag" "$outpost_tag"
elif [ -n "$outpost_tag" ]; then
  printf '[%s]\n' "$outpost_tag"
elif [ -n "$bb_tag" ]; then
  printf '[%s]\n' "$bb_tag"
else
  printf '[bb:off]\n'
fi
