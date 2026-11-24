#!/usr/bin/env sh
# tmux-blackbird: TPM-compatible plugin for Blackbird & multiplayer.tech Outpost.
#
# Keybindings (configurable via tmux @blackbird_* options):
#   prefix + B : launch Blackbird in a tmux display-popup (85% x 85%)
#   prefix + P : capture last 200 lines of current pane to a temporary handoff preview
#
# Status bar interpolation:
#   Add `#{blackbird_party}` to `status-right` to display the passive read-only status pill.

set -eu

CURRENT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
STATUS_SCRIPT="$CURRENT_DIR/scripts/status-pill.sh"
POPUP_SCRIPT="$CURRENT_DIR/scripts/popup-launch.sh"

get_tmux_option() {
  opt="$1"
  default_val="$2"
  val="$(tmux show-option -gqv "$opt" 2>/dev/null || true)"
  if [ -n "$val" ]; then
    printf '%s' "$val"
  else
    printf '%s' "$default_val"
  fi
}

POPUP_KEY="$(get_tmux_option "@blackbird_popup_key" "B")"
CAPTURE_KEY="$(get_tmux_option "@blackbird_capture_key" "P")"
POPUP_WIDTH="$(get_tmux_option "@blackbird_popup_width" "85%")"
POPUP_HEIGHT="$(get_tmux_option "@blackbird_popup_height" "85%")"

# Bind prefix + B (default) to open Blackbird in a popup rooted at the active pane's path.
tmux bind-key "$POPUP_KEY" display-popup -E -w "$POPUP_WIDTH" -h "$POPUP_HEIGHT" -d "#{pane_current_path}" "$POPUP_SCRIPT"

# Bind prefix + P (default) to preview the last 200 lines of the active pane in a read-only popup.
tmux bind-key "$CAPTURE_KEY" display-popup -E -w "$POPUP_WIDTH" -h "$POPUP_HEIGHT" "tmux capture-pane -t '#{pane_id}' -p -S -200 | less"

# Escape \, &, and | in STATUS_SCRIPT before sed replacement.
ESCAPED_STATUS_SCRIPT="$(printf '%s' "$STATUS_SCRIPT" | sed 's/[\\&|]/\\&/g')"

# Interpolate #{blackbird_party} in status-right / status-left if present.
interpolate_option() {
  opt="$1"
  cur="$(tmux show-option -gqv "$opt" 2>/dev/null || true)"
  case "$cur" in
    *'#{blackbird_party}'*)
      updated="$(printf '%s' "$cur" | sed "s|#{blackbird_party}|#(\"$ESCAPED_STATUS_SCRIPT\")|g")"
      tmux set-option -gq "$opt" "$updated"
      ;;
  esac
}

interpolate_option "status-right"
interpolate_option "status-left"
