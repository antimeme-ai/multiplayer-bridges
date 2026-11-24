#!/usr/bin/env sh
# Launches Blackbird inside a tmux display-popup cleanly.
set -eu

if command -v blackbird >/dev/null 2>&1; then
  exec blackbird "$@"
elif [ -x "${HOME:-/nonexistent}/.local/bin/blackbird" ]; then
  exec "${HOME}/.local/bin/blackbird" "$@"
else
  printf 'blackbird not found on PATH.\nInstall: curl -fsSL https://multiplayer.tech/install.sh | sh\n' >&2
  exit 127
fi
