#!/usr/bin/env sh
# Root TPM entrypoint delegating to multiplexers/tmux-blackbird/blackbird.tmux.
set -eu
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$ROOT_DIR/multiplexers/tmux-blackbird/blackbird.tmux" "$@"
