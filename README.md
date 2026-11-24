# multiplayer-bridges

Zero-trust CI Actions, ambient messaging bridges, and terminal multiplexer integrations for [`multiplayer.tech`](https://multiplayer.tech), **Blackbird**, and standalone **`mp-outpost`**.

## Security Architecture

`multiplayer.tech` parties (`iroh` v1.5.0 QUIC + TLS 1.3 Mutual Ed25519 RPK) and Dead-Drop Inbox messages are strictly end-to-end encrypted. Every component in this repository preserves three core invariants:

1. **Dedicated revocable bot/CI device identities:** Never store a human `mprk1_` root recovery key or `.mpkey` backup in CI or a messaging bridge. Provision a scoped, revocable bot device state and pin its canonical Safety Number.
2. **Ingress provenance fencing:** Every external payload (GitHub Actions summaries, Linear `AgentSessionEvent`, Slack `app_mention`, Telegram `getUpdates`, Discord slash commands) is sanitized (BiDi overrides, Unicode tags, C0/C1 controls, raw angle brackets) and wrapped in a per-message 64-bit CSPRNG nonce fence (`<untrusted_external nonce="...">`).
3. **Egress secret refusal:** Outbound messages and `mp-outpost` dispatches refuse recognizable secret formats (`mpinv1_`, `mppi1_`, `mpdl1_`, `mprk1_`, unprefixed Crockford recovery keys, `.mpkey`, PEM/PKCS#8 private keys, `device_secret`, `device_cwt`, provider/platform tokens) even under zero-width or fullwidth obfuscation, without echoing secret bytes.

## Components

### 1. GitHub Action (`actions/outpost-notify/`)

Composite GitHub Action that downloads the SHA-256-verified `mp-outpost` (`v0.4.0` default; `v0.3.0` also pinned) release binary over HTTPS (auditing tarballs against path traversal and symlinks), hydrates an ephemeral mode-`0700` `OUTPOST_STATE_DIR` scoped CI bot device (refusing any `mprk1_` / `.mpkey` / `root.key` material), redacts & bounds CI output, and posts into a `multiplayer.tech` party.

```yaml
- uses: antimeme-ai/multiplayer-bridges/actions/outpost-notify@v0.4.0
  with:
    party-id: "748102938471"
    scope: "board/ci"
    title: "CI build failed on ${{ github.ref_name }}"
    summary: "${{ steps.test.outputs.tail }}"
    status: "failure"
    ci-state-b64: "${{ secrets.MP_OUTPOST_CI_STATE }}"
```

Offline dry-run:

```sh
MP_PARTY_ID=748102938471 MP_SUMMARY="All tests green" MP_STATUS=success MP_DRY_RUN=true \
  python3 actions/outpost-notify/notify.py
```

### 2. Unified Ambient Messaging Bridge (`mp-bridge/`)

Zero-dependency Python 3 stdlib adapters bridging external platforms to `mp-outpost` (`OUTPOST_STATE_DIR`):

- **`mp-bridge/security.py`:** CSPRNG nonce fencing, BiDi/control/tag/angle sanitization, zero-width/fullwidth normalized secret refusal, constant-time HMAC-SHA256 verification, and pure-stdlib strict RFC 8032 Ed25519 signature verification.
- **`mp-bridge/outpost_client.py`:** Thin subprocess wrapper around `mp-outpost` (`party say`, `party read`, `party wait`, `party status`, `daemon status`) with strict 52-bit integer `party_id` validation and pre-exec secret refusal.
- **`mp-bridge/adapters/linear_agent.py`:** Linear Agents API (`actor=app`) webhook HMAC-SHA256 `Linear-Signature` verifier, replay-window check, `< 5s` ACK, org/team allowlists, `AgentSessionEvent` dispatch, and typed `AgentActivity` (`thought`, `action`, `elicitation`, `response`, `error`) GraphQL formatter.
- **`mp-bridge/adapters/slack_socket.py`:** Slack Socket Mode / AI Apps (`assistant_thread_started`, `app_mention`, `message.im`) parser, `v0=` HMAC-SHA256 verifier, `assistant.threads.setSuggestedPrompts` + `setStatus` + `chat.postMessage` formatters.
- **`mp-bridge/adapters/telegram_poll.py`:** Outbound-only Telegram Bot API `getUpdates` long-polling cursor loop (zero inbound firewall port!), fail-closed `allowed_chat_ids` allowlist, inline-keyboard `callback_query` support, and `sendMessage` formatter.
- **`mp-bridge/adapters/discord_gateway.py`:** Discord Interactions RFC 8032 Ed25519 signature verifier + replay check, PING/PONG, guild/channel/user allowlists, and `/party-status`, `/party-say`, `/blackbird` slash command dispatcher.

### 3. Terminal Multiplexer Integrations (`multiplexers/`)

- **`multiplexers/tmux-blackbird/`:** TPM-compatible tmux plugin (`blackbird.tmux`). Binds `prefix + B` to launch Blackbird in an 85%x85% `display-popup`, `prefix + P` to preview the last 200 pane lines, and interpolates `#{blackbird_party}` via `scripts/status-pill.sh` (strictly read-only passive inspection of `.blackbird` / `OUTPOST_STATE_DIR` metadata — never creates dirs, never spawns daemons, never reads secret files):
  ```tmux
  set -g @plugin 'antimeme-ai/multiplayer-bridges'
  # Or source directly from a local checkout:
  # run-shell '/path/to/multiplayer-bridges/multiplexers/tmux-blackbird/blackbird.tmux'
  ```
- **`multiplexers/zellij/blackbird-cockpit.kdl`:** Ready-to-use Zellij cockpit layout with a 65% main Blackbird pane, `mp-outpost doctor` status pane, and operator shell:
  ```sh
  zellij --layout multiplexers/zellij/blackbird-cockpit.kdl
  ```

## Validation & Tests

```sh
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
```

## License

MIT — Copyright (c) 2026 Antimeme AI LLC.
