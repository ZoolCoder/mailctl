---
name: mailctl-setup
description: Install and check mailctl. Puts the binary on PATH, finds or creates the config, stores provider tokens in the macOS Keychain, and runs mailctl doctor until every check passes. Use when the user says "set up mailctl", "install mailctl", when a mailctl command fails with "no config found" or a missing token, or before any other mailctl skill on a new machine.
license: MIT
compatibility: macOS, Linux or Windows. The Keychain steps are macOS only; elsewhere tokens come from the environment.
---

# mailctl setup

Goal: `mailctl doctor` passes. Everything else builds on that.

## 1. The binary

```bash
mailctl version || echo MISSING
```

`MISSING`: tell the user to install it, then stop until it works:

- macOS: `brew tap zoolcoder/mailctl https://github.com/zoolcoder/mailctl && brew install --cask mailctl`
- Any OS with Go: `go install github.com/zoolcoder/mailctl/cmd/mailctl@latest`

## 2. The config

mailctl looks for its config in this order: `-config`, `$MAILCTL_CONFIG`, `./mailctl.yaml`, then `~/.config/mailctl/mailctl.yaml` (`$XDG_CONFIG_HOME` when set). Recommend the last one: it keeps a private config out of every repository.

No config yet: use the `mail-setup` skill to build one from live provider state. Never write a config from guesses.

## 3. Credentials

mailctl reads each variable from the environment first, then from the macOS Keychain (service `mailctl`, account = the variable's name). Tokens belong in the Keychain, not in a shell profile.

Ask the user to run these themselves, one per token the config needs. `-w` with no value makes `security` prompt, so the token never lands in shell history:

```bash
security add-generic-password -U -s mailctl -a CLOUDFLARE_API_TOKEN -w
security add-generic-password -U -s mailctl -a PURELYMAIL_API_TOKEN -w
```

Microsoft 365 domains also need `MS365_TENANT_ID`, `MS365_CLIENT_ID` and `MS365_CLIENT_SECRET`.

Never ask the user to paste a token into the conversation, and never type one yourself.

## 4. Doctor

```bash
mailctl doctor -json
```

Each check has a `status` of `ok`, `warn` or `fail` and a `detail`. Fix every `fail` in order: the binary, the config, each credential, each provider API, DNS. A `warn` on a mailbox `passwordEnv` means mailctl cannot set that mailbox's credential until the variable exists.

## 5. Agent wiring

The MCP server is `mailctl mcp`. In Claude Code the plugin registers it. Other clients add a stdio server with command `mailctl` and args `["mcp"]`.

## Security

- Doctor output names where each credential came from (`env`, `keychain`), never its value. Keep it that way in your replies.
- Generated credentials go to the Keychain (account = the mailbox address) or to a 0600 file. Never read them back into the conversation. Tell the user how to read one: `security find-generic-password -s mailctl -a <address> -w`.
