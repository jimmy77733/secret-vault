# Changelog

## 0.1.1 - 2026-11-10

### Fixed
- `/secret` commands are handled in `pre_gateway_dispatch` (before the Hermes busy
  fast-path) so they work while the agent is running: no "Interrupting current task",
  no vault miss, and the command never reaches the model. Hermes v0.23 only applies
  `busy_policy` to built-in `CommandDef` entries; plugin `register_command` handlers
  are not on that path.

## 0.1.0 - 2026-11-10

### Added
- Secret detection for OpenAI `sk-`, GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, AWS `AKIA`/`ASIA`,
  Telegram bot tokens, Google `AIza`, Slack `xox*`, PEM private-key blocks, and generic high-entropy tokens
  (Shannon entropy, default threshold 4.0 bits/char).
- Inbound gateway messages are rewritten to `{{SECRET:name}}` placeholders (`pre_gateway_dispatch`).
- Placeholders in tool arguments are resolved to real values right before dispatch (`pre_tool_call` modify).
- Known secret values are redacted from tool results, terminal output and the final reply
  (`transform_tool_result`, `transform_terminal_output`, `transform_llm_output`).
- Per-profile vault at `<hermes_home>/secret-vault/vault.bin`, Windows DPAPI (CurrentUser); dev-only file-key
  fallback elsewhere.
- `/secret set|list|rm|show-placeholder`.
- pytest suite (DPAPI tests run only on Windows).
