# Changelog

## 0.1.2 - 2026-11-11

### Fixed
- `/secret` and next-message value capture now run in `post_gateway_admission`, after
  gateway authorization and pairing, so unpaired senders cannot list, delete, or overwrite
  vault entries.
- Replies use the public `{"action": "handled", "reply": text}` hook result instead of the
  private `gateway._delivery_adapter_for` method.
- Inbound `scrub_text` no longer writes detected values to the vault before admission.
  `pre_gateway_dispatch` only rewrites the text; stores are committed when the same message
  is admitted.
- The vault is resolved per call and cached by `get_hermes_home()`, so a gateway serving
  several profiles no longer shares one profile's vault across all of them.

### Changed
- README notes that `pre_tool_call` substitution runs before Hermes' approval prompt, so an
  approval prompt for that tool call may show the real secret in chat.

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
