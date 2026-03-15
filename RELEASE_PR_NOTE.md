# Release PR Note

## Title
Governance-aware chat orchestration plus durable issue remediation with scheduler safety safeguards

## Summary
This release upgrades chat and command orchestration between admin and endpoint agents.

### What changed
- Added structured `ai_task` flow for personal chat request/response over the command queue.
- Added personal and global chat APIs and UI surfaces:
  - Global chat on `/agents`
  - Personal chat on `/agents/{agent_id}`
- Added governance management backend and UI (`/settings`):
  - Categories, policies, script/patch profiles, groups, group members
- Enforced governance controls for chat-triggered command execution:
  - `script_denylist` applied first
  - `script_allowlist` applied when configured
- Added deterministic governance query response for prompts like:
  - `is format command allowed in device profile`
- Added endpoint-context enrichment for AI chat responses so health/profile answers are grounded to the specific device.
- Added Ollama deployment docs and compose files under `deployments/ollama/`.
- Added durable issue detection and alerting pipeline for heartbeat + metrics detectors, persisted in `agent_issues`.
- Added issue remediation APIs for execute-now/schedule workflows via `/api/issues/{id}/actions`.
- Added issue action audit trail in `issue_action_audit`.
- Added scheduler safety guard to prevent duplicate in-flight `restart`/`shutdown` commands per agent.

## Key behavior changes
- Personal chat now supports command intents:
  - `cmd: <command>`
  - `powershell: <command>`
  - `shell: <command>`
  - natural-language ping requests (e.g., `ping sp.parcelat.com`)
- If a command is blocked by governance policy, chat receives an immediate policy-block message instead of executing.
- “Is command allowed?” style prompts are answered from actual policy state (not LLM guesswork).

## API additions
- `GET /api/chat/messages?scope=global|agent&agent_id=...&limit=...`
- `POST /api/chat/messages`
- `GET /api/issues?agent_id=...&status=active|resolved&limit=...`
- `GET /api/issues/{id}`
- `POST /api/issues/{id}/actions`
- Governance CRUD endpoints:
  - `/api/categories`
  - `/api/policies`
  - `/api/profiles/scripts`
  - `/api/profiles/patches`
  - `/api/groups`
  - `/api/groups/{id}/members`

## Migrations
- Added governance tables migration (`006_create_governance_tables_v1_5_0`)
- Added chat messages migration (`007_create_chat_messages_table_v1_6_0`)
- Added agent patch inventory migration (`013_create_agent_patch_inventory_v1_9_0`)
- Added agent issues + issue action audit migration (`014_create_agent_issues_table_v2_0_0`)

## Validation
Executed successfully:
- `go test ./...`
- `go test ./cmd/server ./internal/server`
- `go test ./cmd/agent`

Runtime validation performed:
- Server reachable on `:8070`
- Agent heartbeat flow healthy
- Ollama reachable (`/v1/chat/completions`)
- Personal chat command execution verified (`ping`)
- Governance policy checks verified in chat path

## Risk / impact
- **Medium**: Introduces new chat execution pathway, policy enforcement decisions, and automated alert/remediation workflows.
- Potential behavior change for existing personal chat prompts that now map to command intents.
- Governance misconfiguration (empty/strict allowlist/denylist) can block expected command execution.
- Misconfigured remediation schedules can create operational risk; scheduler now protects against duplicate in-flight power operations.

## Rollout checklist
- [ ] Ensure DB migrations `006` and `007` are applied in target environment
- [ ] Confirm `AGENT_JWT_SECRET` and `ADMIN_JWT_SECRET` are set consistently
- [ ] If using Ollama, confirm endpoint/model env vars on agent:
  - `AGENT_AI_PROVIDER=ollama`
  - `AGENT_AI_ENDPOINT=http://localhost:11434/v1/chat/completions`
  - `AGENT_AI_MODEL=llama3.2`
- [ ] Configure baseline governance policy and assign group memberships before enabling command-heavy chat usage
- [ ] Verify with smoke prompts:
  - `is format command allowed in device profile`
  - `please ping <target>`
  - `is device healthy?`

## Rollback plan
- Revert to previous commit before `582ad65` if urgent.
- Disable command execution path operationally by tightening governance denylist/allowlist.
- Keep chat API/UI active while disabling executable intents through policy.

## Commit reference
- Included in `582ad65` on `main`.

## Queue hardening addendum (2026-03-15)

### Additional changes
- Added `chat-worker` retry policy with backoff (`1s`, `5s`, `30s`, `2m`) for queue-processing failures.
- Added dead-letter publishing for terminal failures with structured payload metadata.
- Added queue payload metadata for idempotency/retries: `attempt`, `max_attempts`, `dedupe_key`.
- Added queue runtime config knobs:
  - `QUEUE_AGENT_CHAT_MAX_ATTEMPTS`
  - `QUEUE_AGENT_CHAT_DLQ_SUBJECT`
- Added DLQ inspection helper script: `scripts/show-chat-dlq.ps1`.

### Runtime validation addendum
- Verified end-to-end queue flow (`server -> chat-worker -> agent -> chat reply`).
- Verified controlled failure simulation triggers retries and dead-letter emission.
- Verified no duplicate final replies in current single-worker + idempotent command path.
