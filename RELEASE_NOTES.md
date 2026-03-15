# Release Notes

## Queue Hardening + Chat Worker + Remediation Workflows

This release delivers a major reliability and operations upgrade across queue processing, chat orchestration, issue remediation, scheduling, patch policy, reporting, and platform documentation.

### Highlights
- Added a dedicated `chat-worker` runtime for queue-based chat task processing.
- Added retry/backoff and dead-letter behavior for resilient worker execution.
- Added DLQ replay tooling for controlled recovery and operational replay workflows.
- Expanded server workflows for issues, remediation actions, schedules, threshold profiles, reports, and patch policy.
- Expanded agent diagnostics and telemetry payloads.
- Synced architecture, deployment, development, and release documentation to current system behavior.

### Reliability and Queue
- Queue-backed chat processing is now explicitly worker-driven.
- Retry policy includes bounded attempts and escalating backoff.
- Dead-letter publication captures terminal failures for post-incident replay.
- Replay utility supports safe dry-run and controlled republish.

### Operations and Governance
- Added issue lifecycle APIs (list/get/resolve/snooze/suppress).
- Added issue action execution/scheduling with audit trail.
- Added scheduler dispatch support and execution reporting.
- Added patch policy management and patch update inventory/action flows.
- Added threshold profile support for metric/heartbeat-driven issue generation.

### Agent Enhancements
- Improved personal chat handling and fallback behavior.
- Added richer endpoint telemetry collection (including hardware/thermal fields where available).
- Added pending update inventory collection.
- Added singleton protections and expanded agent tests.

### Database and Migrations
- Added migrations for schedules and schedule linkage to commands.
- Added migrations for OS patch policy and policy audit.
- Added migrations for patch inventory and overrides.
- Added migrations for issues and issue action audit.
- Added migrations for threshold profiles/rules.
- Added migrations for global chat session/session memory support.

### Validation Notes
- Commit pushed to `main`: `703f187`.
- Worker and queue flow validated in session.
- DLQ replay utility dry-run validated with synthetic dead-letter payload.

### Rollout Checklist
- Apply all pending DB migrations before enabling new runtime features.
- Confirm queue and worker environment configuration:
  - `QUEUE_ENABLED`
  - `QUEUE_PROVIDER`
  - `NATS_URL`
  - `QUEUE_SUBJECT_PREFIX`
  - chat worker subject/group/max-attempts/DLQ subject settings
- Validate in staging:
  - worker startup
  - retry behavior
  - DLQ emission and replay dry-run
- Promote to production after queue health and report visibility are confirmed.

### Known Notes
- Background worker startup succeeded in hidden process mode during session.
- Direct foreground worker runs exited non-zero in some terminal attempts; rely on process-level health checks/log checks during rollout.