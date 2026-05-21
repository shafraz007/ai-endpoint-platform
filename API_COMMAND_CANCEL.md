# Cancel Queued Commands API Endpoint

## Overview

Added a new API endpoint to cancel or skip queued commands that haven't been dispatched to agents yet. This enables incident response when incorrect commands are queued (e.g., wrong binary version in update queue).

## Endpoint

```
POST /api/agents/{agent_id}/commands/{command_id}/cancel
DELETE /api/agents/{agent_id}/commands/{command_id}/cancel
```

**Authentication:** Admin JWT token or session cookie (required)

## Implementation Details

### Backend Changes

#### 1. `internal/server/commands.go`
Added new function `CancelCommand()`:
- Validates command exists and belongs to the specified agent
- Checks command is in 'queued' status (only queued commands can be cancelled)
- Updates status to 'cancelled' with timestamp
- Returns updated command object or error

```go
func CancelCommand(ctx context.Context, commandID int64, agentID string) (*AgentCommand, error)
```

**Returns:**
- `*AgentCommand`: Cancelled command details
- `error`: If command not found, wrong agent, or not queued

**Error Cases:**
- `"command not found"`: Command doesn't exist for the agent
- `"cannot cancel command with status 'X'"`: Command not in queued state

#### 2. `cmd/server/commands.go`
Added new handler `handleCommandCancel()`:
- Validates admin authentication
- Parses agent_id and command_id from URL
- Calls `server.CancelCommand()` to cancel the command
- Returns JSON response with command details
- Handles errors with appropriate HTTP status codes

**Request Validation:**
- Requires admin authorization (JWT or session)
- Validates agent_id is not empty
- Validates command_id is numeric and positive

**Response Codes:**
- `200 OK`: Command successfully cancelled
- `400 Bad Request`: Invalid parameters or command not in queued status
- `401 Unauthorized`: Missing/invalid credentials
- `404 Not Found`: Command not found for agent

#### 3. `cmd/server/patch_updates.go`
Updated `agentPatchUpdatesRouter()` to handle command cancel routes:
- Checks for `/commands/{commandId}/cancel` path pattern
- Delegates to `handleCommandCancel()` handler
- Maintains existing routing for patch updates and agent-update endpoints

#### 4. `cmd/server/main.go`
- Routes already registered via existing `agentPatchUpdatesRouter`
- No additional route registration needed (reuses existing `/api/agents/` handler)

## API Specification

### Request

```bash
curl -X POST https://ai-endpoint.example.com/api/agents/{agent_id}/commands/{command_id}/cancel \
  -H "Authorization: Bearer <admin_jwt_token>" \
  -H "Content-Type: application/json"
```

### Response (200 OK)

```json
{
  "id": 372,
  "agent_id": "08685de0-10c8-434b-a8db-265ea6cc01f2",
  "command_type": "agent_update",
  "payload": "{\"version\":\"1.0.4-linux\"}",
  "status": "cancelled",
  "created_at": "2026-03-20T19:00:00Z"
}
```

### Error Responses

**404 Not Found:**
```json
{"error": "command not found"}
```

**400 Bad Request (Wrong Status):**
```json
{"error": "cannot cancel command with status 'dispatched' (only 'queued' commands can be cancelled)"}
```

**400 Bad Request (Invalid ID):**
```json
{"error": "Invalid command_id"}
```

**401 Unauthorized:**
```json
{"error": "Unauthorized"}
```

## Use Cases

### 1. Fix Command Queue Issues
When incorrect commands are queued due to system logic (e.g., wrong binary version):
```bash
# Cancel the wrong command
curl -X POST https://server/api/agents/{id}/commands/372/cancel \
  -H "Authorization: Bearer $TOKEN"

# Correct command may already be queued and will execute next
```

### 2. Incident Response
Skip problematic commands before agents execute them:
```bash
# Cancel command that could cause issues
curl -X POST https://server/api/agents/{id}/commands/999/cancel \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Queue Management
Remove unnecessary commands from queue:
```bash
# List queued commands
curl https://server/api/commands?agent_id={id} \
  -H "Authorization: Bearer $TOKEN"

# Cancel specific commands
curl -X POST https://server/api/agents/{id}/commands/{cmd_id}/cancel \
  -H "Authorization: Bearer $TOKEN"
```

## Limitations

### Current Constraints
- Only allows cancelling commands in `queued` status
- Cannot cancel `dispatched`, `succeeded`, `failed`, or `cancelled` commands
- Requires admin authorization

### Future Enhancements
- Bulk cancel operations for multiple commands
- Cancel commands with specific properties (type, age, etc.)
- Audit trail of cancelled commands
- UI integration for queue management

## Database Schema

No schema changes required. Uses existing `agent_commands` table:
- Status values: `queued`, `dispatched`, `succeeded`, `failed`, `cancelled`
- Updated `updated_at` timestamp on cancellation

```sql
-- Example: View cancelled commands
SELECT id, command_type, agent_id, status, created_at, updated_at 
FROM agent_commands 
WHERE agent_id = '08685de0-10c8-434b-a8db-265ea6cc01f2' 
  AND status = 'cancelled'
ORDER BY created_at DESC;
```

## Examples

### Python
```python
import requests

def cancel_command(api_url, agent_id, command_id, token):
    url = f"{api_url}/api/agents/{agent_id}/commands/{command_id}/cancel"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers)
    return response.json() if response.status_code == 200 else response.status_code

# Usage
result = cancel_command("https://server", "agent-123", 372, "token")
print(f"Status: {result['status']}")
```

### PowerShell
```powershell
function Cancel-AgentCommand {
    param(
        [string]$ApiUrl,
        [string]$AgentId,
        [int64]$CommandId,
        [string]$Token
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    $uri = "$ApiUrl/api/agents/$AgentId/commands/$CommandId/cancel"
    $response = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers
    return $response.Content | ConvertFrom-Json
}

# Usage
$result = Cancel-AgentCommand -ApiUrl "https://server" `
                              -AgentId "agent-123" `
                              -CommandId 372 `
                              -Token "token"
Write-Host "Command status: $($result.status)"
```

### cURL
```bash
#!/bin/bash

AGENT_ID="08685de0-10c8-434b-a8db-265ea6cc01f2"
COMMAND_ID=372
TOKEN="eyJ..."
API_URL="https://ai-endpoint.example.com"

curl -X POST \
  "$API_URL/api/agents/$AGENT_ID/commands/$COMMAND_ID/cancel" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n"
```

## Testing

### Manual Testing
```bash
# 1. Get list of commands for an agent
curl https://server/api/commands?agent_id=<agent_id> \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.status == "queued")'

# 2. Cancel a queued command
curl -X POST https://server/api/agents/<agent_id>/commands/<cmd_id>/cancel \
  -H "Authorization: Bearer $TOKEN"

# 3. Verify status changed to cancelled
curl https://server/api/commands?agent_id=<agent_id> \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.id == <cmd_id>)'
```

### Expected Behavior
- Queued command status changes to `cancelled`
- `updated_at` timestamp is updated
- No agent interaction needed (immediate)
- Command can be skipped without dispatch

## Incident Response Example

When Windows agent received wrong binary in queue:

```bash
#!/bin/bash

AGENT_ID="08685de0-10c8-434b-a8db-265ea6cc01f2"  # Venom Windows agent
TOKEN="<admin_token>"
API_URL="https://ai-endpoint.example.com"

# 1. List all commands for the agent
echo "=== Queued Commands ==="
curl -s "$API_URL/api/commands?agent_id=$AGENT_ID&limit=10" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '.[] | select(.status == "queued") | {id, command_type, payload: .payload | fromjson}'

# 2. Cancel the incorrect command (372 with 1.0.4-linux)
echo "=== Cancelling Command 372 (1.0.4-linux) ==="
curl -X POST "$API_URL/api/agents/$AGENT_ID/commands/372/cancel" \
  -H "Authorization: Bearer $TOKEN" | jq '{id, status, updated_at: now | todate}'

# 3. Verify next command in queue is correct (373 with 1.0.4.exe)
echo "=== Next Command in Queue ==="
curl -s "$API_URL/api/commands?agent_id=$AGENT_ID&limit=5" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '.[] | select(.status == "queued") | first | {id, command_type, version: .payload | fromjson | .version}'
```

## Integration with UI (Future)

The endpoint enables future UI features:
- View queued commands in agent details
- Delete/cancel buttons on command list
- Bulk cancel operations
- Queue management dashboard

## Related Documentation

- [DEPLOYMENT.md](DEPLOYMENT.md#manage-queued-commands-cancelskip) - Full deployment guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- Agent Commands API: `POST /api/commands` - Create commands
- Command Status: Described in command polling implementation
