package ai

import (
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseTaskPayload
// ---------------------------------------------------------------------------

func TestParseTaskPayload_EmptyPayload(t *testing.T) {
	_, err := ParseTaskPayload("")
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestParseTaskPayload_WhitespaceOnlyPayload(t *testing.T) {
	_, err := ParseTaskPayload("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only payload")
	}
}

func TestParseTaskPayload_InvalidJSON(t *testing.T) {
	_, err := ParseTaskPayload("{not-valid-json}")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseTaskPayload_ValidTask(t *testing.T) {
	task := Task{
		TaskID:      "t-001",
		MotherRole:  MotherInstructor,
		ChildIntent: ChildWork,
		Title:       "Run diagnostics",
		Instruction: "Check system health",
	}
	payload, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	got, err := ParseTaskPayload(string(payload))
	if err != nil {
		t.Fatalf("ParseTaskPayload error: %v", err)
	}
	if got.TaskID != "t-001" {
		t.Errorf("task_id: got %q, want 't-001'", got.TaskID)
	}
	if got.MotherRole != MotherInstructor {
		t.Errorf("mother_role: got %q, want %q", got.MotherRole, MotherInstructor)
	}
	if got.ChildIntent != ChildWork {
		t.Errorf("child_intent: got %q, want %q", got.ChildIntent, ChildWork)
	}
}

func TestParseTaskPayload_InvalidMotherRole(t *testing.T) {
	raw := `{"mother_role":"unknown","child_intent":"work","title":"T","instruction":"I"}`
	_, err := ParseTaskPayload(raw)
	if err == nil {
		t.Fatal("expected error for invalid mother_role")
	}
}

func TestParseTaskPayload_InvalidChildIntent(t *testing.T) {
	raw := `{"mother_role":"instructor","child_intent":"dance","title":"T","instruction":"I"}`
	_, err := ParseTaskPayload(raw)
	if err == nil {
		t.Fatal("expected error for invalid child_intent")
	}
}

func TestParseTaskPayload_MissingTitle(t *testing.T) {
	raw := `{"mother_role":"instructor","child_intent":"work","title":"","instruction":"Do something"}`
	_, err := ParseTaskPayload(raw)
	if err == nil {
		t.Fatal("expected error for empty title")
	}
}

func TestParseTaskPayload_MissingInstruction(t *testing.T) {
	raw := `{"mother_role":"instructor","child_intent":"work","title":"T","instruction":""}`
	_, err := ParseTaskPayload(raw)
	if err == nil {
		t.Fatal("expected error for empty instruction")
	}
}

// ---------------------------------------------------------------------------
// Task.Validate — all MotherRole / ChildIntent combinations
// ---------------------------------------------------------------------------

func TestTaskValidate_AllMotherRoles(t *testing.T) {
	roles := []MotherRole{
		MotherInstructor,
		MotherGuardian,
		MotherApprover,
		MotherCoordinator,
		MotherScheduler,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			task := Task{
				MotherRole:  role,
				ChildIntent: ChildWork,
				Title:       "Test",
				Instruction: "Do it",
			}
			if err := task.Validate(); err != nil {
				t.Errorf("unexpected validation error for role %q: %v", role, err)
			}
		})
	}
}

func TestTaskValidate_AllChildIntents(t *testing.T) {
	intents := []ChildIntent{
		ChildWork,
		ChildResolve,
		ChildSuggest,
		ChildIdentify,
		ChildComplain,
	}
	for _, intent := range intents {
		t.Run(string(intent), func(t *testing.T) {
			task := Task{
				MotherRole:  MotherInstructor,
				ChildIntent: intent,
				Title:       "Test",
				Instruction: "Do it",
			}
			if err := task.Validate(); err != nil {
				t.Errorf("unexpected validation error for intent %q: %v", intent, err)
			}
		})
	}
}

func TestTaskValidate_InvalidRole(t *testing.T) {
	task := Task{
		MotherRole:  "overlord",
		ChildIntent: ChildWork,
		Title:       "Test",
		Instruction: "Do it",
	}
	if err := task.Validate(); err == nil {
		t.Fatal("expected error for invalid mother_role")
	}
}

func TestTaskValidate_InvalidIntent(t *testing.T) {
	task := Task{
		MotherRole:  MotherInstructor,
		ChildIntent: "party",
		Title:       "Test",
		Instruction: "Do it",
	}
	if err := task.Validate(); err == nil {
		t.Fatal("expected error for invalid child_intent")
	}
}
