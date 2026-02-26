package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type MotherRole string

const (
	MotherInstructor  MotherRole = "instructor"
	MotherGuardian    MotherRole = "guardian"
	MotherApprover    MotherRole = "approver"
	MotherCoordinator MotherRole = "coordinator"
	MotherScheduler   MotherRole = "scheduler"
)

type ChildIntent string

const (
	ChildWork     ChildIntent = "work"
	ChildResolve  ChildIntent = "resolve"
	ChildSuggest  ChildIntent = "suggest"
	ChildIdentify ChildIntent = "identify"
	ChildComplain ChildIntent = "complain"
)

type Task struct {
	TaskID           string      `json:"task_id,omitempty"`
	MotherRole       MotherRole  `json:"mother_role"`
	ChildIntent      ChildIntent `json:"child_intent"`
	Title            string      `json:"title"`
	Instruction      string      `json:"instruction"`
	Context          string      `json:"context,omitempty"`
	RequiresApproval bool        `json:"requires_approval,omitempty"`
	ScheduledAt      *time.Time  `json:"scheduled_at,omitempty"`
}

type ChildResult struct {
	TaskID      string      `json:"task_id,omitempty"`
	ChildIntent ChildIntent `json:"child_intent"`
	State       string      `json:"state"`
	Summary     string      `json:"summary"`
	Details     string      `json:"details,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

func ParseTaskPayload(payload string) (*Task, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, fmt.Errorf("payload is required")
	}

	var task Task
	if err := json.Unmarshal([]byte(payload), &task); err != nil {
		return nil, fmt.Errorf("invalid ai_task payload JSON: %w", err)
	}

	if err := task.Validate(); err != nil {
		return nil, err
	}

	return &task, nil
}

func (t Task) Validate() error {
	switch t.MotherRole {
	case MotherInstructor, MotherGuardian, MotherApprover, MotherCoordinator, MotherScheduler:
	default:
		return fmt.Errorf("invalid mother_role")
	}

	switch t.ChildIntent {
	case ChildWork, ChildResolve, ChildSuggest, ChildIdentify, ChildComplain:
	default:
		return fmt.Errorf("invalid child_intent")
	}

	if strings.TrimSpace(t.Title) == "" {
		return fmt.Errorf("title is required")
	}

	if strings.TrimSpace(t.Instruction) == "" {
		return fmt.Errorf("instruction is required")
	}

	return nil
}
