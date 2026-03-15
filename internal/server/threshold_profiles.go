package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type IssueThresholdProfile struct {
	ID          int64                `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	IsActive    bool                 `json:"is_active"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Rules       []IssueThresholdRule `json:"rules"`
}

type IssueThresholdRule struct {
	ID             int64   `json:"id"`
	ProfileID      int64   `json:"profile_id"`
	RuleKey        string  `json:"rule_key"`
	IssueKey       string  `json:"issue_key"`
	Category       string  `json:"category"`
	Severity       string  `json:"severity"`
	Signal         string  `json:"signal"`
	Comparator     string  `json:"comparator"`
	ThresholdValue float64 `json:"threshold_value"`
	DurationMin    int     `json:"duration_minutes"`
	Enabled        bool    `json:"enabled"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Source         string  `json:"source"`
}

func ListIssueThresholdProfiles(ctx context.Context, limit int) ([]IssueThresholdProfile, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	rows, err := DB.Query(ctx, `
		SELECT id, name, COALESCE(description, ''), is_active, created_at, updated_at
		FROM issue_threshold_profiles
		ORDER BY is_active DESC, updated_at DESC, id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list threshold profiles: %w", err)
	}
	defer rows.Close()

	profiles := make([]IssueThresholdProfile, 0, limit)
	for rows.Next() {
		var item IssueThresholdProfile
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.Description,
			&item.IsActive,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan threshold profile: %w", err)
		}

		rules, err := listIssueThresholdRulesByProfile(ctx, item.ID)
		if err != nil {
			return nil, err
		}
		item.Rules = rules
		profiles = append(profiles, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate threshold profiles: %w", err)
	}

	return profiles, nil
}

func GetActiveIssueThresholdProfile(ctx context.Context) (*IssueThresholdProfile, error) {
	var profile IssueThresholdProfile
	err := DB.QueryRow(ctx, `
		SELECT id, name, COALESCE(description, ''), is_active, created_at, updated_at
		FROM issue_threshold_profiles
		WHERE is_active = TRUE
		ORDER BY updated_at DESC, id DESC
		LIMIT 1
	`).Scan(
		&profile.ID,
		&profile.Name,
		&profile.Description,
		&profile.IsActive,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get active threshold profile: %w", err)
	}

	rules, err := listIssueThresholdRulesByProfile(ctx, profile.ID)
	if err != nil {
		return nil, err
	}
	profile.Rules = rules
	return &profile, nil
}

func UpsertActiveIssueThresholdProfile(ctx context.Context, profile IssueThresholdProfile) (*IssueThresholdProfile, error) {
	name := strings.TrimSpace(profile.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(profile.Rules) == 0 {
		return nil, fmt.Errorf("at least one threshold rule is required")
	}

	normalizedRules := make([]IssueThresholdRule, 0, len(profile.Rules))
	for _, item := range profile.Rules {
		rule, err := normalizeIssueThresholdRule(item)
		if err != nil {
			return nil, err
		}
		normalizedRules = append(normalizedRules, rule)
	}

	tx, err := DB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin threshold profile transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var profileID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO issue_threshold_profiles (name, description, is_active)
		VALUES ($1, $2, TRUE)
		ON CONFLICT (name) DO UPDATE SET
			description = EXCLUDED.description,
			is_active = TRUE,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id
	`, name, strings.TrimSpace(profile.Description)).Scan(&profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert threshold profile: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE issue_threshold_profiles SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id <> $1`, profileID); err != nil {
		return nil, fmt.Errorf("failed to deactivate old threshold profiles: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM issue_threshold_rules WHERE profile_id = $1`, profileID); err != nil {
		return nil, fmt.Errorf("failed to clear threshold rules: %w", err)
	}

	for _, item := range normalizedRules {
		if _, err := tx.Exec(ctx, `
			INSERT INTO issue_threshold_rules (
				profile_id, rule_key, issue_key, category, severity,
				signal, comparator, threshold_value, duration_minutes,
				enabled, title, description, source
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`,
			profileID,
			item.RuleKey,
			item.IssueKey,
			item.Category,
			item.Severity,
			item.Signal,
			item.Comparator,
			item.ThresholdValue,
			item.DurationMin,
			item.Enabled,
			item.Title,
			item.Description,
			item.Source,
		); err != nil {
			return nil, fmt.Errorf("failed to upsert threshold rule %s: %w", item.RuleKey, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit threshold profile: %w", err)
	}

	return GetActiveIssueThresholdProfile(ctx)
}

func normalizeIssueThresholdRule(rule IssueThresholdRule) (IssueThresholdRule, error) {
	rule.RuleKey = strings.TrimSpace(rule.RuleKey)
	rule.IssueKey = strings.TrimSpace(rule.IssueKey)
	rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
	rule.Severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	rule.Signal = strings.ToLower(strings.TrimSpace(rule.Signal))
	rule.Comparator = strings.ToLower(strings.TrimSpace(rule.Comparator))
	rule.Title = strings.TrimSpace(rule.Title)
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Source = strings.ToLower(strings.TrimSpace(rule.Source))

	if rule.RuleKey == "" {
		return IssueThresholdRule{}, fmt.Errorf("rule_key is required")
	}
	if rule.IssueKey == "" {
		return IssueThresholdRule{}, fmt.Errorf("issue_key is required")
	}
	if rule.Category == "" {
		rule.Category = "performance"
	}
	switch rule.Severity {
	case "critical", "high", "medium", "low", "warning":
	default:
		return IssueThresholdRule{}, fmt.Errorf("invalid severity for rule %s", rule.RuleKey)
	}
	if rule.Signal == "" {
		return IssueThresholdRule{}, fmt.Errorf("signal is required for rule %s", rule.RuleKey)
	}
	switch rule.Comparator {
	case "gt", "gte", "lt", "lte":
	default:
		return IssueThresholdRule{}, fmt.Errorf("invalid comparator for rule %s", rule.RuleKey)
	}
	if rule.Title == "" {
		return IssueThresholdRule{}, fmt.Errorf("title is required for rule %s", rule.RuleKey)
	}
	if rule.Description == "" {
		return IssueThresholdRule{}, fmt.Errorf("description is required for rule %s", rule.RuleKey)
	}
	if rule.Source == "" {
		rule.Source = "metrics"
	}
	switch rule.Source {
	case "metrics", "heartbeat":
	default:
		return IssueThresholdRule{}, fmt.Errorf("invalid source for rule %s", rule.RuleKey)
	}
	if rule.DurationMin < 0 {
		return IssueThresholdRule{}, fmt.Errorf("duration_minutes must be >= 0 for rule %s", rule.RuleKey)
	}
	return rule, nil
}

func listIssueThresholdRulesByProfile(ctx context.Context, profileID int64) ([]IssueThresholdRule, error) {
	rows, err := DB.Query(ctx, `
		SELECT id, profile_id, rule_key, issue_key, category, severity,
			signal, comparator, threshold_value, duration_minutes,
			enabled, title, description, source
		FROM issue_threshold_rules
		WHERE profile_id = $1
		ORDER BY id ASC
	`, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to list threshold rules: %w", err)
	}
	defer rows.Close()

	rules := make([]IssueThresholdRule, 0, 16)
	for rows.Next() {
		var item IssueThresholdRule
		if err := rows.Scan(
			&item.ID,
			&item.ProfileID,
			&item.RuleKey,
			&item.IssueKey,
			&item.Category,
			&item.Severity,
			&item.Signal,
			&item.Comparator,
			&item.ThresholdValue,
			&item.DurationMin,
			&item.Enabled,
			&item.Title,
			&item.Description,
			&item.Source,
		); err != nil {
			return nil, fmt.Errorf("failed to scan threshold rule: %w", err)
		}
		rules = append(rules, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate threshold rules: %w", err)
	}

	return rules, nil
}
