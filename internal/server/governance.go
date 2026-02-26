package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type CommandPolicy struct {
	Allowlist []string
	Denylist  []string
}

type PatchWindow struct {
	Day   string `json:"day"`
	Start string `json:"start"`
	End   string `json:"end"`
}

type Category struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type GroupPolicy struct {
	ID                   int           `json:"id"`
	Name                 string        `json:"name"`
	Description          string        `json:"description"`
	ScriptAllowlist      []string      `json:"script_allowlist"`
	ScriptDenylist       []string      `json:"script_denylist"`
	PatchWindows         []PatchWindow `json:"patch_windows"`
	MaxConcurrentScripts int           `json:"max_concurrent_scripts"`
	RequireAdminApproval bool          `json:"require_admin_approval"`
	OnlineOnly           bool          `json:"online_only"`
	CreatedAt            time.Time     `json:"created_at"`
	UpdatedAt            time.Time     `json:"updated_at"`
}

type ExecutionProfile struct {
	ID             int               `json:"id"`
	Name           string            `json:"name"`
	RunAs          string            `json:"run_as"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Retries        int               `json:"retries"`
	RebootBehavior string            `json:"reboot_behavior"`
	WorkingDir     string            `json:"working_dir"`
	EnvVars        map[string]string `json:"env_vars"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type AgentGroup struct {
	ID              int       `json:"id"`
	Name            string    `json:"name"`
	CategoryID      *int      `json:"category_id"`
	PolicyID        *int      `json:"policy_id"`
	ScriptProfileID *int      `json:"script_profile_id"`
	PatchProfileID  *int      `json:"patch_profile_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type GroupMember struct {
	GroupID int       `json:"group_id"`
	AgentID string    `json:"agent_id"`
	Created time.Time `json:"created_at"`
}

func ListCategories(ctx context.Context) ([]Category, error) {
	rows, err := DB.Query(ctx, `
		SELECT id, name, COALESCE(description, ''), created_at, updated_at
		FROM agent_categories
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list categories: %w", err)
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan category: %w", err)
		}
		categories = append(categories, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate categories: %w", err)
	}
	return categories, nil
}

func CreateCategory(ctx context.Context, name, description string) (*Category, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	var c Category
	err := DB.QueryRow(ctx, `
		INSERT INTO agent_categories (name, description)
		VALUES ($1, $2)
		RETURNING id, name, COALESCE(description, ''), created_at, updated_at
	`, name, strings.TrimSpace(description)).Scan(&c.ID, &c.Name, &c.Description, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create category: %w", err)
	}
	return &c, nil
}

func UpdateCategory(ctx context.Context, id int, name, description string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("name is required")
	}

	cmd, err := DB.Exec(ctx, `
		UPDATE agent_categories
		SET name = $2, description = $3, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, id, name, strings.TrimSpace(description))
	if err != nil {
		return fmt.Errorf("failed to update category: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("category not found")
	}
	return nil
}

func DeleteCategory(ctx context.Context, id int) error {
	cmd, err := DB.Exec(ctx, `DELETE FROM agent_categories WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete category: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("category not found")
	}
	return nil
}

func ListPolicies(ctx context.Context) ([]GroupPolicy, error) {
	rows, err := DB.Query(ctx, `
		SELECT id, name, COALESCE(description, ''),
		       script_allowlist, script_denylist, patch_windows,
		       max_concurrent_scripts, require_admin_approval, online_only,
		       created_at, updated_at
		FROM group_policies
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()

	var policies []GroupPolicy
	for rows.Next() {
		var p GroupPolicy
		var allowlistJSON, denylistJSON, patchJSON string
		if err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.Description,
			&allowlistJSON,
			&denylistJSON,
			&patchJSON,
			&p.MaxConcurrentScripts,
			&p.RequireAdminApproval,
			&p.OnlineOnly,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		_ = json.Unmarshal([]byte(allowlistJSON), &p.ScriptAllowlist)
		_ = json.Unmarshal([]byte(denylistJSON), &p.ScriptDenylist)
		_ = json.Unmarshal([]byte(patchJSON), &p.PatchWindows)
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate policies: %w", err)
	}
	return policies, nil
}

func CreatePolicy(ctx context.Context, p GroupPolicy) (*GroupPolicy, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.MaxConcurrentScripts <= 0 {
		p.MaxConcurrentScripts = 1
	}

	allowJSON := mustMarshalJSON(p.ScriptAllowlist, "[]")
	denyJSON := mustMarshalJSON(p.ScriptDenylist, "[]")
	patchJSON := mustMarshalJSON(p.PatchWindows, "[]")

	var created GroupPolicy
	var allowOut, denyOut, patchOut string
	if err := DB.QueryRow(ctx, `
		INSERT INTO group_policies (
			name, description, script_allowlist, script_denylist, patch_windows,
			max_concurrent_scripts, require_admin_approval, online_only
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, COALESCE(description, ''), script_allowlist, script_denylist, patch_windows,
		         max_concurrent_scripts, require_admin_approval, online_only, created_at, updated_at
	`, p.Name, strings.TrimSpace(p.Description), allowJSON, denyJSON, patchJSON, p.MaxConcurrentScripts, p.RequireAdminApproval, p.OnlineOnly).
		Scan(&created.ID, &created.Name, &created.Description, &allowOut, &denyOut, &patchOut, &created.MaxConcurrentScripts, &created.RequireAdminApproval, &created.OnlineOnly, &created.CreatedAt, &created.UpdatedAt); err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}
	_ = json.Unmarshal([]byte(allowOut), &created.ScriptAllowlist)
	_ = json.Unmarshal([]byte(denyOut), &created.ScriptDenylist)
	_ = json.Unmarshal([]byte(patchOut), &created.PatchWindows)
	return &created, nil
}

func UpdatePolicy(ctx context.Context, id int, p GroupPolicy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.MaxConcurrentScripts <= 0 {
		p.MaxConcurrentScripts = 1
	}

	allowJSON := mustMarshalJSON(p.ScriptAllowlist, "[]")
	denyJSON := mustMarshalJSON(p.ScriptDenylist, "[]")
	patchJSON := mustMarshalJSON(p.PatchWindows, "[]")

	cmd, err := DB.Exec(ctx, `
		UPDATE group_policies
		SET name = $2,
		    description = $3,
		    script_allowlist = $4,
		    script_denylist = $5,
		    patch_windows = $6,
		    max_concurrent_scripts = $7,
		    require_admin_approval = $8,
		    online_only = $9,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, id, p.Name, strings.TrimSpace(p.Description), allowJSON, denyJSON, patchJSON, p.MaxConcurrentScripts, p.RequireAdminApproval, p.OnlineOnly)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func DeletePolicy(ctx context.Context, id int) error {
	cmd, err := DB.Exec(ctx, `DELETE FROM group_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func ListScriptProfiles(ctx context.Context) ([]ExecutionProfile, error) {
	return listProfiles(ctx, "script_profiles")
}

func ListPatchProfiles(ctx context.Context) ([]ExecutionProfile, error) {
	return listProfiles(ctx, "patch_profiles")
}

func CreateScriptProfile(ctx context.Context, profile ExecutionProfile) (*ExecutionProfile, error) {
	return createProfile(ctx, "script_profiles", profile)
}

func CreatePatchProfile(ctx context.Context, profile ExecutionProfile) (*ExecutionProfile, error) {
	return createProfile(ctx, "patch_profiles", profile)
}

func UpdateScriptProfile(ctx context.Context, id int, profile ExecutionProfile) error {
	return updateProfile(ctx, "script_profiles", id, profile)
}

func UpdatePatchProfile(ctx context.Context, id int, profile ExecutionProfile) error {
	return updateProfile(ctx, "patch_profiles", id, profile)
}

func DeleteScriptProfile(ctx context.Context, id int) error {
	return deleteProfile(ctx, "script_profiles", id)
}

func DeletePatchProfile(ctx context.Context, id int) error {
	return deleteProfile(ctx, "patch_profiles", id)
}

func listProfiles(ctx context.Context, table string) ([]ExecutionProfile, error) {
	rows, err := DB.Query(ctx, fmt.Sprintf(`
		SELECT id, name, run_as, timeout_seconds, retries, reboot_behavior,
		       COALESCE(working_dir, ''), env_vars, created_at, updated_at
		FROM %s
		ORDER BY name ASC
	`, table))
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}
	defer rows.Close()

	var profiles []ExecutionProfile
	for rows.Next() {
		var p ExecutionProfile
		var envJSON string
		if err := rows.Scan(&p.ID, &p.Name, &p.RunAs, &p.TimeoutSeconds, &p.Retries, &p.RebootBehavior, &p.WorkingDir, &envJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan profile: %w", err)
		}
		_ = json.Unmarshal([]byte(envJSON), &p.EnvVars)
		profiles = append(profiles, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate profiles: %w", err)
	}
	return profiles, nil
}

func createProfile(ctx context.Context, table string, profile ExecutionProfile) (*ExecutionProfile, error) {
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	profile.RunAs = normalizeRunAs(profile.RunAs)
	profile.RebootBehavior = normalizeRebootBehavior(profile.RebootBehavior)
	if profile.TimeoutSeconds <= 0 {
		profile.TimeoutSeconds = 3600
	}
	if profile.Retries < 0 {
		profile.Retries = 0
	}

	envJSON := mustMarshalJSON(profile.EnvVars, "{}")

	var created ExecutionProfile
	var envOut string
	if err := DB.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO %s (name, run_as, timeout_seconds, retries, reboot_behavior, working_dir, env_vars)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, name, run_as, timeout_seconds, retries, reboot_behavior, COALESCE(working_dir, ''), env_vars, created_at, updated_at
	`, table),
		profile.Name,
		profile.RunAs,
		profile.TimeoutSeconds,
		profile.Retries,
		profile.RebootBehavior,
		strings.TrimSpace(profile.WorkingDir),
		envJSON,
	).Scan(&created.ID, &created.Name, &created.RunAs, &created.TimeoutSeconds, &created.Retries, &created.RebootBehavior, &created.WorkingDir, &envOut, &created.CreatedAt, &created.UpdatedAt); err != nil {
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}
	_ = json.Unmarshal([]byte(envOut), &created.EnvVars)
	return &created, nil
}

func updateProfile(ctx context.Context, table string, id int, profile ExecutionProfile) error {
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		return fmt.Errorf("name is required")
	}
	profile.RunAs = normalizeRunAs(profile.RunAs)
	profile.RebootBehavior = normalizeRebootBehavior(profile.RebootBehavior)
	if profile.TimeoutSeconds <= 0 {
		profile.TimeoutSeconds = 3600
	}
	if profile.Retries < 0 {
		profile.Retries = 0
	}

	envJSON := mustMarshalJSON(profile.EnvVars, "{}")

	cmd, err := DB.Exec(ctx, fmt.Sprintf(`
		UPDATE %s
		SET name = $2,
		    run_as = $3,
		    timeout_seconds = $4,
		    retries = $5,
		    reboot_behavior = $6,
		    working_dir = $7,
		    env_vars = $8,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, table), id, profile.Name, profile.RunAs, profile.TimeoutSeconds, profile.Retries, profile.RebootBehavior, strings.TrimSpace(profile.WorkingDir), envJSON)
	if err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("profile not found")
	}
	return nil
}

func deleteProfile(ctx context.Context, table string, id int) error {
	cmd, err := DB.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, table), id)
	if err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("profile not found")
	}
	return nil
}

func ListGroups(ctx context.Context) ([]AgentGroup, error) {
	rows, err := DB.Query(ctx, `
		SELECT id, name, category_id, policy_id, script_profile_id, patch_profile_id, created_at, updated_at
		FROM agent_groups
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []AgentGroup
	for rows.Next() {
		var g AgentGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.CategoryID, &g.PolicyID, &g.ScriptProfileID, &g.PatchProfileID, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate groups: %w", err)
	}
	return groups, nil
}

func CreateGroup(ctx context.Context, group AgentGroup) (*AgentGroup, error) {
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	var created AgentGroup
	err := DB.QueryRow(ctx, `
		INSERT INTO agent_groups (name, category_id, policy_id, script_profile_id, patch_profile_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, category_id, policy_id, script_profile_id, patch_profile_id, created_at, updated_at
	`, group.Name, group.CategoryID, group.PolicyID, group.ScriptProfileID, group.PatchProfileID).
		Scan(&created.ID, &created.Name, &created.CategoryID, &created.PolicyID, &created.ScriptProfileID, &created.PatchProfileID, &created.CreatedAt, &created.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}
	return &created, nil
}

func UpdateGroup(ctx context.Context, id int, group AgentGroup) error {
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		return fmt.Errorf("name is required")
	}

	cmd, err := DB.Exec(ctx, `
		UPDATE agent_groups
		SET name = $2,
		    category_id = $3,
		    policy_id = $4,
		    script_profile_id = $5,
		    patch_profile_id = $6,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, id, group.Name, group.CategoryID, group.PolicyID, group.ScriptProfileID, group.PatchProfileID)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

func DeleteGroup(ctx context.Context, id int) error {
	cmd, err := DB.Exec(ctx, `DELETE FROM agent_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

func AddGroupMember(ctx context.Context, groupID int, agentID string) error {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}

	cmd, err := DB.Exec(ctx, `
		INSERT INTO agent_group_members (group_id, agent_id)
		VALUES ($1, $2)
		ON CONFLICT (group_id, agent_id) DO NOTHING
	`, groupID, agentID)
	if err != nil {
		return fmt.Errorf("failed to add group member: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("member already exists")
	}
	return nil
}

func RemoveGroupMember(ctx context.Context, groupID int, agentID string) error {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}

	cmd, err := DB.Exec(ctx, `
		DELETE FROM agent_group_members
		WHERE group_id = $1 AND agent_id = $2
	`, groupID, agentID)
	if err != nil {
		return fmt.Errorf("failed to remove group member: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

func ListGroupMembers(ctx context.Context, groupID int) ([]GroupMember, error) {
	rows, err := DB.Query(ctx, `
		SELECT group_id, agent_id, created_at
		FROM agent_group_members
		WHERE group_id = $1
		ORDER BY agent_id ASC
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list group members: %w", err)
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.GroupID, &m.AgentID, &m.Created); err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate members: %w", err)
	}
	return members, nil
}

func normalizeRunAs(runAs string) string {
	value := strings.ToLower(strings.TrimSpace(runAs))
	if value == "user" {
		return "user"
	}
	return "system"
}

func normalizeRebootBehavior(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "soft", "hard", "reboot_if_required":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "none"
	}
}

func mustMarshalJSON(value interface{}, fallback string) string {
	if value == nil {
		return fallback
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fallback
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func GetMergedCommandPolicyForAgent(ctx context.Context, agentID string) (CommandPolicy, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return CommandPolicy{}, fmt.Errorf("agent_id is required")
	}

	rows, err := DB.Query(ctx, `
		SELECT gp.script_allowlist, gp.script_denylist
		FROM agent_group_members gm
		JOIN agent_groups g ON g.id = gm.group_id
		JOIN group_policies gp ON gp.id = g.policy_id
		WHERE gm.agent_id = $1
	`, agentID)
	if err != nil {
		return CommandPolicy{}, fmt.Errorf("failed to load command policy: %w", err)
	}
	defer rows.Close()

	allowSet := map[string]struct{}{}
	denySet := map[string]struct{}{}

	for rows.Next() {
		var allowJSON, denyJSON string
		if err := rows.Scan(&allowJSON, &denyJSON); err != nil {
			return CommandPolicy{}, fmt.Errorf("failed to scan command policy: %w", err)
		}

		var allow []string
		_ = json.Unmarshal([]byte(allowJSON), &allow)
		for _, value := range allow {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized != "" {
				allowSet[normalized] = struct{}{}
			}
		}

		var deny []string
		_ = json.Unmarshal([]byte(denyJSON), &deny)
		for _, value := range deny {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized != "" {
				denySet[normalized] = struct{}{}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return CommandPolicy{}, fmt.Errorf("failed to iterate command policy rows: %w", err)
	}

	policy := CommandPolicy{
		Allowlist: make([]string, 0, len(allowSet)),
		Denylist:  make([]string, 0, len(denySet)),
	}
	for value := range allowSet {
		policy.Allowlist = append(policy.Allowlist, value)
	}
	for value := range denySet {
		policy.Denylist = append(policy.Denylist, value)
	}

	sort.Strings(policy.Allowlist)
	sort.Strings(policy.Denylist)

	return policy, nil
}
