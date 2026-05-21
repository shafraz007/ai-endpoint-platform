package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const updateManifestDefaultVersion = 1

type UpdateRolloutPolicy struct {
	PolicyVersion             int     `json:"policy_version"`
	DefaultManifestVersion    int     `json:"default_manifest_version"`
	AllowedManifestVersions   []int   `json:"allowed_manifest_versions"`
	InstallApprovedTTLMinutes int     `json:"install_approved_ttl_minutes"`
	UninstallPatchTTLMinutes  int     `json:"uninstall_patch_kb_ttl_minutes"`
	RingCount                 int     `json:"ring_count"`
	ActiveRing                int     `json:"active_ring"`
	RingSalt                  string  `json:"ring_salt,omitempty"`
	HealthGateEnabled         bool    `json:"health_gate_enabled"`
	HealthWindowMinutes       int     `json:"health_window_minutes"`
	HealthMinSamples          int     `json:"health_min_samples"`
	HealthMaxFailureRatePct   float64 `json:"health_max_failure_rate_pct"`
	AutoRollbackEnabled       bool    `json:"auto_rollback_enabled"`
	AutoRollbackRingStep      int     `json:"auto_rollback_ring_step"`
}

type UpdateRolloutHealthSnapshot struct {
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	Samples          int       `json:"samples"`
	Failures         int       `json:"failures"`
	FailureRatePct   float64   `json:"failure_rate_pct"`
	Healthy          bool      `json:"healthy"`
	EffectiveSamples int       `json:"effective_samples"`
}

type UpdateRolloutRingTelemetry struct {
	Ring        int `json:"ring"`
	AgentCount  int `json:"agent_count"`
	InstallOpen int `json:"install_open"`
}

type UpdateRolloutInstallEvent struct {
	CommandID   int64      `json:"command_id"`
	AgentID     string     `json:"agent_id"`
	Hostname    string     `json:"hostname,omitempty"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Ring        int        `json:"ring"`
}

type UpdateRolloutTelemetryReport struct {
	GeneratedAt         time.Time                    `json:"generated_at"`
	Policy              UpdateRolloutPolicy          `json:"policy"`
	EffectiveActiveRing int                          `json:"effective_active_ring"`
	HealthSnapshot      UpdateRolloutHealthSnapshot  `json:"health_snapshot"`
	GateState           string                       `json:"gate_state"`
	RingSummary         []UpdateRolloutRingTelemetry `json:"ring_summary"`
	RecentInstalls      []UpdateRolloutInstallEvent  `json:"recent_installs"`
}

var (
	updateRolloutPolicyOverrideMu sync.RWMutex
	updateRolloutPolicyOverride   *UpdateRolloutPolicy
)

type UpdateCommandManifest struct {
	Version         int       `json:"version"`
	PolicyVersion   int       `json:"policy_version,omitempty"`
	RolloutRing     int       `json:"rollout_ring,omitempty"`
	ManifestID      string    `json:"manifest_id"`
	Action          string    `json:"action"`
	AgentID         string    `json:"agent_id"`
	UpdateIDs       []string  `json:"update_ids,omitempty"`
	KBIDs           []string  `json:"kb_ids,omitempty"`
	RebootBehavior  string    `json:"reboot_behavior,omitempty"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	IssuedBy        string    `json:"issued_by,omitempty"`
	Signature       string    `json:"signature,omitempty"`
	SignatureScheme string    `json:"signature_scheme,omitempty"`
}

func BuildSignedUpdateManifest(manifest UpdateCommandManifest) (UpdateCommandManifest, error) {
	normalized, err := normalizeUpdateManifest(manifest)
	if err != nil {
		return UpdateCommandManifest{}, err
	}

	signingKey, err := resolveUpdateManifestSigningKey()
	if err != nil {
		return UpdateCommandManifest{}, err
	}

	payload, err := canonicalUpdateManifestPayload(normalized)
	if err != nil {
		return UpdateCommandManifest{}, err
	}

	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write(payload)
	normalized.Signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	normalized.SignatureScheme = "hmac-sha256"

	return normalized, nil
}

func ResolveUpdateRolloutPolicy() (UpdateRolloutPolicy, error) {
	policy := defaultUpdateRolloutPolicy()

	if raw := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_POLICY_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_POLICY_JSON: %w", err)
		}
	}

	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_POLICY_VERSION")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_POLICY_VERSION")
		}
		policy.PolicyVersion = parsed
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_RING_COUNT")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_RING_COUNT")
		}
		policy.RingCount = parsed
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_ACTIVE_RING")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_ACTIVE_RING")
		}
		policy.ActiveRing = parsed
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_RING_SALT")); value != "" {
		policy.RingSalt = value
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_HEALTH_GATE_ENABLED")); value != "" {
		policy.HealthGateEnabled = !isFalseLike(value)
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_HEALTH_WINDOW_MINUTES")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_HEALTH_WINDOW_MINUTES")
		}
		policy.HealthWindowMinutes = parsed
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_HEALTH_MIN_SAMPLES")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_HEALTH_MIN_SAMPLES")
		}
		policy.HealthMinSamples = parsed
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_HEALTH_MAX_FAILURE_RATE_PCT")); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_HEALTH_MAX_FAILURE_RATE_PCT")
		}
		policy.HealthMaxFailureRatePct = parsed
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_AUTO_ROLLBACK_ENABLED")); value != "" {
		policy.AutoRollbackEnabled = !isFalseLike(value)
	}
	if value := strings.TrimSpace(os.Getenv("UPDATE_ROLLOUT_AUTO_ROLLBACK_RING_STEP")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return UpdateRolloutPolicy{}, fmt.Errorf("invalid UPDATE_ROLLOUT_AUTO_ROLLBACK_RING_STEP")
		}
		policy.AutoRollbackRingStep = parsed
	}

	if override, ok := getUpdateRolloutPolicyOverride(); ok {
		policy = override
	}

	normalized, err := normalizeUpdateRolloutPolicy(policy)
	if err != nil {
		return UpdateRolloutPolicy{}, err
	}
	return normalized, nil
}

func SetUpdateRolloutPolicyOverride(policy UpdateRolloutPolicy) (UpdateRolloutPolicy, error) {
	normalized, err := normalizeUpdateRolloutPolicy(policy)
	if err != nil {
		return UpdateRolloutPolicy{}, err
	}

	updateRolloutPolicyOverrideMu.Lock()
	defer updateRolloutPolicyOverrideMu.Unlock()
	clone := cloneUpdateRolloutPolicy(normalized)
	updateRolloutPolicyOverride = &clone
	return cloneUpdateRolloutPolicy(clone), nil
}

func ClearUpdateRolloutPolicyOverride() {
	updateRolloutPolicyOverrideMu.Lock()
	defer updateRolloutPolicyOverrideMu.Unlock()
	updateRolloutPolicyOverride = nil
}

func GetUpdateRolloutPolicyOverride() (UpdateRolloutPolicy, bool) {
	return getUpdateRolloutPolicyOverride()
}

func GetUpdateRolloutControlStatus(ctx context.Context) (UpdateRolloutPolicy, int, UpdateRolloutHealthSnapshot, error) {
	policy, err := ResolveUpdateRolloutPolicy()
	if err != nil {
		return UpdateRolloutPolicy{}, 0, UpdateRolloutHealthSnapshot{}, err
	}
	effectiveActiveRing, snapshot, err := ResolveInstallRolloutEffectiveActiveRing(ctx, policy)
	if err != nil {
		return UpdateRolloutPolicy{}, 0, UpdateRolloutHealthSnapshot{}, err
	}
	return policy, effectiveActiveRing, snapshot, nil
}

func CollectUpdateRolloutTelemetry(ctx context.Context, recentLimit int) (UpdateRolloutTelemetryReport, error) {
	if recentLimit <= 0 {
		recentLimit = 30
	}
	if recentLimit > 500 {
		recentLimit = 500
	}

	policy, effectiveActiveRing, healthSnapshot, err := GetUpdateRolloutControlStatus(ctx)
	if err != nil {
		return UpdateRolloutTelemetryReport{}, err
	}

	ringBuckets := make(map[int]UpdateRolloutRingTelemetry, policy.RingCount)
	for ring := 1; ring <= policy.RingCount; ring++ {
		ringBuckets[ring] = UpdateRolloutRingTelemetry{Ring: ring}
	}

	rows, err := DB.Query(ctx, `
		SELECT agent_id
		FROM agents
		WHERE COALESCE(agent_id, '') <> ''
	`)
	if err != nil {
		return UpdateRolloutTelemetryReport{}, fmt.Errorf("failed to collect rollout ring population: %w", err)
	}
	for rows.Next() {
		var agentID string
		if scanErr := rows.Scan(&agentID); scanErr != nil {
			rows.Close()
			return UpdateRolloutTelemetryReport{}, fmt.Errorf("failed to scan rollout ring population: %w", scanErr)
		}
		ring, assignErr := policy.assignRingForAgent(agentID)
		if assignErr != nil {
			continue
		}
		bucket := ringBuckets[ring]
		bucket.AgentCount++
		if ring <= effectiveActiveRing {
			bucket.InstallOpen++
		}
		ringBuckets[ring] = bucket
	}
	rows.Close()

	ringSummary := make([]UpdateRolloutRingTelemetry, 0, policy.RingCount)
	for ring := 1; ring <= policy.RingCount; ring++ {
		ringSummary = append(ringSummary, ringBuckets[ring])
	}

	installRows, err := DB.Query(ctx, `
		SELECT ac.id, ac.agent_id, COALESCE(a.hostname, ''), ac.status, ac.created_at, ac.completed_at
		FROM agent_commands ac
		LEFT JOIN agents a ON a.agent_id = ac.agent_id
		WHERE ac.command_type = 'powershell'
		  AND ac.payload ILIKE '%install_approved_updates%'
		ORDER BY ac.created_at DESC
		LIMIT $1
	`, recentLimit)
	if err != nil {
		return UpdateRolloutTelemetryReport{}, fmt.Errorf("failed to query rollout install history: %w", err)
	}
	recentInstalls := make([]UpdateRolloutInstallEvent, 0, recentLimit)
	for installRows.Next() {
		var event UpdateRolloutInstallEvent
		if scanErr := installRows.Scan(&event.CommandID, &event.AgentID, &event.Hostname, &event.Status, &event.CreatedAt, &event.CompletedAt); scanErr != nil {
			installRows.Close()
			return UpdateRolloutTelemetryReport{}, fmt.Errorf("failed to scan rollout install history: %w", scanErr)
		}
		ring, assignErr := policy.assignRingForAgent(event.AgentID)
		if assignErr == nil {
			event.Ring = ring
		}
		recentInstalls = append(recentInstalls, event)
	}
	installRows.Close()

	return UpdateRolloutTelemetryReport{
		GeneratedAt:         time.Now().UTC(),
		Policy:              policy,
		EffectiveActiveRing: effectiveActiveRing,
		HealthSnapshot:      healthSnapshot,
		GateState:           resolveRolloutGateState(policy, effectiveActiveRing, healthSnapshot),
		RingSummary:         ringSummary,
		RecentInstalls:      recentInstalls,
	}, nil
}

func ValidateUpdateManifestAgainstRolloutPolicy(manifest UpdateCommandManifest, policy UpdateRolloutPolicy) error {
	normalizedPolicy, err := normalizeUpdateRolloutPolicy(policy)
	if err != nil {
		return err
	}

	normalizedManifest, err := normalizeUpdateManifest(manifest)
	if err != nil {
		return err
	}

	if normalizedManifest.PolicyVersion != 0 && normalizedManifest.PolicyVersion != normalizedPolicy.PolicyVersion {
		return fmt.Errorf("manifest policy version %d does not match rollout policy %d", normalizedManifest.PolicyVersion, normalizedPolicy.PolicyVersion)
	}

	allowedVersions := make(map[int]struct{}, len(normalizedPolicy.AllowedManifestVersions))
	for _, version := range normalizedPolicy.AllowedManifestVersions {
		allowedVersions[version] = struct{}{}
	}
	if _, ok := allowedVersions[normalizedManifest.Version]; !ok {
		return fmt.Errorf("manifest version %d is not allowed by rollout policy", normalizedManifest.Version)
	}

	maxTTL, err := normalizedPolicy.manifestTTLForAction(normalizedManifest.Action)
	if err != nil {
		return err
	}
	ttl := normalizedManifest.ExpiresAt.Sub(normalizedManifest.IssuedAt)
	if ttl <= 0 {
		return fmt.Errorf("manifest ttl must be positive")
	}
	if ttl > maxTTL {
		return fmt.Errorf("manifest ttl %s exceeds rollout policy max ttl %s", ttl, maxTTL)
	}

	if normalizedManifest.RolloutRing != 0 {
		if normalizedManifest.RolloutRing < 1 || normalizedManifest.RolloutRing > normalizedPolicy.RingCount {
			return fmt.Errorf("manifest rollout ring %d is out of range 1..%d", normalizedManifest.RolloutRing, normalizedPolicy.RingCount)
		}
		expectedRing, err := normalizedPolicy.assignRingForAgent(normalizedManifest.AgentID)
		if err != nil {
			return err
		}
		if normalizedManifest.RolloutRing != expectedRing {
			return fmt.Errorf("manifest rollout ring %d does not match assigned ring %d", normalizedManifest.RolloutRing, expectedRing)
		}
	}

	if strings.EqualFold(normalizedManifest.Action, "install_approved_updates") {
		if normalizedManifest.RolloutRing == 0 {
			return fmt.Errorf("manifest rollout ring is required for install_approved_updates")
		}
		if normalizedManifest.RolloutRing > normalizedPolicy.ActiveRing {
			return fmt.Errorf("manifest rollout ring %d exceeds active ring %d", normalizedManifest.RolloutRing, normalizedPolicy.ActiveRing)
		}
	}

	return nil
}

func defaultUpdateRolloutPolicy() UpdateRolloutPolicy {
	return UpdateRolloutPolicy{
		PolicyVersion:             1,
		DefaultManifestVersion:    updateManifestDefaultVersion,
		AllowedManifestVersions:   []int{updateManifestDefaultVersion},
		InstallApprovedTTLMinutes: 30,
		UninstallPatchTTLMinutes:  30,
		RingCount:                 4,
		ActiveRing:                4,
		RingSalt:                  "default",
		HealthGateEnabled:         true,
		HealthWindowMinutes:       180,
		HealthMinSamples:          5,
		HealthMaxFailureRatePct:   40,
		AutoRollbackEnabled:       true,
		AutoRollbackRingStep:      1,
	}
}

func normalizeUpdateRolloutPolicy(policy UpdateRolloutPolicy) (UpdateRolloutPolicy, error) {
	if policy.PolicyVersion <= 0 {
		policy.PolicyVersion = 1
	}
	if policy.DefaultManifestVersion <= 0 {
		policy.DefaultManifestVersion = updateManifestDefaultVersion
	}

	if len(policy.AllowedManifestVersions) == 0 {
		policy.AllowedManifestVersions = []int{policy.DefaultManifestVersion}
	}

	normalizedVersions := make([]int, 0, len(policy.AllowedManifestVersions))
	seenVersions := map[int]struct{}{}
	for _, version := range policy.AllowedManifestVersions {
		if version <= 0 {
			continue
		}
		if _, exists := seenVersions[version]; exists {
			continue
		}
		seenVersions[version] = struct{}{}
		normalizedVersions = append(normalizedVersions, version)
	}
	if len(normalizedVersions) == 0 {
		return UpdateRolloutPolicy{}, fmt.Errorf("rollout policy allowed_manifest_versions must include at least one positive version")
	}
	sort.Ints(normalizedVersions)
	policy.AllowedManifestVersions = normalizedVersions

	if _, ok := seenVersions[policy.DefaultManifestVersion]; !ok {
		return UpdateRolloutPolicy{}, fmt.Errorf("rollout policy default_manifest_version must be listed in allowed_manifest_versions")
	}

	if policy.InstallApprovedTTLMinutes <= 0 {
		policy.InstallApprovedTTLMinutes = 30
	}
	if policy.UninstallPatchTTLMinutes <= 0 {
		policy.UninstallPatchTTLMinutes = 30
	}
	if policy.RingCount <= 0 {
		policy.RingCount = 4
	}
	if policy.ActiveRing <= 0 {
		policy.ActiveRing = policy.RingCount
	}
	if policy.ActiveRing > policy.RingCount {
		return UpdateRolloutPolicy{}, fmt.Errorf("rollout policy active_ring must be <= ring_count")
	}
	policy.RingSalt = strings.TrimSpace(policy.RingSalt)
	if policy.RingSalt == "" {
		policy.RingSalt = "default"
	}
	if policy.HealthWindowMinutes <= 0 {
		policy.HealthWindowMinutes = 180
	}
	if policy.HealthMinSamples <= 0 {
		policy.HealthMinSamples = 5
	}
	if policy.HealthMaxFailureRatePct < 0 {
		policy.HealthMaxFailureRatePct = 0
	}
	if policy.HealthMaxFailureRatePct > 100 {
		policy.HealthMaxFailureRatePct = 100
	}
	if policy.AutoRollbackRingStep <= 0 {
		policy.AutoRollbackRingStep = 1
	}

	return policy, nil
}

func (policy UpdateRolloutPolicy) assignRingForAgent(agentID string) (int, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return 0, fmt.Errorf("agent_id is required for rollout ring assignment")
	}
	if policy.RingCount <= 0 {
		return 0, fmt.Errorf("rollout policy ring_count must be > 0")
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.ToLower(agentID) + "|" + strings.ToLower(strings.TrimSpace(policy.RingSalt))))
	bucket := hasher.Sum32() % uint32(policy.RingCount)
	return int(bucket) + 1, nil
}

func ValidateAgentUpdateRolloutStage(agentID, action string, policy UpdateRolloutPolicy) (int, error) {
	normalizedPolicy, err := normalizeUpdateRolloutPolicy(policy)
	if err != nil {
		return 0, err
	}
	ring, err := normalizedPolicy.assignRingForAgent(agentID)
	if err != nil {
		return 0, err
	}

	action = strings.ToLower(strings.TrimSpace(action))
	if action == "install_approved_updates" && ring > normalizedPolicy.ActiveRing {
		return ring, fmt.Errorf("agent rollout ring %d is above active ring %d", ring, normalizedPolicy.ActiveRing)
	}

	return ring, nil
}

func ResolveInstallRolloutEffectiveActiveRing(ctx context.Context, policy UpdateRolloutPolicy) (int, UpdateRolloutHealthSnapshot, error) {
	normalizedPolicy, err := normalizeUpdateRolloutPolicy(policy)
	if err != nil {
		return 0, UpdateRolloutHealthSnapshot{}, err
	}

	effectiveRing := normalizedPolicy.ActiveRing
	snapshot := UpdateRolloutHealthSnapshot{}
	if !normalizedPolicy.HealthGateEnabled {
		snapshot.Healthy = true
		return effectiveRing, snapshot, nil
	}

	windowEnd := time.Now().UTC()
	windowStart := windowEnd.Add(-time.Duration(normalizedPolicy.HealthWindowMinutes) * time.Minute)

	var samples int
	var failures int
	err = DB.QueryRow(ctx, `
		SELECT
			COALESCE(COUNT(*) FILTER (WHERE status IN ('succeeded', 'failed')), 0) AS samples,
			COALESCE(COUNT(*) FILTER (WHERE status = 'failed'), 0) AS failures
		FROM agent_commands
		WHERE command_type = 'powershell'
		  AND payload ILIKE '%install_approved_updates%'
		  AND created_at >= $1
	`, windowStart).Scan(&samples, &failures)
	if err != nil {
		return 0, UpdateRolloutHealthSnapshot{}, fmt.Errorf("failed to resolve rollout health snapshot: %w", err)
	}

	snapshot = evaluateInstallRolloutHealthSnapshot(samples, failures, windowStart, windowEnd, normalizedPolicy)

	if snapshot.Healthy {
		return effectiveRing, snapshot, nil
	}

	if normalizedPolicy.AutoRollbackEnabled {
		reduced := effectiveRing - normalizedPolicy.AutoRollbackRingStep
		if reduced < 1 {
			reduced = 1
		}
		effectiveRing = reduced
		return effectiveRing, snapshot, nil
	}

	return 0, snapshot, fmt.Errorf("rollout health gate blocked installs: failure rate %.2f%% over %d sample(s)", snapshot.FailureRatePct, snapshot.Samples)
}

func evaluateInstallRolloutHealthSnapshot(samples, failures int, windowStart, windowEnd time.Time, policy UpdateRolloutPolicy) UpdateRolloutHealthSnapshot {
	snapshot := UpdateRolloutHealthSnapshot{
		WindowStart:      windowStart,
		WindowEnd:        windowEnd,
		Samples:          samples,
		Failures:         failures,
		Healthy:          true,
		EffectiveSamples: samples,
	}

	if snapshot.Samples <= 0 {
		snapshot.FailureRatePct = 0
		snapshot.Healthy = true
		return snapshot
	}

	if snapshot.Failures < 0 {
		snapshot.Failures = 0
	}
	if snapshot.Failures > snapshot.Samples {
		snapshot.Failures = snapshot.Samples
	}

	snapshot.FailureRatePct = (float64(snapshot.Failures) / float64(snapshot.Samples)) * 100
	if snapshot.Samples < policy.HealthMinSamples {
		snapshot.Healthy = true
		return snapshot
	}

	snapshot.Healthy = snapshot.FailureRatePct <= policy.HealthMaxFailureRatePct
	return snapshot
}

func isFalseLike(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}

func resolveRolloutGateState(policy UpdateRolloutPolicy, effectiveActiveRing int, health UpdateRolloutHealthSnapshot) string {
	if !policy.HealthGateEnabled {
		return "disabled"
	}
	if health.Healthy {
		return "healthy"
	}
	if policy.AutoRollbackEnabled && effectiveActiveRing < policy.ActiveRing {
		return "auto_rollback"
	}
	if !policy.AutoRollbackEnabled {
		return "blocked"
	}
	return "degraded"
}

func getUpdateRolloutPolicyOverride() (UpdateRolloutPolicy, bool) {
	updateRolloutPolicyOverrideMu.RLock()
	defer updateRolloutPolicyOverrideMu.RUnlock()
	if updateRolloutPolicyOverride == nil {
		return UpdateRolloutPolicy{}, false
	}
	return cloneUpdateRolloutPolicy(*updateRolloutPolicyOverride), true
}

func cloneUpdateRolloutPolicy(policy UpdateRolloutPolicy) UpdateRolloutPolicy {
	clone := policy
	if policy.AllowedManifestVersions != nil {
		clone.AllowedManifestVersions = append([]int(nil), policy.AllowedManifestVersions...)
	}
	return clone
}

func (policy UpdateRolloutPolicy) manifestTTLForAction(action string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "install_approved_updates":
		return time.Duration(policy.InstallApprovedTTLMinutes) * time.Minute, nil
	case "uninstall_patch_kb":
		return time.Duration(policy.UninstallPatchTTLMinutes) * time.Minute, nil
	default:
		return 0, fmt.Errorf("rollout policy does not define ttl for action %q", strings.TrimSpace(action))
	}
}

func VerifySignedUpdateManifest(manifest UpdateCommandManifest) error {
	normalized, err := normalizeUpdateManifest(manifest)
	if err != nil {
		return err
	}

	if !strings.EqualFold(strings.TrimSpace(manifest.SignatureScheme), "hmac-sha256") {
		return fmt.Errorf("unsupported signature scheme")
	}

	providedSig := strings.TrimSpace(manifest.Signature)
	if providedSig == "" {
		return fmt.Errorf("manifest signature is required")
	}

	signingKey, err := resolveUpdateManifestSigningKey()
	if err != nil {
		return err
	}

	payload, err := canonicalUpdateManifestPayload(normalized)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)

	rawProvided, decodeErr := base64.StdEncoding.DecodeString(providedSig)
	if decodeErr != nil {
		return fmt.Errorf("invalid manifest signature encoding")
	}
	if !hmac.Equal(rawProvided, expected) {
		return fmt.Errorf("manifest signature mismatch")
	}

	now := time.Now().UTC()
	if normalized.ExpiresAt.Before(now) {
		return fmt.Errorf("manifest expired")
	}

	return nil
}

func normalizeUpdateManifest(manifest UpdateCommandManifest) (UpdateCommandManifest, error) {
	if manifest.Version <= 0 {
		manifest.Version = updateManifestDefaultVersion
	}
	manifest.ManifestID = strings.TrimSpace(manifest.ManifestID)
	manifest.Action = strings.ToLower(strings.TrimSpace(manifest.Action))
	manifest.AgentID = strings.TrimSpace(manifest.AgentID)
	if manifest.PolicyVersion < 0 {
		return UpdateCommandManifest{}, fmt.Errorf("manifest policy_version must be >= 0")
	}
	if manifest.RolloutRing < 0 {
		return UpdateCommandManifest{}, fmt.Errorf("manifest rollout_ring must be >= 0")
	}
	manifest.RebootBehavior = strings.ToLower(strings.TrimSpace(manifest.RebootBehavior))
	manifest.IssuedBy = strings.TrimSpace(manifest.IssuedBy)

	if manifest.ManifestID == "" {
		manifest.ManifestID = fmt.Sprintf("upd-%d", time.Now().UTC().UnixNano())
	}
	if manifest.Action == "" {
		return UpdateCommandManifest{}, fmt.Errorf("manifest action is required")
	}
	if manifest.AgentID == "" {
		return UpdateCommandManifest{}, fmt.Errorf("manifest agent_id is required")
	}

	manifest.UpdateIDs = normalizeManifestStringList(manifest.UpdateIDs)
	manifest.KBIDs = normalizeManifestStringList(manifest.KBIDs)

	if manifest.IssuedAt.IsZero() {
		manifest.IssuedAt = time.Now().UTC()
	}
	if manifest.ExpiresAt.IsZero() {
		manifest.ExpiresAt = manifest.IssuedAt.Add(30 * time.Minute)
	}
	if !manifest.ExpiresAt.After(manifest.IssuedAt) {
		return UpdateCommandManifest{}, fmt.Errorf("manifest expires_at must be after issued_at")
	}

	manifest.Signature = ""
	manifest.SignatureScheme = ""

	return manifest, nil
}

func normalizeManifestStringList(items []string) []string {
	set := make(map[string]struct{}, len(items))
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, exists := set[value]; exists {
			continue
		}
		set[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func canonicalUpdateManifestPayload(manifest UpdateCommandManifest) ([]byte, error) {
	type canonical struct {
		Version        int       `json:"version"`
		PolicyVersion  int       `json:"policy_version,omitempty"`
		RolloutRing    int       `json:"rollout_ring,omitempty"`
		ManifestID     string    `json:"manifest_id"`
		Action         string    `json:"action"`
		AgentID        string    `json:"agent_id"`
		UpdateIDs      []string  `json:"update_ids,omitempty"`
		KBIDs          []string  `json:"kb_ids,omitempty"`
		RebootBehavior string    `json:"reboot_behavior,omitempty"`
		IssuedAt       time.Time `json:"issued_at"`
		ExpiresAt      time.Time `json:"expires_at"`
		IssuedBy       string    `json:"issued_by,omitempty"`
	}

	return json.Marshal(canonical{
		Version:        manifest.Version,
		PolicyVersion:  manifest.PolicyVersion,
		RolloutRing:    manifest.RolloutRing,
		ManifestID:     manifest.ManifestID,
		Action:         manifest.Action,
		AgentID:        manifest.AgentID,
		UpdateIDs:      manifest.UpdateIDs,
		KBIDs:          manifest.KBIDs,
		RebootBehavior: manifest.RebootBehavior,
		IssuedAt:       manifest.IssuedAt,
		ExpiresAt:      manifest.ExpiresAt,
		IssuedBy:       manifest.IssuedBy,
	})
}

func resolveUpdateManifestSigningKey() (string, error) {
	if value := strings.TrimSpace(os.Getenv("UPDATE_MANIFEST_SIGNING_KEY")); value != "" {
		return value, nil
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_JWT_SECRET")); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("update manifest signing key is not configured")
}
