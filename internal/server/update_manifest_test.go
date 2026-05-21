package server

import (
	"strconv"
	"testing"
	"time"
)

func TestBuildAndVerifySignedUpdateManifest(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_SIGNING_KEY", "manifest-test-secret")

	manifest, err := BuildSignedUpdateManifest(UpdateCommandManifest{
		Action:         "install_approved_updates",
		AgentID:        "agent-123",
		UpdateIDs:      []string{"u2", "u1", "u1"},
		KBIDs:          []string{"KB6000001", "KB6000002"},
		RebootBehavior: "reboot_if_required",
		IssuedAt:       time.Now().UTC(),
		IssuedBy:       "unit-test",
	})
	if err != nil {
		t.Fatalf("BuildSignedUpdateManifest error: %v", err)
	}

	if manifest.Signature == "" {
		t.Fatalf("expected non-empty signature")
	}
	if manifest.SignatureScheme != "hmac-sha256" {
		t.Fatalf("expected hmac-sha256 signature scheme, got %q", manifest.SignatureScheme)
	}
	if len(manifest.UpdateIDs) != 2 || manifest.UpdateIDs[0] != "u1" || manifest.UpdateIDs[1] != "u2" {
		t.Fatalf("expected normalized deduplicated update_ids, got %#v", manifest.UpdateIDs)
	}

	if err := VerifySignedUpdateManifest(manifest); err != nil {
		t.Fatalf("VerifySignedUpdateManifest error: %v", err)
	}
}

func TestVerifySignedUpdateManifest_DetectsTamper(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_SIGNING_KEY", "manifest-test-secret")

	manifest, err := BuildSignedUpdateManifest(UpdateCommandManifest{
		Action:   "uninstall_patch_kb",
		AgentID:  "agent-123",
		KBIDs:    []string{"KB6000001"},
		IssuedAt: time.Now().UTC(),
		IssuedBy: "unit-test",
	})
	if err != nil {
		t.Fatalf("BuildSignedUpdateManifest error: %v", err)
	}

	manifest.KBIDs = []string{"KB9999999"}
	if err := VerifySignedUpdateManifest(manifest); err == nil {
		t.Fatalf("expected tampered manifest to fail verification")
	}
}

func TestVerifySignedUpdateManifest_Expired(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_SIGNING_KEY", "manifest-test-secret")

	issuedAt := time.Now().UTC().Add(-2 * time.Hour)
	manifest, err := BuildSignedUpdateManifest(UpdateCommandManifest{
		Action:    "install_approved_updates",
		AgentID:   "agent-123",
		UpdateIDs: []string{"u1"},
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(10 * time.Minute),
		IssuedBy:  "unit-test",
	})
	if err != nil {
		t.Fatalf("BuildSignedUpdateManifest error: %v", err)
	}

	if err := VerifySignedUpdateManifest(manifest); err == nil {
		t.Fatalf("expected expired manifest to fail verification")
	}
}

func TestResolveUpdateRolloutPolicy_Defaults(t *testing.T) {
	t.Setenv("UPDATE_ROLLOUT_POLICY_JSON", "")
	t.Setenv("UPDATE_ROLLOUT_POLICY_VERSION", "")

	policy, err := ResolveUpdateRolloutPolicy()
	if err != nil {
		t.Fatalf("ResolveUpdateRolloutPolicy error: %v", err)
	}

	if policy.PolicyVersion != 1 {
		t.Fatalf("expected default policy version 1, got %d", policy.PolicyVersion)
	}
	if policy.DefaultManifestVersion != 1 {
		t.Fatalf("expected default manifest version 1, got %d", policy.DefaultManifestVersion)
	}
	if len(policy.AllowedManifestVersions) != 1 || policy.AllowedManifestVersions[0] != 1 {
		t.Fatalf("unexpected allowed manifest versions: %#v", policy.AllowedManifestVersions)
	}
}

func TestResolveUpdateRolloutPolicy_FromEnv(t *testing.T) {
	t.Setenv("UPDATE_ROLLOUT_POLICY_JSON", `{"policy_version":2,"default_manifest_version":2,"allowed_manifest_versions":[1,2],"install_approved_ttl_minutes":15,"uninstall_patch_kb_ttl_minutes":20}`)
	t.Setenv("UPDATE_ROLLOUT_POLICY_VERSION", "")

	policy, err := ResolveUpdateRolloutPolicy()
	if err != nil {
		t.Fatalf("ResolveUpdateRolloutPolicy error: %v", err)
	}

	if policy.PolicyVersion != 2 {
		t.Fatalf("expected policy version 2, got %d", policy.PolicyVersion)
	}
	if policy.DefaultManifestVersion != 2 {
		t.Fatalf("expected default manifest version 2, got %d", policy.DefaultManifestVersion)
	}
	if len(policy.AllowedManifestVersions) != 2 || policy.AllowedManifestVersions[0] != 1 || policy.AllowedManifestVersions[1] != 2 {
		t.Fatalf("unexpected allowed manifest versions: %#v", policy.AllowedManifestVersions)
	}
}

func TestValidateUpdateManifestAgainstRolloutPolicy_RejectsVersion(t *testing.T) {
	policy := UpdateRolloutPolicy{
		PolicyVersion:             3,
		DefaultManifestVersion:    3,
		AllowedManifestVersions:   []int{3},
		InstallApprovedTTLMinutes: 30,
		UninstallPatchTTLMinutes:  30,
	}

	now := time.Now().UTC()
	err := ValidateUpdateManifestAgainstRolloutPolicy(UpdateCommandManifest{
		Version:       1,
		PolicyVersion: 3,
		Action:        "install_approved_updates",
		AgentID:       "agent-1",
		IssuedAt:      now,
		ExpiresAt:     now.Add(20 * time.Minute),
	}, policy)
	if err == nil {
		t.Fatalf("expected manifest version rejection")
	}
}

func TestValidateUpdateManifestAgainstRolloutPolicy_RejectsTTL(t *testing.T) {
	policy := UpdateRolloutPolicy{
		PolicyVersion:             1,
		DefaultManifestVersion:    1,
		AllowedManifestVersions:   []int{1},
		InstallApprovedTTLMinutes: 10,
		UninstallPatchTTLMinutes:  10,
	}

	now := time.Now().UTC()
	err := ValidateUpdateManifestAgainstRolloutPolicy(UpdateCommandManifest{
		Version:       1,
		PolicyVersion: 1,
		Action:        "install_approved_updates",
		AgentID:       "agent-1",
		IssuedAt:      now,
		ExpiresAt:     now.Add(25 * time.Minute),
	}, policy)
	if err == nil {
		t.Fatalf("expected ttl rejection")
	}
}

func TestValidateAgentUpdateRolloutStage_DeterministicRing(t *testing.T) {
	policy := UpdateRolloutPolicy{RingCount: 4, ActiveRing: 4, RingSalt: "seed-a"}

	first, err := ValidateAgentUpdateRolloutStage("agent-123", "install_approved_updates", policy)
	if err != nil {
		t.Fatalf("ValidateAgentUpdateRolloutStage error: %v", err)
	}
	second, err := ValidateAgentUpdateRolloutStage("agent-123", "install_approved_updates", policy)
	if err != nil {
		t.Fatalf("ValidateAgentUpdateRolloutStage error: %v", err)
	}
	if first != second {
		t.Fatalf("expected deterministic ring assignment, got %d and %d", first, second)
	}
	if first < 1 || first > 4 {
		t.Fatalf("expected ring in 1..4, got %d", first)
	}
}

func TestValidateAgentUpdateRolloutStage_BlocksInstallOutsideActiveRing(t *testing.T) {
	policy := UpdateRolloutPolicy{RingCount: 4, ActiveRing: 1, RingSalt: "seed-b"}

	blocked := false
	for i := 0; i < 1024; i++ {
		agentID := "agent-" + strconv.Itoa(i)
		ring, err := ValidateAgentUpdateRolloutStage(agentID, "install_approved_updates", policy)
		if err != nil {
			if ring <= 1 {
				t.Fatalf("expected blocked ring to be >1, got %d", ring)
			}
			blocked = true
			break
		}
	}

	if !blocked {
		t.Fatalf("expected at least one install agent to be blocked by active ring")
	}
}

func TestValidateAgentUpdateRolloutStage_UninstallNotBlockedByRing(t *testing.T) {
	policy := UpdateRolloutPolicy{RingCount: 4, ActiveRing: 1, RingSalt: "seed-c"}

	ring, err := ValidateAgentUpdateRolloutStage("agent-very-likely-high-ring", "uninstall_patch_kb", policy)
	if err != nil {
		t.Fatalf("did not expect uninstall stage gating error, got: %v", err)
	}
	if ring < 1 || ring > 4 {
		t.Fatalf("expected ring in 1..4, got %d", ring)
	}
}

func TestValidateUpdateManifestAgainstRolloutPolicy_RejectsMismatchedRing(t *testing.T) {
	policy := UpdateRolloutPolicy{
		PolicyVersion:             1,
		DefaultManifestVersion:    1,
		AllowedManifestVersions:   []int{1},
		InstallApprovedTTLMinutes: 30,
		UninstallPatchTTLMinutes:  30,
		RingCount:                 4,
		ActiveRing:                4,
		RingSalt:                  "seed-d",
	}

	now := time.Now().UTC()
	err := ValidateUpdateManifestAgainstRolloutPolicy(UpdateCommandManifest{
		Version:       1,
		PolicyVersion: 1,
		RolloutRing:   4,
		Action:        "install_approved_updates",
		AgentID:       "agent-123",
		IssuedAt:      now,
		ExpiresAt:     now.Add(10 * time.Minute),
	}, policy)
	if err == nil {
		t.Fatalf("expected mismatched ring rejection")
	}
}

func TestEvaluateInstallRolloutHealthSnapshot_InsufficientSamplesHealthy(t *testing.T) {
	policy := UpdateRolloutPolicy{
		HealthMinSamples:        5,
		HealthMaxFailureRatePct: 20,
	}

	now := time.Now().UTC()
	snapshot := evaluateInstallRolloutHealthSnapshot(3, 3, now.Add(-30*time.Minute), now, policy)
	if !snapshot.Healthy {
		t.Fatalf("expected healthy snapshot when samples below minimum")
	}
	if snapshot.FailureRatePct != 100 {
		t.Fatalf("expected failure rate 100, got %.2f", snapshot.FailureRatePct)
	}
}

func TestEvaluateInstallRolloutHealthSnapshot_ThresholdExceededUnhealthy(t *testing.T) {
	policy := UpdateRolloutPolicy{
		HealthMinSamples:        5,
		HealthMaxFailureRatePct: 20,
	}

	now := time.Now().UTC()
	snapshot := evaluateInstallRolloutHealthSnapshot(10, 3, now.Add(-30*time.Minute), now, policy)
	if snapshot.Healthy {
		t.Fatalf("expected unhealthy snapshot when failure rate exceeds threshold")
	}
	if snapshot.FailureRatePct != 30 {
		t.Fatalf("expected failure rate 30, got %.2f", snapshot.FailureRatePct)
	}
}

func TestEvaluateInstallRolloutHealthSnapshot_WithinThresholdHealthy(t *testing.T) {
	policy := UpdateRolloutPolicy{
		HealthMinSamples:        5,
		HealthMaxFailureRatePct: 40,
	}

	now := time.Now().UTC()
	snapshot := evaluateInstallRolloutHealthSnapshot(10, 4, now.Add(-30*time.Minute), now, policy)
	if !snapshot.Healthy {
		t.Fatalf("expected healthy snapshot at threshold")
	}
	if snapshot.FailureRatePct != 40 {
		t.Fatalf("expected failure rate 40, got %.2f", snapshot.FailureRatePct)
	}
}

func TestUpdateRolloutPolicyOverride_SetGetClear(t *testing.T) {
	ClearUpdateRolloutPolicyOverride()
	t.Cleanup(ClearUpdateRolloutPolicyOverride)

	policy, err := SetUpdateRolloutPolicyOverride(UpdateRolloutPolicy{
		PolicyVersion:             7,
		DefaultManifestVersion:    2,
		AllowedManifestVersions:   []int{1, 2},
		InstallApprovedTTLMinutes: 20,
		UninstallPatchTTLMinutes:  15,
		RingCount:                 4,
		ActiveRing:                2,
		RingSalt:                  "override-seed",
		HealthGateEnabled:         true,
		HealthWindowMinutes:       60,
		HealthMinSamples:          3,
		HealthMaxFailureRatePct:   30,
		AutoRollbackEnabled:       true,
		AutoRollbackRingStep:      1,
	})
	if err != nil {
		t.Fatalf("SetUpdateRolloutPolicyOverride error: %v", err)
	}
	if policy.PolicyVersion != 7 {
		t.Fatalf("expected policy version 7, got %d", policy.PolicyVersion)
	}

	got, ok := GetUpdateRolloutPolicyOverride()
	if !ok {
		t.Fatalf("expected override to be present")
	}
	if got.ActiveRing != 2 {
		t.Fatalf("expected active ring 2, got %d", got.ActiveRing)
	}

	ClearUpdateRolloutPolicyOverride()
	_, ok = GetUpdateRolloutPolicyOverride()
	if ok {
		t.Fatalf("expected override to be cleared")
	}
}

func TestResolveRolloutGateState(t *testing.T) {
	policy := UpdateRolloutPolicy{HealthGateEnabled: false, ActiveRing: 4, AutoRollbackEnabled: true}
	state := resolveRolloutGateState(policy, 4, UpdateRolloutHealthSnapshot{Healthy: true})
	if state != "disabled" {
		t.Fatalf("expected disabled state, got %q", state)
	}

	policy = UpdateRolloutPolicy{HealthGateEnabled: true, ActiveRing: 4, AutoRollbackEnabled: true}
	state = resolveRolloutGateState(policy, 4, UpdateRolloutHealthSnapshot{Healthy: true})
	if state != "healthy" {
		t.Fatalf("expected healthy state, got %q", state)
	}

	state = resolveRolloutGateState(policy, 2, UpdateRolloutHealthSnapshot{Healthy: false})
	if state != "auto_rollback" {
		t.Fatalf("expected auto_rollback state, got %q", state)
	}

	policy.AutoRollbackEnabled = false
	state = resolveRolloutGateState(policy, 4, UpdateRolloutHealthSnapshot{Healthy: false})
	if state != "blocked" {
		t.Fatalf("expected blocked state, got %q", state)
	}

	policy.AutoRollbackEnabled = true
	state = resolveRolloutGateState(policy, 4, UpdateRolloutHealthSnapshot{Healthy: false})
	if state != "degraded" {
		t.Fatalf("expected degraded state, got %q", state)
	}
}
