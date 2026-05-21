package auth

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GenerateToken
// ---------------------------------------------------------------------------

func TestGenerateToken_RequiresSecret(t *testing.T) {
	_, err := GenerateToken("subject", "agent", "", time.Minute)
	if err == nil {
		t.Fatal("expected error when secret is empty")
	}
}

func TestGenerateToken_RequiresSubject(t *testing.T) {
	_, err := GenerateToken("", "agent", "my-secret", time.Minute)
	if err == nil {
		t.Fatal("expected error when subject is empty")
	}
}

func TestGenerateToken_RoleCanBeEmpty(t *testing.T) {
	token, err := GenerateToken("subject", "", "my-secret", time.Minute)
	if err != nil {
		t.Fatalf("unexpected error with empty role: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestGenerateToken_ProducesValidJWT(t *testing.T) {
	token, err := GenerateToken("agent-123", "agent", "test-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if len(token) < 20 {
		t.Fatalf("token looks too short: %q", token)
	}
}

// ---------------------------------------------------------------------------
// ParseAndValidate
// ---------------------------------------------------------------------------

func TestParseAndValidate_RequiresSecret(t *testing.T) {
	token, _ := GenerateToken("sub", "agent", "test-secret", time.Hour)
	_, err := ParseAndValidate(token, "")
	if err == nil {
		t.Fatal("expected error when secret is empty")
	}
}

func TestParseAndValidate_ValidToken(t *testing.T) {
	const secret = "unit-test-secret"
	token, err := GenerateToken("user-42", "admin", secret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	claims, err := ParseAndValidate(token, secret)
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if claims.Subject != "user-42" {
		t.Errorf("expected subject 'user-42', got %q", claims.Subject)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role 'admin', got %q", claims.Role)
	}
}

func TestParseAndValidate_WrongSecret(t *testing.T) {
	token, _ := GenerateToken("sub", "agent", "correct-secret", time.Hour)
	_, err := ParseAndValidate(token, "wrong-secret")
	if err == nil {
		t.Fatal("expected error with wrong secret")
	}
}

func TestParseAndValidate_ExpiredToken(t *testing.T) {
	token, err := GenerateToken("sub", "agent", "test-secret", -1*time.Second)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	_, err = ParseAndValidate(token, "test-secret")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseAndValidate_MalformedToken(t *testing.T) {
	_, err := ParseAndValidate("not.a.valid.jwt", "any-secret")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestParseAndValidate_EmptyToken(t *testing.T) {
	_, err := ParseAndValidate("", "any-secret")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestGenerateAndParse_RoundTrip(t *testing.T) {
	cases := []struct {
		subject string
		role    string
		secret  string
	}{
		{"agent-abc", "agent", "secret-1"},
		{"admin-user", "admin", "secret-2"},
		{"scheduler", "scheduler", "long-secret-value-for-testing"},
	}

	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			token, err := GenerateToken(tc.subject, tc.role, tc.secret, time.Hour)
			if err != nil {
				t.Fatalf("GenerateToken error: %v", err)
			}
			claims, err := ParseAndValidate(token, tc.secret)
			if err != nil {
				t.Fatalf("ParseAndValidate error: %v", err)
			}
			if claims.Subject != tc.subject {
				t.Errorf("subject: got %q, want %q", claims.Subject, tc.subject)
			}
			if claims.Role != tc.role {
				t.Errorf("role: got %q, want %q", claims.Role, tc.role)
			}
		})
	}
}
