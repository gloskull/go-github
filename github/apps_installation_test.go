package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateInstallationToken(t *testing.T) {
	for _, token := range []string{
		"ghs_16C7e42F292c6912E7710c838347Ae178B4a",
		"ghs-v2:signature~blob!123-456_789",
		strings.Repeat("A", 4096),
	} {
		if err := ValidateInstallationToken(token); err != nil {
			t.Errorf("ValidateInstallationToken(%q) returned an error: %v", token, err)
		}
	}

	if err := ValidateInstallationToken(""); err == nil {
		t.Error("ValidateInstallationToken(\"\") returned nil, want an error")
	}
}

func TestCreateInstallationToken_PreservesOpaqueToken(t *testing.T) {
	tokens := map[string]string{
		"legacy":    "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
		"stateless": "ghs-v2:" + strings.Repeat("eyJhbGciOiJSUzI1NiJ9.", 15) + "signature~blob!123-456_789",
	}
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)

	for name, accessToken := range tokens {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/app/installations/12345/access_tokens", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{
			"token": %q,
			"expires_at": %q,
			"permissions": {"issues": "write", "contents": "read"},
			"repository_selection": "all"
				}`, accessToken, expiresAt.Format(time.RFC3339))
			})

			server := httptest.NewServer(mux)
			defer server.Close()

			client := NewClient(nil)
			client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

			token, resp, err := client.Apps.CreateInstallationToken(context.Background(), 12345, &InstallationTokenOptions{})
			if err != nil {
				t.Fatalf("CreateInstallationToken returned error: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status 200, got %d", resp.StatusCode)
			}

			if token.Token == nil || *token.Token != accessToken {
				t.Errorf("Expected token %q, got %v", accessToken, token.Token)
			}

			if token.ExpiresAt == nil || !token.ExpiresAt.Equal(expiresAt) {
				t.Errorf("Expected expires_at %v, got %v", expiresAt, token.ExpiresAt)
			}

			if token.Permissions == nil || *token.Permissions.Issues != "write" {
				t.Errorf("Expected permissions.issues = 'write', got %v", token.Permissions)
			}
		})
	}
}

func TestTokenTransport_StatelessTokenAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		expectedAuth string
	}{
		{
			name:         "stateless installation token",
			token:        "ghs_" + strings.Repeat("veryLongStatelessTokenPayloadPart_", 10),
			expectedAuth: "Bearer " + "ghs_" + strings.Repeat("veryLongStatelessTokenPayloadPart_", 10),
		},
		{
			name:         "classic personal access token",
			token:        "40charactertokenhexstring0123456789abcdef",
			expectedAuth: "token 40charactertokenhexstring0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
				if authHeader := r.Header.Get("Authorization"); authHeader != tt.expectedAuth {
					http.Error(w, fmt.Sprintf("expected auth %q, got %q", tt.expectedAuth, authHeader), http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"login": "octocat"}`)
			})

			server := httptest.NewServer(mux)
			defer server.Close()

			client := NewTokenClient(context.Background(), tt.token)
			client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

			req, err := client.NewRequest("GET", "user", nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}

			var user map[string]interface{}
			resp, err := client.Do(context.Background(), req, &user)
			if err != nil {
				t.Fatalf("Do failed: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}
			if user["login"] != "octocat" {
				t.Errorf("Expected login 'octocat', got %v", user["login"])
			}
		})
	}
}

func TestInstallationToken_JSONUnmarshal(t *testing.T) {
	longToken := "ghs_" + strings.Repeat("A1b2C3d4-", 40)
	rawJSON := fmt.Sprintf(`{
		"token": %q,
		"expires_at": "2030-01-01T00:00:00Z",
		"repositories": [{"id": 1, "name": "test-repo"}]
	}`, longToken)

	var it InstallationToken
	if err := json.Unmarshal([]byte(rawJSON), &it); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if it.Token == nil || *it.Token != longToken {
		t.Errorf("Token mismatch: got %v, want %q", it.Token, longToken)
	}
	if len(it.Repositories) != 1 || *it.Repositories[0].Name != "test-repo" {
		t.Errorf("Repositories mismatch: got %v", it.Repositories)
	}
}
