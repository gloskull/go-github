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

func TestCreateInstallationToken_StatelessToken(t *testing.T) {
	// Installation tokens are opaque values: their length and internal structure
	// are determined by GitHub and must not be validated by the client.
	statelessToken := "ghs_" + strings.Repeat("eyJhbGciOiJSUzI1NiJ9.", 15) + "signature_blob_123-456_789"
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)

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
		}`, statelessToken, expiresAt.Format(time.RFC3339))
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

	if token.Token == nil || *token.Token != statelessToken {
		t.Fatalf("expected token %q, got %v", statelessToken, token.Token)
	}
	if len(*token.Token) <= 250 {
		t.Fatalf("expected a stateless token longer than 250 characters, got %d", len(*token.Token))
	}

	if token.ExpiresAt == nil || !token.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Expected expires_at %v, got %v", expiresAt, token.ExpiresAt)
	}

	if token.Permissions == nil || *token.Permissions.Issues != "write" {
		t.Errorf("Expected permissions.issues = 'write', got %v", token.Permissions)
	}
}

func TestTokenTransport_StatelessTokenAuthorizationHeader(t *testing.T) {
	statelessToken := "ghs_" + strings.Repeat("veryLongStatelessTokenPayloadPart_", 10)

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + statelessToken
		if authHeader != expectedAuth {
			http.Error(w, fmt.Sprintf("expected auth %s, got %s", expectedAuth, authHeader), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login": "octocat"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewTokenClient(context.Background(), statelessToken)
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

func TestInstallationToken_JSONMarshalRoundTrip(t *testing.T) {
	longToken := "ghs_" + strings.Repeat("eyJraWQiOiJhcHAtaW5zdGFsbGF0aW9uIn0.", 10) + "signature"
	original := InstallationToken{Token: &longToken}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded InstallationToken
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if decoded.Token == nil || *decoded.Token != longToken {
		t.Errorf("Token mismatch after round trip: got %v, want %q", decoded.Token, longToken)
	}
}

func TestTokenTransport_DifferentTokenTypes(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		expectedAuth string
	}{
		{name: "stateless installation token", token: "ghs_" + strings.Repeat("payload_", 40), expectedAuth: "Bearer ghs_" + strings.Repeat("payload_", 40)},
		{name: "legacy installation token", token: "ghs_16C7e42F292c6912E7710c838347Ae178B4a", expectedAuth: "Bearer ghs_16C7e42F292c6912E7710c838347Ae178B4a"},
		{name: "fine-grained personal access token", token: "github_pat_11AAAAAA_longFineGrainedPATstring12345", expectedAuth: "Bearer github_pat_11AAAAAA_longFineGrainedPATstring12345"},
		{name: "legacy personal access token", token: "40charactertokenhexstring0123456789abcdef", expectedAuth: "token 40charactertokenhexstring0123456789abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &TokenTransport{Token: tt.token, Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Get("Authorization"); got != tt.expectedAuth {
					t.Errorf("Authorization = %q, want %q", got, tt.expectedAuth)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
			})}
			req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
			if _, err := transport.RoundTrip(req); err != nil {
				t.Fatalf("RoundTrip failed: %v", err)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
