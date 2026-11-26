package kiro

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
)

func TestStartSocialLoginOpensKiroPortal(t *testing.T) {
	raw, err := startKiroLogin([]byte(`{"Provider":"kiro"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeLoginStart(t, raw)
	u, errParse := url.Parse(resp.URL)
	if errParse != nil || u.Host != "app.kiro.dev" || u.Path != "/signin" {
		t.Fatalf("unexpected portal URL %q", resp.URL)
	}
	q := u.Query()
	if q.Get("redirect_uri") != "http://localhost:3128" || q.Get("redirect_from") != "kirocli" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("unexpected portal query %v", q)
	}
	if q.Get("state") != resp.State || !socialStatePattern.MatchString(resp.State) {
		t.Fatalf("state %q not usable as host oauth state", resp.State)
	}
	if resp.Metadata["flow"] != socialFlow || resp.Metadata["codeVerifier"] == "" {
		t.Fatalf("metadata missing social context: %v", resp.Metadata)
	}
}

func TestParseSocialCallback(t *testing.T) {
	state := "kiro-" + strings.Repeat("a", 32)
	cases := []struct {
		raw, redirect, provider, errPart string
	}{
		{"http://localhost:3128/oauth/callback?login_option=google&code=c1&state=" + state, "http://localhost:3128/oauth/callback?login_option=google", "Google", ""},
		{"http://127.0.0.1:49153/signin/callback?login_option=GitHub&code=c1&state=" + state, "http://localhost:49153/signin/callback?login_option=github", "Github", ""},
		{"c1", "", "", "paste the whole address"},
		{"http://localhost:9999/oauth/callback?login_option=google&code=c1&state=" + state, "", "", "paste the whole address"},
		{"http://evil.example:3128/oauth/callback?login_option=google&code=c1&state=" + state, "", "", "paste the whole address"},
		{"http://localhost:3128/oauth/callback?login_option=google&code=c1&state=kiro-other", "", "", "different sign-in"},
		{"http://localhost:3128/oauth/callback?login_option=builderid&code=c1&state=" + state, "", "", "Builder ID"},
	}
	for _, tc := range cases {
		redirect, code, provider, err := parseSocialCallback(tc.raw, state)
		if tc.errPart != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errPart) {
				t.Errorf("%s: want error containing %q, got %v", tc.raw, tc.errPart, err)
			}
			continue
		}
		if err != nil || redirect != tc.redirect || code != "c1" || provider != tc.provider {
			t.Errorf("%s: got (%q,%q,%q,%v)", tc.raw, redirect, code, provider, err)
		}
	}
}

func TestPollSocialLoginExchangesPastedCallback(t *testing.T) {
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	var exchangeBody map[string]string
	var userAgent string
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		if req.URL != kiroSocialTokenURL {
			t.Fatalf("unexpected URL %s", req.URL)
		}
		userAgent = req.Headers["User-Agent"][0]
		_ = json.Unmarshal(req.Body, &exchangeBody)
		return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"accessToken":"at","refreshToken":"rt","profileArn":"arn:aws:codewhisperer:us-east-1:1:profile/X","expiresIn":3600}`)}, nil
	}

	dir := t.TempDir()
	state := "kiro-" + strings.Repeat("b", 32)
	poll := func() pluginapi.AuthLoginPollResponse {
		req, _ := json.Marshal(map[string]any{
			"State":    state,
			"Host":     map[string]any{"AuthDir": dir},
			"Metadata": map[string]any{"flow": socialFlow, "codeVerifier": "verifier-1"},
		})
		raw, err := pollKiroLogin(req)
		if err != nil {
			t.Fatal(err)
		}
		return decodeLoginPoll(t, raw)
	}

	if got := poll(); got.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("want pending before callback, got %+v", got)
	}

	pasted := "http://localhost:3128/oauth/callback?login_option=google&code=the-code&state=" + state
	file := filepath.Join(dir, ".oauth-kiro-"+state+".oauth")
	payload, _ := json.Marshal(map[string]string{"code": pasted, "state": state})
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	got := poll()
	if got.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("want success, got %+v", got)
	}
	if exchangeBody["code"] != "the-code" || exchangeBody["code_verifier"] != "verifier-1" ||
		exchangeBody["redirect_uri"] != "http://localhost:3128/oauth/callback?login_option=google" {
		t.Fatalf("unexpected exchange body %v", exchangeBody)
	}
	if userAgent != kiroCLIUserAgent {
		t.Fatalf("unexpected user agent %q", userAgent)
	}
	var cred kiroCredential
	if err := json.Unmarshal(got.Auth.StorageJSON, &cred); err != nil {
		t.Fatal(err)
	}
	if cred.AuthMethod != "social" || cred.Provider != "Google" || cred.RefreshToken != "rt" || cred.ProfileArn == "" {
		t.Fatalf("unexpected credential %+v", cred)
	}
	if got.Auth.Provider != providerKiro {
		t.Fatalf("auth provider %q", got.Auth.Provider)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("callback file should be consumed")
	}
}

func TestAuthIdentifierDeclaresBothTiles(t *testing.T) {
	resp := authIdentifier()
	if resp.Identifier != providerKiro || len(resp.Entries) != 2 ||
		resp.Entries[1].Identifier != providerKiroBuilderID || !strings.HasPrefix(resp.Entries[0].Logo, "data:image/svg+xml;base64,") {
		t.Fatalf("unexpected identifier response %+v", resp)
	}
}
