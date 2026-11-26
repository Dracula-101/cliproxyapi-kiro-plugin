package kiro

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// Google / GitHub sign-in through Kiro's own portal, the way kiro-cli does it:
//
//	open      https://app.kiro.dev/signin?state&code_challenge&redirect_uri=http://localhost:3128&redirect_from=kirocli
//	callback  http://localhost:3128/oauth/callback?login_option=google&code=…&state=…
//	exchange  POST https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token {code, code_verifier, redirect_uri}
//
// The auth service only accepts allowlisted loopback redirects, so on a remote server the
// browser lands on a dead localhost page; the user pastes that address into the panel, the
// host stores it as the callback "code", and the poll below finishes the exchange.
const (
	providerKiroBuilderID = "kiro-builder-id"
	socialAuthMethod      = "social"
	socialFlow            = "social"
	kiroPortalSignInURL   = "https://app.kiro.dev/signin"
	kiroSocialTokenURL    = "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token"
	kiroCLIUserAgent      = "Kiro-CLI"
	socialRedirectBase    = "http://localhost:3128"
	socialLoginTTL        = 10 * time.Minute
)

//go:embed logo.svg
var logoSVG []byte

var kiroLogo = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(logoSVG)

// Cognito-allowlisted loopback ports (kiro-cli oauth_callback.rs CALLBACK_PORTS).
var socialCallbackPorts = map[string]bool{
	"3128": true, "4649": true, "6588": true, "8008": true, "9091": true,
	"49153": true, "50153": true, "51153": true, "52153": true, "53153": true,
}

var socialCallbackPaths = map[string]bool{"/oauth/callback": true, "/signin/callback": true}

var socialProviders = map[string]string{"google": "Google", "github": "Github"}

var socialStatePattern = regexp.MustCompile(`^kiro-[0-9a-f]{32}$`)

type authIdentifierResponse struct {
	Identifier          string                        `json:"identifier"`
	CredentialProviders []string                      `json:"credential_providers,omitempty"`
	Entries             []pluginapi.AuthProviderEntry `json:"entries,omitempty"`
}

func authIdentifier() authIdentifierResponse {
	return authIdentifierResponse{
		Identifier:          providerKiro,
		CredentialProviders: []string{providerKiro},
		Entries: []pluginapi.AuthProviderEntry{
			{Identifier: providerKiro, Name: "Kiro (Google / GitHub)", Logo: kiroLogo},
			{Identifier: providerKiroBuilderID, Name: "Kiro (Builder ID)", Logo: kiroLogo},
		},
	}
}

func startSocialLogin() ([]byte, error) {
	verifier, errVerifier := pkceVerifier()
	if errVerifier != nil {
		return nil, errVerifier
	}
	challenge := sha256.Sum256([]byte(verifier))
	state := "kiro-" + randomHexN(16)
	query := url.Values{
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"redirect_uri":          {socialRedirectBase},
		"redirect_from":         {"kirocli"},
	}
	return wire.OK(pluginapi.AuthLoginStartResponse{
		Provider:  providerKiro,
		URL:       kiroPortalSignInURL + "?" + query.Encode(),
		State:     state,
		ExpiresAt: time.Now().Add(socialLoginTTL),
		Metadata:  map[string]any{"flow": socialFlow, "codeVerifier": verifier},
	})
}

func pollSocialLogin(req authLoginPollRequest) ([]byte, error) {
	fail := func(message string) ([]byte, error) {
		return wire.OK(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: message})
	}
	verifier := metaString(req.Metadata, "codeVerifier")
	if verifier == "" {
		return fail("login session is missing its PKCE verifier")
	}
	callback, found, errRead := takeSocialCallback(req.Host.AuthDir, req.State)
	if errRead != nil {
		return fail(errRead.Error())
	}
	if !found {
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "waiting for the callback URL",
		})
	}
	if callback.Error != "" {
		return fail("Kiro sign-in failed: " + callback.Error)
	}
	redirectURI, code, provider, errParse := parseSocialCallback(callback.Code, req.State)
	if errParse != nil {
		return fail(errParse.Error())
	}
	token, errExchange := exchangeSocialCode(req.HostCallbackID, code, verifier, redirectURI)
	if errExchange != nil {
		return fail(errExchange.Error())
	}
	expiresIn := token.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultExpiresInSeconds
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	return wire.OK(credentialSuccess(kiroCredential{
		Type:         providerKiro,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ProfileArn:   token.ProfileArn,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		AuthMethod:   socialAuthMethod,
		Provider:     provider,
		Region:       defaultKiroRegion,
	}, expiresAt, "Kiro ("+provider+")"))
}

type socialCallbackFile struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error"`
}

// takeSocialCallback reads and removes the callback file the host writes for a pasted URL.
func takeSocialCallback(authDir, state string) (socialCallbackFile, bool, error) {
	var out socialCallbackFile
	if !socialStatePattern.MatchString(state) {
		return out, false, errors.New("login session has an invalid state")
	}
	if strings.TrimSpace(authDir) == "" {
		return out, false, nil
	}
	path := filepath.Join(authDir, ".oauth-"+providerKiro+"-"+state+".oauth")
	raw, errRead := os.ReadFile(path)
	if errors.Is(errRead, os.ErrNotExist) {
		return out, false, nil
	}
	if errRead != nil {
		return out, false, fmt.Errorf("read callback: %w", errRead)
	}
	_ = os.Remove(path)
	if errUnmarshal := json.Unmarshal(raw, &out); errUnmarshal != nil {
		return out, false, fmt.Errorf("decode callback: %w", errUnmarshal)
	}
	return out, true, nil
}

// parseSocialCallback takes the whole pasted callback address and rebuilds the redirect_uri
// kiro-cli sends to /oauth/token (it must match exactly, login_option included).
func parseSocialCallback(raw, state string) (redirectURI, code, provider string, err error) {
	pasteHint := errors.New("paste the whole address from the browser's address bar (it starts with " + socialRedirectBase + "/oauth/callback)")
	u, errParse := url.Parse(strings.TrimSpace(raw))
	if errParse != nil || u.Scheme != "http" {
		return "", "", "", pasteHint
	}
	if host := u.Hostname(); host != "localhost" && host != "127.0.0.1" {
		return "", "", "", pasteHint
	}
	if !socialCallbackPorts[u.Port()] || !socialCallbackPaths[u.Path] {
		return "", "", "", pasteHint
	}
	query := u.Query()
	if query.Get("state") != state {
		return "", "", "", errors.New("the callback belongs to a different sign-in; start again")
	}
	option := strings.ToLower(strings.TrimSpace(query.Get("login_option")))
	provider, ok := socialProviders[option]
	if !ok {
		if option == "builderid" || option == "awsidc" {
			return "", "", "", errors.New("Builder ID and IAM Identity Center accounts sign in through the Kiro (Builder ID) tile")
		}
		return "", "", "", fmt.Errorf("unsupported Kiro sign-in option %q", option)
	}
	code = strings.TrimSpace(query.Get("code"))
	if code == "" {
		return "", "", "", pasteHint
	}
	redirectURI = "http://localhost:" + u.Port() + u.Path + "?login_option=" + url.QueryEscape(option)
	return redirectURI, code, provider, nil
}

func exchangeSocialCode(callbackID, code, verifier, redirectURI string) (*kiroRefreshResponse, error) {
	body, errMarshal := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  redirectURI,
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
		HostCallbackID: callbackID,
		Method:         http.MethodPost,
		URL:            kiroSocialTokenURL,
		Headers:        map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {kiroCLIUserAgent}},
		Body:           body,
	})
	if errDo != nil {
		return nil, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}
	var out kiroRefreshResponse
	if errUnmarshal := json.Unmarshal(resp.Body, &out); errUnmarshal != nil {
		return nil, fmt.Errorf("decode token exchange response: %w", errUnmarshal)
	}
	if out.AccessToken == "" || out.ProfileArn == "" {
		return nil, errors.New("token exchange response missing accessToken/profileArn")
	}
	return &out, nil
}

func pkceVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
