package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AuthTestResult represents the result of an authentication test
type AuthTestResult struct {
	TestType     string                 `json:"test_type"`
	Vulnerable   bool                   `json:"vulnerable"`
	Details      string                 `json:"details"`
	Evidence     map[string]interface{} `json:"evidence,omitempty"`
	Risk         string                 `json:"risk"`
	Endpoint     string                 `json:"endpoint"`
	Method       string                 `json:"method"`
	StatusCode   int                    `json:"status_code"`
	ResponseSize int                    `json:"response_size"`
}

// JWTTestConfig holds configuration for JWT testing
type JWTTestConfig struct {
	Token           string
	SecretWordlist  []string
	AlgorithmTests  bool
	ExpirationTests bool
}

// APIKeyTestConfig holds configuration for API key testing
type APIKeyTestConfig struct {
	Key             string
	HeaderName      string
	QueryParamName  string
	WeakKeyPatterns []string
}

// SessionTestConfig holds configuration for session testing
type SessionTestConfig struct {
	SessionID      string
	CookieName     string
	FixationTests  bool
	HijackingTests bool
}

// AuthTester performs various authentication and authorization tests
type AuthTester struct {
	client *http.Client
}

// NewAuthTester creates a new authentication tester
func NewAuthTester(client *http.Client) *AuthTester {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &AuthTester{client: client}
}

// TestJWT performs comprehensive JWT security tests
func (a *AuthTester) TestJWT(config JWTTestConfig, endpoint, method string) []AuthTestResult {
	var results []AuthTestResult

	if config.Token == "" {
		return results
	}

	// Parse JWT token
	parts := strings.Split(config.Token, ".")
	if len(parts) != 3 {
		return results
	}

	// Test 1: Algorithm None Attack
	if config.AlgorithmTests {
		result := a.testJWTAlgorithmNone(config.Token, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 2: Algorithm Confusion (HS256 vs RS256)
	if config.AlgorithmTests {
		result := a.testJWTAlgorithmConfusion(config.Token, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 3: Weak Secret Brute Force
	if len(config.SecretWordlist) > 0 {
		result := a.testJWTWeakSecret(config.Token, config.SecretWordlist, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 4: Expiration Bypass
	if config.ExpirationTests {
		result := a.testJWTExpirationBypass(config.Token, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 5: Invalid Signature
	result := a.testJWTInvalidSignature(config.Token, endpoint, method)
	if result != nil {
		results = append(results, *result)
	}

	return results
}

// testJWTAlgorithmNone tests for algorithm none vulnerability
func (a *AuthTester) testJWTAlgorithmNone(token, endpoint, method string) *AuthTestResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode header
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return nil
	}

	// Change algorithm to none
	headerMap["alg"] = "none"
	newHeader, _ := json.Marshal(headerMap)
	newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeader)

	// Create new token with empty signature
	noneToken := newHeaderB64 + "." + parts[1] + "."

	// Test the modified token
	resp, err := a.makeAuthenticatedRequest(noneToken, endpoint, method)
	if err != nil {
		return nil
	}

	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	return &AuthTestResult{
		TestType:     "JWT Algorithm None",
		Vulnerable:   vulnerable,
		Details:      "JWT accepts 'none' algorithm, allowing signature bypass",
		Risk:         "Critical",
		Endpoint:     endpoint,
		Method:       method,
		StatusCode:   resp.StatusCode,
		ResponseSize: int(resp.ContentLength),
		Evidence: map[string]interface{}{
			"modified_token": noneToken,
			"original_alg":   headerMap["alg"],
		},
	}
}

// testJWTAlgorithmConfusion tests for algorithm confusion vulnerability
func (a *AuthTester) testJWTAlgorithmConfusion(token, endpoint, method string) *AuthTestResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode header
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return nil
	}

	originalAlg := headerMap["alg"]

	// Test different algorithm confusions
	algorithms := []string{"HS256", "RS256", "HS512", "RS512"}
	for _, alg := range algorithms {
		if alg == originalAlg {
			continue
		}

		headerMap["alg"] = alg
		newHeader, _ := json.Marshal(headerMap)
		newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeader)

		confusedToken := newHeaderB64 + "." + parts[1] + "." + parts[2]

		resp, err := a.makeAuthenticatedRequest(confusedToken, endpoint, method)
		if err != nil {
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &AuthTestResult{
				TestType:     "JWT Algorithm Confusion",
				Vulnerable:   true,
				Details:      fmt.Sprintf("JWT accepts %s when expecting %s", alg, originalAlg),
				Risk:         "High",
				Endpoint:     endpoint,
				Method:       method,
				StatusCode:   resp.StatusCode,
				ResponseSize: int(resp.ContentLength),
				Evidence: map[string]interface{}{
					"original_alg": originalAlg,
					"accepted_alg": alg,
				},
			}
		}
	}

	return nil
}

// testJWTWeakSecret tests for weak JWT secrets
func (a *AuthTester) testJWTWeakSecret(token string, wordlist []string, endpoint, method string) *AuthTestResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	message := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil
	}

	for _, secret := range wordlist {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		expectedSignature := mac.Sum(nil)

		if hmac.Equal(signature, expectedSignature) {
			return &AuthTestResult{
				TestType:   "JWT Weak Secret",
				Vulnerable: true,
				Details:    fmt.Sprintf("JWT signed with weak secret: %s", secret),
				Risk:       "Critical",
				Endpoint:   endpoint,
				Method:     method,
				Evidence: map[string]interface{}{
					"weak_secret": secret,
				},
			}
		}
	}

	return nil
}

// testJWTExpirationBypass tests for expiration bypass
func (a *AuthTester) testJWTExpirationBypass(token, endpoint, method string) *AuthTestResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return nil
	}

	// Remove expiration claim
	delete(payloadMap, "exp")
	newPayload, _ := json.Marshal(payloadMap)
	newPayloadB64 := base64.RawURLEncoding.EncodeToString(newPayload)

	noExpToken := parts[0] + "." + newPayloadB64 + "." + parts[2]

	resp, err := a.makeAuthenticatedRequest(noExpToken, endpoint, method)
	if err != nil {
		return nil
	}

	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	return &AuthTestResult{
		TestType:     "JWT Expiration Bypass",
		Vulnerable:   vulnerable,
		Details:      "JWT accepted without expiration claim",
		Risk:         "Medium",
		Endpoint:     endpoint,
		Method:       method,
		StatusCode:   resp.StatusCode,
		ResponseSize: int(resp.ContentLength),
	}
}

// testJWTInvalidSignature tests with invalid signature
func (a *AuthTester) testJWTInvalidSignature(token, endpoint, method string) *AuthTestResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	// Create token with invalid signature
	invalidToken := parts[0] + "." + parts[1] + ".invalid_signature"

	resp, err := a.makeAuthenticatedRequest(invalidToken, endpoint, method)
	if err != nil {
		return nil
	}

	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	return &AuthTestResult{
		TestType:     "JWT Invalid Signature",
		Vulnerable:   vulnerable,
		Details:      "JWT accepted with invalid signature",
		Risk:         "Critical",
		Endpoint:     endpoint,
		Method:       method,
		StatusCode:   resp.StatusCode,
		ResponseSize: int(resp.ContentLength),
	}
}

// TestAPIKey performs API key security tests
func (a *AuthTester) TestAPIKey(config APIKeyTestConfig, endpoint, method string) []AuthTestResult {
	var results []AuthTestResult

	if config.Key == "" {
		return results
	}

	// Test 1: API Key Reuse
	result := a.testAPIKeyReuse(config, endpoint, method)
	if result != nil {
		results = append(results, *result)
	}

	// Test 2: Weak API Key Patterns
	for _, pattern := range config.WeakKeyPatterns {
		result := a.testWeakAPIKeyPattern(config.Key, pattern, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 3: API Key in URL
	result = a.testAPIKeyInURL(config, endpoint, method)
	if result != nil {
		results = append(results, *result)
	}

	return results
}

// testAPIKeyReuse tests for API key reuse across endpoints
func (a *AuthTester) testAPIKeyReuse(config APIKeyTestConfig, endpoint, method string) *AuthTestResult {
	// Test the same API key on different endpoints
	testEndpoints := []string{"/admin", "/api/admin", "/v1/admin", "/v2/admin"}

	for _, testEndpoint := range testEndpoints {
		if testEndpoint == endpoint {
			continue
		}

		resp, err := a.makeAPIKeyRequest(config.Key, config.HeaderName, testEndpoint, method)
		if err != nil {
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &AuthTestResult{
				TestType:     "API Key Reuse",
				Vulnerable:   true,
				Details:      fmt.Sprintf("API key valid on multiple endpoints: %s", testEndpoint),
				Risk:         "Medium",
				Endpoint:     testEndpoint,
				Method:       method,
				StatusCode:   resp.StatusCode,
				ResponseSize: int(resp.ContentLength),
			}
		}
	}

	return nil
}

// testWeakAPIKeyPattern tests for weak API key patterns
func (a *AuthTester) testWeakAPIKeyPattern(key, pattern, endpoint, method string) *AuthTestResult {
	if strings.Contains(key, pattern) {
		return &AuthTestResult{
			TestType:   "Weak API Key Pattern",
			Vulnerable: true,
			Details:    fmt.Sprintf("API key contains weak pattern: %s", pattern),
			Risk:       "Medium",
			Endpoint:   endpoint,
			Method:     method,
			Evidence: map[string]interface{}{
				"pattern": pattern,
			},
		}
	}
	return nil
}

// testAPIKeyInURL tests if API key works in URL parameters
func (a *AuthTester) testAPIKeyInURL(config APIKeyTestConfig, endpoint, method string) *AuthTestResult {
	testURL := endpoint + "?" + config.QueryParamName + "=" + config.Key

	resp, err := a.makeSimpleRequest(testURL, method)
	if err != nil {
		return nil
	}

	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	return &AuthTestResult{
		TestType:     "API Key in URL",
		Vulnerable:   vulnerable,
		Details:      "API key accepted in URL parameters",
		Risk:         "Low",
		Endpoint:     testURL,
		Method:       method,
		StatusCode:   resp.StatusCode,
		ResponseSize: int(resp.ContentLength),
	}
}

// TestSession performs session security tests
func (a *AuthTester) TestSession(config SessionTestConfig, endpoint, method string) []AuthTestResult {
	var results []AuthTestResult

	if config.SessionID == "" {
		return results
	}

	// Test 1: Session Fixation
	if config.FixationTests {
		result := a.testSessionFixation(config, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 2: Session Hijacking
	if config.HijackingTests {
		result := a.testSessionHijacking(config, endpoint, method)
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// testSessionFixation tests for session fixation vulnerabilities
func (a *AuthTester) testSessionFixation(config SessionTestConfig, endpoint, method string) *AuthTestResult {
	// Create a request with a predetermined session ID
	fixedSessionID := "fixed_session_12345"

	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil
	}

	req.AddCookie(&http.Cookie{
		Name:  config.CookieName,
		Value: fixedSessionID,
	})

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if the server accepted our fixed session ID
	for _, cookie := range resp.Cookies() {
		if cookie.Name == config.CookieName && cookie.Value == fixedSessionID {
			return &AuthTestResult{
				TestType:     "Session Fixation",
				Vulnerable:   true,
				Details:      "Server accepts predetermined session IDs",
				Risk:         "High",
				Endpoint:     endpoint,
				Method:       method,
				StatusCode:   resp.StatusCode,
				ResponseSize: int(resp.ContentLength),
				Evidence: map[string]interface{}{
					"fixed_session_id": fixedSessionID,
				},
			}
		}
	}

	return nil
}

// testSessionHijacking tests for session hijacking vulnerabilities
func (a *AuthTester) testSessionHijacking(config SessionTestConfig, endpoint, method string) *AuthTestResult {
	// Test with modified session ID
	modifiedSessionID := config.SessionID + "modified"

	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil
	}

	req.AddCookie(&http.Cookie{
		Name:  config.CookieName,
		Value: modifiedSessionID,
	})

	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// If we get a success response with a modified session, it might be vulnerable
	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	return &AuthTestResult{
		TestType:     "Session Hijacking",
		Vulnerable:   vulnerable,
		Details:      "Server accepts modified session IDs",
		Risk:         "High",
		Endpoint:     endpoint,
		Method:       method,
		StatusCode:   resp.StatusCode,
		ResponseSize: int(resp.ContentLength),
	}
}

// Helper methods

// makeAuthenticatedRequest makes a request with JWT token
func (a *AuthTester) makeAuthenticatedRequest(token, endpoint, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return a.client.Do(req)
}

// makeAPIKeyRequest makes a request with API key
func (a *AuthTester) makeAPIKeyRequest(key, headerName, endpoint, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if headerName != "" {
		req.Header.Set(headerName, key)
	}
	return a.client.Do(req)
}

// makeSimpleRequest makes a simple HTTP request
func (a *AuthTester) makeSimpleRequest(endpoint, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil, err
	}

	return a.client.Do(req)
}

// GetDefaultJWTSecretWordlist returns common weak JWT secrets
func GetDefaultJWTSecretWordlist() []string {
	return []string{
		"secret",
		"password",
		"123456",
		"jwt_secret",
		"your-256-bit-secret",
		"supersecret",
		"my_secret",
		"jwt",
		"token",
		"key",
		"secretkey",
		"mysecret",
		"qwerty",
		"admin",
		"test",
		"changeme",
		"default",
		"",
	}
}

// GetDefaultWeakAPIKeyPatterns returns patterns indicating weak API keys
func GetDefaultWeakAPIKeyPatterns() []string {
	return []string{
		"test",
		"demo",
		"admin",
		"default",
		"sample",
		"example",
		"12345",
		"password",
		"secret",
		"key",
		"api",
		"token",
	}
}
