package kiterunner

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/assetnote/kiterunner2/pkg/auth"
	"github.com/assetnote/kiterunner2/pkg/convert"
	httppkg "github.com/assetnote/kiterunner2/pkg/http"
	"github.com/assetnote/kiterunner2/pkg/injection"
	"github.com/assetnote/kiterunner2/pkg/log"
)

// RequestValidator is an interface that lets you add custom validators for what are good and bad responses
type RequestValidator interface {
	Validate(r httppkg.Response, wildcardResponses []WildcardResponse, c *Config) error
}

// SecurityTestingValidator performs comprehensive security testing on discovered endpoints
type SecurityTestingValidator struct {
	AuthTester      *auth.AuthTester
	BusinessTester  *auth.BusinessLogicTester
	InjectionTester *injection.InjectionTester
	Config          SecurityTestingConfig
	HTTPClient      *http.Client
}

// SecurityTestingConfig holds configuration for security testing
type SecurityTestingConfig struct {
	EnableAuthTesting    bool
	EnableBusinessLogic  bool
	EnableInjectionTests bool
	JWTToken             string
	APIKey               string
	AdminToken           string
	TestUserIDs          []string
	AdminEndpoints       []string
	TestParameters       []string
}

// NewSecurityTestingValidator creates a new security testing validator
func NewSecurityTestingValidator(config SecurityTestingConfig, client *http.Client) *SecurityTestingValidator {
	if client == nil {
		client = &http.Client{}
	}

	return &SecurityTestingValidator{
		AuthTester:      auth.NewAuthTester(client),
		BusinessTester:  auth.NewBusinessLogicTester(client),
		InjectionTester: injection.NewInjectionTester(client),
		Config:          config,
		HTTPClient:      client,
	}
}

// Validate performs comprehensive security testing on the response
func (v *SecurityTestingValidator) Validate(r httppkg.Response, wildcardResponses []WildcardResponse, c *Config) error {
	if v == nil {
		return nil
	}

	// Only test successful responses to avoid false positives
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return nil
	}

	// Construct endpoint URL from Target and Route
	endpoint := v.constructEndpointURL(r.OriginRequest)
	method := string(r.OriginRequest.Route.Method)

	// Perform authentication testing
	if v.Config.EnableAuthTesting && v.Config.JWTToken != "" {
		v.performAuthenticationTesting(endpoint, method)
	}

	// Perform business logic testing
	if v.Config.EnableBusinessLogic {
		v.performBusinessLogicTesting(endpoint, method)
	}

	// Perform injection testing
	if v.Config.EnableInjectionTests {
		v.performInjectionTesting(endpoint, method)
	}

	return nil
}

// constructEndpointURL constructs the full endpoint URL from the request
func (v *SecurityTestingValidator) constructEndpointURL(req httppkg.Request) string {
	if req.Target == nil || req.Route == nil {
		return ""
	}

	var endpoint strings.Builder

	// Add scheme
	if req.Target.IsTLS {
		endpoint.WriteString("https://")
	} else {
		endpoint.WriteString("http://")
	}

	// Add host with port
	endpoint.WriteString(req.Target.Host())

	// Add base path
	endpoint.WriteString(req.Target.BasePath)

	// Add route path
	endpoint.Write(req.Route.Path)

	// Add query if present
	if len(req.Route.Query) > 0 {
		endpoint.WriteString("?")
		endpoint.Write(req.Route.Query)
	}

	return endpoint.String()
}

// performAuthenticationTesting performs comprehensive authentication tests
func (v *SecurityTestingValidator) performAuthenticationTesting(endpoint, method string) {
	if v.Config.JWTToken != "" {
		// JWT Testing
		jwtConfig := auth.JWTTestConfig{
			Token:           v.Config.JWTToken,
			SecretWordlist:  auth.GetDefaultJWTSecretWordlist(),
			AlgorithmTests:  true,
			ExpirationTests: true,
		}

		results := v.AuthTester.TestJWT(jwtConfig, endpoint, method)
		for _, result := range results {
			if result.Vulnerable {
				log.Warn().
					Str("test_type", result.TestType).
					Str("endpoint", result.Endpoint).
					Str("method", result.Method).
					Str("risk", result.Risk).
					Str("details", result.Details).
					Msg("Authentication vulnerability detected")
			}
		}
	}

	if v.Config.APIKey != "" {
		// API Key Testing
		apiConfig := auth.APIKeyTestConfig{
			Key:             v.Config.APIKey,
			HeaderName:      "X-API-Key",
			QueryParamName:  "api_key",
			WeakKeyPatterns: auth.GetDefaultWeakAPIKeyPatterns(),
		}

		results := v.AuthTester.TestAPIKey(apiConfig, endpoint, method)
		for _, result := range results {
			if result.Vulnerable {
				log.Warn().
					Str("test_type", result.TestType).
					Str("endpoint", result.Endpoint).
					Str("method", result.Method).
					Str("risk", result.Risk).
					Str("details", result.Details).
					Msg("API key vulnerability detected")
			}
		}
	}
}

// performBusinessLogicTesting performs business logic and access control tests
func (v *SecurityTestingValidator) performBusinessLogicTesting(endpoint, method string) {
	if v.Config.JWTToken != "" {
		// IDOR Testing
		idorConfig := auth.IDORTestConfig{
			UserToken:     v.Config.JWTToken,
			AdminToken:    v.Config.AdminToken,
			TestUserIDs:   v.getTestUserIDs(),
			TestObjectIDs: []string{"1", "2", "3", "admin", "test"},
		}

		results := v.BusinessTester.TestIDOR(idorConfig, endpoint, method)
		for _, result := range results {
			if result.Vulnerable {
				log.Warn().
					Str("test_type", result.TestType).
					Str("endpoint", result.Endpoint).
					Str("method", result.Method).
					Str("risk", result.Risk).
					Str("impact", result.Impact).
					Str("details", result.Details).
					Msg("IDOR vulnerability detected")
			}
		}

		// Privilege Escalation Testing
		privConfig := auth.PrivilegeEscalationConfig{
			UserToken:      v.Config.JWTToken,
			AdminEndpoints: v.getAdminEndpoints(),
			RoleHeaders:    auth.GetDefaultRoleHeaders(),
		}

		results = v.BusinessTester.TestPrivilegeEscalation(privConfig, endpoint, method)
		for _, result := range results {
			if result.Vulnerable {
				log.Warn().
					Str("test_type", result.TestType).
					Str("endpoint", result.Endpoint).
					Str("method", result.Method).
					Str("risk", result.Risk).
					Str("impact", result.Impact).
					Str("details", result.Details).
					Msg("Privilege escalation vulnerability detected")
			}
		}
	}

	// Rate Limiting Testing
	rateLimitConfig := auth.RateLimitTestConfig{
		RequestsPerSecond: 10,
		TotalRequests:     50,
		BurstTest:         true,
	}

	results := v.BusinessTester.TestRateLimit(rateLimitConfig, endpoint, method)
	for _, result := range results {
		if result.Vulnerable {
			log.Warn().
				Str("test_type", result.TestType).
				Str("endpoint", result.Endpoint).
				Str("method", result.Method).
				Str("risk", result.Risk).
				Str("details", result.Details).
				Msg("Rate limiting vulnerability detected")
		}
	}
}

// performInjectionTesting performs injection vulnerability tests
func (v *SecurityTestingValidator) performInjectionTesting(endpoint, method string) {
	// Only test endpoints that likely accept parameters
	if !v.hasParameters(endpoint) {
		return
	}

	// SQL Injection Testing
	sqlConfig := injection.GetDefaultSQLInjectionConfig()
	results := v.InjectionTester.TestSQLInjection(sqlConfig, endpoint, method)
	for _, result := range results {
		if result.Vulnerable {
			log.Warn().
				Str("test_type", result.TestType).
				Str("injection_type", result.InjectionType).
				Str("endpoint", result.Endpoint).
				Str("method", result.Method).
				Str("parameter", result.Parameter).
				Str("risk", result.Risk).
				Str("details", result.Details).
				Msg("SQL injection vulnerability detected")
		}
	}

	// NoSQL Injection Testing
	nosqlConfig := injection.GetDefaultNoSQLInjectionConfig()
	results = v.InjectionTester.TestNoSQLInjection(nosqlConfig, endpoint, method)
	for _, result := range results {
		if result.Vulnerable {
			log.Warn().
				Str("test_type", result.TestType).
				Str("injection_type", result.InjectionType).
				Str("endpoint", result.Endpoint).
				Str("method", result.Method).
				Str("parameter", result.Parameter).
				Str("risk", result.Risk).
				Str("details", result.Details).
				Msg("NoSQL injection vulnerability detected")
		}
	}

	// Command Injection Testing
	cmdConfig := injection.GetDefaultCommandInjectionConfig()
	results = v.InjectionTester.TestCommandInjection(cmdConfig, endpoint, method)
	for _, result := range results {
		if result.Vulnerable {
			log.Warn().
				Str("test_type", result.TestType).
				Str("injection_type", result.InjectionType).
				Str("endpoint", result.Endpoint).
				Str("method", result.Method).
				Str("parameter", result.Parameter).
				Str("risk", result.Risk).
				Str("details", result.Details).
				Msg("Command injection vulnerability detected")
		}
	}
}

// Helper methods

func (v *SecurityTestingValidator) getTestUserIDs() []string {
	if len(v.Config.TestUserIDs) > 0 {
		return v.Config.TestUserIDs
	}
	return auth.GetDefaultIDORTestIDs()
}

func (v *SecurityTestingValidator) getAdminEndpoints() []string {
	if len(v.Config.AdminEndpoints) > 0 {
		return v.Config.AdminEndpoints
	}
	return auth.GetDefaultAdminEndpoints()
}

func (v *SecurityTestingValidator) hasParameters(endpoint string) bool {
	// Check for query parameters
	if strings.Contains(endpoint, "?") {
		return true
	}

	// Check for path parameters (numeric values)
	parts := strings.Split(endpoint, "/")
	for _, part := range parts {
		if len(part) > 0 && isNumeric(part) {
			return true
		}
	}

	return false
}

func isNumeric(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(s) > 0
}

type KnownBadSitesValidator struct{}

var (
	ErrGoogleBadRequest        = fmt.Errorf("google bad request found")
	ErrAmazonGatewayBadRequest = fmt.Errorf("amazon gateway bad request found")
)

func (v *KnownBadSitesValidator) Validate(r httppkg.Response, wildcardResponses []WildcardResponse, c *Config) error {
	if v == nil {
		return nil
	}
	// occurs with body + method mismatch (get with post body)
	if r.StatusCode == 400 &&
		r.BodyLength == 1555 &&
		r.Words == 82 &&
		r.Lines == 12 {
		return ErrGoogleBadRequest
	}

	// {"message":"Authorization header cannot be empty: ''"}
	if r.StatusCode == 403 &&
		r.Lines == 1 &&
		r.Words == 6 &&
		r.BodyLength == 54 {
		if len(r.Headers) > 0 {
			for _, v := range r.Headers {
				if v.Key == "X-Amzn-Requestid" {
					return ErrAmazonGatewayBadRequest
				}
			}
		}
		return ErrAmazonGatewayBadRequest
	}

	// {"message":"'UEh6T0NPYkhOY3JSdGlmNDoxTUZ4WXExREg2bnBVR1Bi' not a valid key=value pair (missing equal-sign) in Authorization header: 'Basic UEh6T0NPYkhOY3JSdGlmNDoxTUZ4WXExREg2bnBVR1Bi'."}
	if r.StatusCode == 403 &&
		r.Lines == 1 &&
		r.Words == 13 &&
		r.BodyLength >= 99 {
		if len(r.Headers) > 0 {
			for _, v := range r.Headers {
				if v.Key == "X-Amzn-Requestid" {
					return ErrAmazonGatewayBadRequest
				}
			}
		}
		return ErrAmazonGatewayBadRequest
	}

	// {"message":"'UEh6T0NPYkhOY3JSdGlmNDoxTUZ4WXExREg2bnBVR1Bi' not a valid key=value pair (missing equal-sign) in Authorization header: 'Basic UEh6T0NPYkhOY3JSdGlmNDoxTUZ4WXExREg2bnBVR1Bi'."}
	if r.StatusCode == 403 &&
		r.Lines == 1 &&
		r.Words == 28 &&
		r.BodyLength >= 277 {
		if len(r.Headers) > 0 {
			for _, v := range r.Headers {
				if v.Key == "X-Amzn-Requestid" {
					return ErrAmazonGatewayBadRequest
				}
			}
		}
		return ErrAmazonGatewayBadRequest
	}

	return nil
}

type WildcardResponseValidator struct{}

func (v *WildcardResponseValidator) Validate(r httppkg.Response, wildcardResponses []WildcardResponse, c *Config) error {
	if v == nil {
		return nil
	}

	// Not all paths provided to us will have a prefixing slash
	// TODO: precalculate this so it doesnt need to be done everytime
	basePathLen := len(r.OriginRequest.Route.Path)

	if basePathLen > 0 && r.OriginRequest.Route.Path[0] == '/' {
		basePathLen -= 1
	}

	// ignore / as a root path for wildcard detection. sometimes is helpful to see it once
	// disabled because its noisy
	if false && basePathLen == 0 {
		return nil
	}

	for _, wr := range wildcardResponses {
		// perform our wildcard detection check
		if r.StatusCode == wr.DefaultStatusCode ||
			(r.StatusCode-wr.DefaultStatusCode < 50) { // handle an edge case where we get load balanced. and
			// the load balanced servers respond on different statuscodes but with the same body

			expectedAdjustedLength := wr.AdjustedContentLength + (wr.AdjustmentScale * basePathLen)

			if r.BodyLength == wr.DefaultContentLength {
				log.Trace().Int("len", len(r.Body)).
					Msg("failed on length match")
				return ErrLengthMatch
			} //  if we have a perfect match on length

			if r.BodyLength == expectedAdjustedLength { // if we have a match on scaled length
				log.Trace().Int("adjustedLen", expectedAdjustedLength).
					Int("len", len(r.Body)).
					Msg("failed on scaled length match")
				return ErrScaledLengthMatch
			}
			// TODO: benchmark whether this is an effective mechanism
			if r.Words == wr.DefaultWordCount &&
				r.Lines == wr.DefaultLineCount {
				log.Trace().
					Int("words", r.Words).
					Int("lines", r.Lines).
					Msg("failed on line/word count match")
				return ErrWordCountMatch
			}

			log.Trace().Int("adjustedLen", expectedAdjustedLength).
				Bytes("basepath", r.OriginRequest.Route.Path).
				Int("basepathlen", basePathLen).
				Int("len", r.BodyLength).
				Bytes("body", r.Body). // TODO: disable this allocation
				Int("statusCode", r.StatusCode).
				Int("expectedSC", wr.DefaultStatusCode).
				Int("words", r.Words).
				Int("lines", r.Lines).
				Int("expectedWords", wr.DefaultWordCount).
				Int("expectedLines", wr.DefaultLineCount).
				Int("baselen", wr.AdjustedContentLength).
				Msg("passed wildcard test")
		}
	}
	return nil
}

type ContentLengthValidator struct {
	IgnoreRanges []httppkg.Range
}

func NewContentLengthValidator(ranges []httppkg.Range) *ContentLengthValidator {
	if len(ranges) == 0 {
		return nil
	}
	return &ContentLengthValidator{
		IgnoreRanges: ranges,
	}
}

func (v ContentLengthValidator) String() string {
	return fmt.Sprintf("ContentLengthValidator{%v}", v.IgnoreRanges)
}

func (v *ContentLengthValidator) Validate(r httppkg.Response, _ []WildcardResponse, _ *Config) error {
	if v == nil {
		return nil
	}
	for _, v := range v.IgnoreRanges {
		if v.Min <= r.BodyLength && r.BodyLength <= v.Max {
			return ErrContentLengthRangeMatch
		}
	}
	return nil
}

type StatusCodeWhitelist struct {
	Codes map[int]interface{}
}

func NewStatusCodeWhitelist(valid []int) *StatusCodeWhitelist {
	if len(valid) == 0 {
		return nil
	}
	ret := &StatusCodeWhitelist{
		Codes: make(map[int]interface{}),
	}
	for _, v := range valid {
		ret.Codes[v] = struct{}{}
	}

	return ret
}

func (v StatusCodeWhitelist) String() string {
	return fmt.Sprintf("StatusCodeWhitelist{%v}", convert.IntMapToSlice(v.Codes))
}

func (v *StatusCodeWhitelist) Validate(r httppkg.Response, _ []WildcardResponse, _ *Config) error {
	if v == nil {
		return nil
	}
	// only consider the whitelist if its populated
	if v.Codes != nil && len(v.Codes) != 0 {
		// we're not in the whitelist
		if _, ok := v.Codes[r.StatusCode]; !ok {
			return ErrWhitelistedStatusCode
		}
	}
	return nil
}

type StatusCodeBlacklist struct {
	Codes map[int]interface{}
}

func NewStatusCodeBlacklist(valid []int) *StatusCodeBlacklist {
	if len(valid) == 0 {
		return nil
	}
	ret := &StatusCodeBlacklist{
		Codes: make(map[int]interface{}),
	}
	for _, v := range valid {
		ret.Codes[v] = struct{}{}
	}

	return ret
}

func (v StatusCodeBlacklist) String() string {
	return fmt.Sprintf("StatusCodeBlacklist{%v}", convert.IntMapToSlice(v.Codes))
}

func (v *StatusCodeBlacklist) Validate(r httppkg.Response, _ []WildcardResponse, _ *Config) error {
	if v == nil {
		return nil
	}
	// only consider the whitelist if its populated
	if v.Codes != nil && len(v.Codes) != 0 {
		// we're in the blacklist
		if _, ok := v.Codes[r.StatusCode]; ok {
			return ErrBlacklistedStatusCode
		}
	}
	return nil
}
