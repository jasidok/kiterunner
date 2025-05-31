package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BusinessLogicTestResult represents the result of a business logic test
type BusinessLogicTestResult struct {
	TestType     string                 `json:"test_type"`
	Vulnerable   bool                   `json:"vulnerable"`
	Details      string                 `json:"details"`
	Evidence     map[string]interface{} `json:"evidence,omitempty"`
	Risk         string                 `json:"risk"`
	Endpoint     string                 `json:"endpoint"`
	Method       string                 `json:"method"`
	StatusCode   int                    `json:"status_code"`
	ResponseSize int                    `json:"response_size"`
	Impact       string                 `json:"impact"`
}

// IDORTestConfig holds configuration for IDOR testing
type IDORTestConfig struct {
	UserToken     string
	AdminToken    string
	TestUserIDs   []string
	TestObjectIDs []string
	IDPatterns    []string
}

// PrivilegeEscalationConfig holds configuration for privilege escalation testing
type PrivilegeEscalationConfig struct {
	UserToken      string
	AdminEndpoints []string
	UserEndpoints  []string
	RoleHeaders    map[string]string
}

// RateLimitTestConfig holds configuration for rate limiting tests
type RateLimitTestConfig struct {
	RequestsPerSecond int
	TotalRequests     int
	BurstTest         bool
	BypassHeaders     []string
}

// BusinessLogicTester performs business logic security tests
type BusinessLogicTester struct {
	client *http.Client
}

// NewBusinessLogicTester creates a new business logic tester
func NewBusinessLogicTester(client *http.Client) *BusinessLogicTester {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &BusinessLogicTester{client: client}
}

// TestIDOR performs comprehensive IDOR testing
func (b *BusinessLogicTester) TestIDOR(config IDORTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	if config.UserToken == "" {
		return results
	}

	// Test 1: Horizontal IDOR (access other users' data)
	results = append(results, b.testHorizontalIDOR(config, endpoint, method)...)

	// Test 2: Vertical IDOR (privilege escalation)
	if config.AdminToken != "" {
		results = append(results, b.testVerticalIDOR(config, endpoint, method)...)
	}

	// Test 3: Sequential ID enumeration
	results = append(results, b.testSequentialIDOR(config, endpoint, method)...)

	// Test 4: Parameter pollution IDOR
	results = append(results, b.testParameterPollutionIDOR(config, endpoint, method)...)

	return results
}

// testHorizontalIDOR tests for horizontal IDOR vulnerabilities
func (b *BusinessLogicTester) testHorizontalIDOR(config IDORTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	// Extract potential ID parameters from the endpoint
	idParams := b.extractIDParameters(endpoint)

	for _, param := range idParams {
		for _, testID := range config.TestUserIDs {
			modifiedEndpoint := b.replaceIDInEndpoint(endpoint, param, testID)

			result := b.testIDORAccess(config.UserToken, modifiedEndpoint, method, "Horizontal IDOR", testID)
			if result != nil {
				results = append(results, *result)
			}
		}
	}

	return results
}

// testVerticalIDOR tests for vertical IDOR vulnerabilities
func (b *BusinessLogicTester) testVerticalIDOR(config IDORTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	// Test accessing admin resources with user token
	adminEndpoints := []string{
		strings.Replace(endpoint, "/user/", "/admin/", -1),
		strings.Replace(endpoint, "/api/", "/api/admin/", -1),
		strings.Replace(endpoint, "/v1/", "/v1/admin/", -1),
		endpoint + "/admin",
	}

	for _, adminEndpoint := range adminEndpoints {
		if adminEndpoint == endpoint {
			continue
		}

		result := b.testIDORAccess(config.UserToken, adminEndpoint, method, "Vertical IDOR", "admin_access")
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// testSequentialIDOR tests for sequential ID enumeration
func (b *BusinessLogicTester) testSequentialIDOR(config IDORTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	// Extract numeric IDs from endpoint
	re := regexp.MustCompile(`/(\d+)(?:/|$)`)
	matches := re.FindAllStringSubmatch(endpoint, -1)

	for _, match := range matches {
		if len(match) > 1 {
			originalID, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}

			// Test sequential IDs
			testIDs := []int{
				originalID - 1,
				originalID + 1,
				originalID - 10,
				originalID + 10,
				1, 2, 3, 100, 1000,
			}

			for _, testID := range testIDs {
				if testID <= 0 {
					continue
				}

				modifiedEndpoint := strings.Replace(endpoint, match[1], strconv.Itoa(testID), 1)
				result := b.testIDORAccess(config.UserToken, modifiedEndpoint, method, "Sequential IDOR", strconv.Itoa(testID))
				if result != nil {
					results = append(results, *result)
				}
			}
		}
	}

	return results
}

// testParameterPollutionIDOR tests for parameter pollution IDOR
func (b *BusinessLogicTester) testParameterPollutionIDOR(config IDORTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	if !strings.Contains(endpoint, "?") {
		return results
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return results
	}

	params := parsedURL.Query()

	// Add duplicate parameters with different values
	for key := range params {
		if b.isIDParameter(key) {
			for _, testID := range config.TestUserIDs {
				params.Add(key, testID)
				newURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path + "?" + params.Encode()

				result := b.testIDORAccess(config.UserToken, newURL, method, "Parameter Pollution IDOR", testID)
				if result != nil {
					results = append(results, *result)
				}

				// Remove the added parameter for next iteration
				values := params[key]
				if len(values) > 1 {
					params[key] = values[:len(values)-1]
				}
			}
		}
	}

	return results
}

// testIDORAccess tests access to a modified endpoint
func (b *BusinessLogicTester) testIDORAccess(token, endpoint, method, testType, targetID string) *BusinessLogicTestResult {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Consider it vulnerable if we get a success response
	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.StatusCode != 404

	if vulnerable {
		impact := "Medium"
		if testType == "Vertical IDOR" {
			impact = "High"
		}

		return &BusinessLogicTestResult{
			TestType:     testType,
			Vulnerable:   true,
			Details:      fmt.Sprintf("Successfully accessed %s with unauthorized token", endpoint),
			Risk:         "High",
			Impact:       impact,
			Endpoint:     endpoint,
			Method:       method,
			StatusCode:   resp.StatusCode,
			ResponseSize: int(resp.ContentLength),
			Evidence: map[string]interface{}{
				"target_id":           targetID,
				"unauthorized_access": true,
			},
		}
	}

	return nil
}

// TestPrivilegeEscalation performs privilege escalation tests
func (b *BusinessLogicTester) TestPrivilegeEscalation(config PrivilegeEscalationConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	if config.UserToken == "" {
		return results
	}

	// Test 1: Admin endpoint access with user token
	for _, adminEndpoint := range config.AdminEndpoints {
		result := b.testPrivilegeEscalationAccess(config.UserToken, adminEndpoint, method, "Admin Endpoint Access")
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 2: Role header manipulation
	for headerName, headerValue := range config.RoleHeaders {
		result := b.testRoleHeaderManipulation(config.UserToken, endpoint, method, headerName, headerValue)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test 3: HTTP method override
	result := b.testHTTPMethodOverride(config.UserToken, endpoint, method)
	if result != nil {
		results = append(results, *result)
	}

	return results
}

// testPrivilegeEscalationAccess tests access to privileged endpoints
func (b *BusinessLogicTester) testPrivilegeEscalationAccess(userToken, endpoint, method, testType string) *BusinessLogicTestResult {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+userToken)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	if vulnerable {
		return &BusinessLogicTestResult{
			TestType:     testType,
			Vulnerable:   true,
			Details:      "User token granted access to privileged endpoint",
			Risk:         "Critical",
			Impact:       "High",
			Endpoint:     endpoint,
			Method:       method,
			StatusCode:   resp.StatusCode,
			ResponseSize: int(resp.ContentLength),
		}
	}

	return nil
}

// testRoleHeaderManipulation tests role header manipulation
func (b *BusinessLogicTester) testRoleHeaderManipulation(userToken, endpoint, method, headerName, headerValue string) *BusinessLogicTestResult {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set(headerName, headerValue)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	if vulnerable {
		return &BusinessLogicTestResult{
			TestType:     "Role Header Manipulation",
			Vulnerable:   true,
			Details:      fmt.Sprintf("Role escalation via %s header", headerName),
			Risk:         "High",
			Impact:       "High",
			Endpoint:     endpoint,
			Method:       method,
			StatusCode:   resp.StatusCode,
			ResponseSize: int(resp.ContentLength),
			Evidence: map[string]interface{}{
				"header_name":  headerName,
				"header_value": headerValue,
			},
		}
	}

	return nil
}

// testHTTPMethodOverride tests HTTP method override attacks
func (b *BusinessLogicTester) testHTTPMethodOverride(userToken, endpoint, method string) *BusinessLogicTestResult {
	overrideHeaders := map[string]string{
		"X-HTTP-Method-Override": "DELETE",
		"X-Method-Override":      "PUT",
		"X-HTTP-Method":          "PATCH",
	}

	for headerName, overrideMethod := range overrideHeaders {
		req, err := http.NewRequest("POST", endpoint, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set(headerName, overrideMethod)

		resp, err := b.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		vulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

		if vulnerable {
			return &BusinessLogicTestResult{
				TestType:     "HTTP Method Override",
				Vulnerable:   true,
				Details:      fmt.Sprintf("Method override successful via %s", headerName),
				Risk:         "Medium",
				Impact:       "Medium",
				Endpoint:     endpoint,
				Method:       "POST->" + overrideMethod,
				StatusCode:   resp.StatusCode,
				ResponseSize: int(resp.ContentLength),
				Evidence: map[string]interface{}{
					"override_header": headerName,
					"override_method": overrideMethod,
				},
			}
		}
	}

	return nil
}

// TestRateLimit performs rate limiting tests
func (b *BusinessLogicTester) TestRateLimit(config RateLimitTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	// Test 1: Basic rate limit detection
	result := b.testBasicRateLimit(config, endpoint, method)
	if result != nil {
		results = append(results, *result)
	}

	// Test 2: Rate limit bypass attempts
	results = append(results, b.testRateLimitBypass(config, endpoint, method)...)

	return results
}

// testBasicRateLimit tests basic rate limiting
func (b *BusinessLogicTester) testBasicRateLimit(config RateLimitTestConfig, endpoint, method string) *BusinessLogicTestResult {
	successCount := 0
	var lastStatusCode int

	interval := time.Second / time.Duration(config.RequestsPerSecond)

	for i := 0; i < config.TotalRequests; i++ {
		req, err := http.NewRequest(method, endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := b.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		lastStatusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}

		if resp.StatusCode == 429 {
			// Rate limited
			break
		}

		if !config.BurstTest {
			time.Sleep(interval)
		}
	}

	rateLimited := lastStatusCode == 429 || successCount < config.TotalRequests

	return &BusinessLogicTestResult{
		TestType:   "Rate Limit Detection",
		Vulnerable: !rateLimited,
		Details:    fmt.Sprintf("Successful requests: %d/%d", successCount, config.TotalRequests),
		Risk:       "Low",
		Impact:     "Low",
		Endpoint:   endpoint,
		Method:     method,
		StatusCode: lastStatusCode,
		Evidence: map[string]interface{}{
			"successful_requests": successCount,
			"total_requests":      config.TotalRequests,
			"rate_limited":        rateLimited,
		},
	}
}

// testRateLimitBypass tests rate limit bypass techniques
func (b *BusinessLogicTester) testRateLimitBypass(config RateLimitTestConfig, endpoint, method string) []BusinessLogicTestResult {
	var results []BusinessLogicTestResult

	bypassTechniques := map[string]map[string]string{
		"X-Forwarded-For": {
			"X-Forwarded-For": "127.0.0.1",
		},
		"X-Real-IP": {
			"X-Real-IP": "192.168.1.1",
		},
		"X-Originating-IP": {
			"X-Originating-IP": "10.0.0.1",
		},
		"User-Agent Rotation": {
			"User-Agent": "Mozilla/5.0 (Different Browser)",
		},
	}

	for technique, headers := range bypassTechniques {
		result := b.testSpecificRateLimitBypass(config, endpoint, method, technique, headers)
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// testSpecificRateLimitBypass tests a specific rate limit bypass technique
func (b *BusinessLogicTester) testSpecificRateLimitBypass(config RateLimitTestConfig, endpoint, method, technique string, headers map[string]string) *BusinessLogicTestResult {
	successCount := 0

	for i := 0; i < config.TotalRequests; i++ {
		req, err := http.NewRequest(method, endpoint, nil)
		if err != nil {
			continue
		}

		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := b.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
	}

	bypassed := successCount >= config.TotalRequests

	if bypassed {
		return &BusinessLogicTestResult{
			TestType:   "Rate Limit Bypass",
			Vulnerable: true,
			Details:    fmt.Sprintf("Rate limit bypassed using %s technique", technique),
			Risk:       "Medium",
			Impact:     "Medium",
			Endpoint:   endpoint,
			Method:     method,
			Evidence: map[string]interface{}{
				"bypass_technique":    technique,
				"bypass_headers":      headers,
				"successful_requests": successCount,
			},
		}
	}

	return nil
}

// Helper methods

// extractIDParameters extracts potential ID parameters from endpoint
func (b *BusinessLogicTester) extractIDParameters(endpoint string) []string {
	var params []string

	// Extract from path parameters
	re := regexp.MustCompile(`/(\w+)`)
	matches := re.FindAllStringSubmatch(endpoint, -1)
	for _, match := range matches {
		if len(match) > 1 && b.isIDParameter(match[1]) {
			params = append(params, match[1])
		}
	}

	// Extract from query parameters
	if strings.Contains(endpoint, "?") {
		parsedURL, err := url.Parse(endpoint)
		if err == nil {
			for key := range parsedURL.Query() {
				if b.isIDParameter(key) {
					params = append(params, key)
				}
			}
		}
	}

	return params
}

// isIDParameter checks if a parameter name suggests it's an ID
func (b *BusinessLogicTester) isIDParameter(param string) bool {
	idPatterns := []string{
		"id", "uid", "user_id", "userid", "account_id", "accountid",
		"object_id", "objectid", "resource_id", "resourceid",
		"entity_id", "entityid", "item_id", "itemid",
	}

	param = strings.ToLower(param)
	for _, pattern := range idPatterns {
		if strings.Contains(param, pattern) {
			return true
		}
	}

	// Check if it's numeric
	if _, err := strconv.Atoi(param); err == nil {
		return true
	}

	return false
}

// replaceIDInEndpoint replaces ID parameter in endpoint with new value
func (b *BusinessLogicTester) replaceIDInEndpoint(endpoint, param, newValue string) string {
	// Replace in path
	re := regexp.MustCompile(`/` + regexp.QuoteMeta(param) + `(?:/|$)`)
	if re.MatchString(endpoint) {
		return re.ReplaceAllString(endpoint, "/"+newValue+"/")
	}

	// Replace in query parameters
	if strings.Contains(endpoint, "?") {
		parsedURL, err := url.Parse(endpoint)
		if err == nil {
			params := parsedURL.Query()
			if params.Has(param) {
				params.Set(param, newValue)
				parsedURL.RawQuery = params.Encode()
				return parsedURL.String()
			}
		}
	}

	return endpoint
}

// GetDefaultIDORTestIDs returns common test IDs for IDOR testing
func GetDefaultIDORTestIDs() []string {
	return []string{
		"1", "2", "3", "0", "999", "1000",
		"admin", "administrator", "root", "system",
		"test", "demo", "guest", "public",
		"null", "undefined", "false", "true",
		"../", "..\\", "%2e%2e%2f", "%2e%2e%5c",
	}
}

// GetDefaultAdminEndpoints returns common admin endpoint patterns
func GetDefaultAdminEndpoints() []string {
	return []string{
		"/admin", "/admin/", "/api/admin", "/api/admin/",
		"/administrator", "/management", "/manage",
		"/control", "/panel", "/dashboard",
		"/v1/admin", "/v2/admin", "/api/v1/admin",
	}
}

// GetDefaultRoleHeaders returns common role manipulation headers
func GetDefaultRoleHeaders() map[string]string {
	return map[string]string{
		"X-Role":         "admin",
		"X-User-Role":    "administrator",
		"X-Admin":        "true",
		"X-Privilege":    "admin",
		"X-Access-Level": "admin",
		"X-Permission":   "admin",
		"X-User-Type":    "admin",
		"Role":           "admin",
		"User-Role":      "admin",
		"Access-Level":   "admin",
	}
}
