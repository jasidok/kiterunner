package scoring

import (
	"regexp"
	"strings"
	"time"

	"github.com/assetnote/kiterunner/pkg/http"
)

// Risk levels
type RiskLevel int

const (
	RiskCritical RiskLevel = iota + 1
	RiskHigh
	RiskMedium
	RiskLow
	RiskInfo
)

func (r RiskLevel) String() string {
	switch r {
	case RiskCritical:
		return "CRITICAL"
	case RiskHigh:
		return "HIGH"
	case RiskMedium:
		return "MEDIUM"
	case RiskLow:
		return "LOW"
	case RiskInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Vulnerability types
type VulnerabilityType int

const (
	VulnIDOR VulnerabilityType = iota + 1
	VulnAuthBypass
	VulnSQLi
	VulnXSS
	VulnCommandInjection
	VulnPathTraversal
	VulnSensitiveDataExposure
	VulnAdminPanelAccess
	VulnAPIKeyExposure
	VulnWeakAuthentication
	VulnRateLimitBypass
	VulnBusinessLogicFlaw
)

func (v VulnerabilityType) String() string {
	switch v {
	case VulnIDOR:
		return "Insecure Direct Object Reference"
	case VulnAuthBypass:
		return "Authentication Bypass"
	case VulnSQLi:
		return "SQL Injection"
	case VulnXSS:
		return "Cross-Site Scripting"
	case VulnCommandInjection:
		return "Command Injection"
	case VulnPathTraversal:
		return "Path Traversal"
	case VulnSensitiveDataExposure:
		return "Sensitive Data Exposure"
	case VulnAdminPanelAccess:
		return "Admin Panel Access"
	case VulnAPIKeyExposure:
		return "API Key Exposure"
	case VulnWeakAuthentication:
		return "Weak Authentication"
	case VulnRateLimitBypass:
		return "Rate Limit Bypass"
	case VulnBusinessLogicFlaw:
		return "Business Logic Flaw"
	default:
		return "Unknown Vulnerability"
	}
}

// EndpointRisk represents the risk assessment of an endpoint
type EndpointRisk struct {
	Endpoint           string    `json:"endpoint"`
	Method             string    `json:"method"`
	RiskLevel          RiskLevel `json:"risk_level"`
	Score              int       `json:"score"`
	SensitivityFactors []string  `json:"sensitivity_factors"`
	BusinessImpact     string    `json:"business_impact"`
	Exploitability     string    `json:"exploitability"`
	AccessLevel        string    `json:"access_level"`
	DataSensitivity    string    `json:"data_sensitivity"`
	Timestamp          time.Time `json:"timestamp"`
}

// VulnerabilityAssessment represents a complete vulnerability assessment
type VulnerabilityAssessment struct {
	VulnerabilityType VulnerabilityType `json:"vulnerability_type"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	RiskLevel         RiskLevel         `json:"risk_level"`
	Score             int               `json:"score"`
	Evidence          []string          `json:"evidence"`
	Payload           string            `json:"payload,omitempty"`
	Response          string            `json:"response,omitempty"`
	BusinessImpact    string            `json:"business_impact"`
	Remediation       string            `json:"remediation"`
	CVSS              float64           `json:"cvss,omitempty"`
	References        []string          `json:"references,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
}

// RiskScorer provides risk scoring functionality
type RiskScorer struct {
	// Sensitive path patterns
	adminPatterns   []*regexp.Regexp
	apiPatterns     []*regexp.Regexp
	userPatterns    []*regexp.Regexp
	paymentPatterns []*regexp.Regexp
	filePatterns    []*regexp.Regexp

	// Sensitive parameter patterns
	sensitiveParams []*regexp.Regexp

	// Technology patterns
	techPatterns map[string][]*regexp.Regexp
}

// NewRiskScorer creates a new risk scorer instance
func NewRiskScorer() *RiskScorer {
	rs := &RiskScorer{
		techPatterns: make(map[string][]*regexp.Regexp),
	}
	rs.initializePatterns()
	return rs
}

// initializePatterns sets up all the regex patterns for risk assessment
func (rs *RiskScorer) initializePatterns() {
	// Admin panel patterns
	rs.adminPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/(admin|administrator|manage|management|control|panel|dashboard|console)/`),
		regexp.MustCompile(`(?i)/(wp-admin|phpmyadmin|adminer|cpanel|plesk)/`),
		regexp.MustCompile(`(?i)/(staff|internal|private|privileged)/`),
		regexp.MustCompile(`(?i)/(system|config|settings|preferences)/`),
	}

	// API patterns
	rs.apiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/api/(v[0-9]+/)?`),
		regexp.MustCompile(`(?i)/rest/`),
		regexp.MustCompile(`(?i)/graphql`),
		regexp.MustCompile(`(?i)/webhook/`),
		regexp.MustCompile(`(?i)/rpc/`),
	}

	// User-related patterns
	rs.userPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/(user|users|profile|account|member|customer)/`),
		regexp.MustCompile(`(?i)/(auth|login|register|signup|oauth)/`),
		regexp.MustCompile(`(?i)/(password|token|session|jwt)/`),
	}

	// Payment-related patterns
	rs.paymentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/(payment|billing|invoice|subscription|plan)/`),
		regexp.MustCompile(`(?i)/(credit|debit|card|bank|transaction)/`),
		regexp.MustCompile(`(?i)/(stripe|paypal|square|braintree)/`),
	}

	// File operation patterns
	rs.filePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/(file|files|upload|download|document)/`),
		regexp.MustCompile(`(?i)/(backup|export|import|dump)/`),
		regexp.MustCompile(`(?i)/(media|assets|static|resources)/`),
	}

	// Sensitive parameter patterns
	rs.sensitiveParams = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(id|user_?id|account_?id|customer_?id)`),
		regexp.MustCompile(`(?i)(token|api_?key|secret|password)`),
		regexp.MustCompile(`(?i)(admin|privileged|role|permission)`),
		regexp.MustCompile(`(?i)(file|path|url|redirect)`),
		regexp.MustCompile(`(?i)(email|phone|ssn|credit_?card)`),
	}

	// Technology-specific patterns
	rs.techPatterns["java"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/servlet/`),
		regexp.MustCompile(`(?i)\.jsp`),
		regexp.MustCompile(`(?i)/spring/`),
	}

	rs.techPatterns["php"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\.php`),
		regexp.MustCompile(`(?i)/wordpress/`),
		regexp.MustCompile(`(?i)/drupal/`),
	}

	rs.techPatterns["asp"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\.aspx?`),
		regexp.MustCompile(`(?i)/umbraco/`),
		regexp.MustCompile(`(?i)/sitecore/`),
	}
}

// ScoreEndpoint calculates risk score for an endpoint
func (rs *RiskScorer) ScoreEndpoint(target *http.Target, route *http.Route, response *http.Response) *EndpointRisk {
	endpoint := target.String() + string(route.Path)
	method := string(route.Method)

	baseScore := 10
	factors := []string{}

	// Path-based scoring
	pathScore, pathFactors := rs.scoreByPath(string(route.Path))
	baseScore += pathScore
	factors = append(factors, pathFactors...)

	// Method-based scoring
	methodScore, methodFactor := rs.scoreByMethod(method)
	baseScore += methodScore
	if methodFactor != "" {
		factors = append(factors, methodFactor)
	}

	// Response-based scoring
	if response != nil {
		respScore, respFactors := rs.scoreByResponse(response)
		baseScore += respScore
		factors = append(factors, respFactors...)
	}

	// Parameter-based scoring (if available)
	// This would be enhanced by parameter discovery results

	riskLevel := rs.calculateRiskLevel(baseScore)
	businessImpact := rs.assessBusinessImpact(endpoint, factors)
	exploitability := rs.assessExploitability(method, factors)
	accessLevel := rs.determineAccessLevel(factors)
	dataSensitivity := rs.assessDataSensitivity(factors)

	return &EndpointRisk{
		Endpoint:           endpoint,
		Method:             method,
		RiskLevel:          riskLevel,
		Score:              baseScore,
		SensitivityFactors: factors,
		BusinessImpact:     businessImpact,
		Exploitability:     exploitability,
		AccessLevel:        accessLevel,
		DataSensitivity:    dataSensitivity,
		Timestamp:          time.Now(),
	}
}

// scoreByPath analyzes the URL path for risk indicators
func (rs *RiskScorer) scoreByPath(path string) (int, []string) {
	score := 0
	factors := []string{}

	// Admin panel detection
	for _, pattern := range rs.adminPatterns {
		if pattern.MatchString(path) {
			score += 30
			factors = append(factors, "admin_panel")
			break
		}
	}

	// API endpoint detection
	for _, pattern := range rs.apiPatterns {
		if pattern.MatchString(path) {
			score += 15
			factors = append(factors, "api_endpoint")
			break
		}
	}

	// User-related endpoint
	for _, pattern := range rs.userPatterns {
		if pattern.MatchString(path) {
			score += 20
			factors = append(factors, "user_data")
			break
		}
	}

	// Payment-related endpoint
	for _, pattern := range rs.paymentPatterns {
		if pattern.MatchString(path) {
			score += 25
			factors = append(factors, "payment_data")
			break
		}
	}

	// File operation endpoint
	for _, pattern := range rs.filePatterns {
		if pattern.MatchString(path) {
			score += 15
			factors = append(factors, "file_operations")
			break
		}
	}

	// Depth scoring (deeper paths often more sensitive)
	depth := strings.Count(path, "/")
	if depth > 3 {
		score += (depth - 3) * 2
		factors = append(factors, "deep_path")
	}

	return score, factors
}

// scoreByMethod analyzes HTTP method for risk indicators
func (rs *RiskScorer) scoreByMethod(method string) (int, string) {
	switch strings.ToUpper(method) {
	case "DELETE":
		return 20, "destructive_method"
	case "PUT", "PATCH":
		return 15, "modification_method"
	case "POST":
		return 10, "creation_method"
	case "GET":
		return 5, ""
	case "HEAD", "OPTIONS":
		return 2, ""
	default:
		return 8, "unusual_method"
	}
}

// scoreByResponse analyzes response for risk indicators
func (rs *RiskScorer) scoreByResponse(response *http.Response) (int, []string) {
	score := 0
	factors := []string{}

	// Status code analysis
	switch {
	case response.StatusCode == 200:
		score += 10
		factors = append(factors, "successful_response")
	case response.StatusCode >= 400 && response.StatusCode < 500:
		score += 5
		factors = append(factors, "client_error")
	case response.StatusCode >= 500:
		score += 15
		factors = append(factors, "server_error")
	case response.StatusCode >= 300 && response.StatusCode < 400:
		score += 3
		factors = append(factors, "redirect")
	}

	// Content length analysis
	if response.BodyLength > 10000 {
		score += 5
		factors = append(factors, "large_response")
	}

	// TODO: Add header analysis when available
	// TODO: Add body content analysis for sensitive data

	return score, factors
}

// calculateRiskLevel converts numeric score to risk level
func (rs *RiskScorer) calculateRiskLevel(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 60:
		return RiskHigh
	case score >= 40:
		return RiskMedium
	case score >= 20:
		return RiskLow
	default:
		return RiskInfo
	}
}

// assessBusinessImpact determines business impact based on factors
func (rs *RiskScorer) assessBusinessImpact(endpoint string, factors []string) string {
	for _, factor := range factors {
		switch factor {
		case "admin_panel":
			return "HIGH - Administrative access could lead to complete system compromise"
		case "payment_data":
			return "CRITICAL - Payment data exposure could lead to financial fraud"
		case "user_data":
			return "HIGH - User data exposure could violate privacy regulations"
		case "api_endpoint":
			return "MEDIUM - API endpoints often expose sensitive business logic"
		}
	}
	return "LOW - Standard endpoint with limited business impact"
}

// assessExploitability determines how easily the endpoint can be exploited
func (rs *RiskScorer) assessExploitability(method string, factors []string) string {
	hasDestructive := false
	hasAuth := false

	for _, factor := range factors {
		if factor == "destructive_method" || factor == "modification_method" {
			hasDestructive = true
		}
		if factor == "user_data" || factor == "admin_panel" {
			hasAuth = true
		}
	}

	if hasDestructive && hasAuth {
		return "HIGH - Authenticated destructive operations"
	} else if hasDestructive {
		return "MEDIUM - Destructive operations may be unprotected"
	} else if hasAuth {
		return "MEDIUM - Authentication bypass may be possible"
	}

	return "LOW - Limited exploitation potential"
}

// determineAccessLevel determines the required access level
func (rs *RiskScorer) determineAccessLevel(factors []string) string {
	for _, factor := range factors {
		switch factor {
		case "admin_panel":
			return "ADMINISTRATIVE"
		case "user_data":
			return "AUTHENTICATED"
		case "api_endpoint":
			return "API_KEY"
		}
	}
	return "PUBLIC"
}

// assessDataSensitivity determines data sensitivity level
func (rs *RiskScorer) assessDataSensitivity(factors []string) string {
	for _, factor := range factors {
		switch factor {
		case "payment_data":
			return "PCI - Payment Card Industry data"
		case "user_data":
			return "PII - Personally Identifiable Information"
		case "admin_panel":
			return "CONFIDENTIAL - Administrative data"
		}
	}
	return "PUBLIC - No sensitive data detected"
}

// ScoreVulnerability creates a vulnerability assessment
func (rs *RiskScorer) ScoreVulnerability(vulnType VulnerabilityType, endpoint, method string, evidence []string, payload, response string) *VulnerabilityAssessment {
	baseScore := rs.getBaseVulnerabilityScore(vulnType)
	riskLevel := rs.getVulnerabilityRiskLevel(vulnType)

	// Adjust score based on endpoint sensitivity
	endpointScore, _ := rs.scoreByPath(endpoint)
	adjustedScore := baseScore + (endpointScore / 2)

	if adjustedScore > 100 {
		adjustedScore = 100
	}

	// Recalculate risk level based on adjusted score
	adjustedRiskLevel := rs.calculateRiskLevel(adjustedScore)
	if adjustedRiskLevel > riskLevel {
		riskLevel = adjustedRiskLevel
	}

	return &VulnerabilityAssessment{
		VulnerabilityType: vulnType,
		Endpoint:          endpoint,
		Method:            method,
		RiskLevel:         riskLevel,
		Score:             adjustedScore,
		Evidence:          evidence,
		Payload:           payload,
		Response:          response,
		BusinessImpact:    rs.getVulnerabilityBusinessImpact(vulnType),
		Remediation:       rs.getVulnerabilityRemediation(vulnType),
		CVSS:              rs.getVulnerabilityCVSS(vulnType),
		References:        rs.getVulnerabilityReferences(vulnType),
		Timestamp:         time.Now(),
	}
}

// getBaseVulnerabilityScore returns base score for vulnerability type
func (rs *RiskScorer) getBaseVulnerabilityScore(vulnType VulnerabilityType) int {
	switch vulnType {
	case VulnIDOR:
		return 70
	case VulnAuthBypass:
		return 85
	case VulnSQLi:
		return 90
	case VulnCommandInjection:
		return 95
	case VulnPathTraversal:
		return 75
	case VulnSensitiveDataExposure:
		return 65
	case VulnAdminPanelAccess:
		return 80
	case VulnAPIKeyExposure:
		return 70
	case VulnWeakAuthentication:
		return 60
	case VulnRateLimitBypass:
		return 45
	case VulnBusinessLogicFlaw:
		return 55
	default:
		return 40
	}
}

// getVulnerabilityRiskLevel returns initial risk level for vulnerability type
func (rs *RiskScorer) getVulnerabilityRiskLevel(vulnType VulnerabilityType) RiskLevel {
	switch vulnType {
	case VulnCommandInjection, VulnSQLi:
		return RiskCritical
	case VulnAuthBypass, VulnAdminPanelAccess:
		return RiskHigh
	case VulnIDOR, VulnPathTraversal, VulnAPIKeyExposure:
		return RiskHigh
	case VulnSensitiveDataExposure, VulnWeakAuthentication:
		return RiskMedium
	case VulnBusinessLogicFlaw, VulnRateLimitBypass:
		return RiskMedium
	default:
		return RiskLow
	}
}

// getVulnerabilityBusinessImpact returns business impact description
func (rs *RiskScorer) getVulnerabilityBusinessImpact(vulnType VulnerabilityType) string {
	switch vulnType {
	case VulnCommandInjection:
		return "CRITICAL - Complete server compromise possible"
	case VulnSQLi:
		return "CRITICAL - Database compromise and data theft possible"
	case VulnAuthBypass:
		return "HIGH - Unauthorized access to protected resources"
	case VulnIDOR:
		return "HIGH - Access to other users' data and resources"
	case VulnAdminPanelAccess:
		return "HIGH - Administrative control over application"
	case VulnPathTraversal:
		return "HIGH - Access to sensitive files and system information"
	case VulnAPIKeyExposure:
		return "MEDIUM - Potential service abuse and data access"
	case VulnSensitiveDataExposure:
		return "MEDIUM - Privacy violations and regulatory compliance issues"
	case VulnWeakAuthentication:
		return "MEDIUM - Account takeover and unauthorized access"
	case VulnBusinessLogicFlaw:
		return "MEDIUM - Abuse of application functionality"
	case VulnRateLimitBypass:
		return "LOW - Potential for brute force and resource abuse"
	default:
		return "Variable business impact"
	}
}

// getVulnerabilityRemediation returns remediation guidance
func (rs *RiskScorer) getVulnerabilityRemediation(vulnType VulnerabilityType) string {
	switch vulnType {
	case VulnCommandInjection:
		return "Implement input validation, use parameterized commands, apply principle of least privilege"
	case VulnSQLi:
		return "Use parameterized queries, input validation, and least privilege database access"
	case VulnAuthBypass:
		return "Review authentication logic, implement proper session management, use secure tokens"
	case VulnIDOR:
		return "Implement proper authorization checks, use indirect object references, validate user permissions"
	case VulnAdminPanelAccess:
		return "Restrict admin panel access, implement strong authentication, use IP whitelisting"
	case VulnPathTraversal:
		return "Validate file paths, use absolute paths, implement file access controls"
	case VulnAPIKeyExposure:
		return "Rotate API keys, implement proper key management, use environment variables"
	case VulnSensitiveDataExposure:
		return "Encrypt sensitive data, implement proper access controls, review data exposure"
	case VulnWeakAuthentication:
		return "Implement strong password policies, use multi-factor authentication, secure session management"
	case VulnBusinessLogicFlaw:
		return "Review business logic implementation, implement proper validation, use rate limiting"
	case VulnRateLimitBypass:
		return "Implement robust rate limiting, use CAPTCHA, monitor for abuse patterns"
	default:
		return "Follow security best practices for the specific vulnerability type"
	}
}

// getVulnerabilityCVSS returns CVSS score for vulnerability type
func (rs *RiskScorer) getVulnerabilityCVSS(vulnType VulnerabilityType) float64 {
	switch vulnType {
	case VulnCommandInjection:
		return 9.8
	case VulnSQLi:
		return 9.1
	case VulnAuthBypass:
		return 8.1
	case VulnAdminPanelAccess:
		return 7.5
	case VulnIDOR:
		return 6.5
	case VulnPathTraversal:
		return 6.1
	case VulnAPIKeyExposure:
		return 5.3
	case VulnSensitiveDataExposure:
		return 5.0
	case VulnWeakAuthentication:
		return 4.3
	case VulnBusinessLogicFlaw:
		return 4.0
	case VulnRateLimitBypass:
		return 3.1
	default:
		return 0.0
	}
}

// getVulnerabilityReferences returns reference links for vulnerability type
func (rs *RiskScorer) getVulnerabilityReferences(vulnType VulnerabilityType) []string {
	switch vulnType {
	case VulnCommandInjection:
		return []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
			"https://cwe.mitre.org/data/definitions/78.html",
		}
	case VulnSQLi:
		return []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cwe.mitre.org/data/definitions/89.html",
		}
	case VulnAuthBypass:
		return []string{
			"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
			"https://cwe.mitre.org/data/definitions/287.html",
		}
	case VulnIDOR:
		return []string{
			"https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
			"https://cwe.mitre.org/data/definitions/639.html",
		}
	default:
		return []string{
			"https://owasp.org/www-project-top-ten/",
			"https://cwe.mitre.org/",
		}
	}
}
