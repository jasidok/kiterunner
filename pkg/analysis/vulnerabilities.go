package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/assetnote/kiterunner/pkg/http"
	"github.com/assetnote/kiterunner/pkg/kiterunner"
	"github.com/assetnote/kiterunner/pkg/log"
)

// VulnerabilityDetector implements RequestValidator to detect vulnerabilities during scanning
type VulnerabilityDetector struct {
	Findings []VulnerabilityFinding
}

// VulnerabilityFinding represents a discovered vulnerability
type VulnerabilityFinding struct {
	Type        string
	Severity    string
	Description string
	Evidence    string
	Response    http.Response
	Request     *http.Route
}

// NewVulnerabilityDetector creates a new vulnerability detector
func NewVulnerabilityDetector() *VulnerabilityDetector {
	return &VulnerabilityDetector{
		Findings: make([]VulnerabilityFinding, 0),
	}
}

// Validate implements the RequestValidator interface
func (vd *VulnerabilityDetector) Validate(r http.Response, wildcardResponses []kiterunner.WildcardResponse, c *kiterunner.Config) error {
	// Detect various vulnerabilities and log findings
	vd.detectIDOR(r)
	vd.detectPathTraversal(r)
	vd.detectInformationDisclosure(r)
	vd.detectAuthenticationBypass(r)
	vd.detectSensitiveDataExposure(r)
	vd.detectErrorMessageLeakage(r)
	vd.detectDebugModeEnabled(r)
	vd.detectAdminPanelAccess(r)

	// Always return nil so the response is still processed normally
	// Vulnerability findings are stored separately
	return nil
}

// detectIDOR looks for potential Insecure Direct Object Reference vulnerabilities
func (vd *VulnerabilityDetector) detectIDOR(r http.Response) {
	path := string(r.OriginRequest.Route.Path)

	// Look for numeric IDs in path that might be manipulatable
	idRegex := regexp.MustCompile(`/(\d+)(?:/|$|\?)`)
	if matches := idRegex.FindStringSubmatch(path); len(matches) > 1 {
		// Check if response contains user-specific data
		body := string(r.Body)
		if vd.containsUserData(body) && r.StatusCode == 200 {
			finding := VulnerabilityFinding{
				Type:        "IDOR",
				Severity:    "High",
				Description: fmt.Sprintf("Potential IDOR vulnerability with ID parameter: %s", matches[1]),
				Evidence:    fmt.Sprintf("Response contains user data for ID %s", matches[1]),
				Response:    r,
				Request:     r.OriginRequest.Route,
			}
			vd.addFinding(finding)
		}
	}
}

// detectPathTraversal looks for path traversal vulnerabilities
func (vd *VulnerabilityDetector) detectPathTraversal(r http.Response) {
	body := string(r.Body)

	// Common path traversal indicators
	pathTraversalIndicators := []string{
		"root:x:0:0:",             // /etc/passwd content
		"[boot loader]",           // boot.ini content
		"Windows Registry Editor", // Windows registry
		"<Directory",              // Apache config
		"/bin/bash",               // Common shell paths
		"/usr/bin",
		"#!/bin/sh",
		"#!/bin/bash",
	}

	for _, indicator := range pathTraversalIndicators {
		if strings.Contains(body, indicator) {
			finding := VulnerabilityFinding{
				Type:        "Path Traversal",
				Severity:    "High",
				Description: "Path traversal vulnerability detected",
				Evidence:    fmt.Sprintf("Response contains system file content: %s", indicator),
				Response:    r,
				Request:     r.OriginRequest.Route,
			}
			vd.addFinding(finding)
			break
		}
	}
}

// detectInformationDisclosure looks for information disclosure vulnerabilities
func (vd *VulnerabilityDetector) detectInformationDisclosure(r http.Response) {
	body := string(r.Body)

	// Check for stack traces
	stackTracePatterns := []string{
		"at java.",
		"at org.springframework",
		"at com.mysql",
		"Traceback (most recent call last):",
		"Error in line",
		"Fatal error:",
		"Warning:",
		"Notice:",
		"PHP Stack trace:",
		"System.Exception:",
		"Microsoft.AspNet",
		"ORA-[0-9]{5}",
	}

	for _, pattern := range stackTracePatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			finding := VulnerabilityFinding{
				Type:        "Information Disclosure",
				Severity:    "Medium",
				Description: "Stack trace or error information disclosed",
				Evidence:    pattern,
				Response:    r,
				Request:     r.OriginRequest.Route,
			}
			vd.addFinding(finding)
			break
		}
	}
}

// detectAuthenticationBypass looks for authentication bypass indicators
func (vd *VulnerabilityDetector) detectAuthenticationBypass(r http.Response) {
	path := string(r.OriginRequest.Route.Path)

	// Check if accessing admin/protected paths without authentication returns 200
	protectedPaths := []string{
		"/admin", "/administrator", "/dashboard", "/control", "/manage",
		"/panel", "/console", "/config", "/settings", "/system",
	}

	for _, protectedPath := range protectedPaths {
		if strings.Contains(strings.ToLower(path), protectedPath) && r.StatusCode == 200 {
			// Check if response doesn't look like a login page
			body := strings.ToLower(string(r.Body))
			if !strings.Contains(body, "login") && !strings.Contains(body, "password") &&
				!strings.Contains(body, "sign in") && !strings.Contains(body, "authentication") {
				finding := VulnerabilityFinding{
					Type:        "Authentication Bypass",
					Severity:    "Critical",
					Description: "Protected admin area accessible without authentication",
					Evidence:    fmt.Sprintf("Admin path %s returned 200 without auth headers", path),
					Response:    r,
					Request:     r.OriginRequest.Route,
				}
				vd.addFinding(finding)
			}
		}
	}
}

// detectSensitiveDataExposure looks for exposed sensitive data
func (vd *VulnerabilityDetector) detectSensitiveDataExposure(r http.Response) {
	body := string(r.Body)

	// Email pattern
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emails := emailRegex.FindAllString(body, -1); len(emails) > 0 {
		finding := VulnerabilityFinding{
			Type:        "Data Exposure",
			Severity:    "Medium",
			Description: "Email addresses exposed in response",
			Evidence:    fmt.Sprintf("Found %d email addresses", len(emails)),
			Response:    r,
			Request:     r.OriginRequest.Route,
		}
		vd.addFinding(finding)
	}

	// API keys and tokens
	tokenPatterns := []string{
		`(?i)api[_-]?key['":\s]*[a-zA-Z0-9]{20,}`,
		`(?i)secret['":\s]*[a-zA-Z0-9]{20,}`,
		`(?i)token['":\s]*[a-zA-Z0-9]{20,}`,
		`(?i)password['":\s]*[a-zA-Z0-9]{8,}`,
		`(?i)aws[_-]?access[_-]?key['":\s]*[A-Z0-9]{20}`,
		`(?i)sk_live_[a-zA-Z0-9]{24,}`, // Stripe keys
	}

	for _, pattern := range tokenPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			finding := VulnerabilityFinding{
				Type:        "Sensitive Data Exposure",
				Severity:    "High",
				Description: "Potential API keys or secrets exposed",
				Evidence:    "Response contains patterns matching API keys or secrets",
				Response:    r,
				Request:     r.OriginRequest.Route,
			}
			vd.addFinding(finding)
			break
		}
	}
}

// detectErrorMessageLeakage looks for verbose error messages
func (vd *VulnerabilityDetector) detectErrorMessageLeakage(r http.Response) {
	if r.StatusCode >= 400 && r.StatusCode < 600 {
		body := string(r.Body)

		// Check for database error messages
		dbErrors := []string{
			"SQL syntax error", "mysql_", "ORA-", "PostgreSQL",
			"sqlite", "SQLSTATE", "database error", "SQL Server",
			"OLE DB", "ODBC", "JET Database Engine",
		}

		for _, dbError := range dbErrors {
			if strings.Contains(strings.ToLower(body), strings.ToLower(dbError)) {
				finding := VulnerabilityFinding{
					Type:        "Information Disclosure",
					Severity:    "Medium",
					Description: "Database error message disclosed",
					Evidence:    dbError,
					Response:    r,
					Request:     r.OriginRequest.Route,
				}
				vd.addFinding(finding)
				break
			}
		}
	}
}

// detectDebugModeEnabled looks for debug mode indicators
func (vd *VulnerabilityDetector) detectDebugModeEnabled(r http.Response) {
	// Check headers for debug information
	for _, header := range r.Headers {
		headerName := strings.ToLower(string(header.Key))
		headerValue := strings.ToLower(string(header.Value))

		if strings.Contains(headerName, "debug") || strings.Contains(headerValue, "debug") ||
			strings.Contains(headerValue, "development") || strings.Contains(headerValue, "trace") {
			finding := VulnerabilityFinding{
				Type:        "Information Disclosure",
				Severity:    "Low",
				Description: "Debug mode or development information in headers",
				Evidence:    fmt.Sprintf("Header %s: %s", header.Key, header.Value),
				Response:    r,
				Request:     r.OriginRequest.Route,
			}
			vd.addFinding(finding)
		}
	}
}

// detectAdminPanelAccess looks for accessible admin panels
func (vd *VulnerabilityDetector) detectAdminPanelAccess(r http.Response) {
	if r.StatusCode == 200 {
		body := strings.ToLower(string(r.Body))
		path := strings.ToLower(string(r.OriginRequest.Route.Path))

		// Check for admin panel indicators
		adminIndicators := []string{
			"admin panel", "administration", "dashboard", "control panel",
			"management console", "admin area", "administrator",
		}

		// Only trigger if path suggests admin area
		if strings.Contains(path, "admin") || strings.Contains(path, "dashboard") ||
			strings.Contains(path, "control") || strings.Contains(path, "manage") {
			for _, indicator := range adminIndicators {
				if strings.Contains(body, indicator) {
					finding := VulnerabilityFinding{
						Type:        "Unauthorized Access",
						Severity:    "High",
						Description: "Admin panel accessible",
						Evidence:    fmt.Sprintf("Admin panel found at %s", path),
						Response:    r,
						Request:     r.OriginRequest.Route,
					}
					vd.addFinding(finding)
					break
				}
			}
		}
	}
}

// containsUserData checks if response contains user-specific data
func (vd *VulnerabilityDetector) containsUserData(body string) bool {
	userDataIndicators := []string{
		"user_id", "username", "email", "profile", "account",
		"personal", "private", "confidential", "ssn", "phone",
		"address", "credit_card", "password", "token",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range userDataIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

// addFinding adds a vulnerability finding and logs it
func (vd *VulnerabilityDetector) addFinding(finding VulnerabilityFinding) {
	vd.Findings = append(vd.Findings, finding)

	// Log the finding immediately
	log.Info().
		Str("type", finding.Type).
		Str("severity", finding.Severity).
		Str("description", finding.Description).
		Str("evidence", finding.Evidence).
		Bytes("path", finding.Request.Path).
		Str("method", string(finding.Request.Method)).
		Int("status", finding.Response.StatusCode).
		Msg("🚨 VULNERABILITY DETECTED")
}

// GetFindings returns all discovered vulnerability findings
func (vd *VulnerabilityDetector) GetFindings() []VulnerabilityFinding {
	return vd.Findings
}

// GetHighSeverityFindings returns only high and critical severity findings
func (vd *VulnerabilityDetector) GetHighSeverityFindings() []VulnerabilityFinding {
	var highSeverity []VulnerabilityFinding
	for _, finding := range vd.Findings {
		if finding.Severity == "High" || finding.Severity == "Critical" {
			highSeverity = append(highSeverity, finding)
		}
	}
	return highSeverity
}

// PrintSummary prints a summary of all findings
func (vd *VulnerabilityDetector) PrintSummary() {
	if len(vd.Findings) == 0 {
		log.Info().Msg("No vulnerabilities detected")
		return
	}

	critical := 0
	high := 0
	medium := 0
	low := 0

	for _, finding := range vd.Findings {
		switch finding.Severity {
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		case "Low":
			low++
		}
	}

	log.Info().
		Int("critical", critical).
		Int("high", high).
		Int("medium", medium).
		Int("low", low).
		Int("total", len(vd.Findings)).
		Msg("🔍 VULNERABILITY SCAN SUMMARY")
}
