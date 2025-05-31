package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/assetnote/kiterunner/pkg/http"
	"github.com/assetnote/kiterunner/pkg/log"
)

// TechnologyFingerprint represents a detected technology
type TechnologyFingerprint struct {
	Technology string
	Version    string
	Confidence float64
	Evidence   string
}

// ResponseIntelligence extracts intelligence from HTTP responses
type ResponseIntelligence struct {
	Technologies  []TechnologyFingerprint
	APIs          []string
	Endpoints     []string
	Parameters    []string
	Secrets       []string
	ErrorMessages []string
	Frameworks    []string
	Databases     []string
	CloudServices []string
}

// ResponseAnalyzer analyzes responses for intelligence gathering
type ResponseAnalyzer struct {
	intelligence map[string]*ResponseIntelligence // keyed by target host
}

// NewResponseAnalyzer creates a new response analyzer
func NewResponseAnalyzer() *ResponseAnalyzer {
	return &ResponseAnalyzer{
		intelligence: make(map[string]*ResponseIntelligence),
	}
}

// AnalyzeResponse extracts intelligence from a response
func (ra *ResponseAnalyzer) AnalyzeResponse(r http.Response) *ResponseIntelligence {
	targetKey := string(r.OriginRequest.Target.Bytes())

	if ra.intelligence[targetKey] == nil {
		ra.intelligence[targetKey] = &ResponseIntelligence{
			Technologies:  make([]TechnologyFingerprint, 0),
			APIs:          make([]string, 0),
			Endpoints:     make([]string, 0),
			Parameters:    make([]string, 0),
			Secrets:       make([]string, 0),
			ErrorMessages: make([]string, 0),
			Frameworks:    make([]string, 0),
			Databases:     make([]string, 0),
			CloudServices: make([]string, 0),
		}
	}

	intelligence := ra.intelligence[targetKey]

	// Analyze different aspects
	ra.detectTechnologies(r, intelligence)
	ra.extractAPIPaths(r, intelligence)
	ra.extractParameters(r, intelligence)
	ra.detectFrameworks(r, intelligence)
	ra.detectDatabases(r, intelligence)
	ra.detectCloudServices(r, intelligence)
	ra.extractSecrets(r, intelligence)
	ra.extractErrorMessages(r, intelligence)

	return intelligence
}

// detectTechnologies identifies technologies from headers and response content
func (ra *ResponseAnalyzer) detectTechnologies(r http.Response, intel *ResponseIntelligence) {
	// Check headers for technology indicators
	for _, header := range r.Headers {
		headerName := strings.ToLower(string(header.Key))
		headerValue := string(header.Value)

		var tech TechnologyFingerprint
		found := false

		switch headerName {
		case "server":
			tech = ra.parseServerHeader(headerValue)
			found = true
		case "x-powered-by":
			tech = ra.parseXPoweredByHeader(headerValue)
			found = true
		case "x-aspnet-version":
			tech = TechnologyFingerprint{
				Technology: "ASP.NET",
				Version:    headerValue,
				Confidence: 0.9,
				Evidence:   fmt.Sprintf("Header: %s", headerValue),
			}
			found = true
		case "x-framework":
			tech = TechnologyFingerprint{
				Technology: headerValue,
				Version:    "",
				Confidence: 0.8,
				Evidence:   "X-Framework header",
			}
			found = true
		}

		if found && !ra.technologyExists(intel.Technologies, tech.Technology) {
			intel.Technologies = append(intel.Technologies, tech)
		}
	}

	// Analyze response body for technology indicators
	body := string(r.Body)
	ra.detectBodyTechnologies(body, intel)
}

// parseServerHeader extracts technology information from Server header
func (ra *ResponseAnalyzer) parseServerHeader(serverHeader string) TechnologyFingerprint {
	patterns := map[string]*regexp.Regexp{
		"nginx":  regexp.MustCompile(`nginx/([0-9.]+)`),
		"Apache": regexp.MustCompile(`Apache/([0-9.]+)`),
		"IIS":    regexp.MustCompile(`Microsoft-IIS/([0-9.]+)`),
		"Tomcat": regexp.MustCompile(`Apache-Coyote/([0-9.]+)`),
		"Jetty":  regexp.MustCompile(`Jetty\(([0-9.]+)`),
	}

	for tech, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(serverHeader); len(matches) > 1 {
			return TechnologyFingerprint{
				Technology: tech,
				Version:    matches[1],
				Confidence: 0.95,
				Evidence:   fmt.Sprintf("Server header: %s", serverHeader),
			}
		}
	}

	// Fallback to simple string matching
	for tech := range patterns {
		if strings.Contains(strings.ToLower(serverHeader), strings.ToLower(tech)) {
			return TechnologyFingerprint{
				Technology: tech,
				Version:    "",
				Confidence: 0.7,
				Evidence:   fmt.Sprintf("Server header: %s", serverHeader),
			}
		}
	}

	return TechnologyFingerprint{
		Technology: serverHeader,
		Version:    "",
		Confidence: 0.5,
		Evidence:   "Server header",
	}
}

// parseXPoweredByHeader extracts technology from X-Powered-By header
func (ra *ResponseAnalyzer) parseXPoweredByHeader(poweredBy string) TechnologyFingerprint {
	patterns := map[string]*regexp.Regexp{
		"PHP":         regexp.MustCompile(`PHP/([0-9.]+)`),
		"ASP.NET":     regexp.MustCompile(`ASP\.NET`),
		"Express":     regexp.MustCompile(`Express`),
		"Django":      regexp.MustCompile(`Django/([0-9.]+)`),
		"Rails":       regexp.MustCompile(`Rails ([0-9.]+)`),
		"Laravel":     regexp.MustCompile(`Laravel`),
		"CodeIgniter": regexp.MustCompile(`CodeIgniter`),
	}

	for tech, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(poweredBy); len(matches) > 1 {
			return TechnologyFingerprint{
				Technology: tech,
				Version:    matches[1],
				Confidence: 0.9,
				Evidence:   fmt.Sprintf("X-Powered-By: %s", poweredBy),
			}
		} else if pattern.MatchString(poweredBy) {
			return TechnologyFingerprint{
				Technology: tech,
				Version:    "",
				Confidence: 0.85,
				Evidence:   fmt.Sprintf("X-Powered-By: %s", poweredBy),
			}
		}
	}

	return TechnologyFingerprint{
		Technology: poweredBy,
		Version:    "",
		Confidence: 0.6,
		Evidence:   "X-Powered-By header",
	}
}

// detectBodyTechnologies analyzes response body for technology indicators
func (ra *ResponseAnalyzer) detectBodyTechnologies(body string, intel *ResponseIntelligence) {
	bodyLower := strings.ToLower(body)

	// Framework detection patterns
	frameworks := map[string][]string{
		"Django":    {"django", "csrf_token", "{% if ", "{% for "},
		"Rails":     {"rails", "csrf-token", "_method", "authenticity_token"},
		"Laravel":   {"laravel", "_token", "csrf-token", "laravel_session"},
		"Spring":    {"spring", "spring-boot", "spring-mvc", "org.springframework"},
		"Express":   {"express", "connect.sid", "express-session"},
		"Flask":     {"flask", "session", "csrf_token", "werkzeug"},
		"React":     {"react", "_reactListening", "react-dom", "__REACT_DEVTOOLS"},
		"Angular":   {"angular", "ng-", "angular.js", "_angular"},
		"Vue":       {"vue", "vue.js", "v-model", "v-if"},
		"jQuery":    {"jquery", "$.ajax", "$(document)", "jquery.min.js"},
		"Bootstrap": {"bootstrap", "btn btn-", "container-fluid", "bootstrap.min.css"},
	}

	for framework, patterns := range frameworks {
		count := 0
		for _, pattern := range patterns {
			if strings.Contains(bodyLower, pattern) {
				count++
			}
		}

		if count >= 2 && !ra.technologyExists(intel.Technologies, framework) {
			tech := TechnologyFingerprint{
				Technology: framework,
				Version:    "",
				Confidence: float64(count) / float64(len(patterns)),
				Evidence:   fmt.Sprintf("Found %d/%d framework indicators", count, len(patterns)),
			}
			intel.Technologies = append(intel.Technologies, tech)
		}
	}
}

// extractAPIPaths extracts API endpoint information from responses
func (ra *ResponseAnalyzer) extractAPIPaths(r http.Response, intel *ResponseIntelligence) {
	body := string(r.Body)

	// Look for API paths in response content
	apiPatterns := []*regexp.Regexp{
		regexp.MustCompile(`"(\/api\/[^"]+)"`),
		regexp.MustCompile(`'(\/api\/[^']+)'`),
		regexp.MustCompile(`href="([^"]*\/api\/[^"]*)""`),
		regexp.MustCompile(`action="([^"]*\/api\/[^"]*)""`),
		regexp.MustCompile(`url:\s*["']([^"']*\/api\/[^"']*)`),
		regexp.MustCompile(`fetch\(["']([^"']*\/api\/[^"']*)`),
		regexp.MustCompile(`axios\.[^(]+\(["']([^"']*\/api\/[^"']*)`),
	}

	for _, pattern := range apiPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if !ra.stringInSlice(endpoint, intel.APIs) {
					intel.APIs = append(intel.APIs, endpoint)
				}
			}
		}
	}
}

// extractParameters extracts parameter names from responses
func (ra *ResponseAnalyzer) extractParameters(r http.Response, intel *ResponseIntelligence) {
	body := string(r.Body)

	// Extract parameter names from JSON responses
	jsonParamPattern := regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_]*)":\s*[^{]`)
	matches := jsonParamPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			param := match[1]
			if len(param) > 2 && !ra.stringInSlice(param, intel.Parameters) {
				intel.Parameters = append(intel.Parameters, param)
			}
		}
	}

	// Extract parameter names from form inputs
	inputPattern := regexp.MustCompile(`<input[^>]+name=["']([^"']+)["']`)
	matches = inputPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			param := match[1]
			if !ra.stringInSlice(param, intel.Parameters) {
				intel.Parameters = append(intel.Parameters, param)
			}
		}
	}
}

// detectFrameworks identifies web frameworks
func (ra *ResponseAnalyzer) detectFrameworks(r http.Response, intel *ResponseIntelligence) {
	body := strings.ToLower(string(r.Body))

	frameworkIndicators := map[string][]string{
		"WordPress":  {"wp-content", "wp-includes", "wordpress"},
		"Drupal":     {"drupal", "/sites/default", "drupal.js"},
		"Joomla":     {"joomla", "/administrator", "joomla.js"},
		"Magento":    {"magento", "mage/cookies.js", "varien"},
		"Shopify":    {"shopify", "cdn.shopify.com", "shopify-analytics"},
		"Salesforce": {"salesforce", "force.com", "lightning"},
		"SharePoint": {"sharepoint", "_layouts", "microsoft sharepoint"},
	}

	for framework, indicators := range frameworkIndicators {
		for _, indicator := range indicators {
			if strings.Contains(body, indicator) {
				if !ra.stringInSlice(framework, intel.Frameworks) {
					intel.Frameworks = append(intel.Frameworks, framework)
				}
				break
			}
		}
	}
}

// detectDatabases identifies database technologies
func (ra *ResponseAnalyzer) detectDatabases(r http.Response, intel *ResponseIntelligence) {
	body := strings.ToLower(string(r.Body))

	dbIndicators := map[string][]string{
		"MySQL":         {"mysql", "mysqld", "mysql server"},
		"PostgreSQL":    {"postgresql", "postgres", "pg_"},
		"MongoDB":       {"mongodb", "mongo", "mongod"},
		"Redis":         {"redis", "redis-server"},
		"Oracle":        {"oracle", "ora-", "oracle database"},
		"SQL Server":    {"sql server", "mssql", "microsoft sql"},
		"SQLite":        {"sqlite", "sqlite3"},
		"CouchDB":       {"couchdb", "apache couchdb"},
		"Elasticsearch": {"elasticsearch", "elastic search"},
	}

	for db, indicators := range dbIndicators {
		for _, indicator := range indicators {
			if strings.Contains(body, indicator) {
				if !ra.stringInSlice(db, intel.Databases) {
					intel.Databases = append(intel.Databases, db)
				}
				break
			}
		}
	}
}

// detectCloudServices identifies cloud service usage
func (ra *ResponseAnalyzer) detectCloudServices(r http.Response, intel *ResponseIntelligence) {
	body := strings.ToLower(string(r.Body))

	// Check headers for cloud indicators
	for _, header := range r.Headers {
		headerValue := strings.ToLower(string(header.Value))

		cloudIndicators := map[string]string{
			"AWS":          "amazonaws",
			"Google Cloud": "googleapi",
			"Azure":        "azure",
			"Cloudflare":   "cloudflare",
			"Fastly":       "fastly",
			"Akamai":       "akamai",
		}

		for service, indicator := range cloudIndicators {
			if strings.Contains(headerValue, indicator) {
				if !ra.stringInSlice(service, intel.CloudServices) {
					intel.CloudServices = append(intel.CloudServices, service)
				}
			}
		}
	}

	// Check body for cloud service indicators
	cloudBodyIndicators := map[string][]string{
		"AWS":          {"amazonaws.com", "aws-", "s3."},
		"Google Cloud": {"googleapis.com", "gcp-", "google cloud"},
		"Azure":        {"azure.com", "microsoft azure", "azure-"},
		"Heroku":       {"heroku", "herokuapp.com"},
		"Netlify":      {"netlify", "netlify.com"},
		"Vercel":       {"vercel", "vercel.com", "now.sh"},
	}

	for service, indicators := range cloudBodyIndicators {
		for _, indicator := range indicators {
			if strings.Contains(body, indicator) {
				if !ra.stringInSlice(service, intel.CloudServices) {
					intel.CloudServices = append(intel.CloudServices, service)
				}
				break
			}
		}
	}
}

// extractSecrets looks for potential secrets in responses
func (ra *ResponseAnalyzer) extractSecrets(r http.Response, intel *ResponseIntelligence) {
	body := string(r.Body)

	secretPatterns := map[string]*regexp.Regexp{
		"API Key":    regexp.MustCompile(`(?i)api[_-]?key['":\s=]*([a-zA-Z0-9]{20,})`),
		"Secret":     regexp.MustCompile(`(?i)secret['":\s=]*([a-zA-Z0-9]{20,})`),
		"Token":      regexp.MustCompile(`(?i)token['":\s=]*([a-zA-Z0-9]{20,})`),
		"Password":   regexp.MustCompile(`(?i)password['":\s=]*([a-zA-Z0-9]{8,})`),
		"AWS Key":    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Stripe Key": regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),
		"JWT":        regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	}

	for secretType, pattern := range secretPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 0 {
				secret := fmt.Sprintf("%s: %s", secretType, match[0])
				if !ra.stringInSlice(secret, intel.Secrets) {
					intel.Secrets = append(intel.Secrets, secret)
				}
			}
		}
	}
}

// extractErrorMessages extracts useful error messages
func (ra *ResponseAnalyzer) extractErrorMessages(r http.Response, intel *ResponseIntelligence) {
	if r.StatusCode >= 400 {
		body := string(r.Body)

		// Extract structured error messages
		errorPatterns := []*regexp.Regexp{
			regexp.MustCompile(`"message":\s*"([^"]+)"`),
			regexp.MustCompile(`"error":\s*"([^"]+)"`),
			regexp.MustCompile(`<title>([^<]*error[^<]*)</title>`),
			regexp.MustCompile(`Exception:\s*([^\n\r]+)`),
			regexp.MustCompile(`Error:\s*([^\n\r]+)`),
		}

		for _, pattern := range errorPatterns {
			matches := pattern.FindAllStringSubmatch(body, -1)
			for _, match := range matches {
				if len(match) > 1 {
					errorMsg := strings.TrimSpace(match[1])
					if len(errorMsg) > 10 && !ra.stringInSlice(errorMsg, intel.ErrorMessages) {
						intel.ErrorMessages = append(intel.ErrorMessages, errorMsg)
					}
				}
			}
		}
	}
}

// Helper functions
func (ra *ResponseAnalyzer) technologyExists(technologies []TechnologyFingerprint, techName string) bool {
	for _, tech := range technologies {
		if strings.EqualFold(tech.Technology, techName) {
			return true
		}
	}
	return false
}

func (ra *ResponseAnalyzer) stringInSlice(str string, slice []string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// GetIntelligence returns all gathered intelligence for a target
func (ra *ResponseAnalyzer) GetIntelligence(target string) *ResponseIntelligence {
	return ra.intelligence[target]
}

// GetAllIntelligence returns intelligence for all targets
func (ra *ResponseAnalyzer) GetAllIntelligence() map[string]*ResponseIntelligence {
	return ra.intelligence
}

// PrintIntelligenceSummary prints a summary of gathered intelligence
func (ra *ResponseAnalyzer) PrintIntelligenceSummary(target string) {
	intel := ra.intelligence[target]
	if intel == nil {
		log.Info().Str("target", target).Msg("No intelligence gathered for target")
		return
	}

	log.Info().
		Str("target", target).
		Int("technologies", len(intel.Technologies)).
		Int("apis", len(intel.APIs)).
		Int("parameters", len(intel.Parameters)).
		Int("frameworks", len(intel.Frameworks)).
		Int("databases", len(intel.Databases)).
		Int("cloud_services", len(intel.CloudServices)).
		Int("secrets", len(intel.Secrets)).
		Msg("🧠 INTELLIGENCE SUMMARY")

	// Print details if any findings
	if len(intel.Technologies) > 0 {
		for _, tech := range intel.Technologies {
			log.Info().
				Str("technology", tech.Technology).
				Str("version", tech.Version).
				Float64("confidence", tech.Confidence).
				Str("evidence", tech.Evidence).
				Msg("Technology detected")
		}
	}

	if len(intel.Secrets) > 0 {
		log.Warn().
			Int("count", len(intel.Secrets)).
			Msg("🔐 SECRETS DETECTED - Review immediately!")
	}
}
