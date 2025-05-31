package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/assetnote/kiterunner/pkg/http"
	"github.com/assetnote/kiterunner/pkg/scoring"
)

// OutputFormat represents different output formats
type OutputFormat int

const (
	FormatJSON OutputFormat = iota
	FormatXML
	FormatBurp
	FormatNuclei
	FormatMarkdown
	FormatHTML
	FormatCSV
	FormatSARIF
)

// ScanResults represents the complete scan results
type ScanResults struct {
	Metadata        ScanMetadata                      `json:"metadata" xml:"metadata"`
	Targets         []TargetResult                    `json:"targets" xml:"targets>target"`
	Endpoints       []EndpointResult                  `json:"endpoints" xml:"endpoints>endpoint"`
	Risks           []scoring.EndpointRisk            `json:"risks" xml:"risks>risk"`
	Vulnerabilities []scoring.VulnerabilityAssessment `json:"vulnerabilities" xml:"vulnerabilities>vulnerability"`
	Statistics      ScanStatistics                    `json:"statistics" xml:"statistics"`
}

// ScanMetadata holds metadata about the scan
type ScanMetadata struct {
	Version      string    `json:"version" xml:"version"`
	Tool         string    `json:"tool" xml:"tool"`
	StartTime    time.Time `json:"start_time" xml:"start_time"`
	EndTime      time.Time `json:"end_time" xml:"end_time"`
	Duration     string    `json:"duration" xml:"duration"`
	CommandLine  string    `json:"command_line" xml:"command_line"`
	WordlistUsed []string  `json:"wordlist_used" xml:"wordlist_used>wordlist"`
	ConfigFile   string    `json:"config_file,omitempty" xml:"config_file,omitempty"`
	User         string    `json:"user,omitempty" xml:"user,omitempty"`
	Host         string    `json:"host,omitempty" xml:"host,omitempty"`
}

// TargetResult represents results for a specific target
type TargetResult struct {
	URL             string    `json:"url" xml:"url"`
	Status          string    `json:"status" xml:"status"`
	TotalRequests   int       `json:"total_requests" xml:"total_requests"`
	SuccessRequests int       `json:"success_requests" xml:"success_requests"`
	FailedRequests  int       `json:"failed_requests" xml:"failed_requests"`
	StartTime       time.Time `json:"start_time" xml:"start_time"`
	EndTime         time.Time `json:"end_time" xml:"end_time"`
	Duration        string    `json:"duration" xml:"duration"`
	Technology      []string  `json:"technology,omitempty" xml:"technology>tech,omitempty"`
	Errors          []string  `json:"errors,omitempty" xml:"errors>error,omitempty"`
}

// EndpointResult represents a discovered endpoint
type EndpointResult struct {
	URL           string            `json:"url" xml:"url"`
	Method        string            `json:"method" xml:"method"`
	StatusCode    int               `json:"status_code" xml:"status_code"`
	ContentLength int               `json:"content_length" xml:"content_length"`
	ResponseTime  int64             `json:"response_time_ms" xml:"response_time_ms"`
	Headers       map[string]string `json:"headers,omitempty" xml:"headers>header,omitempty"`
	Title         string            `json:"title,omitempty" xml:"title,omitempty"`
	Technology    []string          `json:"technology,omitempty" xml:"technology>tech,omitempty"`
	Parameters    []string          `json:"parameters,omitempty" xml:"parameters>param,omitempty"`
	Redirects     []string          `json:"redirects,omitempty" xml:"redirects>redirect,omitempty"`
	Timestamp     time.Time         `json:"timestamp" xml:"timestamp"`
}

// ScanStatistics holds statistics about the scan
type ScanStatistics struct {
	TotalRequests          int            `json:"total_requests" xml:"total_requests"`
	TotalEndpoints         int            `json:"total_endpoints" xml:"total_endpoints"`
	TotalVulnerabilities   int            `json:"total_vulnerabilities" xml:"total_vulnerabilities"`
	RiskDistribution       map[string]int `json:"risk_distribution" xml:"risk_distribution"`
	StatusCodeDistribution map[int]int    `json:"status_code_distribution" xml:"status_code_distribution"`
	MethodDistribution     map[string]int `json:"method_distribution" xml:"method_distribution"`
	AverageResponseTime    float64        `json:"average_response_time_ms" xml:"average_response_time_ms"`
	RequestsPerSecond      float64        `json:"requests_per_second" xml:"requests_per_second"`
}

// BurpSuiteProject represents a Burp Suite project structure
type BurpSuiteProject struct {
	XMLName  xml.Name      `xml:"burp"`
	Version  string        `xml:"version,attr"`
	Issues   []BurpIssue   `xml:"issue"`
	Requests []BurpRequest `xml:"request"`
}

// BurpIssue represents a Burp Suite issue
type BurpIssue struct {
	XMLName      xml.Name `xml:"issue"`
	SerialNumber int      `xml:"serialNumber"`
	Type         int      `xml:"type"`
	Name         string   `xml:"name"`
	Host         string   `xml:"host"`
	Path         string   `xml:"path"`
	Location     string   `xml:"location"`
	Severity     string   `xml:"severity"`
	Confidence   string   `xml:"confidence"`
	Background   string   `xml:"issueBackground"`
	Detail       string   `xml:"issueDetail"`
	Remediation  string   `xml:"remediationBackground"`
}

// BurpRequest represents a Burp Suite request
type BurpRequest struct {
	XMLName  xml.Name `xml:"request"`
	URL      string   `xml:"url"`
	Method   string   `xml:"method"`
	Request  string   `xml:"request"`
	Response string   `xml:"response"`
	Status   int      `xml:"status"`
	Length   int      `xml:"length"`
}

// NucleiTemplate represents a Nuclei template
type NucleiTemplate struct {
	ID   string           `yaml:"id"`
	Info NucleiInfo       `yaml:"info"`
	HTTP []NucleiHTTPRule `yaml:"http"`
}

// NucleiInfo represents Nuclei template info
type NucleiInfo struct {
	Name        string   `yaml:"name"`
	Author      []string `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
	Reference   []string `yaml:"reference,omitempty"`
}

// NucleiHTTPRule represents a Nuclei HTTP rule
type NucleiHTTPRule struct {
	Method   string            `yaml:"method"`
	Path     []string          `yaml:"path"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Matchers []NucleiMatcher   `yaml:"matchers"`
}

// NucleiMatcher represents a Nuclei matcher
type NucleiMatcher struct {
	Type   string   `yaml:"type"`
	Status []int    `yaml:"status,omitempty"`
	Words  []string `yaml:"words,omitempty"`
	Regex  []string `yaml:"regex,omitempty"`
}

// SARIFResult represents SARIF format results
type SARIFResult struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a SARIF run
type SARIFRun struct {
	Tool    SARIFTool    `json:"tool"`
	Results []SARIFIssue `json:"results"`
}

// SARIFTool represents a SARIF tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents a SARIF driver
type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules"`
}

// SARIFRule represents a SARIF rule
type SARIFRule struct {
	ID               string           `json:"id"`
	ShortDescription SARIFDescription `json:"shortDescription"`
	FullDescription  SARIFDescription `json:"fullDescription"`
	Help             SARIFDescription `json:"help"`
}

// SARIFDescription represents a SARIF description
type SARIFDescription struct {
	Text string `json:"text"`
}

// SARIFIssue represents a SARIF issue
type SARIFIssue struct {
	RuleID    string          `json:"ruleId"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	Level     string          `json:"level"`
}

// SARIFMessage represents a SARIF message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a SARIF location
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a SARIF physical location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation represents a SARIF artifact location
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// OutputManager handles different output formats
type OutputManager struct {
	results      *ScanResults
	outputDir    string
	baseFilename string
}

// NewOutputManager creates a new output manager
func NewOutputManager(outputDir, baseFilename string) *OutputManager {
	return &OutputManager{
		results:      &ScanResults{},
		outputDir:    outputDir,
		baseFilename: baseFilename,
	}
}

// Initialize sets up the scan results structure
func (om *OutputManager) Initialize(metadata ScanMetadata) {
	om.results.Metadata = metadata
	om.results.Statistics.RiskDistribution = make(map[string]int)
	om.results.Statistics.StatusCodeDistribution = make(map[int]int)
	om.results.Statistics.MethodDistribution = make(map[string]int)
}

// AddEndpoint adds an endpoint result
func (om *OutputManager) AddEndpoint(target *http.Target, route *http.Route, response *http.Response) {
	endpoint := EndpointResult{
		URL:           target.String() + string(route.Path),
		Method:        string(route.Method),
		StatusCode:    response.StatusCode,
		ContentLength: response.BodyLength,
		ResponseTime:  0, // Would need to be tracked during scan
		Timestamp:     time.Now(),
	}

	// Extract headers
	endpoint.Headers = make(map[string]string)
	for _, header := range response.Headers {
		headerStr := string(header.Key) + ": " + string(header.Value)
		parts := strings.SplitN(headerStr, ":", 2)
		if len(parts) == 2 {
			endpoint.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	om.results.Endpoints = append(om.results.Endpoints, endpoint)

	// Update statistics
	om.results.Statistics.TotalEndpoints++
	om.results.Statistics.StatusCodeDistribution[response.StatusCode]++
	om.results.Statistics.MethodDistribution[endpoint.Method]++
}

// AddRisk adds a risk assessment result
func (om *OutputManager) AddRisk(risk *scoring.EndpointRisk) {
	om.results.Risks = append(om.results.Risks, *risk)
	om.results.Statistics.RiskDistribution[risk.RiskLevel.String()]++
}

// AddVulnerability adds a vulnerability assessment result
func (om *OutputManager) AddVulnerability(vuln *scoring.VulnerabilityAssessment) {
	om.results.Vulnerabilities = append(om.results.Vulnerabilities, *vuln)
	om.results.Statistics.TotalVulnerabilities++
}

// Finalize completes the scan results
func (om *OutputManager) Finalize(endTime time.Time) {
	om.results.Metadata.EndTime = endTime
	om.results.Metadata.Duration = endTime.Sub(om.results.Metadata.StartTime).String()

	// Calculate average response time if we had timing data
	// om.results.Statistics.AverageResponseTime = ...

	// Calculate requests per second
	duration := endTime.Sub(om.results.Metadata.StartTime).Seconds()
	if duration > 0 {
		om.results.Statistics.RequestsPerSecond = float64(om.results.Statistics.TotalRequests) / duration
	}
}

// Export exports results in the specified format
func (om *OutputManager) Export(format OutputFormat, filename string) error {
	if filename == "" {
		filename = om.getDefaultFilename(format)
	}

	fullPath := filepath.Join(om.outputDir, filename)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(om.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	switch format {
	case FormatJSON:
		return om.exportJSON(fullPath)
	case FormatXML:
		return om.exportXML(fullPath)
	case FormatBurp:
		return om.exportBurp(fullPath)
	case FormatNuclei:
		return om.exportNuclei(fullPath)
	case FormatMarkdown:
		return om.exportMarkdown(fullPath)
	case FormatHTML:
		return om.exportHTML(fullPath)
	case FormatCSV:
		return om.exportCSV(fullPath)
	case FormatSARIF:
		return om.exportSARIF(fullPath)
	default:
		return fmt.Errorf("unsupported output format: %d", format)
	}
}

// exportJSON exports results as JSON
func (om *OutputManager) exportJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(om.results)
}

// exportXML exports results as XML
func (om *OutputManager) exportXML(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create XML file: %w", err)
	}
	defer file.Close()

	file.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	return encoder.Encode(om.results)
}

// exportBurp exports results as Burp Suite project
func (om *OutputManager) exportBurp(filename string) error {
	burpProject := om.createBurpProject()

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create Burp file: %w", err)
	}
	defer file.Close()

	file.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	return encoder.Encode(burpProject)
}

// exportNuclei exports results as Nuclei templates
func (om *OutputManager) exportNuclei(baseFilename string) error {
	// Create Nuclei templates for high-risk findings
	templates := om.createNucleiTemplates()

	for i, template := range templates {
		filename := fmt.Sprintf("%s-template-%d.yaml", baseFilename, i+1)
		if err := om.writeNucleiTemplate(filename, template); err != nil {
			return err
		}
	}

	return nil
}

// exportMarkdown exports results as Markdown report
func (om *OutputManager) exportMarkdown(filename string) error {
	content := om.generateMarkdownReport()
	return os.WriteFile(filename, []byte(content), 0644)
}

// exportHTML exports results as HTML report
func (om *OutputManager) exportHTML(filename string) error {
	content := om.generateHTMLReport()
	return os.WriteFile(filename, []byte(content), 0644)
}

// exportCSV exports results as CSV
func (om *OutputManager) exportCSV(filename string) error {
	content := om.generateCSVReport()
	return os.WriteFile(filename, []byte(content), 0644)
}

// exportSARIF exports results as SARIF format
func (om *OutputManager) exportSARIF(filename string) error {
	sarifResult := om.createSARIFResult()

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create SARIF file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifResult)
}

// createBurpProject creates a Burp Suite project from results
func (om *OutputManager) createBurpProject() *BurpSuiteProject {
	project := &BurpSuiteProject{
		Version:  "1.0",
		Issues:   []BurpIssue{},
		Requests: []BurpRequest{},
	}

	// Convert vulnerabilities to Burp issues
	for i, vuln := range om.results.Vulnerabilities {
		issue := BurpIssue{
			SerialNumber: i + 1,
			Type:         om.getBurpIssueType(vuln.VulnerabilityType),
			Name:         vuln.VulnerabilityType.String(),
			Host:         om.extractHost(vuln.Endpoint),
			Path:         om.extractPath(vuln.Endpoint),
			Location:     vuln.Endpoint,
			Severity:     om.getBurpSeverity(vuln.RiskLevel),
			Confidence:   "Certain",
			Background:   vuln.BusinessImpact,
			Detail:       strings.Join(vuln.Evidence, "\n"),
			Remediation:  vuln.Remediation,
		}
		project.Issues = append(project.Issues, issue)
	}

	// Convert endpoints to Burp requests
	for _, endpoint := range om.results.Endpoints {
		request := BurpRequest{
			URL:      endpoint.URL,
			Method:   endpoint.Method,
			Request:  om.generateBurpRequest(endpoint),
			Response: om.generateBurpResponse(endpoint),
			Status:   endpoint.StatusCode,
			Length:   endpoint.ContentLength,
		}
		project.Requests = append(project.Requests, request)
	}

	return project
}

// createNucleiTemplates creates Nuclei templates from high-risk findings
func (om *OutputManager) createNucleiTemplates() []NucleiTemplate {
	var templates []NucleiTemplate

	// Create templates for critical and high-risk vulnerabilities
	for i, vuln := range om.results.Vulnerabilities {
		if vuln.RiskLevel >= scoring.RiskHigh {
			template := NucleiTemplate{
				ID: fmt.Sprintf("kiterunner-vuln-%d", i+1),
				Info: NucleiInfo{
					Name:        fmt.Sprintf("Kiterunner - %s", vuln.VulnerabilityType.String()),
					Author:      []string{"Kiterunner Godmode"},
					Severity:    strings.ToLower(vuln.RiskLevel.String()),
					Description: vuln.BusinessImpact,
					Tags:        []string{"kiterunner", "api", strings.ToLower(vuln.VulnerabilityType.String())},
					Reference:   vuln.References,
				},
				HTTP: []NucleiHTTPRule{
					{
						Method: vuln.Method,
						Path:   []string{om.extractPath(vuln.Endpoint)},
						Matchers: []NucleiMatcher{
							{
								Type:   "status",
								Status: []int{200, 401, 403, 500},
							},
						},
					},
				},
			}
			templates = append(templates, template)
		}
	}

	return templates
}

// createSARIFResult creates SARIF format result
func (om *OutputManager) createSARIFResult() *SARIFResult {
	rules := []SARIFRule{}
	issues := []SARIFIssue{}

	// Create rules for each vulnerability type
	ruleMap := make(map[string]bool)
	for _, vuln := range om.results.Vulnerabilities {
		ruleID := fmt.Sprintf("KR-%s", strings.ToUpper(strings.ReplaceAll(vuln.VulnerabilityType.String(), " ", "_")))
		if !ruleMap[ruleID] {
			rule := SARIFRule{
				ID:               ruleID,
				ShortDescription: SARIFDescription{Text: vuln.VulnerabilityType.String()},
				FullDescription:  SARIFDescription{Text: vuln.BusinessImpact},
				Help:             SARIFDescription{Text: vuln.Remediation},
			}
			rules = append(rules, rule)
			ruleMap[ruleID] = true
		}

		issue := SARIFIssue{
			RuleID:  ruleID,
			Message: SARIFMessage{Text: fmt.Sprintf("%s found at %s", vuln.VulnerabilityType.String(), vuln.Endpoint)},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: vuln.Endpoint},
					},
				},
			},
			Level: om.getSARIFLevel(vuln.RiskLevel),
		}
		issues = append(issues, issue)
	}

	return &SARIFResult{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "Kiterunner Godmode",
						Version: "1.0.0",
						Rules:   rules,
					},
				},
				Results: issues,
			},
		},
	}
}

// Helper methods for format conversion
func (om *OutputManager) getBurpIssueType(vulnType scoring.VulnerabilityType) int {
	// Map vulnerability types to Burp issue type IDs
	switch vulnType {
	case scoring.VulnSQLi:
		return 1048832 // SQL injection
	case scoring.VulnXSS:
		return 2097408 // Cross-site scripting
	case scoring.VulnCommandInjection:
		return 1048833 // OS command injection
	case scoring.VulnPathTraversal:
		return 1048834 // Path traversal
	default:
		return 134217728 // Information disclosure
	}
}

func (om *OutputManager) getBurpSeverity(riskLevel scoring.RiskLevel) string {
	switch riskLevel {
	case scoring.RiskCritical:
		return "High"
	case scoring.RiskHigh:
		return "Medium"
	case scoring.RiskMedium:
		return "Low"
	default:
		return "Information"
	}
}

func (om *OutputManager) getSARIFLevel(riskLevel scoring.RiskLevel) string {
	switch riskLevel {
	case scoring.RiskCritical:
		return "error"
	case scoring.RiskHigh:
		return "warning"
	case scoring.RiskMedium:
		return "note"
	default:
		return "note"
	}
}

func (om *OutputManager) extractHost(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return url
}

func (om *OutputManager) extractPath(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) >= 4 {
		return "/" + strings.Join(parts[3:], "/")
	}
	return "/"
}

func (om *OutputManager) generateBurpRequest(endpoint EndpointResult) string {
	headers := []string{
		fmt.Sprintf("%s %s HTTP/1.1", endpoint.Method, om.extractPath(endpoint.URL)),
		fmt.Sprintf("Host: %s", om.extractHost(endpoint.URL)),
		"User-Agent: Kiterunner Godmode",
	}

	for key, value := range endpoint.Headers {
		headers = append(headers, fmt.Sprintf("%s: %s", key, value))
	}

	return strings.Join(headers, "\r\n") + "\r\n\r\n"
}

func (om *OutputManager) generateBurpResponse(endpoint EndpointResult) string {
	headers := []string{
		fmt.Sprintf("HTTP/1.1 %d", endpoint.StatusCode),
	}

	for key, value := range endpoint.Headers {
		headers = append(headers, fmt.Sprintf("%s: %s", key, value))
	}

	return strings.Join(headers, "\r\n") + "\r\n\r\n"
}

func (om *OutputManager) getDefaultFilename(format OutputFormat) string {
	timestamp := time.Now().Format("20060102-150405")
	base := fmt.Sprintf("%s-%s", om.baseFilename, timestamp)

	switch format {
	case FormatJSON:
		return base + ".json"
	case FormatXML:
		return base + ".xml"
	case FormatBurp:
		return base + ".xml"
	case FormatNuclei:
		return base + "-nuclei"
	case FormatMarkdown:
		return base + ".md"
	case FormatHTML:
		return base + ".html"
	case FormatCSV:
		return base + ".csv"
	case FormatSARIF:
		return base + ".sarif"
	default:
		return base + ".txt"
	}
}

// Report generation methods
func (om *OutputManager) generateMarkdownReport() string {
	var report strings.Builder

	report.WriteString("# Kiterunner Godmode Scan Report\n\n")
	report.WriteString(fmt.Sprintf("**Scan Date:** %s\n", om.results.Metadata.StartTime.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("**Duration:** %s\n", om.results.Metadata.Duration))
	report.WriteString(fmt.Sprintf("**Total Endpoints:** %d\n", om.results.Statistics.TotalEndpoints))
	report.WriteString(fmt.Sprintf("**Total Vulnerabilities:** %d\n\n", om.results.Statistics.TotalVulnerabilities))

	// Vulnerabilities section
	if len(om.results.Vulnerabilities) > 0 {
		report.WriteString("## 🚨 Vulnerabilities\n\n")
		for i, vuln := range om.results.Vulnerabilities {
			report.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, vuln.VulnerabilityType.String(), vuln.RiskLevel.String()))
			report.WriteString(fmt.Sprintf("**Endpoint:** %s\n", vuln.Endpoint))
			report.WriteString(fmt.Sprintf("**Method:** %s\n", vuln.Method))
			report.WriteString(fmt.Sprintf("**CVSS Score:** %.1f\n", vuln.CVSS))
			report.WriteString(fmt.Sprintf("**Business Impact:** %s\n\n", vuln.BusinessImpact))
			report.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", vuln.Remediation))
		}
	}

	// High-risk endpoints section
	if len(om.results.Risks) > 0 {
		report.WriteString("## ⚠️ High-Risk Endpoints\n\n")
		for i, risk := range om.results.Risks {
			if risk.RiskLevel >= scoring.RiskMedium {
				report.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, risk.Endpoint, risk.RiskLevel.String()))
				report.WriteString(fmt.Sprintf("**Method:** %s\n", risk.Method))
				report.WriteString(fmt.Sprintf("**Risk Score:** %d/100\n", risk.Score))
				report.WriteString(fmt.Sprintf("**Business Impact:** %s\n\n", risk.BusinessImpact))
			}
		}
	}

	return report.String()
}

func (om *OutputManager) generateHTMLReport() string {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Kiterunner Godmode Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .vuln { margin: 20px 0; padding: 15px; border-left: 4px solid #ff4444; background: #fff5f5; }
        .risk { margin: 20px 0; padding: 15px; border-left: 4px solid #ffaa00; background: #fff8f0; }
        .critical { border-left-color: #ff0000; }
        .high { border-left-color: #ff6600; }
        .medium { border-left-color: #ffcc00; }
        .low { border-left-color: #00ff00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Kiterunner Godmode Scan Report</h1>
        <p><strong>Scan Date:</strong> %s</p>
        <p><strong>Duration:</strong> %s</p>
        <p><strong>Total Endpoints:</strong> %d</p>
        <p><strong>Total Vulnerabilities:</strong> %d</p>
    </div>`,
		om.results.Metadata.StartTime.Format("2006-01-02 15:04:05"),
		om.results.Metadata.Duration,
		om.results.Statistics.TotalEndpoints,
		om.results.Statistics.TotalVulnerabilities)

	// Add vulnerabilities
	if len(om.results.Vulnerabilities) > 0 {
		html += "\n<h2>🚨 Vulnerabilities</h2>\n"
		for _, vuln := range om.results.Vulnerabilities {
			severityClass := strings.ToLower(vuln.RiskLevel.String())
			html += fmt.Sprintf(`<div class="vuln %s">
				<h3>%s (%s)</h3>
				<p><strong>Endpoint:</strong> %s</p>
				<p><strong>Method:</strong> %s</p>
				<p><strong>CVSS Score:</strong> %.1f</p>
				<p><strong>Business Impact:</strong> %s</p>
				<p><strong>Remediation:</strong> %s</p>
			</div>`, severityClass, vuln.VulnerabilityType.String(), vuln.RiskLevel.String(),
				vuln.Endpoint, vuln.Method, vuln.CVSS, vuln.BusinessImpact, vuln.Remediation)
		}
	}

	html += "\n</body>\n</html>"
	return html
}

func (om *OutputManager) generateCSVReport() string {
	var csv strings.Builder

	// CSV header
	csv.WriteString("Type,Endpoint,Method,Severity,Score,Description\n")

	// Add vulnerabilities
	for _, vuln := range om.results.Vulnerabilities {
		csv.WriteString(fmt.Sprintf("Vulnerability,%s,%s,%s,%.1f,%s\n",
			vuln.Endpoint, vuln.Method, vuln.RiskLevel.String(), vuln.CVSS, vuln.VulnerabilityType.String()))
	}

	// Add risks
	for _, risk := range om.results.Risks {
		csv.WriteString(fmt.Sprintf("Risk,%s,%s,%s,%d,%s\n",
			risk.Endpoint, risk.Method, risk.RiskLevel.String(), risk.Score, risk.BusinessImpact))
	}

	return csv.String()
}

func (om *OutputManager) writeNucleiTemplate(filename string, template NucleiTemplate) error {
	// This would require a YAML library to properly serialize
	// For now, we'll generate a simple YAML structure
	content := fmt.Sprintf(`id: %s

info:
  name: %s
  author: %s
  severity: %s
  description: %s
  tags: %s

http:
  - method: %s
    path:
      - %s
    matchers:
      - type: status
        status:
          - 200
          - 401
          - 403
          - 500
`,
		template.ID,
		template.Info.Name,
		strings.Join(template.Info.Author, ", "),
		template.Info.Severity,
		template.Info.Description,
		strings.Join(template.Info.Tags, ", "),
		template.HTTP[0].Method,
		strings.Join(template.HTTP[0].Path, "\n      - "))

	return os.WriteFile(filename, []byte(content), 0644)
}
