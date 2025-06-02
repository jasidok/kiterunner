package bug_bounty

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/assetnote/kiterunner/pkg/http"
	"github.com/assetnote/kiterunner/pkg/kiterunner"
	"github.com/assetnote/kiterunner/pkg/log"
	"github.com/assetnote/kiterunner/pkg/proute"
)

// KiterunnerAgent provides bug bounty-focused API discovery capabilities
type KiterunnerAgent struct {
	// Configuration options
	Wordlists             []string
	MaxConnectionsPerHost int
	MaxParallelHosts      int
	Timeout               time.Duration
	IgnoreLength          []string
	Headers               []string
	FailStatusCodes       []int
	PreflightDepth        int
	Extensions            []string
	DirsearchCompat       bool
	// Internal logger
	logger *log.Logger
}

// NewKiterunnerAgent creates a new KiterunnerAgent with default settings
func NewKiterunnerAgent() *KiterunnerAgent {
	return &KiterunnerAgent{
		Wordlists:             []string{"apiroutes-210328:20000"},
		MaxConnectionsPerHost: 10,
		MaxParallelHosts:      100,
		Timeout:               3 * time.Second,
		IgnoreLength:          nil,
		Headers:               []string{"x-forwarded-for: 127.0.0.1"},
		FailStatusCodes:       []int{400, 401, 404, 403, 501, 502, 426, 411},
		PreflightDepth:        1,
		Extensions:            nil,
		DirsearchCompat:       false,
		logger:                log.NewLogger(),
	}
}

// Result represents a discovered endpoint from Kiterunner
type Result struct {
	Method         string
	StatusCode     int
	ContentLength  int
	URL            string
	RequestID      string
	InterestFactor int  // 1-10 scale of how interesting the result is
	PotentialVuln  bool // Whether this endpoint potentially indicates a vulnerability
}

// ScanTarget performs a scan on a single target using configured Kiterunner settings
func (k *KiterunnerAgent) ScanTarget(target string) ([]Result, error) {
	return k.ScanTargets([]string{target})
}

// ScanTargets performs a scan on multiple targets using configured Kiterunner settings
func (k *KiterunnerAgent) ScanTargets(targets []string) ([]Result, error) {
	// Set logger level
	k.logger.SetLevel(log.ErrorLevel)

	// Setup scanner configuration
	opts := kiterunner.ScannerOptions{
		MaxParallelHosts:     k.MaxParallelHosts,
		MaxConnPerHost:       k.MaxConnectionsPerHost,
		Timeout:              k.Timeout,
		Headers:              k.Headers,
		BlacklistStatusCodes: k.FailStatusCodes,
		PreflightDepth:       k.PreflightDepth,
		IgnoreLength:         k.IgnoreLength,
	}

	// Convert targets to hosts
	hosts, err := http.ParseInputToHosts(targets)
	if err != nil {
		return nil, fmt.Errorf("error parsing targets: %w", err)
	}

	// Load wordlists
	apis := []*proute.APIs{}
	for _, wordlist := range k.Wordlists {
		// Check if it's an Assetnote wordlist
		if !strings.HasSuffix(wordlist, ".kite") && !strings.HasSuffix(wordlist, ".json") && !strings.HasSuffix(wordlist, ".txt") {
			// Assume it's an Assetnote wordlist
			wordlistName := wordlist
			wordlistLines := 0

			// Check if it has a line limit using the head syntax
			parts := strings.Split(wordlist, ":")
			if len(parts) > 1 {
				wordlistName = parts[0]
				// Parse the line limit
				fmt.Sscanf(parts[1], "%d", &wordlistLines)
			}

			// TODO: Implement Assetnote wordlist fetching
			// This is a placeholder - actual implementation would use wordlist.GetAssetnoteWordlist
			return nil, fmt.Errorf("assetnote wordlists not implemented in this integration yet")
		} else {
			// Load from file
			api, err := proute.LoadAPIsFromFile(wordlist)
			if err != nil {
				return nil, fmt.Errorf("error loading wordlist %s: %w", wordlist, err)
			}
			apis = append(apis, api)
		}
	}

	// Merge APIs if multiple wordlists
	var mergedAPIs *proute.APIs
	if len(apis) == 1 {
		mergedAPIs = apis[0]
	} else if len(apis) > 1 {
		mergedAPIs = proute.MergeAPIs(apis...)
	} else {
		return nil, fmt.Errorf("no wordlists loaded")
	}

	// Create scanner
	scanner := kiterunner.NewScanner(mergedAPIs, opts, k.logger)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create results channel
	resultsChan := make(chan kiterunner.ScanResult)

	// Start scanner
	go func() {
		defer close(resultsChan)
		scanner.Scan(ctx, hosts, resultsChan)
	}()

	// Collect results and enhance them for bug bounty relevance
	results := []Result{}
	for result := range resultsChan {
		// Calculate interest factor based on status code and content
		interestFactor := calculateInterestFactor(result)

		// Determine if potentially vulnerable
		potentialVuln := isPotentiallyVulnerable(result)

		results = append(results, Result{
			Method:         result.Method,
			StatusCode:     result.StatusCode,
			ContentLength:  result.ContentLength,
			URL:            result.URL.String(),
			RequestID:      result.RequestID,
			InterestFactor: interestFactor,
			PotentialVuln:  potentialVuln,
		})
	}

	return results, nil
}

// BruteforceTarget performs a bruteforce scan against a single target
func (k *KiterunnerAgent) BruteforceTarget(target, wordlist string) ([]Result, error) {
	// Check if wordlist is a file
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist file %s does not exist", wordlist)
	}

	// Create a temporary copy of the agent with modified wordlist
	agent := *k
	agent.Wordlists = []string{wordlist}

	// Call the main scan function
	return agent.ScanTargets([]string{target})
}

// ScanSubpaths scans a target using common API paths without a wordlist
// Useful for quick recon when wordlists aren't available
func (k *KiterunnerAgent) ScanSubpaths(target string) ([]Result, error) {
	// Common API paths that often yield results in bug bounty programs
	commonPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/v1",
		"/v2",
		"/graphql",
		"/graphiql",
		"/playground",
		"/console",
		"/swagger",
		"/swagger-ui",
		"/swagger-ui.html",
		"/api-docs",
		"/openapi",
		"/docs",
		"/redoc",
		"/health",
		"/status",
		"/ping",
		"/metrics",
		"/debug",
		"/admin",
		"/actuator",
	}

	// Create a temporary file with common paths
	tmpfile, err := os.CreateTemp("", "kr-common-paths-*.txt")
	if err != nil {
		return nil, fmt.Errorf("error creating temporary file: %w", err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up

	// Write paths to file
	for _, path := range commonPaths {
		tmpfile.WriteString(path + "\n")
	}
	tmpfile.Close()

	// Run a bruteforce scan with this temporary file
	return k.BruteforceTarget(target, tmpfile.Name())
}

// SortResultsByInterest sorts results by interest factor (descending)
func (k *KiterunnerAgent) SortResultsByInterest(results []Result) []Result {
	// Create a copy to avoid modifying the original
	sorted := make([]Result, len(results))
	copy(sorted, results)

	// Sort by interest factor (descending)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].InterestFactor < sorted[j].InterestFactor {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}

// FilterVulnerableResults returns only potentially vulnerable results
func (k *KiterunnerAgent) FilterVulnerableResults(results []Result) []Result {
	filtered := []Result{}

	for _, result := range results {
		if result.PotentialVuln {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

// FormatResultsForReport generates a report-ready string with the results
func (k *KiterunnerAgent) FormatResultsForReport(results []Result) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Kiterunner Scan Report\n\n"))
	sb.WriteString(fmt.Sprintf("Found %d interesting endpoints\n\n", len(results)))

	// Group results by potential vulnerability
	potentialVulns := k.FilterVulnerableResults(results)
	if len(potentialVulns) > 0 {
		sb.WriteString(fmt.Sprintf("## Potentially Vulnerable Endpoints (%d)\n\n", len(potentialVulns)))

		for i, result := range potentialVulns {
			sb.WriteString(fmt.Sprintf("%d. **%s %s** - Status: %d, Size: %d bytes, Interest: %d/10\n",
				i+1,
				result.Method,
				result.URL,
				result.StatusCode,
				result.ContentLength,
				result.InterestFactor))
		}

		sb.WriteString("\n")
	}

	// List all results sorted by interest
	sortedResults := k.SortResultsByInterest(results)
	sb.WriteString("## All Discovered Endpoints (Sorted by Interest)\n\n")

	for i, result := range sortedResults {
		vulnMarker := ""
		if result.PotentialVuln {
			vulnMarker = " [VULN]"
		}
		sb.WriteString(fmt.Sprintf("%d. %s %s - Status: %d, Size: %d bytes, Interest: %d/10%s\n",
			i+1,
			result.Method,
			result.URL,
			result.StatusCode,
			result.ContentLength,
			result.InterestFactor,
			vulnMarker))
	}

	return sb.String()
}

// Helper functions for analyzing results

// calculateInterestFactor rates a result's interestingness on a scale of 1-10
func calculateInterestFactor(result kiterunner.ScanResult) int {
	interest := 5 // Start at middle

	// Adjust based on status code
	switch {
	case result.StatusCode >= 200 && result.StatusCode < 300:
		interest += 2 // Success responses are interesting
	case result.StatusCode == 401 || result.StatusCode == 403:
		interest += 3 // Auth-related responses are very interesting
	case result.StatusCode >= 500:
		interest += 3 // Server errors could indicate vulnerabilities
	case result.StatusCode == 404:
		interest -= 2 // Not found is less interesting
	}

	// Adjust based on content length
	switch {
	case result.ContentLength > 10000:
		interest += 1 // Larger responses might contain more info
	case result.ContentLength < 100 && result.ContentLength > 0:
		interest += 1 // Very small but non-empty responses can be interesting
	case result.ContentLength == 0:
		interest -= 1 // Empty responses are less interesting
	}

	// Adjust based on path characteristics
	path := result.URL.Path
	if strings.Contains(path, "admin") || strings.Contains(path, "config") ||
		strings.Contains(path, "backup") || strings.Contains(path, "secret") ||
		strings.Contains(path, "internal") || strings.Contains(path, "private") ||
		strings.Contains(path, "dev") || strings.Contains(path, "test") ||
		strings.Contains(path, "debug") || strings.Contains(path, "console") ||
		strings.Contains(path, "dashboard") || strings.Contains(path, "manage") {
		interest += 2 // Sensitive-looking paths are more interesting
	}

	// Make sure we stay in the 1-10 range
	if interest < 1 {
		interest = 1
	} else if interest > 10 {
		interest = 10
	}

	return interest
}

// isPotentiallyVulnerable determines if an endpoint might indicate a vulnerability
func isPotentiallyVulnerable(result kiterunner.ScanResult) bool {
	// Server errors often indicate potential issues
	if result.StatusCode >= 500 {
		return true
	}

	// Unauthorized/Forbidden might indicate an access control issue when combined with sensitive paths
	if result.StatusCode == 401 || result.StatusCode == 403 {
		path := result.URL.Path
		if strings.Contains(path, "admin") || strings.Contains(path, "config") ||
			strings.Contains(path, "internal") || strings.Contains(path, "private") ||
			strings.Contains(path, "dev") || strings.Contains(path, "test") ||
			strings.Contains(path, "debug") || strings.Contains(path, "console") ||
			strings.Contains(path, "dashboard") || strings.Contains(path, "manage") {
			return true
		}
	}

	// Check for potentially vulnerable API paths
	path := strings.ToLower(result.URL.Path)
	if strings.Contains(path, "graphql") || strings.Contains(path, "graphiql") ||
		strings.Contains(path, "playground") || strings.Contains(path, "console") ||
		strings.Contains(path, "swagger") || strings.Contains(path, "api-docs") ||
		strings.Contains(path, "/debug") || strings.Contains(path, "/actuator") ||
		strings.Contains(path, "/metrics") {
		return true
	}

	return false
}
