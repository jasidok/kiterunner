package cai

import (
	"fmt"
	"strings"
	"time"
)

// CAI represents the Custom AI integration with Kiterunner
type CAI struct {
	KrConfig KiterunnerConfig
}

// NewCAI creates a new CAI instance with default Kiterunner configuration
func NewCAI() *CAI {
	return &CAI{
		KrConfig: DefaultKiterunnerConfig(),
	}
}

// ScanTarget scans a single target using Kiterunner
func (c *CAI) ScanTarget(target string) ([]Result, error) {
	return ScanWithKiterunner([]string{target}, c.KrConfig)
}

// ScanTargets scans multiple targets using Kiterunner
func (c *CAI) ScanTargets(targets []string) ([]Result, error) {
	return ScanWithKiterunner(targets, c.KrConfig)
}

// BruteforceTarget performs a bruteforce scan against a single target
func (c *CAI) BruteforceTarget(target, wordlist string) ([]Result, error) {
	return BruteforceWithKiterunner([]string{target}, wordlist, c.KrConfig)
}

// SetWordlists configures which wordlists to use for scanning
// Can be file paths (.kite, .json, .txt) or assetnote wordlist names
func (c *CAI) SetWordlists(wordlists ...string) {
	c.KrConfig.Wordlists = wordlists
}

// SetConcurrency configures concurrency settings
func (c *CAI) SetConcurrency(connectionsPerHost, parallelHosts int) {
	c.KrConfig.MaxConnectionsPerHost = connectionsPerHost
	c.KrConfig.MaxParallelHosts = parallelHosts
}

// SetTimeout configures the request timeout
func (c *CAI) SetTimeout(timeout time.Duration) {
	c.KrConfig.Timeout = timeout
}

// SetFailStatusCodes configures which status codes should be considered failures
func (c *CAI) SetFailStatusCodes(codes ...int) {
	c.KrConfig.FailStatusCodes = codes
}

// EnableDirsearchMode enables dirsearch compatibility mode with the specified extensions
func (c *CAI) EnableDirsearchMode(extensions ...string) {
	c.KrConfig.DirsearchCompat = true
	c.KrConfig.Extensions = extensions
}

// FormatResults returns a human-readable string of scan results
func (c *CAI) FormatResults(results []Result) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Found %d interesting endpoints:\n\n", len(results)))

	for i, result := range results {
		sb.WriteString(fmt.Sprintf("%d. %s %d [%d bytes] %s\n",
			i+1,
			result.Method,
			result.StatusCode,
			result.ContentLength,
			result.URL))
	}

	return sb.String()
}
