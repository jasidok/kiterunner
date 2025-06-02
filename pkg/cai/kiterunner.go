package cai

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

// KiterunnerConfig stores configuration for Kiterunner integration
type KiterunnerConfig struct {
	// Wordlists to use for scanning (can be .kite files or assetnote wordlists)
	Wordlists []string
	// Maximum connections per host
	MaxConnectionsPerHost int
	// Maximum parallel hosts
	MaxParallelHosts int
	// Request timeout
	Timeout time.Duration
	// Content lengths to ignore
	IgnoreLength []string
	// Headers to add to requests
	Headers []string
	// Status codes that indicate failure
	FailStatusCodes []int
	// Depth for preflight checks
	PreflightDepth int
	// Extensions to use with dirsearch compat mode
	Extensions []string
	// Whether to use dirsearch compatibility mode
	DirsearchCompat bool
}

// DefaultKiterunnerConfig returns a config with sensible defaults
func DefaultKiterunnerConfig() KiterunnerConfig {
	return KiterunnerConfig{
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
	}
}

// Result represents a Kiterunner scan result
type Result struct {
	Method        string
	StatusCode    int
	ContentLength int
	URL           string
	RequestID     string
}

// ScanWithKiterunner performs a scan using Kiterunner against the provided targets
func ScanWithKiterunner(targets []string, config KiterunnerConfig) ([]Result, error) {
	// Initialize logger
	logger := log.NewLogger()
	logger.SetLevel(log.ErrorLevel)

	// Setup scanner configuration
	opts := kiterunner.ScannerOptions{
		MaxParallelHosts:     config.MaxParallelHosts,
		MaxConnPerHost:       config.MaxConnectionsPerHost,
		Timeout:              config.Timeout,
		Headers:              config.Headers,
		BlacklistStatusCodes: config.FailStatusCodes,
		PreflightDepth:       config.PreflightDepth,
		IgnoreLength:         config.IgnoreLength,
	}

	// Convert targets to hosts
	hosts, err := http.ParseInputToHosts(targets)
	if err != nil {
		return nil, fmt.Errorf("error parsing targets: %w", err)
	}

	// Load wordlists
	apis := []*proute.APIs{}
	for _, wordlist := range config.Wordlists {
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
	scanner := kiterunner.NewScanner(mergedAPIs, opts, logger)

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

	// Collect results
	results := []Result{}
	for result := range resultsChan {
		results = append(results, Result{
			Method:        result.Method,
			StatusCode:    result.StatusCode,
			ContentLength: result.ContentLength,
			URL:           result.URL.String(),
			RequestID:     result.RequestID,
		})
	}

	return results, nil
}

// BruteforceWithKiterunner performs a bruteforce scan using Kiterunner
func BruteforceWithKiterunner(targets []string, wordlist string, config KiterunnerConfig) ([]Result, error) {
	// For bruteforce mode, we need to create a wordlist from scratch or use a text file
	// This is a simplified implementation - full implementation would need to handle dirsearch compat mode

	// Check if wordlist is a file
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist file %s does not exist", wordlist)
	}

	// Create bruteforce wordlist config
	config.Wordlists = []string{wordlist}

	// Set dirsearch extensions if needed
	if config.DirsearchCompat && len(config.Extensions) > 0 {
		// In a full implementation, this would need to handle the %EXT% replacement
		// For now, we just pass through the configuration
	}

	// Call the main scan function
	return ScanWithKiterunner(targets, config)
}
