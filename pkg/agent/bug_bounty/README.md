# Bug Bounty Agent - Kiterunner Integration

This package provides specialized Kiterunner functionality tailored for bug bounty hunters. It enhances the standard Kiterunner capabilities with:

- Automatic vulnerability assessment
- Interest factor scoring for endpoints
- Bug bounty-focused reporting
- Quick reconnaissance scanning

## Quick Start

```go
package main

import (
	"fmt"
	"github.com/assetnote/kiterunner/pkg/agent/bug_bounty"
)

func main() {
	// Create a new agent
	agent := bug_bounty.NewKiterunnerAgent()

	// Scan a target
	results, err := agent.ScanTarget("https://example.com")
	if err != nil {
		panic(err)
	}

	// Filter potentially vulnerable results
	vulnerableEndpoints := agent.FilterVulnerableResults(results)

	// Generate report
	report := agent.FormatResultsForReport(results)
	fmt.Println(report)
}
```

## Features

### Quick API Discovery

The `ScanSubpaths` function performs a quick scan of common API paths without requiring a wordlist:

```go
// Quick scan of common API endpoints
results, err := agent.ScanSubpaths("https://example.com")
```

### Bug Bounty-Focused Analysis

Results include additional metadata specifically helpful for bug bounty hunters:

- **Interest Factor**: A 1-10 rating of how interesting an endpoint is
- **Potential Vulnerability**: Flag indicating if the endpoint might be vulnerable

### Result Filtering and Sorting

```go
// Sort results by interest factor (most interesting first)
sortedResults := agent.SortResultsByInterest(results)

// Filter only potentially vulnerable endpoints
vulnResults := agent.FilterVulnerableResults(results)
```

### Comprehensive Reporting

```go
// Generate a markdown report
report := agent.FormatResultsForReport(results)

// Save to file
os.WriteFile("kiterunner_report.md", []byte(report), 0644)
```

## Usage Examples

### Program Scope Scanning

The `scope_scan.go` example shows how to scan an entire bug bounty program scope:

```bash
go run scope_scan.go scope.txt
```

Where `scope.txt` contains one target URL per line.

### Quick Target Assessment

The `quick_scan.go` example provides a fast way to assess a single target:

```bash
go run quick_scan.go https://example.com
```

This will:
1. Run a quick scan of common API paths
2. Highlight potentially vulnerable endpoints
3. Optionally run a full scan

## Configuration

The agent can be configured with various options:

```go
agent := bug_bounty.NewKiterunnerAgent()

// Set wordlists (kite files, text files, or Assetnote wordlists)
agent.Wordlists = []string{"routes-small.kite", "apiroutes-210328:20000"}

// Set concurrency
agent.MaxConnectionsPerHost = 5
agent.MaxParallelHosts = 50

// Set timeout
agent.Timeout = 5 * time.Second

// Set which status codes to consider failures
agent.FailStatusCodes = []int{400, 401, 404, 403, 501, 502, 426, 411}
```

## Bug Bounty Workflow Integration

This agent is designed to integrate into a typical bug bounty workflow:

1. **Reconnaissance**: Use `ScanSubpaths` for quick API discovery
2. **Deep Scanning**: Run full scans with specialized wordlists
3. **Vulnerability Assessment**: Focus on endpoints flagged as potentially vulnerable
4. **Reporting**: Generate comprehensive reports for your findings

## Advanced Usage

For advanced users, the agent provides direct access to the underlying Kiterunner configuration, allowing for fine-tuning of all scan parameters.
