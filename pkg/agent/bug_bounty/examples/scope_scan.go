package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/assetnote/kiterunner2/pkg/agent/bug_bounty"
)

func main() {
	// Verify arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: scope_scan <scope_file>")
		fmt.Println("  scope_file: Text file containing one target URL per line")
		os.Exit(1)
	}

	scopeFile := os.Args[1]

	// Read scope file
	file, err := os.Open(scopeFile)
	if err != nil {
		log.Fatalf("Error opening scope file: %v", err)
	}
	defer file.Close()

	// Read targets
	targets := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if len(targets) == 0 {
		log.Fatalf("No targets found in scope file")
	}

	// Create bug bounty agent
	agent := bug_bounty.NewKiterunnerAgent()

	// Configure for efficient scanning
	agent.MaxConnectionsPerHost = 5
	agent.MaxParallelHosts = 10 // Reduced to avoid overwhelming targets
	agent.Timeout = 5 * time.Second
	agent.Wordlists = []string{"routes-small.kite"}

	// Display scan info
	fmt.Printf("[+] Starting scan of %d targets\n", len(targets))
	fmt.Printf("[+] Using wordlist: %s\n", strings.Join(agent.Wordlists, ", "))
	fmt.Printf("[+] Concurrency: %d connections per host, %d parallel hosts\n\n",
		agent.MaxConnectionsPerHost, agent.MaxParallelHosts)

	// Track overall results
	allResults := []bug_bounty.Result{}
	vulnerableTargets := make(map[string][]bug_bounty.Result)

	// Scan each target
	for i, target := range targets {
		fmt.Printf("[%d/%d] Scanning %s...\n", i+1, len(targets), target)

		// Run scan
		results, err := agent.ScanTarget(target)
		if err != nil {
			log.Printf("Error scanning %s: %v", target, err)
			continue
		}

		// Process results
		if len(results) > 0 {
			vulnResults := agent.FilterVulnerableResults(results)
			allResults = append(allResults, results...)

			fmt.Printf("  [+] Found %d endpoints (%d potentially vulnerable)\n",
				len(results), len(vulnResults))

			if len(vulnResults) > 0 {
				vulnerableTargets[target] = vulnResults
			}
		} else {
			fmt.Printf("  [-] No interesting endpoints found\n")
		}
	}

	// Generate summary report
	if len(allResults) > 0 {
		fmt.Printf("\n[+] Scan complete! Found %d total endpoints across %d targets\n",
			len(allResults), len(targets))

		// List vulnerable targets
		if len(vulnerableTargets) > 0 {
			fmt.Printf("\n[!] %d targets have potentially vulnerable endpoints:\n", len(vulnerableTargets))

			for target, vulns := range vulnerableTargets {
				fmt.Printf("  - %s (%d vulnerable endpoints)\n", target, len(vulns))
			}

			// Create individual reports for each vulnerable target
			fmt.Println("\n[+] Generating reports for vulnerable targets...")

			os.Mkdir("reports", 0755)
			for target, vulns := range vulnerableTargets {
				// Create target-specific filename
				targetName := strings.ReplaceAll(target, "://", "_")
				targetName = strings.ReplaceAll(targetName, "/", "_")
				targetName = strings.ReplaceAll(targetName, ":", "_")
				reportFile := fmt.Sprintf("reports/%s_report.md", targetName)

				// Generate report
				report := agent.FormatResultsForReport(vulns)

				// Save report
				err := os.WriteFile(reportFile, []byte(report), 0644)
				if err != nil {
					log.Printf("Error saving report for %s: %v", target, err)
				} else {
					fmt.Printf("  [+] Report for %s saved to %s\n", target, reportFile)
				}
			}
		} else {
			fmt.Println("\n[-] No potentially vulnerable endpoints found in any target")
		}

		// Create overall summary report
		fmt.Println("\n[+] Generating overall summary report...")

		var sb strings.Builder
		sb.WriteString("# Kiterunner Bug Bounty Scan Summary\n\n")
		sb.WriteString(fmt.Sprintf("- **Targets Scanned**: %d\n", len(targets)))
		sb.WriteString(fmt.Sprintf("- **Endpoints Found**: %d\n", len(allResults)))
		sb.WriteString(fmt.Sprintf("- **Vulnerable Targets**: %d\n\n", len(vulnerableTargets)))

		if len(vulnerableTargets) > 0 {
			sb.WriteString("## Vulnerable Targets\n\n")

			for target, vulns := range vulnerableTargets {
				sb.WriteString(fmt.Sprintf("### %s\n\n", target))
				sb.WriteString(fmt.Sprintf("Found %d potentially vulnerable endpoints:\n\n", len(vulns)))

				for i, result := range vulns {
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
		}

		// Save summary report
		summaryReport := sb.String()
		err := os.WriteFile("reports/summary_report.md", []byte(summaryReport), 0644)
		if err != nil {
			log.Printf("Error saving summary report: %v", err)
		} else {
			fmt.Println("[+] Summary report saved to reports/summary_report.md")
		}
	} else {
		fmt.Println("\n[-] No interesting endpoints found across any targets")
	}
}
