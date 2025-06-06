package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/assetnote/kiterunner2/pkg/agent/bug_bounty"
)

func main() {
	// Verify arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: quick_scan <target_url>")
		os.Exit(1)
	}

	target := os.Args[1]

	// Create a new Kiterunner agent for bug bounty
	agent := bug_bounty.NewKiterunnerAgent()

	// Configure for quick scanning
	agent.MaxConnectionsPerHost = 10
	agent.MaxParallelHosts = 50
	agent.Timeout = 5 * time.Second

	// First, try a quick scan of common API paths
	fmt.Println("[+] Running quick scan of common API paths...")
	quickResults, err := agent.ScanSubpaths(target)
	if err != nil {
		log.Fatalf("Error in quick scan: %v", err)
	}

	// If we found interesting endpoints, report them
	if len(quickResults) > 0 {
		fmt.Printf("[+] Found %d interesting endpoints!\n\n", len(quickResults))

		// Print vulnerable results first
		vulnResults := agent.FilterVulnerableResults(quickResults)
		if len(vulnResults) > 0 {
			fmt.Printf("[!] %d potentially vulnerable endpoints found:\n", len(vulnResults))
			for i, result := range vulnResults {
				fmt.Printf("    %d. %s %s (Status: %d)\n",
					i+1, result.Method, result.URL, result.StatusCode)
			}
			fmt.Println()
		}

		// Ask if user wants to run a full scan
		fmt.Print("Do you want to run a full API scan? (y/n): ")
		var answer string
		fmt.Scanln(&answer)

		if answer == "y" || answer == "Y" {
			// Run a more comprehensive scan
			fmt.Println("\n[+] Running comprehensive API scan...")
			agent.Wordlists = []string{"routes-small.kite"} // Use the small routes wordlist

			fullResults, err := agent.ScanTarget(target)
			if err != nil {
				log.Fatalf("Error in full scan: %v", err)
			}

			// Generate and print report
			report := agent.FormatResultsForReport(fullResults)
			fmt.Println(report)

			// Save report to file
			reportFile := "kiterunner_scan_report.md"
			err = os.WriteFile(reportFile, []byte(report), 0644)
			if err != nil {
				log.Printf("Error saving report: %v", err)
			} else {
				fmt.Printf("[+] Report saved to %s\n", reportFile)
			}
		}
	} else {
		fmt.Println("[-] No interesting API endpoints found in quick scan.")

		// Ask if user wants to run a full scan anyway
		fmt.Print("Run a full API scan anyway? (y/n): ")
		var answer string
		fmt.Scanln(&answer)

		if answer == "y" || answer == "Y" {
			// Run a more comprehensive scan
			fmt.Println("\n[+] Running comprehensive API scan...")
			agent.Wordlists = []string{"routes-small.kite"} // Use the small routes wordlist

			fullResults, err := agent.ScanTarget(target)
			if err != nil {
				log.Fatalf("Error in full scan: %v", err)
			}

			if len(fullResults) > 0 {
				// Generate and print report
				report := agent.FormatResultsForReport(fullResults)
				fmt.Println(report)

				// Save report to file
				reportFile := "kiterunner_scan_report.md"
				err = os.WriteFile(reportFile, []byte(report), 0644)
				if err != nil {
					log.Printf("Error saving report: %v", err)
				} else {
					fmt.Printf("[+] Report saved to %s\n", reportFile)
				}
			} else {
				fmt.Println("[-] No API endpoints found in full scan.")
			}
		}
	}
}
