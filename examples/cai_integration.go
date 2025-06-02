package main

import (
	"fmt"
	"log"
	"time"

	"github.com/assetnote/kiterunner/pkg/cai"
)

func main() {
	// Create new CAI instance
	ai := cai.NewCAI()

	// Configure for optimal performance
	ai.SetConcurrency(5, 100)
	ai.SetTimeout(5 * time.Second)

	// Use the small routes wordlist
	ai.SetWordlists("routes-small.kite")

	// Define which status codes to treat as failures
	ai.SetFailStatusCodes(400, 401, 404, 403, 501, 502, 426, 411)

	// Define target(s)
	target := "https://api.example.com"

	// Perform scan
	fmt.Println("Starting API scan of", target)
	results, err := ai.ScanTarget(target)
	if err != nil {
		log.Fatalf("Error scanning target: %v", err)
	}

	// Print results
	fmt.Println(ai.FormatResults(results))

	// Example of bruteforce mode with dirsearch compatibility
	fmt.Println("\nStarting bruteforce scan with dirsearch compatibility")
	ai.EnableDirsearchMode("json", "xml", "php")

	bruteResults, err := ai.BruteforceTarget(target, "dirsearch_wordlist.txt")
	if err != nil {
		log.Fatalf("Error performing bruteforce scan: %v", err)
	}

	fmt.Println(ai.FormatResults(bruteResults))
}
