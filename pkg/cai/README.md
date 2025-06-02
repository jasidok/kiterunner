# CAI - Kiterunner Integration

This package provides an integration between Custom AI (CAI) systems and Kiterunner, a powerful API discovery and content discovery tool.

## Features

- Simple API for scanning targets with Kiterunner
- Support for both API scanning and traditional bruteforcing
- Configuration options for optimizing performance
- Dirsearch compatibility mode
- Flexible result handling

## Quick Start

```go
package main

import (
	"fmt"
	"github.com/assetnote/kiterunner/pkg/cai"
)

func main() {
	// Create new CAI instance
	ai := cai.NewCAI()

	// Configure for API scanning
	ai.SetWordlists("apiroutes-210328:20000")

	// Scan a target
	results, err := ai.ScanTarget("https://api.example.com")
	if err != nil {
		panic(err)
	}

	// Print results
	fmt.Println(ai.FormatResults(results))
}
```

## API Scanning vs Bruteforcing

Kiterunner supports two main modes of operation:

1. **API Scanning** - Uses a dataset of API routes to discover endpoints using the correct HTTP methods, headers, and parameters
2. **Bruteforcing** - Traditional content discovery similar to tools like dirsearch or gobuster

### API Scanning Example

```go
// Configure for API scanning
ai.SetWordlists("routes-small.kite") // Use a .kite file or Assetnote wordlist
results, err := ai.ScanTarget("https://api.example.com")
```

### Bruteforcing Example

```go
// Enable dirsearch compatibility with extensions
ai.EnableDirsearchMode("json", "xml", "php")

// Use a text wordlist
results, err := ai.BruteforceTarget("https://example.com", "wordlist.txt")
```

## Configuration Options

```go
// Set concurrency settings
ai.SetConcurrency(5, 100) // 5 connections per host, 100 parallel hosts

// Set request timeout
ai.SetTimeout(5 * time.Second)

// Define which status codes to treat as failures
ai.SetFailStatusCodes(400, 401, 404, 403, 501, 502, 426, 411)

// Use multiple wordlists
ai.SetWordlists("routes-small.kite", "apiroutes-210328:20000")
```

## Wordlist Options

You can use several types of wordlists:

1. **Kite files** - Pre-compiled binary format for fast loading (`.kite`)
2. **JSON schema files** - Source files for compilation (`.json`)
3. **Text files** - Simple wordlists (`.txt`)
4. **Assetnote wordlists** - Specify by name, optionally with line limit using colon syntax

### Assetnote Wordlist Head Syntax

To use only the first N lines of an Assetnote wordlist, use the syntax: `wordlistname:N`

```go
// Use only the first 20000 lines of the apiroutes wordlist
ai.SetWordlists("apiroutes-210328:20000")
```

## Result Handling

Results are returned as a slice of `cai.Result` structs containing:

- HTTP Method
- Status Code
- Content Length
- URL
- Request ID (for debugging/replay)

You can use the built-in formatter or access the raw results:

```go
// Use built-in formatter
fmt.Println(ai.FormatResults(results))

// Access raw results
for _, result := range results {
	fmt.Printf("%s %d %s\n", result.Method, result.StatusCode, result.URL)
}
```
