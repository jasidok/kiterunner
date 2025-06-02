package cai

import (
	"testing"
	"time"
)

func TestDefaultKiterunnerConfig(t *testing.T) {
	config := DefaultKiterunnerConfig()

	// Verify default values
	if len(config.Wordlists) != 1 || config.Wordlists[0] != "apiroutes-210328:20000" {
		t.Errorf("Expected default wordlist to be 'apiroutes-210328:20000', got %v", config.Wordlists)
	}

	if config.MaxConnectionsPerHost != 10 {
		t.Errorf("Expected MaxConnectionsPerHost to be 10, got %d", config.MaxConnectionsPerHost)
	}

	if config.MaxParallelHosts != 100 {
		t.Errorf("Expected MaxParallelHosts to be 100, got %d", config.MaxParallelHosts)
	}

	if config.Timeout != 3*time.Second {
		t.Errorf("Expected Timeout to be 3s, got %s", config.Timeout)
	}

	if len(config.Headers) != 1 || config.Headers[0] != "x-forwarded-for: 127.0.0.1" {
		t.Errorf("Expected Headers to contain default header, got %v", config.Headers)
	}

	if len(config.FailStatusCodes) != 8 {
		t.Errorf("Expected 8 fail status codes, got %d", len(config.FailStatusCodes))
	}

	if config.PreflightDepth != 1 {
		t.Errorf("Expected PreflightDepth to be 1, got %d", config.PreflightDepth)
	}

	if config.DirsearchCompat != false {
		t.Errorf("Expected DirsearchCompat to be false, got %t", config.DirsearchCompat)
	}
}
