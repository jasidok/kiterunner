// Package stealth provides advanced stealth and evasion capabilities for HTTP requests
package stealth

import (
	"math/rand"
	"sync"
	"time"

	"github.com/assetnote/kiterunner2/pkg/log"
	"github.com/valyala/fasthttp"
)

// ThreatLevel represents the aggression level of stealth features
type ThreatLevel int

const (
	// ThreatLevelLow uses minimal stealth features for fast scanning
	ThreatLevelLow ThreatLevel = iota
	// ThreatLevelMedium uses moderate stealth features
	ThreatLevelMedium
	// ThreatLevelHigh uses aggressive stealth features for maximum evasion
	ThreatLevelHigh
)

// StealthEngine manages advanced stealth capabilities
type StealthEngine struct {
	threatLevel     ThreatLevel
	requestCount    int64
	lastRequestTime time.Time
	mu              sync.RWMutex

	// Timing patterns
	baseDelay       time.Duration
	jitterRange     time.Duration
	burstProtection bool

	// Header rotation
	headerSets       []map[string]string
	currentHeaderSet int

	// Traffic patterns
	trafficProfile TrafficProfile
}

// TrafficProfile defines how to mimic legitimate traffic
type TrafficProfile struct {
	Name                string
	MinDelayBetweenReqs time.Duration
	MaxDelayBetweenReqs time.Duration
	BurstSize           int
	BurstDelay          time.Duration
	HeaderRotationFreq  int
}

// Common traffic profiles
var (
	BrowserProfile = TrafficProfile{
		Name:                "browser",
		MinDelayBetweenReqs: 100 * time.Millisecond,
		MaxDelayBetweenReqs: 2 * time.Second,
		BurstSize:           3,
		BurstDelay:          5 * time.Second,
		HeaderRotationFreq:  10,
	}

	APIClientProfile = TrafficProfile{
		Name:                "api_client",
		MinDelayBetweenReqs: 50 * time.Millisecond,
		MaxDelayBetweenReqs: 500 * time.Millisecond,
		BurstSize:           5,
		BurstDelay:          2 * time.Second,
		HeaderRotationFreq:  20,
	}

	CrawlerProfile = TrafficProfile{
		Name:                "crawler",
		MinDelayBetweenReqs: 200 * time.Millisecond,
		MaxDelayBetweenReqs: 1 * time.Second,
		BurstSize:           2,
		BurstDelay:          3 * time.Second,
		HeaderRotationFreq:  5,
	}
)

// NewStealthEngine creates a new stealth engine with the specified threat level
func NewStealthEngine(level ThreatLevel, profile TrafficProfile) *StealthEngine {
	headerSets := generateHeaderSets()

	return &StealthEngine{
		threatLevel:     level,
		trafficProfile:  profile,
		headerSets:      headerSets,
		burstProtection: level >= ThreatLevelMedium,
		baseDelay:       profile.MinDelayBetweenReqs,
		jitterRange:     profile.MaxDelayBetweenReqs - profile.MinDelayBetweenReqs,
	}
}

// ApplyStealthToRequest applies stealth modifications to an HTTP request
func (s *StealthEngine) ApplyStealthToRequest(req *fasthttp.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply timing delays
	s.applyTimingDelay()

	// Rotate headers based on frequency
	if s.requestCount%int64(s.trafficProfile.HeaderRotationFreq) == 0 {
		s.rotateHeaders()
	}

	// Apply current header set
	s.applyHeaderSet(req)

	// Apply threat-level specific modifications
	switch s.threatLevel {
	case ThreatLevelHigh:
		s.applyHighThreatModifications(req)
	case ThreatLevelMedium:
		s.applyMediumThreatModifications(req)
	case ThreatLevelLow:
		s.applyLowThreatModifications(req)
	}

	s.requestCount++
	s.lastRequestTime = time.Now()
}

// applyTimingDelay implements intelligent timing delays
func (s *StealthEngine) applyTimingDelay() {
	now := time.Now()

	// Calculate adaptive delay based on traffic profile
	baseDelay := s.baseDelay
	jitter := time.Duration(rand.Int63n(int64(s.jitterRange)))
	totalDelay := baseDelay + jitter

	// Apply burst protection
	if s.burstProtection {
		timeSinceLastReq := now.Sub(s.lastRequestTime)
		if timeSinceLastReq < s.trafficProfile.MinDelayBetweenReqs {
			additionalDelay := s.trafficProfile.MinDelayBetweenReqs - timeSinceLastReq
			totalDelay += additionalDelay
		}
	}

	if totalDelay > 0 {
		time.Sleep(totalDelay)
	}
}

// rotateHeaders switches to next header set
func (s *StealthEngine) rotateHeaders() {
	s.currentHeaderSet = (s.currentHeaderSet + 1) % len(s.headerSets)
	log.Trace().Int("header_set", s.currentHeaderSet).Msg("Rotating header set")
}

// applyHeaderSet applies the current header set to the request
func (s *StealthEngine) applyHeaderSet(req *fasthttp.Request) {
	if s.currentHeaderSet < len(s.headerSets) {
		headerSet := s.headerSets[s.currentHeaderSet]
		for key, value := range headerSet {
			req.Header.Set(key, value)
		}
	}
}

// applyHighThreatModifications applies maximum stealth features
func (s *StealthEngine) applyHighThreatModifications(req *fasthttp.Request) {
	// Randomize request order and add decoy headers
	s.addDecoyHeaders(req)
	s.randomizeExistingHeaders(req)

	// Add browser-like connection management
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Add random cache control
	cacheControls := []string{"no-cache", "max-age=0", "no-store", "must-revalidate"}
	req.Header.Set("Cache-Control", cacheControls[rand.Intn(len(cacheControls))])
}

// applyMediumThreatModifications applies moderate stealth features
func (s *StealthEngine) applyMediumThreatModifications(req *fasthttp.Request) {
	// Add some decoy headers occasionally
	if rand.Float32() < 0.3 {
		s.addDecoyHeaders(req)
	}

	// Set connection keep-alive
	req.Header.Set("Connection", "keep-alive")
}

// applyLowThreatModifications applies minimal stealth features
func (s *StealthEngine) applyLowThreatModifications(req *fasthttp.Request) {
	// Just ensure basic browser-like headers
	if req.Header.Peek("User-Agent") == nil {
		req.Header.Set("User-Agent", getRandomUserAgent())
	}
}

// addDecoyHeaders adds harmless but realistic headers to blend in
func (s *StealthEngine) addDecoyHeaders(req *fasthttp.Request) {
	decoyHeaders := map[string][]string{
		"X-Requested-With":  {"XMLHttpRequest", "fetch"},
		"Sec-Fetch-Site":    {"same-origin", "cross-site", "same-site"},
		"Sec-Fetch-Mode":    {"cors", "navigate", "no-cors"},
		"Sec-Fetch-Dest":    {"document", "empty", "script"},
		"DNT":               {"1"},
		"X-Forwarded-Proto": {"https"},
	}

	for header, values := range decoyHeaders {
		if rand.Float32() < 0.4 { // 40% chance to add each header
			value := values[rand.Intn(len(values))]
			req.Header.Set(header, value)
		}
	}
}

// randomizeExistingHeaders slightly modifies existing headers for uniqueness
func (s *StealthEngine) randomizeExistingHeaders(req *fasthttp.Request) {
	// Randomize Accept-Language
	if acceptLang := req.Header.Peek("Accept-Language"); acceptLang != nil {
		languages := []string{
			"en-US,en;q=0.9",
			"en-GB,en;q=0.8",
			"en-US,en;q=0.5",
			"en-CA,en;q=0.7",
		}
		req.Header.Set("Accept-Language", languages[rand.Intn(len(languages))])
	}
}

// generateHeaderSets creates different sets of headers to rotate through
func generateHeaderSets() []map[string]string {
	return []map[string]string{
		// Chrome-like headers
		{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		},
		// Firefox-like headers
		{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate",
		},
		// Safari-like headers
		{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-GB,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		},
		// API client headers
		{
			"User-Agent":   "PostmanRuntime/7.35.0",
			"Accept":       "application/json,text/plain,*/*",
			"Content-Type": "application/json",
		},
		// Mobile Chrome headers
		{
			"User-Agent":      "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		},
	}
}

// getRandomUserAgent returns a random user agent string
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	}
	return userAgents[rand.Intn(len(userAgents))]
}

// GetStats returns current stealth engine statistics
func (s *StealthEngine) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"request_count":      s.requestCount,
		"threat_level":       s.threatLevel,
		"current_header_set": s.currentHeaderSet,
		"traffic_profile":    s.trafficProfile.Name,
	}
}
