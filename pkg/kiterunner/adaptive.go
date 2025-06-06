// Package kiterunner provides adaptive concurrency and resource management
package kiterunner

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/assetnote/kiterunner2/pkg/log"
)

// AdaptiveConcurrencyManager manages dynamic concurrency based on target performance
type AdaptiveConcurrencyManager struct {
	// Current concurrency settings
	currentConnections int32
	maxConnections     int32
	minConnections     int32

	// Performance metrics
	avgResponseTime int64 // nanoseconds
	successRate     float64
	errorCount      int64
	requestCount    int64

	// Adaptive parameters
	targetResponseTime time.Duration
	adjustmentFactor   float64
	lastAdjustment     time.Time
	adjustmentInterval time.Duration

	// Thread safety
	mu sync.RWMutex

	// Performance history for trend analysis
	responseTimeHistory []time.Duration
	historySize         int
	historyIndex        int
}

// NewAdaptiveConcurrencyManager creates a new adaptive concurrency manager
func NewAdaptiveConcurrencyManager(initialConns, maxConns int, targetResponseTime time.Duration) *AdaptiveConcurrencyManager {
	minConns := max(1, initialConns/4) // Minimum 1, or 1/4 of initial

	return &AdaptiveConcurrencyManager{
		currentConnections:  int32(initialConns),
		maxConnections:      int32(maxConns),
		minConnections:      int32(minConns),
		targetResponseTime:  targetResponseTime,
		adjustmentFactor:    0.1, // 10% adjustment steps
		adjustmentInterval:  2 * time.Second,
		historySize:         50,
		responseTimeHistory: make([]time.Duration, 50),
	}
}

// RecordRequest records metrics for a completed request
func (acm *AdaptiveConcurrencyManager) RecordRequest(responseTime time.Duration, success bool) {
	atomic.AddInt64(&acm.requestCount, 1)

	if !success {
		atomic.AddInt64(&acm.errorCount, 1)
	}

	// Update response time history
	acm.mu.Lock()
	acm.responseTimeHistory[acm.historyIndex] = responseTime
	acm.historyIndex = (acm.historyIndex + 1) % acm.historySize
	acm.mu.Unlock()

	// Update moving average response time
	acm.updateAverageResponseTime(responseTime)

	// Trigger adaptive adjustment if needed
	if time.Since(acm.lastAdjustment) >= acm.adjustmentInterval {
		acm.adjustConcurrency()
	}
}

// GetCurrentConnections returns the current optimal connection count
func (acm *AdaptiveConcurrencyManager) GetCurrentConnections() int {
	return int(atomic.LoadInt32(&acm.currentConnections))
}

// updateAverageResponseTime updates the moving average response time
func (acm *AdaptiveConcurrencyManager) updateAverageResponseTime(responseTime time.Duration) {
	// Use exponential moving average
	currentAvg := time.Duration(atomic.LoadInt64(&acm.avgResponseTime))
	alpha := 0.1 // Smoothing factor
	newAvg := time.Duration(float64(currentAvg)*(1-alpha) + float64(responseTime)*alpha)
	atomic.StoreInt64(&acm.avgResponseTime, int64(newAvg))
}

// adjustConcurrency performs adaptive concurrency adjustment
func (acm *AdaptiveConcurrencyManager) adjustConcurrency() {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if time.Since(acm.lastAdjustment) < acm.adjustmentInterval {
		return // Too soon to adjust again
	}

	currentAvgResponseTime := time.Duration(atomic.LoadInt64(&acm.avgResponseTime))
	currentConns := atomic.LoadInt32(&acm.currentConnections)

	// Calculate success rate
	totalRequests := atomic.LoadInt64(&acm.requestCount)
	errorCount := atomic.LoadInt64(&acm.errorCount)
	successRate := 1.0
	if totalRequests > 0 {
		successRate = float64(totalRequests-errorCount) / float64(totalRequests)
	}

	log.Debug().
		Dur("avg_response_time", currentAvgResponseTime).
		Dur("target_response_time", acm.targetResponseTime).
		Float64("success_rate", successRate).
		Int32("current_connections", currentConns).
		Msg("Evaluating concurrency adjustment")

	var newConnections int32

	// Decision logic for concurrency adjustment
	if successRate < 0.8 { // High error rate - reduce concurrency
		adjustment := float64(currentConns) * acm.adjustmentFactor
		newConnections = currentConns - int32(math.Max(1, adjustment))
		log.Debug().Msg("Reducing concurrency due to high error rate")
	} else if currentAvgResponseTime > acm.targetResponseTime*2 { // Very slow responses
		adjustment := float64(currentConns) * acm.adjustmentFactor
		newConnections = currentConns - int32(math.Max(1, adjustment))
		log.Debug().Msg("Reducing concurrency due to slow responses")
	} else if currentAvgResponseTime < acm.targetResponseTime/2 && successRate > 0.95 { // Fast responses, low errors
		adjustment := float64(currentConns) * acm.adjustmentFactor
		newConnections = currentConns + int32(math.Max(1, adjustment))
		log.Debug().Msg("Increasing concurrency due to good performance")
	} else {
		// No adjustment needed
		acm.lastAdjustment = time.Now()
		return
	}

	// Apply bounds
	newConnections = int32(math.Max(float64(acm.minConnections), math.Min(float64(acm.maxConnections), float64(newConnections))))

	if newConnections != currentConns {
		atomic.StoreInt32(&acm.currentConnections, newConnections)
		log.Info().
			Int32("old_connections", currentConns).
			Int32("new_connections", newConnections).
			Msg("Adjusted concurrency")
	}

	acm.lastAdjustment = time.Now()
}

// GetPerformanceMetrics returns current performance metrics
func (acm *AdaptiveConcurrencyManager) GetPerformanceMetrics() map[string]interface{} {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	totalRequests := atomic.LoadInt64(&acm.requestCount)
	errorCount := atomic.LoadInt64(&acm.errorCount)
	successRate := 1.0
	if totalRequests > 0 {
		successRate = float64(totalRequests-errorCount) / float64(totalRequests)
	}

	return map[string]interface{}{
		"current_connections":  atomic.LoadInt32(&acm.currentConnections),
		"max_connections":      acm.maxConnections,
		"min_connections":      acm.minConnections,
		"avg_response_time":    time.Duration(atomic.LoadInt64(&acm.avgResponseTime)),
		"target_response_time": acm.targetResponseTime,
		"success_rate":         successRate,
		"total_requests":       totalRequests,
		"error_count":          errorCount,
	}
}

// ResourceManager manages memory and cache optimization
type ResourceManager struct {
	// Memory management
	maxMemoryUsage     int64 // bytes
	currentMemoryUsage int64

	// Cache management
	responseCache sync.Map // Thread-safe cache for similar requests
	cacheHits     int64
	cacheMisses   int64
	cacheSize     int64
	maxCacheSize  int64

	// Request deduplication
	inflightRequests sync.Map // Track in-flight requests to avoid duplicates

	// Performance optimization
	streamingMode bool // Stream large wordlists instead of loading into memory
}

// NewResourceManager creates a new resource manager
func NewResourceManager(maxMemoryMB, maxCacheMB int) *ResourceManager {
	return &ResourceManager{
		maxMemoryUsage: int64(maxMemoryMB) * 1024 * 1024,
		maxCacheSize:   int64(maxCacheMB) * 1024 * 1024,
		streamingMode:  true,
	}
}

// CacheKey represents a cache key for responses
type CacheKey struct {
	Host   string
	Path   string
	Method string
}

// CacheEntry represents a cached response
type CacheEntry struct {
	Response    []byte
	StatusCode  int
	Timestamp   time.Time
	AccessCount int64
}

// GetCachedResponse retrieves a cached response if available
func (rm *ResourceManager) GetCachedResponse(key CacheKey) (*CacheEntry, bool) {
	if value, ok := rm.responseCache.Load(key); ok {
		entry := value.(*CacheEntry)
		atomic.AddInt64(&entry.AccessCount, 1)
		atomic.AddInt64(&rm.cacheHits, 1)

		// Check if cache entry is still valid (5 minutes)
		if time.Since(entry.Timestamp) < 5*time.Minute {
			return entry, true
		}

		// Remove expired entry
		rm.responseCache.Delete(key)
		atomic.AddInt64(&rm.cacheSize, -int64(len(entry.Response)))
	}

	atomic.AddInt64(&rm.cacheMisses, 1)
	return nil, false
}

// CacheResponse stores a response in the cache
func (rm *ResourceManager) CacheResponse(key CacheKey, response []byte, statusCode int) {
	if atomic.LoadInt64(&rm.cacheSize) >= rm.maxCacheSize {
		rm.evictOldEntries()
	}

	entry := &CacheEntry{
		Response:   response,
		StatusCode: statusCode,
		Timestamp:  time.Now(),
	}

	rm.responseCache.Store(key, entry)
	atomic.AddInt64(&rm.cacheSize, int64(len(response)))
}

// evictOldEntries removes old cache entries when cache is full
func (rm *ResourceManager) evictOldEntries() {
	cutoff := time.Now().Add(-2 * time.Minute)

	rm.responseCache.Range(func(key, value interface{}) bool {
		entry := value.(*CacheEntry)
		if entry.Timestamp.Before(cutoff) || atomic.LoadInt64(&entry.AccessCount) == 0 {
			rm.responseCache.Delete(key)
			atomic.AddInt64(&rm.cacheSize, -int64(len(entry.Response)))
		}
		return true
	})
}

// TrackInflightRequest tracks a request to avoid duplicates
func (rm *ResourceManager) TrackInflightRequest(key CacheKey) bool {
	_, loaded := rm.inflightRequests.LoadOrStore(key, time.Now())
	return !loaded // Returns true if this is a new request
}

// CompleteInflightRequest marks a request as complete
func (rm *ResourceManager) CompleteInflightRequest(key CacheKey) {
	rm.inflightRequests.Delete(key)
}

// GetCacheStats returns cache performance statistics
func (rm *ResourceManager) GetCacheStats() map[string]interface{} {
	hits := atomic.LoadInt64(&rm.cacheHits)
	misses := atomic.LoadInt64(&rm.cacheMisses)
	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return map[string]interface{}{
		"cache_hits":     hits,
		"cache_misses":   misses,
		"cache_hit_rate": hitRate,
		"cache_size":     atomic.LoadInt64(&rm.cacheSize),
		"max_cache_size": rm.maxCacheSize,
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
