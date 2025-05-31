package kiterunner

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/assetnote/kiterunner/pkg/http"
	"github.com/assetnote/kiterunner/pkg/stealth"
)

type ProgressBar interface {
	Incr(n int64)
	AddTotal(n int64)
}

type NullProgressBar struct {
	total int64
	hits  int64
}

func (n *NullProgressBar) Incr(v int64) {
	atomic.AddInt64(&n.hits, v)
}

func (n *NullProgressBar) AddTotal(v int64) {
	atomic.AddInt64(&n.total, v)
}

var _ ProgressBar = &NullProgressBar{}

type Config struct {
	MaxParallelHosts     int           `toml:"max_parallel_hosts" json:"max_parallel_hosts" mapstructure:"max_parallel_hosts"`
	MaxConnPerHost       int           `toml:"max_conn_per_host" json:"max_conn_per_host" mapstructure:"max_conn_per_host"`
	WildcardDetection    bool          `json:"wildcard_detection"`
	Delay                time.Duration `toml:"delay_ms" json:"delay_ms" mapstructure:"delay_ms"`
	HTTP                 http.Config   `toml:"http" json:"http" mapstructure:"http"`
	QuarantineThreshold  int64
	PreflightCheckRoutes []*http.Route // these are the routes use to calculate the baseline. If the slice is empty, no baselines will be created so requests will match on the status codes
	ProgressBar          ProgressBar
	RequestValidators    []RequestValidator

	// Phase 5: Stealth and Performance Features
	EnableStealth       bool                   `toml:"enable_stealth" json:"enable_stealth" mapstructure:"enable_stealth"`
	StealthLevel        stealth.ThreatLevel    `toml:"stealth_level" json:"stealth_level" mapstructure:"stealth_level"`
	TrafficProfile      stealth.TrafficProfile `toml:"traffic_profile" json:"traffic_profile" mapstructure:"traffic_profile"`
	AdaptiveConcurrency bool                   `toml:"adaptive_concurrency" json:"adaptive_concurrency" mapstructure:"adaptive_concurrency"`
	TargetResponseTime  time.Duration          `toml:"target_response_time" json:"target_response_time" mapstructure:"target_response_time"`
	EnableCache         bool                   `toml:"enable_cache" json:"enable_cache" mapstructure:"enable_cache"`
	MaxCacheSize        int                    `toml:"max_cache_size_mb" json:"max_cache_size_mb" mapstructure:"max_cache_size_mb"`
	MaxMemoryUsage      int                    `toml:"max_memory_mb" json:"max_memory_mb" mapstructure:"max_memory_mb"`

	// Internal adaptive managers (not serialized)
	AdaptiveManager *AdaptiveConcurrencyManager `json:"-"`
	ResourceManager *ResourceManager            `json:"-"`
	StealthEngine   *stealth.StealthEngine      `json:"-"`
}

func NewDefaultConfig() *Config {
	return &Config{
		MaxParallelHosts: 50,
		MaxConnPerHost:   5,
		Delay:            0 * time.Duration(0),
		// we have no default status codes, we rely on our wildcard detection
		ProgressBar:          &NullProgressBar{},
		PreflightCheckRoutes: append([]*http.Route{}, PreflightCheckRoutes...),
		RequestValidators: []RequestValidator{
			&KnownBadSitesValidator{},
			&WildcardResponseValidator{},
		},

		// Phase 5 defaults
		EnableStealth:       false,
		StealthLevel:        stealth.ThreatLevelLow,
		TrafficProfile:      stealth.BrowserProfile,
		AdaptiveConcurrency: false,
		TargetResponseTime:  500 * time.Millisecond,
		EnableCache:         false,
		MaxCacheSize:        100, // 100MB
		MaxMemoryUsage:      500, // 500MB
	}
}

type ErrBadConfig struct {
	fields []string
}

func (e *ErrBadConfig) Error() string {
	return fmt.Sprintf("config has invalid values in: %v", strings.Join(e.fields, ", "))
}

func (c *Config) Validate() error {
	badFields := make([]string, 0)
	if c.MaxConnPerHost < 1 {
		badFields = append(badFields, "MaxConnPerHost")
	}
	if c.MaxParallelHosts < 1 {
		badFields = append(badFields, "MaxParallelHosts")
	}
	if len(badFields) != 0 {
		return &ErrBadConfig{fields: badFields}
	}

	if c.ProgressBar == nil {
		c.ProgressBar = &NullProgressBar{}
	}

	actualValidators := make([]RequestValidator, 0)
	for _, v := range c.RequestValidators {
		if v != nil {
			actualValidators = append(actualValidators, v)
		}
	}
	c.RequestValidators = actualValidators

	return nil
}

type ConfigOption func(*Config)

func MaxTimeout(n time.Duration) ConfigOption {
	return func(c *Config) {
		c.HTTP.Timeout = n
	}
}

func Delay(n time.Duration) ConfigOption {
	return func(c *Config) {
		c.Delay = n
	}
}

func MaxRedirects(n int) ConfigOption {
	return func(c *Config) {
		c.HTTP.MaxRedirects = n
	}
}

func MaxConnPerHost(v int) ConfigOption {
	return func(c *Config) {
		c.MaxConnPerHost = v
	}
}

func MaxParallelHosts(v int) ConfigOption {
	return func(c *Config) {
		c.MaxParallelHosts = v
	}
}

func ReadBody(v bool) ConfigOption {
	return func(c *Config) {
		c.HTTP.ReadBody = v
	}
}

func ReadHeaders(v bool) ConfigOption {
	return func(c *Config) {
		c.HTTP.ReadHeaders = v
	}
}

func BlacklistDomains(in []string) ConfigOption {
	return func(o *Config) {
		o.HTTP.BlacklistRedirects = append(o.HTTP.BlacklistRedirects, in...)
	}
}

func WildcardDetection(enabled bool) ConfigOption {
	return func(o *Config) {
		o.WildcardDetection = enabled
	}
}

func AddRequestFilter(f RequestValidator) ConfigOption {
	return func(o *Config) {
		if f != nil {
			o.RequestValidators = append(o.RequestValidators, f)
		}
	}
}

// SkipPreflight will zero out the preflight check routes
func SkipPreflight(enabled bool) ConfigOption {
	return func(o *Config) {
		if enabled {
			o.PreflightCheckRoutes = o.PreflightCheckRoutes[:0]
		}
	}
}

func AddProgressBar(p ProgressBar) ConfigOption {
	return func(o *Config) {
		o.ProgressBar = p
	}
}

func TargetQuarantineThreshold(n int64) ConfigOption {
	return func(o *Config) {
		o.QuarantineThreshold = n
	}
}

func SetPreflightCheckRoutes(r []*http.Route) ConfigOption {
	return func(o *Config) {
		o.PreflightCheckRoutes = append(o.PreflightCheckRoutes[:0], r...)
	}
}

func EnableStealthMode(level stealth.ThreatLevel, profile stealth.TrafficProfile) ConfigOption {
	return func(c *Config) {
		c.EnableStealth = true
		c.StealthLevel = level
		c.TrafficProfile = profile

		// Initialize stealth engine
		c.StealthEngine = stealth.NewStealthEngine(level, profile)

		// Configure HTTP client stealth
		if c.HTTP.StealthConfig == nil {
			c.HTTP.StealthConfig = http.DefaultStealthConfig()
		}
	}
}

func EnableAdaptiveConcurrency(targetResponseTime time.Duration) ConfigOption {
	return func(c *Config) {
		c.AdaptiveConcurrency = true
		c.TargetResponseTime = targetResponseTime

		// Initialize adaptive manager
		c.AdaptiveManager = NewAdaptiveConcurrencyManager(
			c.MaxConnPerHost,
			c.MaxConnPerHost*2, // Allow up to 2x the initial connections
			targetResponseTime,
		)
	}
}

func EnableSmartCache(maxCacheSizeMB int) ConfigOption {
	return func(c *Config) {
		c.EnableCache = true
		c.MaxCacheSize = maxCacheSizeMB

		// Initialize resource manager
		c.ResourceManager = NewResourceManager(c.MaxMemoryUsage, maxCacheSizeMB)
	}
}

func SetMemoryLimit(maxMemoryMB int) ConfigOption {
	return func(c *Config) {
		c.MaxMemoryUsage = maxMemoryMB
	}
}

func SetStealthUserAgents(userAgents []string) ConfigOption {
	return func(c *Config) {
		if c.HTTP.StealthConfig == nil {
			c.HTTP.StealthConfig = http.DefaultStealthConfig()
		}
		c.HTTP.StealthConfig.UserAgents = userAgents
	}
}

func SetStealthProxy(proxyURL string) ConfigOption {
	return func(c *Config) {
		if c.HTTP.StealthConfig == nil {
			c.HTTP.StealthConfig = http.DefaultStealthConfig()
		}
		c.HTTP.StealthConfig.ProxyURL = proxyURL
	}
}

func SetStealthDelay(minMS, maxMS int) ConfigOption {
	return func(c *Config) {
		if c.HTTP.StealthConfig == nil {
			c.HTTP.StealthConfig = http.DefaultStealthConfig()
		}
		c.HTTP.StealthConfig.DelayRange = [2]int{minMS, maxMS}
	}
}

// QuickStealthMode provides preset stealth configurations
func QuickStealthMode(mode string) ConfigOption {
	return func(c *Config) {
		switch strings.ToLower(mode) {
		case "ghost":
			// Maximum stealth for highly protected targets
			EnableStealthMode(stealth.ThreatLevelHigh, stealth.CrawlerProfile)(c)
			SetStealthDelay(500, 2000)(c) // 500ms-2s delay
		case "ninja":
			// Moderate stealth for balanced speed/stealth
			EnableStealthMode(stealth.ThreatLevelMedium, stealth.BrowserProfile)(c)
			SetStealthDelay(100, 500)(c) // 100-500ms delay
		case "fast":
			// Minimal stealth for speed
			EnableStealthMode(stealth.ThreatLevelLow, stealth.APIClientProfile)(c)
			SetStealthDelay(50, 200)(c) // 50-200ms delay
		}
	}
}

// PerformanceMode optimizes for different use cases
func PerformanceMode(mode string) ConfigOption {
	return func(c *Config) {
		switch strings.ToLower(mode) {
		case "aggressive":
			// Maximum performance, minimum stealth
			c.MaxConnPerHost = 20
			c.MaxParallelHosts = 100
			EnableAdaptiveConcurrency(200 * time.Millisecond)(c)
			EnableSmartCache(200)(c) // 200MB cache
		case "balanced":
			// Balanced performance and stealth
			c.MaxConnPerHost = 10
			c.MaxParallelHosts = 50
			EnableAdaptiveConcurrency(500 * time.Millisecond)(c)
			EnableSmartCache(100)(c) // 100MB cache
		case "conservative":
			// Minimal resource usage
			c.MaxConnPerHost = 3
			c.MaxParallelHosts = 20
			EnableAdaptiveConcurrency(1 * time.Second)(c)
			EnableSmartCache(50)(c) // 50MB cache
		}
	}
}

func HTTPExtraHeaders(h []http.Header) ConfigOption {
	return func(o *Config) {
		o.HTTP.ExtraHeaders = append(o.HTTP.ExtraHeaders, h...)
	}
}
