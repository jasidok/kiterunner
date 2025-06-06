package scan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/assetnote/kiterunner2/internal/wordlist"
	"github.com/assetnote/kiterunner2/pkg/convert"
	errors2 "github.com/assetnote/kiterunner2/pkg/errors"
	"github.com/assetnote/kiterunner2/pkg/http"
	"github.com/assetnote/kiterunner2/pkg/kitebuilder"
	"github.com/assetnote/kiterunner2/pkg/kiterunner"
	"github.com/assetnote/kiterunner2/pkg/log"
	"github.com/assetnote/kiterunner2/pkg/proute"
	"github.com/hashicorp/go-multierror"
)

const (
	DefaultUserAgent       = "Chrome. Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"
	DefaultMaxConnPerHost  = 3
	DefaultMaxParallelHost = 50
	DefaultMaxRedirects    = 3
	DefaultDelay           = 0 * time.Second
	DefaultTimeout         = 3 * time.Second
)

var ()

type ScanOptions struct {
	Routes                   []*http.Route
	Headers                  []http.Header
	PrecheckTargets          bool
	MaxConnPerHost           int
	MaxParallelHosts         int
	Delay                    time.Duration
	UserAgent                string
	Timeout                  time.Duration
	MaxRedirects             int
	ForceMethod              string
	ShowProgress             bool
	WildcardDetection        bool
	ContentLengthIgnoreRange []http.Range
	ProgressBar              bool
	QuarantineThreshold      int64
	PreflightDepth           int64

	KitebuilderFullScan bool
	SuccessStatusCodes  map[int]interface{}
	FailStatusCodes     map[int]interface{}

	BlacklistRedirectDomains []string
	FilterAPIs               map[string]interface{}

	// New AI-powered features
	ParameterDiscovery      bool
	VulnerabilityDetection  bool
	ResponseIntelligence    bool
	SmartWordlistGeneration bool
	AllAIFeatures           bool

	// Phase 2: Advanced Discovery Features
	MultiMethodDiscovery bool
	HeaderBasedDiscovery bool
	EncodingBypass       bool
	AllPhase2Features    bool

	// Phase 4: Intelligence & Reporting Features
	RiskScoring       bool
	Notifications     bool
	AdvancedOutput    bool
	AllPhase4Features bool

	// Phase 5: Stealth and Performance Features
	EnableStealth       bool
	StealthMode         string
	PerformanceMode     string
	AdaptiveConcurrency bool
	TargetResponseTime  time.Duration
	EnableCache         bool
	MaxCacheSize        int
	MaxMemoryUsage      int
	StealthProxy        string
	StealthUserAgents   []string
	StealthDelayMin     int
	StealthDelayMax     int

	// Output options
	OutputFormats        []string
	OutputDirectory      string
	BurpProjectOutput    string
	NucleiTemplateOutput string
	MarkdownReportOutput string
	HTMLReportOutput     string
	SARIFOutput          string

	// Risk scoring options
	RiskThreshold string

	// Notification options
	NotificationConfig string
	SlackWebhook       string
	DiscordWebhook     string
	EmailConfig        string
	WebhookURL         string
	NotificationLevel  string

	// Bug bounty context
	BountyProgram  string
	BountyPlatform string
	Researcher     string

	// internal fields for logging
	extensions                 []string
	dirsearchCompatabilityMode bool
	kitebuilderAPINames        []string
	assetnoteAPINames          []string
	wordlistNames              []string

	// interim struct for conversion
	kitebuilderAPIs []kitebuilder.API

	// actual routes that we'll be scanning prior to conversion to Routes
	prouteAPIs []proute.API
}

func (s ScanOptions) KiterunnerOptions() []kiterunner.ConfigOption {
	opts := []kiterunner.ConfigOption{
		kiterunner.MaxRedirects(s.MaxRedirects),
		kiterunner.MaxParallelHosts(s.MaxParallelHosts),
		kiterunner.MaxConnPerHost(s.MaxConnPerHost),
		kiterunner.MaxTimeout(s.Timeout),
		kiterunner.Delay(s.Delay),
		kiterunner.ReadHeaders(false),
		kiterunner.ReadBody(false),
		kiterunner.HTTPExtraHeaders(s.Headers),
		kiterunner.HTTPExtraHeaders([]http.Header{{Key: "User-Agent", Value: s.UserAgent}}),
		kiterunner.AddRequestFilter(kiterunner.NewStatusCodeWhitelist(convert.IntMapToSlice(s.SuccessStatusCodes))),
		kiterunner.AddRequestFilter(kiterunner.NewStatusCodeBlacklist(convert.IntMapToSlice(s.FailStatusCodes))),
		kiterunner.AddRequestFilter(kiterunner.NewContentLengthValidator(s.ContentLengthIgnoreRange)),
		kiterunner.BlacklistDomains(s.BlacklistRedirectDomains),
		kiterunner.WildcardDetection(s.WildcardDetection),
		kiterunner.TargetQuarantineThreshold(s.QuarantineThreshold),
		kiterunner.SkipPreflight(!s.PrecheckTargets),
	}

	// Phase 5: Apply stealth and performance configurations
	if s.StealthMode != "" {
		opts = append(opts, kiterunner.QuickStealthMode(s.StealthMode))
	}

	if s.PerformanceMode != "" {
		opts = append(opts, kiterunner.PerformanceMode(s.PerformanceMode))
	}

	if s.AdaptiveConcurrency {
		targetTime := s.TargetResponseTime
		if targetTime == 0 {
			targetTime = 500 * time.Millisecond
		}
		opts = append(opts, kiterunner.EnableAdaptiveConcurrency(targetTime))
	}

	if s.EnableCache {
		cacheSize := s.MaxCacheSize
		if cacheSize == 0 {
			cacheSize = 100
		}
		opts = append(opts, kiterunner.EnableSmartCache(cacheSize))
	}

	if s.MaxMemoryUsage > 0 {
		opts = append(opts, kiterunner.SetMemoryLimit(s.MaxMemoryUsage))
	}

	if s.StealthProxy != "" {
		opts = append(opts, kiterunner.SetStealthProxy(s.StealthProxy))
	}

	if len(s.StealthUserAgents) > 0 {
		opts = append(opts, kiterunner.SetStealthUserAgents(s.StealthUserAgents))
	}

	if s.StealthDelayMin > 0 || s.StealthDelayMax > 0 {
		opts = append(opts, kiterunner.SetStealthDelay(s.StealthDelayMin, s.StealthDelayMax))
	}

	return opts
}

func (s ScanOptions) String() string {
	p := map[string]interface{}{
		"Routes":                   len(s.Routes),
		"Headers":                  s.Headers,
		"PrecheckTargets":          s.PrecheckTargets,
		"MaxConnPerHost":           s.MaxConnPerHost,
		"MaxParallelHosts":         s.MaxParallelHosts,
		"Delay":                    s.Delay,
		"UserAgent":                s.UserAgent,
		"Timeout":                  s.Timeout,
		"MaxRedirects":             s.MaxRedirects,
		"ForceMethod":              s.ForceMethod,
		"ShowProgress":             s.ShowProgress,
		"KitebuilderAPIs":          len(s.kitebuilderAPIs),
		"KitebuilderFullScan":      s.KitebuilderFullScan,
		"SuccessStatusCodes":       convert.IntMapToSlice(s.SuccessStatusCodes),
		"FailStatusCodes":          convert.IntMapToSlice(s.FailStatusCodes),
		"BlacklistRedirectDomains": s.BlacklistRedirectDomains,
		"WildcardDetection":        s.WildcardDetection,
		"ProgressBar":              s.ProgressBar,
		"QuarantineThreshold":      s.QuarantineThreshold,
		"PreflightDepth":           s.PreflightDepth,
		"FilterAPIs":               s.FilterAPIs,
		"ParameterDiscovery":       s.ParameterDiscovery,
		"VulnerabilityDetection":   s.VulnerabilityDetection,
		"ResponseIntelligence":     s.ResponseIntelligence,
		"SmartWordlistGeneration":  s.SmartWordlistGeneration,
		"AllAIFeatures":            s.AllAIFeatures,
		"MultiMethodDiscovery":     s.MultiMethodDiscovery,
		"HeaderBasedDiscovery":     s.HeaderBasedDiscovery,
		"EncodingBypass":           s.EncodingBypass,
		"AllPhase2Features":        s.AllPhase2Features,
		"RiskScoring":              s.RiskScoring,
		"Notifications":            s.Notifications,
		"AdvancedOutput":           s.AdvancedOutput,
		"AllPhase4Features":        s.AllPhase4Features,
		"EnableStealth":            s.EnableStealth,
		"StealthMode":              s.StealthMode,
		"PerformanceMode":          s.PerformanceMode,
		"AdaptiveConcurrency":      s.AdaptiveConcurrency,
		"TargetResponseTime":       s.TargetResponseTime,
		"EnableCache":              s.EnableCache,
		"MaxCacheSize":             s.MaxCacheSize,
		"MaxMemoryUsage":           s.MaxMemoryUsage,
		"StealthProxy":             s.StealthProxy,
		"StealthUserAgents":        s.StealthUserAgents,
		"StealthDelayMin":          s.StealthDelayMin,
		"StealthDelayMax":          s.StealthDelayMax,
		"OutputFormats":            s.OutputFormats,
		"BountyProgram":            s.BountyProgram,
		"NotificationLevel":        s.NotificationLevel,
	}
	ret := make([]string, 0)
	for k, v := range p {
		ret = append(ret, fmt.Sprintf("%s: %v", k, v))
	}
	return strings.Join(ret, "\n")
}

func NewDefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		MaxConnPerHost:      DefaultMaxConnPerHost,
		MaxRedirects:        DefaultMaxRedirects,
		MaxParallelHosts:    DefaultMaxParallelHost,
		Delay:               DefaultDelay,
		Timeout:             DefaultTimeout,
		UserAgent:           DefaultUserAgent,
		ShowProgress:        false,
		KitebuilderFullScan: false,
		SuccessStatusCodes:  make(map[int]interface{}),
		FailStatusCodes:     make(map[int]interface{}),
		WildcardDetection:   true,
		ProgressBar:         false,
		FilterAPIs:          make(map[string]interface{}),
		OutputDirectory:     "./results",
		RiskThreshold:       "medium",
		NotificationLevel:   "high",
	}
}

// FilteredRoutes will return the routes that match have a source in s.FilterAPIs. If s.FilterAPIs is empty
// then this will return s.Routes
func (s ScanOptions) FilteredRoutes() (ret []*http.Route) {
	if len(s.FilterAPIs) == 0 {
		return s.Routes
	}
	for _, v := range s.Routes {
		if _, ok := s.FilterAPIs[v.Source]; !ok {
			continue
		}
		ret = append(ret, v)
	}
	return ret
}

// Validate will ensure the config is sane after all the flags and then
// return an error if things dont make sense
func (s ScanOptions) Validate() error {
	if s.MaxConnPerHost <= 0 {
		return fmt.Errorf("max conn per host is too low (%d)", s.MaxConnPerHost)
	}
	if s.MaxParallelHosts <= 0 {
		return fmt.Errorf("max conn per host is too low (%d)", s.MaxParallelHosts)
	}
	if len(s.Routes) == 0 {
		return fmt.Errorf("no routes loaded. please specify some")
	}

	// Update the method
	if s.ForceMethod != "" {
		m, err := http.MethodFromString(s.ForceMethod)
		if err != nil {
			return fmt.Errorf("failed to parse method %s: %w", s.ForceMethod, err)
		}
		for _, v := range s.Routes {
			v.Method = m
		}
	}

	if len(s.SuccessStatusCodes) == 0 && len(s.FailStatusCodes) == 0 {
		return fmt.Errorf("no status codes in success or fail list")
	}

	return nil
}

func ForceMethod(method string) ScanOption {
	return func(o *ScanOptions) error {
		o.ForceMethod = method
		return nil
	}
}

func Precheck(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.PrecheckTargets = v
		return nil
	}
}

func ShowProgress(n bool) ScanOption {
	return func(o *ScanOptions) error {
		o.ShowProgress = n
		return nil
	}
}

func UserAgent(n string) ScanOption {
	return func(o *ScanOptions) error {
		o.UserAgent = n
		return nil
	}
}

func Timeout(n time.Duration) ScanOption {
	return func(o *ScanOptions) error {
		o.Timeout = n
		return nil
	}
}

func Delay(n time.Duration) ScanOption {
	return func(o *ScanOptions) error {
		o.Delay = n
		return nil
	}
}

func MaxParallelHosts(n int) ScanOption {
	return func(o *ScanOptions) error {
		o.MaxParallelHosts = n
		return nil
	}
}

func MaxRedirects(n int) ScanOption {
	return func(o *ScanOptions) error {
		o.MaxRedirects = n
		return nil
	}
}

func MaxConnPerHost(n int) ScanOption {
	return func(o *ScanOptions) error {
		o.MaxConnPerHost = n
		return nil
	}
}

// readLines reads all of the lines from a text file in to
// a slice of strings, returning the slice and any error
func readLines(filename string) ([][]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return [][]byte{}, err
	}
	defer f.Close()

	lines := make([][]byte, 0)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, []byte(sc.Text()))
	}

	return lines, sc.Err()
}

// LoadTextWordlist will load the lines from the text wordlist, ensure the paths are valid with a prefixing slash
// and append any required extensions to the wordlist
// we do not lazy load the wordlist because thats hard and a pain for allocations
func LoadTextWordlist(fns []string, extensions []string, dirsearchCompatabilityMode bool) ScanOption {
	return func(o *ScanOptions) error {
		o.extensions = append(o.extensions, extensions...)

		for _, filename := range fns {
			if filename == "" {
				return nil
			}

			if strings.HasSuffix(filename, ".kite") {
				return fmt.Errorf("attempted to load kitefile as plain text wordlist: %s. Please provide a plain wordlist", filename)
			}

			if strings.HasSuffix(filename, ".json") {
				return fmt.Errorf("attempted to load json as plain text wordlist: %s. Please provide a plain wordlist", filename)
			}

			lines, err := readLines(filename)
			if err != nil {
				return fmt.Errorf("failed to load file %s: %w", filename, err)
			}

			for _, v := range lines {
				if len(v) == 0 {
					continue
				}
				// ensure we prepend the / for a path
				if v[0] != '/' {
					v = append([]byte("/"), v...)
				}

				o.Routes = append(o.Routes, &http.Route{Method: http.GET, Path: v})

				// do all the extensions
				for _, ext := range extensions {
					path := []byte(v)
					if dirsearchCompatabilityMode {
						path = bytes.Replace(path, []byte("%EXT%"), []byte(ext), -1)
					} else {
						path = append(path, "."...)
						path = append(path, ext...)
					}
					o.Routes = append(o.Routes, &http.Route{Method: http.GET, Path: path})
				}
			}
		}
		return nil
	}
}

func LoadAssetnoteWordlist(fns []string, extensions []string, dirsearchCompatabilityMode bool) ScanOption {
	return func(o *ScanOptions) error {
		o.extensions = append(o.extensions, extensions...)

		// handle the filename;<maxlen> syntax
		maxLens := make(map[string]int)
		filenames := make([]string, 0)
		for _, v := range fns {
			f, err := ParseFileWithLen(v)
			if err != nil {
				return fmt.Errorf("failed to parse input filename: %w", err)
			}
			maxLens[f.Filename] = f.MaxLength
			filenames = append(filenames, f.Filename)
		}

		wms, err := wordlist.Get(context.Background(), filenames...)
		if err != nil {
			return fmt.Errorf("failed to get wordlists: %w", err)
		}

		for _, v := range wms {
			maxLen := maxLens[v.Shortname]
			if maxLens[v.Filename] > 0 {
				maxLen = maxLens[v.Filename]
			}

			w, err := v.Words()
			if err != nil {
				return fmt.Errorf("failed to load words: %w", err)
			}

			if maxLen > 0 {
				w = w[:maxLen]
			}
			for _, vv := range w {
				if len(vv) == 0 {
					continue
				}

				// ensure we prepend the / for a path
				if vv[0] != '/' {
					vv = "/" + vv
				}
				o.Routes = append(o.Routes, &http.Route{Method: http.GET, Path: []byte(vv)})

				for _, ext := range extensions {
					path := []byte(vv)
					if dirsearchCompatabilityMode {
						path = bytes.Replace(path, []byte("%EXT%"), []byte(ext), -1)
					} else {
						path = append(path, "."...)
						path = append(path, ext...)
					}
					o.Routes = append(o.Routes, &http.Route{Method: http.GET, Path: path})
				}
			}
		}

		o.wordlistNames = append(o.wordlistNames, fns...)

		return nil
	}
}

func LoadAssetnoteWordlistKitebuilder(fns []string) ScanOption {
	return func(o *ScanOptions) error {
		// handle the filename:<maxlen> syntax
		maxLens := make(map[string]int)
		filenames := make([]string, 0)
		for _, v := range fns {
			f, err := ParseFileWithLen(v)
			if err != nil {
				return fmt.Errorf("failed to parse input filename: %w", err)
			}
			maxLens[f.Filename] = f.MaxLength
			filenames = append(filenames, f.Filename)
		}

		wms, err := wordlist.Get(context.Background(), filenames...)
		if err != nil {
			return fmt.Errorf("failed to get wordlists: %w", err)
		}

		for _, v := range wms {
			maxLen := maxLens[v.Shortname]
			if maxLens[v.Filename] > 0 {
				maxLen = maxLens[v.Filename]
			}
			log.Debug().Int("max", maxLen).Str("name", v.Shortname).Msg("parsing kite input")

			api, err := v.APIS()
			if err != nil {
				return fmt.Errorf("failed to get API for wordlist: %w", err)
			}
			api = api.First(maxLen)

			var merr *multierror.Error
			routes, err := proute.APIsToKiterunnerRoutes(api)
			if errors.As(err, &merr) {
				log.Error().Str("id", v.Filename).Msg("errors while parsing api")
				for _, v := range merr.Errors {
					errors2.PrintError(v, 0)
				}
			} else if err != nil {
				return fmt.Errorf("failed to parse api: %w", err)
			}

			o.Routes = append(o.Routes, routes...)
		}

		o.assetnoteAPINames = append(o.assetnoteAPINames, fns...)

		return nil
	}
}

func LoadKitebuilderFile(fns []string) ScanOption {
	return func(o *ScanOptions) error {
		for _, filename := range fns {
			if filename == "" {
				return nil
			}

			var merr *multierror.Error
			apis, err := proute.DecodeAPIProtoFile(filename)
			if err != nil {
				return fmt.Errorf("failed to decode kite file: %w", err)
			}
			o.prouteAPIs = append(o.prouteAPIs, apis...)

			for _, v := range apis {
				wcr, err := proute.ToKiterunnerRoutes(v)
				if errors.As(err, &merr) {
					log.Error().Str("id", v.ID).Msg("errors while parsing api")
					for _, v := range merr.Errors {
						errors2.PrintError(v, 0)
					}
				} else if err != nil {
					return fmt.Errorf("failed to parse api: %w", err)
				}

				o.Routes = append(o.Routes, wcr...)
			}

			o.kitebuilderAPINames = append(o.kitebuilderAPINames, filename)

			// clear it so we can garbage collect it
			apis = proute.APIS{}
		}

		return nil
	}
}

// FilterAPIs will modify the output of FilteredRoutes to return the routes that only match the apis set
func FilterAPIs(apis []string) ScanOption {
	return func(o *ScanOptions) error {
		for _, v := range apis {
			o.FilterAPIs[v] = struct{}{}
		}
		return nil
	}
}

func AddHeaders(hs []string) ScanOption {
	return func(o *ScanOptions) error {
		for _, h := range hs {
			sp := strings.SplitN(h, ": ", 2)
			if len(sp) != 2 {
				return fmt.Errorf("invalid header format: %s", h)
			}
			o.Headers = append(o.Headers, http.Header{sp[0], sp[1]})
		}
		return nil
	}
}

func AddHeader(h string) ScanOption {
	return func(o *ScanOptions) error {
		sp := strings.SplitN(h, ": ", 2)
		if len(sp) != 2 {
			return fmt.Errorf("invalid header format: %s", h)
		}
		o.Headers = append(o.Headers, http.Header{sp[0], sp[1]})
		return nil
	}
}

func FailStatusCodes(v []int) ScanOption {
	return func(o *ScanOptions) error {
		if o.FailStatusCodes == nil {
			o.FailStatusCodes = make(map[int]interface{})
		}
		for _, vv := range v {
			o.FailStatusCodes[vv] = struct{}{}
		}
		return nil
	}
}

func SuccessStatusCodes(v []int) ScanOption {
	return func(o *ScanOptions) error {
		if o.SuccessStatusCodes == nil {
			o.SuccessStatusCodes = make(map[int]interface{})
		}
		for _, vv := range v {
			o.SuccessStatusCodes[vv] = struct{}{}
		}
		return nil
	}
}

func BlacklistDomains(in []string) ScanOption {
	return func(o *ScanOptions) error {
		o.BlacklistRedirectDomains = append(o.BlacklistRedirectDomains, in...)
		return nil
	}
}

func KitebuilderFullScan(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.KitebuilderFullScan = v
		return nil
	}
}

func WildcardDetection(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.WildcardDetection = v
		return nil
	}
}

func ContentLengthIgnoreRanges(v []string) ScanOption {
	return func(o *ScanOptions) error {
		for _, v := range v {
			vv, err := http.RangeFromString(v)
			if err != nil {
				return err
			}
			o.ContentLengthIgnoreRange = append(o.ContentLengthIgnoreRange, vv)
		}
		return nil
	}
}

func ContentLengthIgnoreRange(v string) ScanOption {
	return func(o *ScanOptions) error {
		vv, err := http.RangeFromString(v)
		if err != nil {
			return err
		}
		o.ContentLengthIgnoreRange = append(o.ContentLengthIgnoreRange, vv)
		return nil
	}
}

func ProgressBarEnabled(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.ProgressBar = v
		return nil
	}
}

func QuarantineThreshold(n int64) ScanOption {
	return func(o *ScanOptions) error {
		o.QuarantineThreshold = n
		return nil
	}
}

func PreflightDepth(n int64) ScanOption {
	return func(o *ScanOptions) error {
		o.PreflightDepth = n
		return nil
	}
}

// New AI-powered option functions
func EnableParameterDiscovery(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.ParameterDiscovery = v
		return nil
	}
}

func EnableVulnerabilityDetection(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.VulnerabilityDetection = v
		return nil
	}
}

func EnableResponseIntelligence(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.ResponseIntelligence = v
		return nil
	}
}

func EnableSmartWordlistGeneration(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.SmartWordlistGeneration = v
		return nil
	}
}

func EnableAllAIFeatures(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.AllAIFeatures = v
		if v {
			o.ParameterDiscovery = true
			o.VulnerabilityDetection = true
			o.ResponseIntelligence = true
			o.SmartWordlistGeneration = true
		}
		return nil
	}
}

// Phase 2 option functions
func EnableMultiMethodDiscovery(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.MultiMethodDiscovery = v
		return nil
	}
}

func EnableHeaderBasedDiscovery(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.HeaderBasedDiscovery = v
		return nil
	}
}

func EnableEncodingBypass(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.EncodingBypass = v
		return nil
	}
}

func EnableAllPhase2Features(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.AllPhase2Features = v
		if v {
			o.MultiMethodDiscovery = true
			o.HeaderBasedDiscovery = true
			o.EncodingBypass = true
		}
		return nil
	}
}

// Phase 4 option functions
func EnableRiskScoring(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.RiskScoring = v
		return nil
	}
}

func EnableNotifications(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.Notifications = v
		return nil
	}
}

func EnableAdvancedOutput(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.AdvancedOutput = v
		return nil
	}
}

func EnableAllPhase4Features(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.AllPhase4Features = v
		if v {
			o.RiskScoring = true
			o.Notifications = true
			o.AdvancedOutput = true
		}
		return nil
	}
}

// Phase 5: Stealth and Performance option functions
func EnableStealth(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.EnableStealth = v
		return nil
	}
}

func SetStealthMode(mode string) ScanOption {
	return func(o *ScanOptions) error {
		o.StealthMode = mode
		return nil
	}
}

func SetPerformanceMode(mode string) ScanOption {
	return func(o *ScanOptions) error {
		o.PerformanceMode = mode
		return nil
	}
}

func EnableAdaptiveConcurrency(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.AdaptiveConcurrency = v
		return nil
	}
}

func SetTargetResponseTime(duration time.Duration) ScanOption {
	return func(o *ScanOptions) error {
		o.TargetResponseTime = duration
		return nil
	}
}

func EnableCache(v bool) ScanOption {
	return func(o *ScanOptions) error {
		o.EnableCache = v
		return nil
	}
}

func SetMaxCacheSize(size int) ScanOption {
	return func(o *ScanOptions) error {
		o.MaxCacheSize = size
		return nil
	}
}

func SetMaxMemoryUsage(memory int) ScanOption {
	return func(o *ScanOptions) error {
		o.MaxMemoryUsage = memory
		return nil
	}
}

func SetStealthProxy(proxy string) ScanOption {
	return func(o *ScanOptions) error {
		o.StealthProxy = proxy
		return nil
	}
}

func SetStealthUserAgents(agents []string) ScanOption {
	return func(o *ScanOptions) error {
		o.StealthUserAgents = agents
		return nil
	}
}

func SetStealthDelayMin(min int) ScanOption {
	return func(o *ScanOptions) error {
		o.StealthDelayMin = min
		return nil
	}
}

func SetStealthDelayMax(max int) ScanOption {
	return func(o *ScanOptions) error {
		o.StealthDelayMax = max
		return nil
	}
}

func SetStealthDelay(min, max int) ScanOption {
	return func(o *ScanOptions) error {
		o.StealthDelayMin = min
		o.StealthDelayMax = max
		return nil
	}
}

// Output configuration functions
func SetOutputFormats(formats []string) ScanOption {
	return func(o *ScanOptions) error {
		o.OutputFormats = formats
		return nil
	}
}

func SetOutputDirectory(dir string) ScanOption {
	return func(o *ScanOptions) error {
		o.OutputDirectory = dir
		return nil
	}
}

func SetBurpProjectOutput(filename string) ScanOption {
	return func(o *ScanOptions) error {
		o.BurpProjectOutput = filename
		return nil
	}
}

func SetNucleiTemplateOutput(filename string) ScanOption {
	return func(o *ScanOptions) error {
		o.NucleiTemplateOutput = filename
		return nil
	}
}

func SetMarkdownReportOutput(filename string) ScanOption {
	return func(o *ScanOptions) error {
		o.MarkdownReportOutput = filename
		return nil
	}
}

func SetHTMLReportOutput(filename string) ScanOption {
	return func(o *ScanOptions) error {
		o.HTMLReportOutput = filename
		return nil
	}
}

func SetSARIFOutput(filename string) ScanOption {
	return func(o *ScanOptions) error {
		o.SARIFOutput = filename
		return nil
	}
}

// Risk scoring configuration functions
func SetRiskThreshold(threshold string) ScanOption {
	return func(o *ScanOptions) error {
		o.RiskThreshold = threshold
		return nil
	}
}

// Notification configuration functions
func SetNotificationConfig(config string) ScanOption {
	return func(o *ScanOptions) error {
		o.NotificationConfig = config
		return nil
	}
}

func SetSlackWebhook(webhook string) ScanOption {
	return func(o *ScanOptions) error {
		o.SlackWebhook = webhook
		return nil
	}
}

func SetDiscordWebhook(webhook string) ScanOption {
	return func(o *ScanOptions) error {
		o.DiscordWebhook = webhook
		return nil
	}
}

func SetEmailConfig(config string) ScanOption {
	return func(o *ScanOptions) error {
		o.EmailConfig = config
		return nil
	}
}

func SetWebhookURL(url string) ScanOption {
	return func(o *ScanOptions) error {
		o.WebhookURL = url
		return nil
	}
}

func SetNotificationLevel(level string) ScanOption {
	return func(o *ScanOptions) error {
		o.NotificationLevel = level
		return nil
	}
}

// Bug bounty context configuration functions
func SetBountyProgram(program string) ScanOption {
	return func(o *ScanOptions) error {
		o.BountyProgram = program
		return nil
	}
}

func SetBountyPlatform(platform string) ScanOption {
	return func(o *ScanOptions) error {
		o.BountyPlatform = platform
		return nil
	}
}

func SetResearcher(researcher string) ScanOption {
	return func(o *ScanOptions) error {
		o.Researcher = researcher
		return nil
	}
}

type ScanOption func(o *ScanOptions) error
