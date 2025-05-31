package http

import (
	"fmt"
	"strings"
)

// AdminHeaders contains headers that might reveal admin functionality
var AdminHeaders = []Header{
	{Key: "X-Admin", Value: "true"},
	{Key: "X-Admin", Value: "1"},
	{Key: "X-Debug", Value: "true"},
	{Key: "X-Debug", Value: "1"},
	{Key: "X-Test", Value: "true"},
	{Key: "X-Test", Value: "1"},
	{Key: "X-Development", Value: "true"},
	{Key: "X-Dev", Value: "true"},
	{Key: "X-Override", Value: "admin"},
	{Key: "X-Role", Value: "admin"},
	{Key: "X-User-Role", Value: "admin"},
	{Key: "X-Access-Level", Value: "admin"},
	{Key: "X-Privilege", Value: "admin"},
	{Key: "X-Auth-Level", Value: "admin"},
	{Key: "X-Internal", Value: "true"},
	{Key: "X-Staff", Value: "true"},
	{Key: "X-Employee", Value: "true"},
	{Key: "X-Admin-Access", Value: "true"},
	{Key: "X-Superuser", Value: "true"},
	{Key: "X-Root", Value: "true"},
	{Key: "X-Elevated", Value: "true"},
	{Key: "X-Bypass", Value: "true"},
	{Key: "X-Skip-Auth", Value: "true"},
	{Key: "X-No-Auth", Value: "true"},
}

// DebugHeaders contains headers that might reveal debug information
var DebugHeaders = []Header{
	{Key: "X-Debug-Mode", Value: "true"},
	{Key: "X-Verbose", Value: "true"},
	{Key: "X-Trace", Value: "true"},
	{Key: "X-Profile", Value: "true"},
	{Key: "X-Log-Level", Value: "debug"},
	{Key: "X-Show-Errors", Value: "true"},
	{Key: "X-Stack-Trace", Value: "true"},
	{Key: "X-Debug-Info", Value: "true"},
	{Key: "X-Developer", Value: "true"},
	{Key: "X-Debug-Headers", Value: "true"},
	{Key: "X-Show-SQL", Value: "true"},
	{Key: "X-Debug-SQL", Value: "true"},
}

// BypassHeaders contains headers that might bypass security
var BypassHeaders = []Header{
	{Key: "X-Forwarded-For", Value: "127.0.0.1"},
	{Key: "X-Real-IP", Value: "127.0.0.1"},
	{Key: "X-Client-IP", Value: "127.0.0.1"},
	{Key: "X-Originating-IP", Value: "127.0.0.1"},
	{Key: "X-Remote-IP", Value: "127.0.0.1"},
	{Key: "X-Remote-Addr", Value: "127.0.0.1"},
	{Key: "True-Client-IP", Value: "127.0.0.1"},
	{Key: "CF-Connecting-IP", Value: "127.0.0.1"},
	{Key: "X-Cluster-Client-IP", Value: "127.0.0.1"},
	{Key: "Fastly-Client-IP", Value: "127.0.0.1"},
	{Key: "X-Forwarded", Value: "for=127.0.0.1"},
	{Key: "Forwarded-For", Value: "127.0.0.1"},
	{Key: "Forwarded", Value: "for=127.0.0.1"},
	{Key: "X-Source-IP", Value: "127.0.0.1"},
	{Key: "X-Original-IP", Value: "127.0.0.1"},
}

// CustomHeaders contains additional headers to test
var CustomHeaders = []Header{
	{Key: "X-API-Key", Value: "test"},
	{Key: "X-Token", Value: "test"},
	{Key: "X-Access-Token", Value: "test"},
	{Key: "X-Auth-Token", Value: "test"},
	{Key: "X-Session-Token", Value: "test"},
	{Key: "X-CSRF-Token", Value: "test"},
	{Key: "X-Request-ID", Value: "test"},
	{Key: "X-Correlation-ID", Value: "test"},
	{Key: "X-Trace-ID", Value: "test"},
	{Key: "X-User-ID", Value: "1"},
	{Key: "X-Account-ID", Value: "1"},
	{Key: "X-Tenant-ID", Value: "1"},
	{Key: "X-Organization-ID", Value: "1"},
	{Key: "X-Client-ID", Value: "1"},
	{Key: "X-Application-ID", Value: "1"},
	{Key: "X-Version", Value: "v1"},
	{Key: "X-API-Version", Value: "1.0"},
	{Key: "X-Accept-Version", Value: "1.0"},
}

// HeaderDiscovery handles testing various headers for hidden functionality
type HeaderDiscovery struct {
	TestAdminHeaders  bool
	TestDebugHeaders  bool
	TestBypassHeaders bool
	TestCustomHeaders bool
	CustomHeaderList  []Header
}

// NewHeaderDiscovery creates a new header discovery instance
func NewHeaderDiscovery() *HeaderDiscovery {
	return &HeaderDiscovery{
		TestAdminHeaders:  true,
		TestDebugHeaders:  true,
		TestBypassHeaders: true,
		TestCustomHeaders: true,
		CustomHeaderList:  []Header{},
	}
}

// GenerateHeaderVariations creates route variations with different headers
func (hd *HeaderDiscovery) GenerateHeaderVariations(baseRoute *Route) []*Route {
	var variations []*Route

	// Test admin headers
	if hd.TestAdminHeaders {
		variations = append(variations, hd.generateVariationsWithHeaders(baseRoute, AdminHeaders, "admin")...)
	}

	// Test debug headers
	if hd.TestDebugHeaders {
		variations = append(variations, hd.generateVariationsWithHeaders(baseRoute, DebugHeaders, "debug")...)
	}

	// Test bypass headers
	if hd.TestBypassHeaders {
		variations = append(variations, hd.generateVariationsWithHeaders(baseRoute, BypassHeaders, "bypass")...)
	}

	// Test custom headers
	if hd.TestCustomHeaders {
		variations = append(variations, hd.generateVariationsWithHeaders(baseRoute, CustomHeaders, "custom")...)
	}

	// Test user-provided custom headers
	if len(hd.CustomHeaderList) > 0 {
		variations = append(variations, hd.generateVariationsWithHeaders(baseRoute, hd.CustomHeaderList, "user-custom")...)
	}

	return variations
}

// generateVariationsWithHeaders creates variations by adding specific headers
func (hd *HeaderDiscovery) generateVariationsWithHeaders(baseRoute *Route, headers []Header, category string) []*Route {
	var variations []*Route

	for _, header := range headers {
		variation := *baseRoute

		// Copy existing headers
		newHeaders := make([]Header, len(baseRoute.Headers))
		copy(newHeaders, baseRoute.Headers)

		// Add the test header
		newHeaders = append(newHeaders, header)
		variation.Headers = newHeaders

		// Set source to indicate this is a header test
		variation.Source = fmt.Sprintf("%s-header-%s", category, strings.ToLower(header.Key))

		variations = append(variations, &variation)
	}

	return variations
}

// GenerateHeaderCombinations creates variations with multiple headers combined
func (hd *HeaderDiscovery) GenerateHeaderCombinations(baseRoute *Route) []*Route {
	var variations []*Route

	// Common combinations that might be effective together
	combinations := [][]Header{
		// Admin + Debug combination
		{
			{Key: "X-Admin", Value: "true"},
			{Key: "X-Debug", Value: "true"},
		},
		// Admin + Bypass combination
		{
			{Key: "X-Admin", Value: "true"},
			{Key: "X-Forwarded-For", Value: "127.0.0.1"},
		},
		// Debug + Bypass combination
		{
			{Key: "X-Debug", Value: "true"},
			{Key: "X-Real-IP", Value: "127.0.0.1"},
		},
		// Triple threat combination
		{
			{Key: "X-Admin", Value: "true"},
			{Key: "X-Debug", Value: "true"},
			{Key: "X-Forwarded-For", Value: "127.0.0.1"},
		},
	}

	for i, combo := range combinations {
		variation := *baseRoute

		// Copy existing headers
		newHeaders := make([]Header, len(baseRoute.Headers))
		copy(newHeaders, baseRoute.Headers)

		// Add combination headers
		newHeaders = append(newHeaders, combo...)
		variation.Headers = newHeaders

		// Set source to indicate this is a combination test
		variation.Source = fmt.Sprintf("header-combo-%d", i+1)

		variations = append(variations, &variation)
	}

	return variations
}

// AddCustomHeader adds a custom header to test
func (hd *HeaderDiscovery) AddCustomHeader(key, value string) {
	hd.CustomHeaderList = append(hd.CustomHeaderList, Header{
		Key:   key,
		Value: value,
	})
}
