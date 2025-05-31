package http

import (
	"strings"
)

// AllHTTPMethods contains all standard HTTP methods to test
var AllHTTPMethods = []Method{
	GET,
	POST,
	PUT,
	DELETE,
	PATCH,
	TRACE,
	[]byte("HEAD"),
	[]byte("OPTIONS"),
	[]byte("CONNECT"),
}

// MethodOverrideHeaders contains headers used to override HTTP methods
var MethodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
	"_method",
}

// MethodEnumerator handles testing multiple HTTP methods on endpoints
type MethodEnumerator struct {
	TestAllMethods      bool
	TestMethodOverrides bool
	SkipMethods         []Method
}

// NewMethodEnumerator creates a new method enumerator with default settings
func NewMethodEnumerator() *MethodEnumerator {
	return &MethodEnumerator{
		TestAllMethods:      true,
		TestMethodOverrides: true,
		SkipMethods:         []Method{},
	}
}

// GenerateMethodVariations creates multiple route variations with different HTTP methods
func (me *MethodEnumerator) GenerateMethodVariations(baseRoute *Route) []*Route {
	var variations []*Route

	if !me.TestAllMethods {
		return []*Route{baseRoute}
	}

	// Test all HTTP methods
	for _, method := range AllHTTPMethods {
		if me.shouldSkipMethod(method) {
			continue
		}

		variation := *baseRoute
		variation.Method = method
		variations = append(variations, &variation)
	}

	// Test method override headers if enabled
	if me.TestMethodOverrides {
		variations = append(variations, me.generateMethodOverrideVariations(baseRoute)...)
	}

	return variations
}

// shouldSkipMethod checks if a method should be skipped
func (me *MethodEnumerator) shouldSkipMethod(method Method) bool {
	for _, skipMethod := range me.SkipMethods {
		if string(method) == string(skipMethod) {
			return true
		}
	}
	return false
}

// generateMethodOverrideVariations creates variations using method override headers
func (me *MethodEnumerator) generateMethodOverrideVariations(baseRoute *Route) []*Route {
	var variations []*Route

	// Test method overrides with POST as base method
	for _, overrideHeader := range MethodOverrideHeaders {
		for _, targetMethod := range []string{"PUT", "DELETE", "PATCH"} {
			variation := *baseRoute
			variation.Method = POST

			// Add method override header
			overrideHdr := Header{
				Key:   overrideHeader,
				Value: targetMethod,
			}
			variation.Headers = append(variation.Headers, overrideHdr)
			variations = append(variations, &variation)
		}
	}

	return variations
}

// ContentTypeEnumerator handles testing different content types
type ContentTypeEnumerator struct {
	TestMultipleContentTypes bool
}

// ContentTypes to test for different responses
var TestContentTypes = []string{
	"application/json",
	"application/xml",
	"text/xml",
	"application/x-www-form-urlencoded",
	"multipart/form-data",
	"text/plain",
	"application/yaml",
}

// NewContentTypeEnumerator creates a new content type enumerator
func NewContentTypeEnumerator() *ContentTypeEnumerator {
	return &ContentTypeEnumerator{
		TestMultipleContentTypes: true,
	}
}

// GenerateContentTypeVariations creates route variations with different content types
func (cte *ContentTypeEnumerator) GenerateContentTypeVariations(baseRoute *Route) []*Route {
	if !cte.TestMultipleContentTypes {
		return []*Route{baseRoute}
	}

	var variations []*Route

	// Only test content types for methods that typically have bodies
	if !cte.methodSupportsBody(baseRoute.Method) {
		return []*Route{baseRoute}
	}

	for _, contentType := range TestContentTypes {
		variation := *baseRoute

		// Replace or add Content-Type header
		variation.Headers = cte.replaceContentTypeHeader(variation.Headers, contentType)
		variations = append(variations, &variation)
	}

	return variations
}

// methodSupportsBody checks if an HTTP method typically supports request bodies
func (cte *ContentTypeEnumerator) methodSupportsBody(method Method) bool {
	methodStr := strings.ToUpper(string(method))
	switch methodStr {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// replaceContentTypeHeader replaces or adds Content-Type header
func (cte *ContentTypeEnumerator) replaceContentTypeHeader(headers []Header, contentType string) []Header {
	// Remove existing Content-Type header
	var newHeaders []Header

	for _, header := range headers {
		if strings.ToLower(header.Key) != "content-type" {
			newHeaders = append(newHeaders, header)
		}
	}

	// Add new Content-Type header
	newHeaders = append(newHeaders, Header{
		Key:   "Content-Type",
		Value: contentType,
	})

	return newHeaders
}
