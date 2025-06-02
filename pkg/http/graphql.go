package http

import (
	"encoding/json"
	"strings"

	"github.com/assetnote/kiterunner/pkg/log"
	"github.com/valyala/fasthttp"
)

// GraphQLConfig holds configuration for GraphQL-specific features
type GraphQLConfig struct {
	// AutoInjectToken determines whether to automatically inject Bearer tokens into GraphQL requests
	AutoInjectToken bool
	// Token is the Bearer token to inject
	Token string
	// ScanIntrospection determines whether to automatically scan GraphQL introspection
	ScanIntrospection bool
	// IntrospectionQueries contains GraphQL introspection queries to use
	IntrospectionQueries []string
}

// DefaultGraphQLConfig returns a default GraphQL configuration
func DefaultGraphQLConfig() *GraphQLConfig {
	return &GraphQLConfig{
		AutoInjectToken:   false,
		Token:             "",
		ScanIntrospection: true,
		IntrospectionQueries: []string{
			// Basic introspection query to get schema information
			`{"query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}`,
			// Query to get all types
			`{"query": "{ __schema { types { name kind description fields { name description } } } }"}`,
			// Query to get all queries
			`{"query": "{ __schema { queryType { fields { name description args { name type { name kind } } type { name kind } } } } }"}`,
			// Query to get all mutations
			`{"query": "{ __schema { mutationType { fields { name description args { name type { name kind } } type { name kind } } } } }"}`,
		},
	}
}

// IsGraphQLRequest determines if a request is a GraphQL request
func IsGraphQLRequest(req *fasthttp.Request) bool {
	// Check Content-Type header
	contentType := string(req.Header.Peek("Content-Type"))
	if strings.Contains(contentType, "application/graphql") {
		return true
	}

	// Check if path contains graphql
	path := string(req.URI().Path())
	if strings.Contains(strings.ToLower(path), "graphql") {
		return true
	}

	// Check if body contains a GraphQL query
	body := req.Body()
	if len(body) > 0 {
		// Check for JSON with query field
		var jsonBody map[string]interface{}
		if err := json.Unmarshal(body, &jsonBody); err == nil {
			if _, ok := jsonBody["query"]; ok {
				return true
			}
		}

		// Check for GraphQL query syntax
		if strings.Contains(string(body), "query") &&
			(strings.Contains(string(body), "{") && strings.Contains(string(body), "}")) {
			return true
		}
	}

	return false
}

// ApplyGraphQLFeatures applies GraphQL-specific features to a request
func ApplyGraphQLFeatures(req *fasthttp.Request, config *GraphQLConfig) {
	if config == nil || !IsGraphQLRequest(req) {
		return
	}

	// Auto-inject Bearer token if configured
	if config.AutoInjectToken && config.Token != "" {
		authHeader := string(req.Header.Peek("Authorization"))
		if authHeader == "" {
			req.Header.Set("Authorization", "Bearer "+config.Token)
			log.Debug().Str("token", config.Token).Msg("Auto-injected Bearer token into GraphQL request")
		}
	}
}

// PerformIntrospectionScan performs a GraphQL introspection scan
// Returns true if introspection is enabled, false otherwise
func PerformIntrospectionScan(client *HTTPClient, target string, config *GraphQLConfig) (bool, map[string]interface{}, error) {
	if config == nil || !config.ScanIntrospection {
		return false, nil, nil
	}

	log.Debug().Str("target", target).Msg("Performing GraphQL introspection scan")

	for _, query := range config.IntrospectionQueries {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(target)
		req.Header.SetMethod("POST")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		if config.AutoInjectToken && config.Token != "" {
			req.Header.Set("Authorization", "Bearer "+config.Token)
		}

		req.SetBodyString(query)

		if err := client.Do(req, resp); err != nil {
			log.Error().Err(err).Msg("Error performing GraphQL introspection")
			continue
		}

		// Check if introspection is enabled
		if resp.StatusCode() == 200 {
			var result map[string]interface{}
			if err := json.Unmarshal(resp.Body(), &result); err != nil {
				log.Error().Err(err).Msg("Error parsing GraphQL introspection response")
				continue
			}

			// Check if the response contains schema information
			if data, ok := result["data"].(map[string]interface{}); ok {
				if schema, ok := data["__schema"].(map[string]interface{}); ok {
					log.Info().Str("target", target).Msg("GraphQL introspection is enabled")
					return true, schema, nil
				}
			}
		}
	}

	log.Info().Str("target", target).Msg("GraphQL introspection appears to be disabled")
	return false, nil, nil
}
