package parameters

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/assetnote/kiterunner2/pkg/http"
)

// CommonParameters contains high-value parameters commonly found in APIs
var CommonParameters = []string{
	// Authentication & Authorization
	"token", "api_key", "access_token", "refresh_token", "auth", "authorization",
	"jwt", "bearer", "session", "session_id", "sessionid", "sessid",

	// User & Account Management
	"user_id", "userid", "user", "username", "email", "account_id", "account",
	"profile_id", "profile", "member_id", "customer_id", "client_id",

	// Object References & IDs
	"id", "uuid", "guid", "key", "ref", "reference", "object_id", "entity_id",
	"resource_id", "item_id", "doc_id", "file_id", "message_id", "order_id",

	// Admin & Debug
	"admin", "debug", "test", "dev", "development", "internal", "private",
	"secret", "hidden", "backdoor", "maintenance", "system", "root",

	// API & Versioning
	"version", "v", "api_version", "format", "output", "response_type",
	"callback", "jsonp", "method", "action", "cmd", "command",

	// Search & Filtering
	"search", "query", "q", "filter", "sort", "order", "limit", "offset",
	"page", "per_page", "count", "size", "from", "to", "start", "end",

	// File & Upload
	"file", "filename", "path", "upload", "download", "attachment", "document",
	"image", "photo", "avatar", "media", "content", "data", "payload",

	// Configuration & Settings
	"config", "configuration", "settings", "options", "params", "parameters",
	"env", "environment", "mode", "status", "state", "flag", "enable", "disable",
}

// AdminParameters contains parameters that often lead to admin functionality
var AdminParameters = []string{
	"admin", "administrator", "root", "superuser", "sudo", "elevated",
	"privilege", "role", "permission", "access_level", "security_level",
	"admin_panel", "admin_console", "dashboard", "control_panel",
	"manage", "management", "maintenance", "system", "internal",
}

// ContextualParameters generates parameters based on endpoint context
type ContextualParameters struct {
	BasePath string
	Method   string
}

// GenerateParameters creates context-aware parameter lists
func (cp *ContextualParameters) GenerateParameters() []string {
	var params []string

	// Add common parameters
	params = append(params, CommonParameters...)

	// Add context-specific parameters based on path
	if strings.Contains(cp.BasePath, "/admin") {
		params = append(params, AdminParameters...)
	}

	if strings.Contains(cp.BasePath, "/api") {
		params = append(params, []string{
			"api_key", "client_id", "client_secret", "scope", "grant_type",
			"response_type", "redirect_uri", "state", "nonce",
		}...)
	}

	if strings.Contains(cp.BasePath, "/user") {
		params = append(params, []string{
			"user_id", "username", "email", "password", "first_name", "last_name",
			"phone", "address", "profile", "preferences", "settings",
		}...)
	}

	if strings.Contains(cp.BasePath, "/auth") {
		params = append(params, []string{
			"username", "password", "email", "phone", "code", "otp", "2fa",
			"remember_me", "stay_logged_in", "redirect", "next", "return_url",
		}...)
	}

	if strings.Contains(cp.BasePath, "/file") || strings.Contains(cp.BasePath, "/upload") {
		params = append(params, []string{
			"file", "filename", "path", "directory", "folder", "size", "type",
			"mimetype", "extension", "upload_id", "chunk", "offset",
		}...)
	}

	// Add HTTP method specific parameters
	switch cp.Method {
	case "POST", "PUT", "PATCH":
		params = append(params, []string{
			"data", "payload", "body", "content", "json", "xml", "form",
		}...)
	case "DELETE":
		params = append(params, []string{
			"force", "cascade", "permanent", "soft_delete", "archive",
		}...)
	case "GET":
		params = append(params, []string{
			"include", "exclude", "fields", "expand", "embed", "populate",
		}...)
	}

	return removeDuplicates(params)
}

// ParameterTester handles parameter discovery testing
type ParameterTester struct {
	BaseRoute  *http.Route
	Target     *http.Target
	Parameters []string
}

// NewParameterTester creates a new parameter discovery tester
func NewParameterTester(route *http.Route, target *http.Target) *ParameterTester {
	cp := &ContextualParameters{
		BasePath: string(route.Path),
		Method:   string(route.Method),
	}

	return &ParameterTester{
		BaseRoute:  route,
		Target:     target,
		Parameters: cp.GenerateParameters(),
	}
}

// GenerateTestRoutes creates routes with parameter variations
func (pt *ParameterTester) GenerateTestRoutes() []*http.Route {
	var routes []*http.Route

	for _, param := range pt.Parameters {
		// Test as query parameter
		route := &http.Route{
			Path:   pt.BaseRoute.Path,
			Method: pt.BaseRoute.Method,
		}

		// Add parameter to existing query or create new
		originalPath := string(pt.BaseRoute.Path)
		var newPath string

		if strings.Contains(originalPath, "?") {
			newPath = fmt.Sprintf("%s&%s=test", originalPath, param)
		} else {
			newPath = fmt.Sprintf("%s?%s=test", originalPath, param)
		}

		route.Path = []byte(newPath)
		routes = append(routes, route)

		// Test with different parameter values for interesting cases
		if isHighValueParam(param) {
			// Test with common sensitive values
			sensitiveValues := []string{"1", "0", "true", "false", "admin", "../", "null", "undefined"}
			for _, value := range sensitiveValues {
				sensitiveRoute := &http.Route{
					Path:   pt.BaseRoute.Path,
					Method: pt.BaseRoute.Method,
				}

				var sensitivePath string
				if strings.Contains(originalPath, "?") {
					sensitivePath = fmt.Sprintf("%s&%s=%s", originalPath, param, url.QueryEscape(value))
				} else {
					sensitivePath = fmt.Sprintf("%s?%s=%s", originalPath, param, url.QueryEscape(value))
				}

				sensitiveRoute.Path = []byte(sensitivePath)
				routes = append(routes, sensitiveRoute)
			}
		}
	}

	return routes
}

// isHighValueParam checks if a parameter is likely to be high-value for testing
func isHighValueParam(param string) bool {
	highValueParams := []string{
		"admin", "debug", "test", "user_id", "id", "token", "auth", "role",
		"permission", "access_level", "file", "path", "command", "cmd",
	}

	for _, hvp := range highValueParams {
		if strings.Contains(strings.ToLower(param), hvp) {
			return true
		}
	}
	return false
}

// removeDuplicates removes duplicate strings from slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}
