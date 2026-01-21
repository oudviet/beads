// Package validation provides utilities for filtering sensitive data from logs and error messages.
// This prevents credentials, API keys, tokens, and other sensitive information from leaking
// into debug output, error messages, or audit logs.
package validation

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Sensitive patterns that should be redacted from logs
var (
	// Matches API keys: sk-ant-xxx, sk-xxx, api_key=xxx, etc.
	apiKeyPattern = regexp.MustCompile(`(?i)(api[_-]?key|apikey|anthropic[_-]?api[_-]?key|openai[_-]?api[_-]?key|linear[_-]?api[_-]?key)\s*[:=]\s*[\'\"]?([a-zA-Z0-9_\-]{16,})[\'\"]?`)

	// Matches Bearer tokens and authorization headers
	authPattern = regexp.MustCompile(`(?i)(authorization|bearer|token)\s*[:=]\s*[\'\"]?([a-zA-Z0-9_\-\.]{20,})[\'\"]?`)

	// Matches passwords in URLs and config
	passwordPattern = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*[\'\"]?([^\s\'"]{4,})[\'\"]?`)

	// Matches secret keys
	secretPattern = regexp.MustCompile(`(?i)(secret|secret[_-]?key|private[_-]?key|access[_-]?key)\s*[:=]\s*[\'\"]?([a-zA-Z0-9_\-]{16,})[\'\"]?`)

	// Matches JWT tokens (header.payload.signature format)
	jwtPattern = regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.(eyJ[a-zA-Z0-9_\-]+\.)?[a-zA-Z0-9_\-]+`)
)

// RedactSensitiveData replaces sensitive information with [REDACTED] placeholders.
// This protects credentials, API keys, tokens, and other sensitive data from appearing in logs.
//
// Example:
//
//	input := "api_key=sk-ant-1234567890abcdef"
//	output := RedactSensitiveData(input)
//	// output: "api_key=[REDACTED]"
func RedactSensitiveData(input string) string {
	if input == "" {
		return input
	}

	result := input

	// Redact API keys
	result = apiKeyPattern.ReplaceAllString(result, "$1=[REDACTED]")

	// Redact authorization headers and tokens
	result = authPattern.ReplaceAllString(result, "$1=[REDACTED]")

	// Redact passwords
	result = passwordPattern.ReplaceAllString(result, "$1=[REDACTED]")

	// Redact secret keys
	result = secretPattern.ReplaceAllString(result, "$1=[REDACTED]")

	// Redact JWT tokens
	result = jwtPattern.ReplaceAllString(result, "[REDACTED_JWT]")

	return result
}

// SensitiveString wraps a string containing sensitive data (passwords, API keys, tokens).
// It prevents accidental logging or serialization of the sensitive value.
//
// Usage:
//
//	func ProcessAPIKey(key SensitiveString) {
//	    // key is never accidentally logged
//	    log.Printf("Processing key") // Safe: doesn't log the value
//	    apiClient.UseKey(string(key)) // Explicit conversion for use
//	}
type SensitiveString string

// String returns "[REDACTED]" instead of the actual value.
// This prevents accidental logging via fmt.Print, log.Printf, etc.
func (s SensitiveString) String() string {
	return "[REDACTED]"
}

// GoString returns "[REDACTED]" for debug output (%#v).
func (s SensitiveString) GoString() string {
	return "[REDACTED]"
}

// MarshalJSON returns a JSON null value to prevent serialization.
func (s SensitiveString) MarshalJSON() ([]byte, error) {
	return []byte("null"), nil
}

// Value returns the actual sensitive string value.
// Use this carefully and only when passing the value to authorized systems.
func (s SensitiveString) Value() string {
	return string(s)
}

// RedactURL removes passwords and sensitive tokens from URLs.
// This is useful for logging connection strings or remote URLs.
//
// Example:
//
//	url := "https://user:password@example.com/path"
//	safeURL := RedactURL(url)
//	// safeURL: "https://user:***@example.com/path"
func RedactURL(url string) string {
	if url == "" {
		return url
	}

	// Find :// separator
	protoIdx := strings.Index(url, "://")
	if protoIdx == -1 {
		// Not a URL with protocol
		return RedactSensitiveData(url)
	}

	// Find @ separator (credentials present)
	atIdx := strings.Index(url[protoIdx+3:], "@")
	if atIdx == -1 {
		// No credentials
		return RedactSensitiveData(url)
	}

	atIdx += protoIdx + 3

	// Find : before @ (password separator)
	colonIdx := strings.LastIndex(url[:atIdx], ":")
	if colonIdx == -1 || colonIdx < protoIdx {
		// No password in credentials
		return RedactSensitiveData(url)
	}

	// Reconstruct URL with redacted password
	result := url[:colonIdx+1] + "***" + url[atIdx:]
	return result
}

// RedactJSON recursively redacts sensitive keys in JSON-like strings.
// This provides defense-in-depth for structured logging.
//
// Recognized sensitive keys (case-insensitive):
//   - password, passwd, pwd
//   - api_key, apikey, apiKey
//   - secret, secretKey, private_key
//   - token, auth_token, access_token
//   - authorization, bearer
//
// Example:
//
//	json := `{"user":"john","api_key":"sk-123"}`
//	safeJSON := RedactJSON(json)
//	// safeJSON: `{"user":"john","api_key":"[REDACTED]"}`
func RedactJSON(jsonStr string) string {
	if jsonStr == "" {
		return jsonStr
	}

	// List of sensitive keys to redact (case-insensitive)
	sensitiveKeys := map[string]bool{
		"password":        true,
		"passwd":          true,
		"pwd":             true,
		"api_key":         true,
		"apikey":          true,
		"secret":          true,
		"secret_key":      true,
		"secretkey":       true,
		"private_key":     true,
		"privatekey":      true,
		"token":           true,
		"auth_token":      true,
		"authtoken":       true,
		"access_token":    true,
		"accesstoken":     true,
		"authorization":   true,
		"bearer":          true,
		"credential":      true,
		"credentials":     true,
		"anthropic_api_key": true,
		"openai_api_key":  true,
		"linear_api_key":  true,
	}

	result := jsonStr
	lowerJSON := strings.ToLower(jsonStr)

	for key := range sensitiveKeys {
		// Look for "key": "value" pattern (case-insensitive key)
		pattern := regexp.MustCompile(`(?i)("`+regexp.QuoteMeta(key)+`"\s*:\s*")[^"]*"`)
		result = pattern.ReplaceAllString(result, "$1[REDACTED]")

		// Also look for "key": value (without quotes)
		pattern2 := regexp.MustCompile(`(?i)("`+regexp.QuoteMeta(key)+`"\s*:\s*)([a-zA-Z0-9_\-]+)`)
		result = pattern2.ReplaceAllString(result, "$1[REDACTED]")
	}

	return result
}

// ContainsSensitiveData checks if a string contains patterns that look like sensitive data.
// This can be used to prevent logging of entire messages that contain credentials.
//
// Returns true if the string contains:
//   - API keys (sk-*, apiKey=*, etc.)
//   - Auth headers (Bearer: *, authorization: *)
//   - Passwords (password=*, pwd:*)
//   - JWT tokens
//   - Secret keys
func ContainsSensitiveData(input string) bool {
	if input == "" {
		return false
	}

	lowerInput := strings.ToLower(input)

	// Quick checks for common sensitive patterns
	sensitiveIndicators := []string{
		"api_key=", "apikey=", "api-key=",
		"password=", "passwd=", "pwd=",
		"secret=", "secret_key=", "secret-key=",
		"bearer ", "authorization:",
		"sk-ant-", "sk-", "pk-", // Common API key prefixes
	}

	for _, indicator := range sensitiveIndicators {
		if strings.Contains(lowerInput, indicator) {
			return true
		}
	}

	// Check for JWT tokens
	if jwtPattern.MatchString(input) {
		return true
	}

	return false
}

// TruncateForLog safely truncates a string for logging.
// If the string contains sensitive data, it returns a redacted placeholder.
// Otherwise, it returns the string truncated to maxLen characters.
//
// Example:
//
//	long := "This is a very long string..."
//	log.Printf("Value: %s", TruncateForLog(long, 20))
//	// Output: "Value: This is a very long..."
func TruncateForLog(input string, maxLen int) string {
	if input == "" {
		return input
	}

	// Check for sensitive data first
	if ContainsSensitiveData(input) {
		return "[REDACTED_SENSITIVE]"
	}

	// Safe UTF-8 truncation
	runeCount := utf8.RuneCountInString(input)
	if runeCount <= maxLen {
		return input
	}

	runes := []rune(input)
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

// FormatSafeLog formats a log message with automatic sensitive data redaction.
// This is a convenience wrapper around fmt.Sprintf with RedactSensitiveData.
//
// Example:
//
//	// Safely log potentially sensitive config
//	log.Printf("Config loaded: %s", FormatSafeLog(configStr))
func FormatSafeLog(format string, args ...interface{}) string {
	// Format the message first
	var b strings.Builder
	for i, arg := range args {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(fmtLogArg(arg))
	}

	result := fmt.Sprintf(format, b.String())
	return RedactSensitiveData(result)
}

// fmtLogArg converts an argument to string, handling sensitive types safely
func fmtLogArg(arg interface{}) string {
	switch v := arg.(type) {
	case SensitiveString:
		return v.String()
	case string:
		return v
	case []byte:
		// Truncate byte slices to prevent dumping large binary data
		if len(v) > 64 {
			return fmt.Sprintf("[%d bytes]", len(v))
		}
		return string(v)
	default:
		// For other types, let fmt.Sprintf handle it
		return fmt.Sprintf("%v", v)
	}
}
