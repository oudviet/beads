package validation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrorSanitizer removes sensitive information from error messages
type ErrorSanitizer struct {
	hidePaths     bool
	hideVersions  bool
	hideUsernames bool
	customFilters []string
}

// NewErrorSanitizer creates a new error sanitizer with default settings
func NewErrorSanitizer() *ErrorSanitizer {
	return &ErrorSanitizer{
		hidePaths:     true,
		hideVersions:  true,
		hideUsernames: false,
	}
}

// WithHidePaths controls whether file paths are hidden in error messages
func (es *ErrorSanitizer) WithHidePaths(hide bool) *ErrorSanitizer {
	es.hidePaths = hide
	return es
}

// WithHideVersions controls whether version numbers are hidden in error messages
func (es *ErrorSanitizer) WithHideVersions(hide bool) *ErrorSanitizer {
	es.hideVersions = hide
	return es
}

// WithHideUsernames controls whether usernames are hidden in error messages
func (es *ErrorSanitizer) WithHideUsernames(hide bool) *ErrorSanitizer {
	es.hideUsernames = hide
	return es
}

// WithCustomFilters adds custom regex patterns to filter from error messages
func (es *ErrorSanitizer) WithCustomFilters(filters []string) *ErrorSanitizer {
	es.customFilters = filters
	return es
}

// SanitizeError removes sensitive information from an error message
// Returns a sanitized error message string, or original error if input is nil
func (es *ErrorSanitizer) SanitizeError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	// Hide file paths
	if es.hidePaths {
		msg = es.sanitizePaths(msg)
	}

	// Hide version numbers
	if es.hideVersions {
		msg = es.sanitizeVersions(msg)
	}

	// Hide usernames
	if es.hideUsernames {
		msg = es.sanitizeUsernames(msg)
	}

	// Apply custom filters
	for _, filter := range es.customFilters {
		re, err := regexp.Compile(filter)
		if err == nil {
			msg = re.ReplaceAllString(msg, "[REDACTED]")
		}
	}

	return msg
}

// sanitizePaths replaces file paths with generic placeholders
func (es *ErrorSanitizer) sanitizePaths(msg string) string {
	// Match absolute paths (Unix and Windows)
	// Unix: /home/user/project/file.go
	// Windows: C:\Users\user\project\file.go

	// First, detect if we have a path-like pattern
	pathRegex := regexp.MustCompile(`[/\\][\w\-./\\]+[\w\-./\\]+`)

	// Find all path-like patterns and replace
	matches := pathRegex.FindAllString(msg, -1)
	for _, match := range matches {
		// Check if it looks like a real path (contains separators)
		if strings.Contains(match, "/") || strings.Contains(match, "\\") {
			// Replace with generic placeholder, keeping the filename
			baseName := filepath.Base(match)
			msg = strings.ReplaceAll(msg, match, "[path]/"+baseName)
		}
	}

	// Hide home directory paths
	homePatterns := []string{
		"/home/[^/]+/",
		"/Users/[^/]+/",
		`C:\\Users\\[^\\]+\\`,
	}
	for _, pattern := range homePatterns {
		re := regexp.MustCompile(pattern)
		msg = re.ReplaceAllString(msg, "[home]/")
	}

	// Hide .beads directory paths
	beadsPathRegex := regexp.MustCompile(`\.beads/[^/]+/`)
	msg = beadsPathRegex.ReplaceAllString(msg, ".beads/[db]/")

	return msg
}

// sanitizeVersions replaces version numbers with generic placeholders
func (es *ErrorSanitizer) sanitizeVersions(msg string) string {
	// Match semantic versioning: v1.2.3, 1.2.3, etc.
	versionRegex := regexp.MustCompile(`v?\d+\.\d+\.\d+[-\w]*`)
	msg = versionRegex.ReplaceAllString(msg, "[version]")

	// Match git commit hashes (7-40 hex chars)
	commitRegex := regexp.MustCompile(`\b[0-9a-f]{7,40}\b`)
	msg = commitRegex.ReplaceAllString(msg, "[commit]")

	return msg
}

// sanitizeUsernames replaces usernames with generic placeholders
func (es *ErrorSanitizer) sanitizeUsernames(msg string) string {
	// Match common username patterns
	// Unix: /home/username/
	usernameRegex := regexp.MustCompile(`/home/[^/]+/`)
	msg = usernameRegex.ReplaceAllString(msg, "/home/[user]/")

	// Windows: C:\Users\username\
	winUsernameRegex := regexp.MustCompile(`C:\\Users\\[^\\]+\\`)
	msg = winUsernameRegex.ReplaceAllString(msg, "C:\\Users\\[user]\\")

	return msg
}

// SanitizeErrorString is a convenience function that sanitizes an error message string
func SanitizeErrorString(errMsg string) string {
	if errMsg == "" {
		return ""
	}

	sanitizer := NewErrorSanitizer()
	return sanitizer.SanitizeError(fmt.Errorf("%s", errMsg))
}

// SafeError wraps an error with sanitized information
// Returns a new error with sensitive information removed
func SafeError(err error) error {
	if err == nil {
		return nil
	}

	sanitizer := NewErrorSanitizer()
	sanitized := sanitizer.SanitizeError(err)
	return fmt.Errorf("%s", sanitized)
}

// SafeErrorf formats an error message and sanitizes it
// Use this instead of fmt.Errorf for user-facing error messages
func SafeErrorf(format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	sanitizer := NewErrorSanitizer()
	sanitized := sanitizer.SanitizeError(err)
	return fmt.Errorf("%s", sanitized)
}
