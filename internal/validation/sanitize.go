package validation

import (
	"regexp"
	"strings"
	"unicode"
)

// SanitizeGitOutput removes control characters and dangerous content from git command output.
// This prevents injection of control characters, ANSI escape sequences, and other malicious content.
func SanitizeGitOutput(output string) string {
	// Remove ANSI escape sequences first (common in git output with colors)
	ansiEscape := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	cleaned := ansiEscape.ReplaceAllString(output, "")

	// Remove null bytes and other control characters except newline/tab/carriage return
	var sb strings.Builder
	for _, r := range cleaned {
		if r == '\n' || r == '\t' || r == '\r' {
			sb.WriteRune(r)
		} else if !unicode.IsControl(r) && (unicode.IsPrint(r) || unicode.IsSpace(r)) {
			sb.WriteRune(r)
		}
		// Skip: null bytes, other control characters, non-printable chars
	}

	return sb.String()
}

// SanitizeString removes or escapes dangerous characters from user input.
// Limits length to prevent DoS and removes ANSI escape sequences.
func SanitizeString(input string) string {
	// Remove ANSI escape sequences
	ansiEscape := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	cleaned := ansiEscape.ReplaceAllString(input, "")

	// Limit length to prevent DoS (arbitrary but reasonable limit for names/emails)
	const maxLen = 4096
	if len(cleaned) > maxLen {
		cleaned = cleaned[:maxLen]
	}

	return strings.TrimSpace(cleaned)
}

// SanitizeEmail removes dangerous characters from email addresses while preserving valid format.
func SanitizeEmail(email string) string {
	cleaned := SanitizeString(email)
	// Lowercase email for consistency
	return strings.ToLower(cleaned)
}
