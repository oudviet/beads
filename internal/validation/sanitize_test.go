package validation

import (
	"strings"
	"testing"
)

func TestSanitizeGitOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal text",
			input:    "John Doe",
			expected: "John Doe",
		},
		{
			name:     "with newline",
			input:    "John Doe\n",
			expected: "John Doe\n",
		},
		{
			name:     "with tab",
			input:    "John\tDoe",
			expected: "John\tDoe",
		},
		{
			name:     "ANSI escape sequences",
			input:    "\x1b[31mJohn Doe\x1b[0m",
			expected: "John Doe",
		},
		{
			name:     "null byte",
			input:    "John\x00Doe",
			expected: "JohnDoe",
		},
		{
			name:     "control characters",
			input:    "John\x01\x02Doe",
			expected: "JohnDoe",
		},
		{
			name:     "mixed",
			input:    "\x1b[31mJohn\x00\n\tDoe\x1b[0m",
			expected: "John\n\tDoe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeGitOutput(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeGitOutput() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // What the result should contain (for length-limited tests)
	}{
		{
			name:     "normal text",
			input:    "John Doe",
			contains: "John Doe",
		},
		{
			name:     "with leading/trailing whitespace",
			input:    "  John Doe  ",
			contains: "John Doe",
		},
		{
			name:     "ANSI escape sequences",
			input:    "\x1b[31mJohn Doe\x1b[0m",
			contains: "John Doe",
		},
		{
			name:     "very long string",
			input:    strings.Repeat("a", 5000),
			contains: strings.Repeat("a", 4096),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("SanitizeString() = %q, should contain %q", result, tt.contains)
			}
		})
	}
}

func TestSanitizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal email",
			input:    "John.Doe@example.com",
			expected: "john.doe@example.com",
		},
		{
			name:     "with whitespace",
			input:    "  John.Doe@example.com  ",
			expected: "john.doe@example.com",
		},
		{
			name:     "uppercase",
			input:    "JOHN.DOE@EXAMPLE.COM",
			expected: "john.doe@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeEmail(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeEmail() = %q, want %q", result, tt.expected)
			}
		})
	}
}
