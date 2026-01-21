// Package debug provides safe logging utilities that automatically redact sensitive data.
// This prevents credentials, API keys, tokens, and other sensitive information from appearing
// in debug output, logs, or error messages.
package debug

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/steveyegge/beads/internal/validation"
)

// Log levels for debugging
const (
	LevelNone  = iota // No debug output
	LevelError        // Errors only
	LevelWarn         // Warnings and errors
	LevelInfo         // Info, warnings, and errors
	LevelDebug        // All output (default)
	LevelTrace        // Verbose tracing
)

var (
	// Current log level (can be set via BD_DEBUG_LEVEL env var)
	currentLogLevel = LevelDebug
	// Mutex for thread-safe logging
	logMutex sync.Mutex
	// Flag to enable safe mode (always redact, even in debug builds)
	safeModeEnabled = true
)

func init() {
	// Read log level from environment
	if env := os.Getenv("BD_DEBUG_LEVEL"); env != "" {
		switch strings.ToLower(env) {
		case "none", "0":
			currentLogLevel = LevelNone
		case "error", "1":
			currentLogLevel = LevelError
		case "warn", "warning", "2":
			currentLogLevel = LevelWarn
		case "info", "3":
			currentLogLevel = LevelInfo
		case "debug", "4":
			currentLogLevel = LevelDebug
		case "trace", "5":
			currentLogLevel = LevelTrace
		}
	}

	// Safe mode is always enabled by default for security
	// Can be disabled via BD_DEBUG_UNSAFE env var (NOT RECOMMENDED)
	if env := os.Getenv("BD_DEBUG_UNSAFE"); env == "1" || env == "true" {
		safeModeEnabled = false
	}
}

// SetLogLevel sets the current log level
func SetLogLevel(level int) {
	logMutex.Lock()
	defer logMutex.Unlock()
	currentLogLevel = level
}

// SetSafeMode enables or disables safe mode (automatic redaction)
// WARNING: Disabling safe mode may expose sensitive data in logs!
func SetSafeMode(enabled bool) {
	logMutex.Lock()
	defer logMutex.Unlock()
	safeModeEnabled = enabled
}

// shouldLog returns true if a message at the given level should be logged
func shouldLog(level int) bool {
	return level <= currentLogLevel
}

// Logf logs a formatted message with automatic sensitive data redaction.
// This is the preferred logging function for debug output.
//
// Example:
//
//	debug.Logf("Connecting to %s with api_key=%s", host, apiKey)
//	// Output (with safe mode): "Connecting to example.com with api_key=[REDACTED]"
func Logf(format string, args ...interface{}) {
	if !shouldLog(LevelDebug) {
		return
	}

	message := formatMessage(format, args...)
	outputToStderr("[DEBUG] " + message)
}

// LogfAt logs a formatted message at the specified level
func LogfAt(level int, format string, args ...interface{}) {
	if !shouldLog(level) {
		return
	}

	levelName := levelName(level)
	message := formatMessage(format, args...)
	outputToStderr("[" + levelName + "] " + message)
}

// Errorf logs an error message
func Errorf(format string, args ...interface{}) {
	LogfAt(LevelError, format, args...)
}

// Warnf logs a warning message
func Warnf(format string, args ...interface{}) {
	LogfAt(LevelWarn, format, args...)
}

// Infof logs an info message
func Infof(format string, args ...interface{}) {
	LogfAt(LevelInfo, format, args...)
}

// Tracef logs a trace message (verbose)
func Tracef(format string, args ...interface{}) {
	LogfAt(LevelTrace, format, args...)
}

// SafeLogf logs a message that is ALWAYS redacted, regardless of safe mode setting.
// Use this for messages that are known to potentially contain sensitive data.
//
// Example:
//
//	debug.SafeLogf("User credentials: username=%s, password=%s", username, password)
//	// Output (always): "User credentials: username=john, password=[REDACTED]"
func SafeLogf(format string, args ...interface{}) {
	message := formatMessage(format, args...)
	message = validation.RedactSensitiveData(message)
	message = validation.RedactJSON(message)
	outputToStderr("[SAFE] " + message)
}

// formatMessage formats a log message with redaction
func formatMessage(format string, args []interface{}) string {
	// First, format the message normally
	message := fmt.Sprintf(format, args...)

	// Apply redaction based on mode
	if safeModeEnabled {
		message = validation.RedactSensitiveData(message)
		message = validation.RedactJSON(message)
		message = validation.RedactURL(message)
	}

	return message
}

// outputToStderr writes a message to stderr in a thread-safe manner
func outputToStderr(message string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Fprintln(os.Stderr, message)
}

// levelName returns the name of a log level
func levelName(level int) string {
	switch level {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

// LogEnabled returns true if debug logging is enabled
func LogEnabled() bool {
	return shouldLog(LevelDebug)
}

// TraceEnabled returns true if trace logging is enabled
func TraceEnabled() bool {
	return shouldLog(LevelTrace)
}

// SafeMode returns true if safe mode (automatic redaction) is enabled
func SafeMode() bool {
	return safeModeEnabled
}

// LogBytes logs byte data as hex (safe for binary data)
// Automatically truncates large data to prevent log spam
func LogBytes(label string, data []byte, maxLen int) {
	if !shouldLog(LevelDebug) {
		return
	}

	if len(data) > maxLen {
		Logf("%s: [%d bytes, truncated to %d] %x...", label, len(data), maxLen, data[:maxLen])
	} else {
		Logf("%s: [%d bytes] %x", label, len(data), data)
	}
}

// LogStruct logs a struct as JSON with redaction
func LogStruct(label string, obj interface{}) {
	if !shouldLog(LevelDebug) {
		return
	}

	// Convert to JSON string (using fmt.Sprintf for simplicity)
	jsonStr := fmt.Sprintf("%+v", obj)
	Logf("%s: %s", label, jsonStr)
}

// Redacted returns a placeholder for sensitive values
// Use this when you want to explicitly mark a value as sensitive
//
// Example:
//
//	debug.Logf("Connecting with password=%s", debug.Redacted())
//	// Output: "Connecting with password=[REDACTED]"
func Redacted() string {
	return "[REDACTED]"
}

// SensitiveValue wraps any value to prevent it from being logged
// Returns a string that will be redacted in logs
//
// Example:
//
//	apiKey := "sk-ant-1234567890"
//	debug.Logf("Using API key: %s", debug.SensitiveValue(apiKey))
//	// Output: "Using API key: [REDACTED]"
func SensitiveValue(_ interface{}) string {
	return "[REDACTED]"
}
