package validation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateBodyFilePath validates that a file path is safe for reading.
// Prevents path traversal attacks by ensuring:
// - Path is absolute or relative to current directory only
// - No path traversal components (..)
// - File exists and is readable
// - File is within allowed directories (if specified)
func ValidateBodyFilePath(filePath string) error {
	// Allow stdin special case
	if filePath == "-" {
		return nil
	}

	// Must be non-empty
	if filePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Clean the path to resolve any embedded ".." or "."
	cleanPath := filepath.Clean(filePath)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal detected: %s", filePath)
	}

	// Convert to absolute path for validation
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Verify file exists and is readable
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}

	// Must be a regular file (not directory, symlink, device)
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", filePath)
	}

	// Restrict to current working directory or subdirectories
	// This prevents reading sensitive files like /etc/passwd
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot determine current directory: %w", err)
	}

	// Check if file is within current directory tree
	if !isWithinDirectory(absPath, cwd) {
		return fmt.Errorf("file outside working directory: %s", filePath)
	}

	return nil
}

// isWithinDirectory checks if path is within directory tree
func isWithinDirectory(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}
