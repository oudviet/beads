package validation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBodyFilePath(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		input     string
		wantError bool
		errorMsg  string
		setup     func() string // Optional setup to create test files
	}{
		{"stdin special case", "-", false, "", nil},
		{"relative file ok", testFile, false, "", nil},
		{"relative file with ./", "./"+testFile, false, "", nil},
		{"empty path", "", true, "cannot be empty", nil},
		{"path traversal ../etc/passwd", "../../../etc/passwd", true, "path traversal", nil},
		{"path traversal with ./", "./../../../etc/passwd", true, "path traversal", nil},
		{"path traversal mid path", tmpDir + "/../etc/passwd", true, "path traversal", nil},
		{"non-existent file", filepath.Join(tmpDir, "nonexistent.txt"), true, "cannot access file", nil},
	}

	// Save current directory and restore after test
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// Change to temp directory for testing
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBodyFilePath(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateBodyFilePath() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Error message = %v, should contain %q", err.Error(), tt.errorMsg)
				}
			}
		})
	}
}

func TestIsWithinDirectory(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		dir      string
		expected bool
	}{
		{"file in directory", "/home/user/project/file.txt", "/home/user/project", true},
		{"file in subdirectory", "/home/user/project/subdir/file.txt", "/home/user/project", true},
		{"file outside directory", "/etc/passwd", "/home/user/project", false},
		{"parent directory", "/home/user", "/home/user/project", false},
		{"same directory", "/home/user/project", "/home/user/project", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWithinDirectory(tt.path, tt.dir)
			if result != tt.expected {
				t.Errorf("isWithinDirectory() = %v, want %v", result, tt.expected)
			}
		})
	}
}
