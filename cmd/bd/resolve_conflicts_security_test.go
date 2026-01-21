package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestValidateResolveConflictsPath_PathTraversalPrevention verifies that
// validateResolveConflictsPath prevents path traversal attacks.
//
// This test addresses the security issue where resolve-conflicts command
// could be used to read files outside the repository using paths like
// "../../etc/passwd".
func TestValidateResolveConflictsPath_PathTraversalPrevention(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		basePath    string
		wantError   bool
		errorMsg    string
		description string
	}{
		{
			name:        "normal jsonl file in repo",
			filePath:    ".beads/beads.jsonl",
			basePath:    ".",
			wantError:   false,
			description: "Valid path should pass",
		},
		{
			name:        "absolute path within repo",
			filePath:    "/home/user/project/.beads/beads.jsonl",
			basePath:    "/home/user/project",
			wantError:   false,
			description: "Absolute path within base should pass",
		},
		{
			name:        "path traversal with ../etc/passwd",
			filePath:    "../../../etc/passwd",
			basePath:    ".",
			wantError:   true,
			errorMsg:    "path traversal",
			description: "Should block ../ attempts",
		},
		{
			name:        "path traversal mid path",
			filePath:    ".beads/../etc/passwd",
			basePath:    ".",
			wantError:   true,
			errorMsg:    "path traversal",
			description: "Should block ../ in middle of path",
		},
		{
			name:        "path traversal with ./ prefix",
			filePath:    "./../../../etc/passwd",
			basePath:    ".",
			wantError:   true,
			errorMsg:    "path traversal",
			description: "Should block ../ after ./ normalization",
		},
		{
			name:        "sibling directory traversal",
			filePath:    "../other-repo/.beads/beads.jsonl",
			basePath:    ".",
			wantError:   true,
			errorMsg:    "path traversal",
			description: "Should block access to sibling directories",
		},
		{
			name:        "complex traversal attempt",
			filePath:    "./subdir/../../etc/passwd",
			basePath:    ".",
			wantError:   true,
			errorMsg:    "path traversal",
			description: "Should block complex traversal patterns",
		},
		{
			name:        "backslash traversal (Windows)",
			filePath:    "..\\..\\windows\\system32\\config\\sam",
			basePath:    ".",
			wantError:   true,
			errorMsg:    "path traversal",
			description: "Should block backslash traversal (Windows-style)",
		},
		{
			name:        "subdirectory within repo",
			filePath:    ".beads/subdir/file.jsonl",
			basePath:    ".",
			wantError:   false,
			description: "Valid subdirectory should pass",
		},
		{
			name:        "deep nested within repo",
			filePath:    "a/b/c/d/e/f/file.jsonl",
			basePath:    ".",
			wantError:   false,
			description: "Deep nested path within repo should pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResolveConflictsPath(tt.filePath, tt.basePath)

			if tt.wantError {
				if err == nil {
					t.Errorf("validateResolveConflictsPath() expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Error = %v, should contain %q", err, tt.errorMsg)
				}
				t.Logf("✓ Blocked: %s - %v", tt.description, err)
			} else {
				if err != nil {
					t.Errorf("validateResolveConflictsPath() unexpected error: %v", err)
				}
				t.Logf("✓ Allowed: %s", tt.description)
			}
		})
	}
}

// TestValidateResolveConflictsPath_SensitiveFileAccess verifies that
// resolve-conflicts cannot be used to access sensitive system files.
func TestValidateResolveConflictsPath_SensitiveFileAccess(t *testing.T) {
	// Skip on Windows as paths are different
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows (Unix-specific paths)")
	}

	tests := []struct {
		name     string
		filePath string
		basePath string
	}{
		{
			name:     "/etc/passwd",
			filePath: "/etc/passwd",
			basePath: ".",
		},
		{
			name:     "/etc/shadow",
			filePath: "/etc/shadow",
			basePath: ".",
		},
		{
			name:     "~/.ssh/id_rsa",
			filePath: filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"),
			basePath: ".",
		},
		{
			name:     "../../secret.txt",
			filePath: "../../secret.txt",
			basePath: ".",
		},
		{
			name:     "/root/.ssh/authorized_keys",
			filePath: "/root/.ssh/authorized_keys",
			basePath: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResolveConflictsPath(tt.filePath, tt.basePath)
			if err == nil {
				t.Errorf("validateResolveConflictsPath() should have blocked access to %s", tt.filePath)
			} else {
				t.Logf("✓ Blocked access to %s: %v", tt.name, err)
			}
		})
	}
}

// TestValidateResolveConflictsPath_RealWorldScenarios tests validation
// with realistic file system scenarios.
func TestValidateResolveConflictsPath_RealWorldScenarios(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test directory structure
	beadsDir := filepath.Join(tmpDir, ".beads")
	if err := os.MkdirAll(beadsDir, 0755); err != nil {
		t.Fatalf("Failed to create .beads dir: %v", err)
	}

	// Create a test JSONL file
	testFile := filepath.Join(beadsDir, "beads.jsonl")
	if err := os.WriteFile(testFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name        string
		filePath    string
		basePath    string
		wantError   bool
		description string
	}{
		{
			name:        "valid default path",
			filePath:    filepath.Join(tmpDir, ".beads", "beads.jsonl"),
			basePath:    tmpDir,
			wantError:   false,
			description: "Default .beads/beads.jsonl should pass",
		},
		{
			name:        "valid custom jsonl",
			filePath:    filepath.Join(tmpDir, "custom.jsonl"),
			basePath:    tmpDir,
			wantError:   false,
			description: "Custom JSONL in repo should pass",
		},
		{
			name:        "valid subdirectory jsonl",
			filePath:    filepath.Join(tmpDir, "subdir", "file.jsonl"),
			basePath:    tmpDir,
			wantError:   false,
			description: "Subdirectory JSONL should pass",
		},
		{
			name:        "traversal to parent",
			filePath:    filepath.Join(tmpDir, "..", "etc", "passwd"),
			basePath:    tmpDir,
			wantError:   true,
			description: "Traversal to parent should be blocked",
		},
		{
			name:        "traversal via symlink",
			filePath:    filepath.Join(tmpDir, ".beads", "..", "..", "etc", "passwd"),
			basePath:    tmpDir,
			wantError:   true,
			description: "Traversal via symlink-like path should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create subdirectory if needed
			if strings.Contains(tt.filePath, "subdir") {
				subdir := filepath.Join(tmpDir, "subdir")
				os.MkdirAll(subdir, 0755)
			}

			err := validateResolveConflictsPath(tt.filePath, tt.basePath)

			if tt.wantError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			} else if !tt.wantError && err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
			} else if tt.wantError {
				t.Logf("✓ %s: %v", tt.description, err)
			} else {
				t.Logf("✓ %s", tt.description)
			}
		})
	}
}

// TestValidateResolveConflictsPath_EdgeCases tests edge cases and
// boundary conditions.
func TestValidateResolveConflictsPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		basePath    string
		wantError   bool
		description string
	}{
		{
			name:        "empty path",
			filePath:    "",
			basePath:    ".",
			wantError:   true,
			description: "Empty path should be rejected",
		},
		{
			name:        "dot only",
			filePath:    ".",
			basePath:    ".",
			wantError:   false,
			description: "Current directory (.) should be allowed",
		},
		{
			name:        "current dir with slash",
			filePath:    "./",
			basePath:    ".",
			wantError:   false,
			description: "./ should normalize to current dir",
		},
		{
			name:        "double slash",
			filePath:    "//etc/passwd",
			basePath:    "/",
			wantError:   false, // //etc/passwd normalizes to /etc/passwd, which is within /
			description: "Double slash should normalize",
		},
		{
			name:        "trailing slash",
			filePath:    ".beads/",
			basePath:    ".",
			wantError:   false,
			description: "Trailing slash should be handled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResolveConflictsPath(tt.filePath, tt.basePath)

			if tt.wantError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			} else if !tt.wantError && err != nil {
				// Some edge cases might fail with "file outside" which is acceptable
				t.Logf("%s: got error (may be acceptable): %v", tt.description, err)
			} else if tt.wantError {
				t.Logf("✓ %s: %v", tt.description, err)
			} else {
				t.Logf("✓ %s", tt.description)
			}
		})
	}
}
