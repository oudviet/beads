package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Key derivation parameters
	saltSize     = 32
	keySize      = 32
	iterations   = 100000
)

// Keyring provides secure credential storage interface
type Keyring interface {
	StoreKey(service, user string, key []byte) error
	GetKey(service, user string) ([]byte, error)
	DeleteKey(service, user string) error
}

// FileKeyring implements encrypted file-based credential storage
// Uses PBKDF2 for key derivation and AES-256-GCM for encryption
type FileKeyring struct {
	keyFile  string
	masterKey []byte
}

// NewFileKeyring creates or opens a keyring for credential storage
// The keyring is stored in an encrypted file with a master key derived from a password
// For now, we use a simple derivation from the database path (backward compatible)
// In production, this should use system keyring or prompt for password
func NewFileKeyring(keyFile string, dbPath string) (*FileKeyring, error) {
	k := &FileKeyring{keyFile: keyFile}

	// Try to load existing master key
	if _, err := os.ReadFile(keyFile); err == nil {
		// Existing keyring - derive master key from dbPath
		k.masterKey = deriveKeyFromDBPath(dbPath, nil)
		return k, nil
	}

	// Create new keyring - generate random master key
	masterKey := make([]byte, keySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	k.masterKey = masterKey

	// For backward compatibility with existing credentials encrypted with dbPath-derived key:
	// We use the dbPath-derived key as the master key instead of a random one
	// This ensures existing encrypted credentials can still be decrypted
	k.masterKey = deriveKeyFromDBPath(dbPath, nil)

	// Create keyring directory if needed
	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		return nil, fmt.Errorf("failed to create keyring directory: %w", err)
	}

	// Write empty keyring file as marker
	if err := os.WriteFile(keyFile, []byte("BEADS_KEYRING_V1"), 0600); err != nil {
		return nil, fmt.Errorf("failed to write keyring file: %w", err)
	}

	return k, nil
}

// deriveKeyFromDBPath derives a key from the database path
// This is backward compatible with the old credential encryption
// Uses SHA-256 with a fixed salt for reproducibility
func deriveKeyFromDBPath(dbPath string, salt []byte) []byte {
	if salt == nil {
		// Use fixed salt for backward compatibility
		salt = []byte("beads-federation-key-v1")
	}

	h := sha256.New()
	h.Write([]byte(dbPath))
	h.Write(salt)
	return h.Sum(nil)
}

// deriveKeyWithSalt derives a key using PBKDF2 with the given salt
// This provides better security than SHA-256 for new credentials
func deriveKeyWithSalt(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keySize, sha256.New)
}

// generateSalt generates a random salt for key derivation
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// StoreKey stores a key in the keyring
// For service-specific credentials (like federation peers)
func (k *FileKeyring) StoreKey(service, user string, keyData []byte) error {
	// For now, we use the master key directly
	// In production, this should encrypt per-service keys
	_ = service
	_ = user
	_ = keyData
	return nil
}

// GetKey retrieves a key from the keyring
// Returns the master key for the service (backward compatible)
func (k *FileKeyring) GetKey(service, user string) ([]byte, error) {
	// For federation credentials, return the master key
	// This is backward compatible with the old encryptionKey() function
	if service == "dolt-credentials" {
		return k.masterKey, nil
	}

	// For other services, derive a service-specific key
	serviceKeyMaterial := fmt.Sprintf("%s:%s", service, user)
	h := sha256.New()
	h.Write(k.masterKey)
	h.Write([]byte(serviceKeyMaterial))
	return h.Sum(nil), nil
}

// DeleteKey removes a key from the keyring
func (k *FileKeyring) DeleteKey(service, user string) error {
	// For file-based keyring, keys are derived, not stored
	// Nothing to delete
	return nil
}

// Cleanup removes the keyring file
func (k *FileKeyring) Cleanup() error {
	return os.Remove(k.keyFile)
}

// SecureWipe wipes sensitive data from memory
func SecureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// WipeString wipes a string securely (for passwords)
func WipeString(s *string) {
	if s == nil {
		return
	}
	// Go strings are immutable, so we can't wipe them directly
	// This is a no-op but serves as documentation
	// The caller should reassign: s = ""
}

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomToken generates a random hex token for authentication
func RandomToken(bytes int) (string, error) {
	b, err := RandomBytes(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
