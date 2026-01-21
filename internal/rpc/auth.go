package rpc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuthManager handles daemon authentication
type AuthManager struct {
	mu           sync.RWMutex
	secretKey    []byte
	token        string
	tokenFile    string
	startTime    time.Time
	socketPath   string
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(socketPath string, startTime time.Time) (*AuthManager, error) {
	am := &AuthManager{
		socketPath: socketPath,
		startTime:  startTime,
		tokenFile:  filepath.Join(filepath.Dir(socketPath), "daemon-auth-token"),
	}

	// Try to load existing secret key, or generate new one
	if err := am.loadOrGenerateSecret(); err != nil {
		return nil, fmt.Errorf("failed to initialize auth: %w", err)
	}

	// Generate auth token
	am.token = am.generateToken()

	return am, nil
}

// loadOrGenerateSecret loads an existing secret key or generates a new one
func (am *AuthManager) loadOrGenerateSecret() error {
	// Try to read existing secret
	if data, err := os.ReadFile(am.tokenFile); err == nil {
		am.secretKey = data
		return nil
	}

	// Generate new secret key
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}
	am.secretKey = secret

	// Write secret to file with restricted permissions
	if err := os.WriteFile(am.tokenFile, am.secretKey, 0600); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}

	return nil
}

// generateToken creates an authentication token
func (am *AuthManager) generateToken() string {
	// Create HMAC using secret key with socketPath and startTime as message
	h := hmac.New(sha256.New, am.secretKey)
	h.Write([]byte(am.socketPath))
	h.Write([]byte(am.startTime.Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// GetToken returns the current authentication token
func (am *AuthManager) GetToken() string {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.token
}

// ValidateToken checks if the provided token matches the expected token
func (am *AuthManager) ValidateToken(token string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return hmac.Equal([]byte(am.token), []byte(token))
}

// Cleanup removes the secret key file
func (am *AuthManager) Cleanup() error {
	return os.Remove(am.tokenFile)
}

// ValidateRequestAuth validates the authentication in a request
// Operations that skip authentication: ping, health, metrics (for diagnostics)
func (am *AuthManager) ValidateRequestAuth(req *Request) error {
	// Skip auth for diagnostic operations
	if req.Operation == OpPing || req.Operation == OpHealth || req.Operation == OpMetrics {
		return nil
	}

	// Check if token is provided and valid
	if req.AuthToken == "" {
		return fmt.Errorf("authentication required: missing auth_token")
	}

	if !am.ValidateToken(req.AuthToken) {
		return fmt.Errorf("authentication failed: invalid auth_token")
	}

	return nil
}
