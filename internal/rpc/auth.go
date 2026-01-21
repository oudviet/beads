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

// AuthManager handles daemon authentication and request signing
type AuthManager struct {
	mu           sync.RWMutex
	secretKey    []byte
	token        string
	tokenFile    string
	startTime    time.Time
	socketPath   string
	signer       *RequestSigner
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

	// Save token to file so clients can read it
	if err := am.saveToken(); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	// Initialize request signer with the same secret key
	am.signer = NewRequestSigner(am.secretKey)

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

// saveToken writes the current authentication token to the token file
// This allows clients to read the token for authentication
func (am *AuthManager) saveToken() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Write the actual token (not the secret key) to the file
	// The client reads this token to authenticate
	if err := os.WriteFile(am.tokenFile, []byte(am.token), 0600); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
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

// GetSecretKey returns the secret key for signing operations
func (am *AuthManager) GetSecretKey() []byte {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.secretKey
}

// ValidateToken checks if the provided token matches the expected token
func (am *AuthManager) ValidateToken(token string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return hmac.Equal([]byte(am.token), []byte(token))
}

// SignRequest signs a request with HMAC
func (am *AuthManager) SignRequest(req *Request, timestamp time.Time) string {
	return am.signer.SignRequest(req, timestamp)
}

// VerifyRequest verifies a request's HMAC signature
func (am *AuthManager) VerifyRequest(req *Request, timestamp time.Time, signature string) error {
	return am.signer.VerifyRequest(req, timestamp, signature)
}

// SignResponse signs a response with HMAC
func (am *AuthManager) SignResponse(resp *Response, timestamp time.Time) string {
	return am.signer.SignResponse(resp, timestamp)
}

// VerifyResponse verifies a response's HMAC signature
func (am *AuthManager) VerifyResponse(resp *Response, timestamp time.Time, signature string) error {
	return am.signer.VerifyResponse(resp, timestamp, signature)
}

// Cleanup removes the secret key file
func (am *AuthManager) Cleanup() error {
	return os.Remove(am.tokenFile)
}

// ValidateRequestAuth validates the authentication and signature in a request
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

	// Check signature if timestamp is provided
	if req.Timestamp > 0 && req.Signature != "" {
		timestamp := time.Unix(req.Timestamp, 0)
		if err := am.VerifyRequest(req, timestamp, req.Signature); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return nil
}
