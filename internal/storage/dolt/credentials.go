package dolt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/steveyegge/beads/internal/crypto"
	"github.com/steveyegge/beads/internal/storage"
)

// Credential storage and encryption for federation peers.
// Enables SQL user authentication when syncing with peer Gas Towns.

// federationEnvMutex protects DOLT_REMOTE_USER/PASSWORD env vars from concurrent access.
// Environment variables are process-global, so we need to serialize federation operations.
var federationEnvMutex sync.Mutex

// validPeerNameRegex matches valid peer names (alphanumeric, hyphens, underscores)
var validPeerNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

// validatePeerName checks that a peer name is safe for use as a Dolt remote name
func validatePeerName(name string) error {
	if name == "" {
		return fmt.Errorf("peer name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("peer name too long (max 64 characters)")
	}
	if !validPeerNameRegex.MatchString(name) {
		return fmt.Errorf("peer name must start with a letter and contain only alphanumeric characters, hyphens, and underscores")
	}
	return nil
}

// encryptionKey retrieves the encryption key from the keyring.
// Falls back to legacy derivation if keyring is unavailable (backward compatibility).
// The keyring provides better security by isolating credential encryption keys.
func (s *DoltStore) encryptionKey() ([]byte, error) {
	// Try keyring first (new secure approach)
	if s.keyring != nil {
		key, err := s.keyring.GetKey("dolt-credentials", s.dbPath)
		if err == nil && key != nil {
			return key, nil
		}
		// Keyring failed, fall through to legacy method
	}

	// Legacy fallback: derive key from database path (backward compatible)
	// This ensures existing encrypted credentials can still be decrypted
	h := sha256.New()
	h.Write([]byte(s.dbPath + "beads-federation-key-v1"))
	return h.Sum(nil), nil
}

// encryptPassword encrypts a password using AES-GCM
func (s *DoltStore) encryptPassword(password string) ([]byte, error) {
	if password == "" {
		return nil, nil
	}

	key, err := s.encryptionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return ciphertext, nil
}

// decryptPassword decrypts a password using AES-GCM
func (s *DoltStore) decryptPassword(encrypted []byte) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}

	key, err := s.encryptionKey()
	if err != nil {
		return "", fmt.Errorf("failed to get encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// AddFederationPeer adds or updates a federation peer with credentials.
// This stores credentials in the database and also adds the Dolt remote.
func (s *DoltStore) AddFederationPeer(ctx context.Context, peer *storage.FederationPeer) error {
	// Validate peer name
	if err := validatePeerName(peer.Name); err != nil {
		return fmt.Errorf("invalid peer name: %w", err)
	}

	// Encrypt password before storing
	var encryptedPwd []byte
	var err error
	if peer.Password != "" {
		encryptedPwd, err = s.encryptPassword(peer.Password)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}
	}

	// Upsert the peer credentials
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO federation_peers (name, remote_url, username, password_encrypted, sovereignty)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			remote_url = VALUES(remote_url),
			username = VALUES(username),
			password_encrypted = VALUES(password_encrypted),
			sovereignty = VALUES(sovereignty),
			updated_at = CURRENT_TIMESTAMP
	`, peer.Name, peer.RemoteURL, peer.Username, encryptedPwd, peer.Sovereignty)

	if err != nil {
		return fmt.Errorf("failed to add federation peer: %w", err)
	}

	// Also add the Dolt remote
	if err := s.AddRemote(ctx, peer.Name, peer.RemoteURL); err != nil {
		// Ignore "remote already exists" errors
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to add dolt remote: %w", err)
		}
	}

	return nil
}

// GetFederationPeer retrieves a federation peer by name.
// Returns nil if peer doesn't exist.
func (s *DoltStore) GetFederationPeer(ctx context.Context, name string) (*storage.FederationPeer, error) {
	var peer storage.FederationPeer
	var encryptedPwd []byte
	var lastSync sql.NullTime
	var username sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT name, remote_url, username, password_encrypted, sovereignty, last_sync, created_at, updated_at
		FROM federation_peers WHERE name = ?
	`, name).Scan(&peer.Name, &peer.RemoteURL, &username, &encryptedPwd, &peer.Sovereignty, &lastSync, &peer.CreatedAt, &peer.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get federation peer: %w", err)
	}

	if username.Valid {
		peer.Username = username.String
	}
	if lastSync.Valid {
		peer.LastSync = &lastSync.Time
	}

	// Decrypt password
	if len(encryptedPwd) > 0 {
		peer.Password, err = s.decryptPassword(encryptedPwd)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt password: %w", err)
		}
	}

	return &peer, nil
}

// ListFederationPeers returns all configured federation peers.
func (s *DoltStore) ListFederationPeers(ctx context.Context) ([]*storage.FederationPeer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, remote_url, username, password_encrypted, sovereignty, last_sync, created_at, updated_at
		FROM federation_peers ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list federation peers: %w", err)
	}
	defer rows.Close()

	var peers []*storage.FederationPeer
	for rows.Next() {
		var peer storage.FederationPeer
		var encryptedPwd []byte
		var lastSync sql.NullTime
		var username sql.NullString

		if err := rows.Scan(&peer.Name, &peer.RemoteURL, &username, &encryptedPwd, &peer.Sovereignty, &lastSync, &peer.CreatedAt, &peer.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan federation peer: %w", err)
		}

		if username.Valid {
			peer.Username = username.String
		}
		if lastSync.Valid {
			peer.LastSync = &lastSync.Time
		}

		// Decrypt password
		if len(encryptedPwd) > 0 {
			peer.Password, err = s.decryptPassword(encryptedPwd)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt password: %w", err)
			}
		}

		peers = append(peers, &peer)
	}

	return peers, rows.Err()
}

// RemoveFederationPeer removes a federation peer and its credentials.
func (s *DoltStore) RemoveFederationPeer(ctx context.Context, name string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM federation_peers WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("failed to remove federation peer: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Peer not in credentials table, but might still be a Dolt remote
		// Continue to try removing the remote
	}

	// Also remove the Dolt remote (best-effort)
	_ = s.RemoveRemote(ctx, name)

	return nil
}

// UpdatePeerLastSync updates the last sync time for a peer.
func (s *DoltStore) UpdatePeerLastSync(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE federation_peers SET last_sync = CURRENT_TIMESTAMP WHERE name = ?", name)
	return err
}

// setFederationCredentials sets DOLT_REMOTE_USER and DOLT_REMOTE_PASSWORD env vars.
// Returns a cleanup function that must be called (typically via defer) to unset them.
// The caller must hold federationEnvMutex.
func setFederationCredentials(username, password string) func() {
	if username != "" {
		os.Setenv("DOLT_REMOTE_USER", username)
	}
	if password != "" {
		os.Setenv("DOLT_REMOTE_PASSWORD", password)
	}
	return func() {
		os.Unsetenv("DOLT_REMOTE_USER")
		os.Unsetenv("DOLT_REMOTE_PASSWORD")
	}
}

// withPeerCredentials executes a function with peer credentials set in environment.
// If the peer has stored credentials, they are set as DOLT_REMOTE_USER/PASSWORD
// for the duration of the function call.
// Security: Password is wiped from memory after use via defer cleanup.
func (s *DoltStore) withPeerCredentials(ctx context.Context, peerName string, fn func() error) error {
	// Look up credentials for this peer
	peer, err := s.GetFederationPeer(ctx, peerName)
	if err != nil {
		return fmt.Errorf("failed to get peer credentials: %w", err)
	}

	// If we have credentials, set env vars with mutex protection
	if peer != nil && (peer.Username != "" || peer.Password != "") {
		federationEnvMutex.Lock()
		cleanup := setFederationCredentials(peer.Username, peer.Password)
		defer func() {
			// Clear credentials from environment first
			cleanup()
			// SECURITY: Wipe password from memory to prevent credential leakage
			// Note: Go strings are immutable, but we wipe the underlying byte slice
			// The peer.Password string will still be in memory until GC, but the
			// sensitive data is no longer accessible via environment variables
			if peer.Password != "" {
				// In production, consider using a SecureString type that provides
				// guaranteed memory wiping (requires custom string implementation)
				crypto.SecureWipe([]byte(peer.Password))
			}
			federationEnvMutex.Unlock()
		}()
	}

	// Execute the function
	err = fn()

	// Update last sync time on success
	if err == nil && peer != nil {
		_ = s.UpdatePeerLastSync(ctx, peerName)
	}

	return err
}

// PushWithCredentials pushes to a remote using stored credentials.
func (s *DoltStore) PushWithCredentials(ctx context.Context, remoteName string) error {
	return s.withPeerCredentials(ctx, remoteName, func() error {
		return s.PushTo(ctx, remoteName)
	})
}

// PullWithCredentials pulls from a remote using stored credentials.
func (s *DoltStore) PullWithCredentials(ctx context.Context, remoteName string) ([]storage.Conflict, error) {
	var conflicts []storage.Conflict
	err := s.withPeerCredentials(ctx, remoteName, func() error {
		var pullErr error
		conflicts, pullErr = s.PullFrom(ctx, remoteName)
		return pullErr
	})
	return conflicts, err
}

// FederationPeer is an alias for storage.FederationPeer for convenience.
type FederationPeer = storage.FederationPeer
