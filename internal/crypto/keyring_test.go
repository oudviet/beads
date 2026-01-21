package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyring(t *testing.T) {
	tmpDir := t.TempDir()
	keyringFile := filepath.Join(tmpDir, "test-keyring")
	dbPath := "/test/db/path"

	t.Run("NewFileKeyring creates new keyring", func(t *testing.T) {
		keyring, err := NewFileKeyring(keyringFile, dbPath)
		if err != nil {
			t.Fatalf("NewFileKeyring() error = %v", err)
		}
		if keyring == nil {
			t.Fatal("NewFileKeyring() returned nil")
		}

		// Check keyring file was created
		if _, err := os.Stat(keyringFile); err != nil {
			t.Errorf("keyring file not created: %v", err)
		}
	})

	t.Run("GetKey returns consistent key", func(t *testing.T) {
		keyring, err := NewFileKeyring(keyringFile, dbPath)
		if err != nil {
			t.Fatal(err)
		}

		key1, err := keyring.GetKey("dolt-credentials", dbPath)
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		key2, err := keyring.GetKey("dolt-credentials", dbPath)
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		// Keys should be identical (deterministic from dbPath for backward compatibility)
		if len(key1) != len(key2) {
			t.Errorf("Key size mismatch: %d != %d", len(key1), len(key2))
		}

		for i := range key1 {
			if key1[i] != key2[i] {
				t.Errorf("Key mismatch at index %d: %x != %x", i, key1[i], key2[i])
			}
		}
	})

	t.Run("StoreKey and DeleteKey are no-ops for backward compatibility", func(t *testing.T) {
		keyring, err := NewFileKeyring(keyringFile, dbPath)
		if err != nil {
			t.Fatal(err)
		}

		// StoreKey should not error
		err = keyring.StoreKey("test-service", "test-user", []byte("test-key"))
		if err != nil {
			t.Errorf("StoreKey() error = %v", err)
		}

		// DeleteKey should not error
		err = keyring.DeleteKey("test-service", "test-user")
		if err != nil {
			t.Errorf("DeleteKey() error = %v", err)
		}
	})

	t.Run("Service-specific key derivation", func(t *testing.T) {
		keyring, err := NewFileKeyring(keyringFile, dbPath)
		if err != nil {
			t.Fatal(err)
		}

		key1, err := keyring.GetKey("service1", "user1")
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		key2, err := keyring.GetKey("service2", "user2")
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		// Different services should get different keys
		if len(key1) != len(key2) {
			t.Errorf("Key size mismatch: %d != %d", len(key1), len(key2))
		}

		same := true
		for i := range key1 {
			if key1[i] != key2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Different services got same key")
		}
	})

	t.Run("Load existing keyring", func(t *testing.T) {
		// Create initial keyring
		keyring1, err := NewFileKeyring(keyringFile, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		key1, _ := keyring1.GetKey("dolt-credentials", dbPath)

		// Load existing keyring
		keyring2, err := NewFileKeyring(keyringFile, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		key2, _ := keyring2.GetKey("dolt-credentials", dbPath)

		// Keys should match
		if len(key1) != len(key2) {
			t.Errorf("Key size mismatch: %d != %d", len(key1), len(key2))
		}

		for i := range key1 {
			if key1[i] != key2[i] {
				t.Errorf("Key mismatch at index %d: %x != %x", i, key1[i], key2[i])
			}
		}
	})
}

func TestSecureWipe(t *testing.T) {
	t.Run("SecureWipe zeros data", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5}
		SecureWipe(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("Data at index %d not zeroed: %d", i, b)
			}
		}
	})

	t.Run("SecureWipe handles empty slice", func(t *testing.T) {
		data := []byte{}
		SecureWipe(data) // Should not panic
	})

	t.Run("SecureWipe handles nil slice", func(t *testing.T) {
		var data []byte = nil
		SecureWipe(data) // Should not panic
	})
}

func TestRandomBytes(t *testing.T) {
	t.Run("RandomBytes returns correct size", func(t *testing.T) {
		size := 32
		data, err := RandomBytes(size)
		if err != nil {
			t.Fatalf("RandomBytes() error = %v", err)
		}
		if len(data) != size {
			t.Errorf("RandomBytes() size = %d, want %d", len(data), size)
		}
	})

	t.Run("RandomBytes returns different values", func(t *testing.T) {
		data1, err := RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}

		data2, err := RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}

		// Very unlikely to be the same
		same := true
		for i := range data1 {
			if data1[i] != data2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("RandomBytes() returned identical values")
		}
	})
}

func TestRandomToken(t *testing.T) {
	t.Run("RandomToken returns hex string", func(t *testing.T) {
		bytes := 16
		token, err := RandomToken(bytes)
		if err != nil {
			t.Fatalf("RandomToken() error = %v", err)
		}

		// Hex encoding doubles the size
		expectedLen := bytes * 2
		if len(token) != expectedLen {
			t.Errorf("RandomToken() length = %d, want %d", len(token), expectedLen)
		}

		// Check it's valid hex
		for _, c := range token {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				t.Errorf("RandomToken() returned invalid hex: %q", token)
				break
			}
		}
	})

	t.Run("RandomToken returns different values", func(t *testing.T) {
		token1, err := RandomToken(16)
		if err != nil {
			t.Fatal(err)
		}

		token2, err := RandomToken(16)
		if err != nil {
			t.Fatal(err)
		}

		if token1 == token2 {
			t.Error("RandomToken() returned identical values")
		}
	})
}

func TestDeriveKeyFromDBPath(t *testing.T) {
	t.Run("Same path produces same key", func(t *testing.T) {
		dbPath := "/test/db"
		key1 := deriveKeyFromDBPath(dbPath, nil)
		key2 := deriveKeyFromDBPath(dbPath, nil)

		if len(key1) != len(key2) {
			t.Fatalf("Key size mismatch: %d != %d", len(key1), len(key2))
		}

		for i := range key1 {
			if key1[i] != key2[i] {
				t.Errorf("Key mismatch at index %d", i)
			}
		}
	})

	t.Run("Different paths produce different keys", func(t *testing.T) {
		key1 := deriveKeyFromDBPath("/db/path1", nil)
		key2 := deriveKeyFromDBPath("/db/path2", nil)

		same := true
		for i := range key1 {
			if key1[i] != key2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Different paths produced same key")
		}
	})

	t.Run("Key size is correct for AES-256", func(t *testing.T) {
		key := deriveKeyFromDBPath("/test/db", nil)
		if len(key) != 32 {
			t.Errorf("Key size = %d, want 32 for AES-256", len(key))
		}
	})
}
