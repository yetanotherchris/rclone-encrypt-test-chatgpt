package crypt

import (
	"bytes"
	"io"
	"testing"
)

const sampleData = "abandon ability able about above absent absorb abstract absurd abuse access accident"

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher("Testpassword1", "", "base32")
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err := c.Encrypt(bytes.NewReader([]byte(sampleData)), &encrypted); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	if err := c.Decrypt(&encrypted, &decrypted); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted.String() != sampleData {
		t.Fatalf("expected %q got %q", sampleData, decrypted.String())
	}
}

func TestCipherWithSalt(t *testing.T) {
	c, err := NewCipher("Testpassword1", "my-salt", "base32")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	var encrypted bytes.Buffer
	if err := c.Encrypt(bytes.NewReader([]byte(sampleData)), &encrypted); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var decrypted bytes.Buffer
	if err := c.Decrypt(&encrypted, &decrypted); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted.String() != sampleData {
		t.Fatalf("expected %q got %q", sampleData, decrypted.String())
	}
}

func TestFilenameEncodingBase64(t *testing.T) {
	c, err := NewCipher("password", "", "base64")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	encrypted := c.EncryptFileName("TEST_FILE.txt")
	if encrypted == "" {
		t.Fatalf("failed to produce encrypted name")
	}
	decrypted, err := c.DecryptFileName(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted != "TEST_FILE.txt" {
		t.Fatalf("expected TEST_FILE.txt got %q", decrypted)
	}
}

func TestDecryptInvalidInput(t *testing.T) {
	c, err := NewCipher("password", "", "base32")
	if err != nil {
		t.Fatal(err)
	}
	var decrypted bytes.Buffer
	if err := c.Decrypt(io.NopCloser(&bytes.Buffer{}), &decrypted); err == nil {
		t.Fatalf("expected error for empty stream")
	}
}
