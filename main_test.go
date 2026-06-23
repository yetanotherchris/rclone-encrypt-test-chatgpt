package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yetanotherchris/rclone-encrypt-test-chatgpt/internal/crypt"
)

const cliSampleData = "abandon ability able about above absent absorb abstract absurd abuse access accident"

func TestCLIEncryptDecryptWithPassword(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(input, []byte(cliSampleData), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	encrypted := filepath.Join(dir, "out.bin")
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	orig := passwordReader
	passwordReader = func(prompt string, stdin io.Reader, stdout io.Writer) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { passwordReader = orig })
	if err := run([]string{"tool", "encrypt", "-i", input, "-o", encrypted, "--password", "Testpassword1"}, bytes.NewBufferString(""), stdout, stderr); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "WARNING") {
		t.Fatalf("expected warning when using --password")
	}
	decrypted := filepath.Join(dir, "roundtrip.txt")
	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"tool", "decrypt", "-i", encrypted, "-o", decrypted, "--password", "Testpassword1"}, bytes.NewBufferString(""), stdout, stderr); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(got) != cliSampleData {
		t.Fatalf("expected %q got %q", cliSampleData, string(got))
	}
}

func TestCLIBase64FilenameEncoding(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "TEST_FILE.txt")
	if err := os.WriteFile(input, []byte(cliSampleData), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	orig := passwordReader
	passwordReader = func(prompt string, stdin io.Reader, stdout io.Writer) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { passwordReader = orig })
	if err := run([]string{"tool", "encrypt", "-i", input, "--password", "Testpassword1", "--filename-encoding", "base64"}, bytes.NewBufferString(""), stdout, stderr); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	c, err := crypt.NewCipher("Testpassword1", "", "base64")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	expected := filepath.Join(dir, c.EncryptFileName("TEST_FILE.txt"))
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("expected %s to exist: %v", expected, err)
	}
}

func TestCLIPromptForPasswordAndSalt(t *testing.T) {
	orig := passwordReader
	defer func() { passwordReader = orig }()
	calls := 0
	secrets := []string{"prompt-pass", "prompt-salt"}
	passwordReader = func(prompt string, stdin io.Reader, stdout io.Writer) (string, error) {
		if calls >= len(secrets) {
			return "", io.EOF
		}
		calls++
		return secrets[calls-1], nil
	}

	dir := t.TempDir()
	input := filepath.Join(dir, "prompt.txt")
	if err := os.WriteFile(input, []byte(cliSampleData), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	output := filepath.Join(dir, "prompt.out")
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	if err := run([]string{"tool", "encrypt", "-i", input, "-o", output}, bytes.NewBufferString(""), stdout, stderr); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected two prompts got %d", calls)
	}
}
