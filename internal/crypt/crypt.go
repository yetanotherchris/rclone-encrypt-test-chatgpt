package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Max-Sum/base32768"
	"github.com/rfjakob/eme"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	nameCipherBlockSize = aes.BlockSize
	fileMagic           = "RCLONE\x00\x00"
	fileMagicSize       = len(fileMagic)
	blockDataSize       = 64 * 1024
	blockHeaderSize     = secretbox.Overhead
	fileNonceSize       = 24
	fileHeaderSize      = fileMagicSize + fileNonceSize
)

var (
	ErrInvalidMagic   = errors.New("not an rclone encrypted file")
	ErrInvalidBlock   = errors.New("invalid encrypted block")
	ErrHeaderTooShort = errors.New("encrypted stream truncated")
	defaultSalt       = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}
	fileMagicBytes    = []byte(fileMagic)
)

type fileNameEncoding interface {
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
}

type caseInsensitiveBase32Encoding struct{}

func (caseInsensitiveBase32Encoding) EncodeToString(src []byte) string {
	encoded := base32.HexEncoding.EncodeToString(src)
	encoded = strings.TrimRight(encoded, "=")
	return strings.ToLower(encoded)
}

func (caseInsensitiveBase32Encoding) DecodeString(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, fmt.Errorf("invalid base32 encoding")
	}
	paddedLen := (len(s) + 7) &^ 7
	equals := paddedLen - len(s)
	s = strings.ToUpper(s) + strings.Repeat("=", equals)
	return base32.HexEncoding.DecodeString(s)
}

func newNameEncoding(mode string) (fileNameEncoding, error) {
	switch strings.ToLower(mode) {
	case "base32":
		return caseInsensitiveBase32Encoding{}, nil
	case "base64":
		return base64.RawURLEncoding, nil
	case "base32768":
		return base32768.SafeEncoding, nil
	default:
		return nil, fmt.Errorf("unknown filename encoding %q", mode)
	}
}

type Cipher struct {
	dataKey     [32]byte
	nameKey     [32]byte
	nameTweak   [nameCipherBlockSize]byte
	block       cipher.Block
	fileNameEnc fileNameEncoding
}

func NewCipher(password, salt, encoding string) (*Cipher, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}
	enc, err := newNameEncoding(encoding)
	if err != nil {
		return nil, err
	}
	c := &Cipher{fileNameEnc: enc}
	if err := c.deriveKeys(password, salt); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cipher) deriveKeys(password, salt string) error {
	keyMaterialLen := len(c.dataKey) + len(c.nameKey) + len(c.nameTweak)
	saltBytes := defaultSalt
	if salt != "" {
		saltBytes = []byte(salt)
	}
	key, err := scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, keyMaterialLen)
	if err != nil {
		return err
	}
	copy(c.dataKey[:], key[:len(c.dataKey)])
	copy(c.nameKey[:], key[len(c.dataKey):len(c.dataKey)+len(c.nameKey)])
	copy(c.nameTweak[:], key[len(c.dataKey)+len(c.nameKey):])
	block, err := aes.NewCipher(c.nameKey[:])
	if err != nil {
		return err
	}
	c.block = block
	return nil
}

func (c *Cipher) EncryptFileName(name string) string {
	if name == "" {
		return ""
	}
	padded := pkcs7Pad([]byte(name), nameCipherBlockSize)
	cipherText := eme.Transform(c.block, c.nameTweak[:], padded, eme.DirectionEncrypt)
	return c.fileNameEnc.EncodeToString(cipherText)
}

func (c *Cipher) DecryptFileName(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := c.fileNameEnc.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw)%nameCipherBlockSize != 0 {
		return "", fmt.Errorf("ciphertext not aligned")
	}
	padded := eme.Transform(c.block, c.nameTweak[:], raw, eme.DirectionDecrypt)
	unpadded, err := pkcs7Unpad(padded, nameCipherBlockSize)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding size")
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

type nonce [fileNonceSize]byte

func (n *nonce) pointer() *[fileNonceSize]byte {
	return (*[fileNonceSize]byte)(n)
}

func (n *nonce) increment() {
	for i := 0; i < len(n); i++ {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func (c *Cipher) Encrypt(in io.Reader, out io.Writer) error {
	var header [fileHeaderSize]byte
	copy(header[:fileMagicSize], fileMagicBytes)
	var nonce nonce
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	copy(header[fileMagicSize:], nonce[:])
	if _, err := out.Write(header[:]); err != nil {
		return err
	}

	buf := make([]byte, blockDataSize)
	for {
		n, err := io.ReadFull(in, buf)
		if err == io.EOF {
			return nil
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}
		sealed := secretbox.Seal(nil, buf[:n], nonce.pointer(), &c.dataKey)
		if _, err := out.Write(sealed); err != nil {
			return err
		}
		nonce.increment()
		if err == io.ErrUnexpectedEOF {
			return nil
		}
	}
}

func (c *Cipher) Decrypt(in io.Reader, out io.Writer) error {
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(in, header); err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return ErrHeaderTooShort
		}
		return err
	}
	if !bytes.Equal(header[:len(fileMagicBytes)], fileMagicBytes) {
		return ErrInvalidMagic
	}
	var nonce nonce
	copy(nonce[:], header[len(fileMagicBytes):])

	buf := make([]byte, blockHeaderSize+blockDataSize)
	for {
		n, err := io.ReadFull(in, buf)
		if n == 0 && err == io.EOF {
			return nil
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}
		if n < blockHeaderSize {
			return ErrHeaderTooShort
		}
		opened, ok := secretbox.Open(nil, buf[:n], nonce.pointer(), &c.dataKey)
		if !ok {
			return ErrInvalidBlock
		}
		if _, err := out.Write(opened); err != nil {
			return err
		}
		nonce.increment()
		if err == io.ErrUnexpectedEOF {
			return nil
		}
	}
}
