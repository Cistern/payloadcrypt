// Package payloadcrypt provides payload encryption and decryption
// utilities, primarily for UDP packets.
package payloadcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// Crypt represents a payload encrypter and decrypter
// based on shared encryption and authentication keys.
type Crypt struct {
	encryptionKey []byte
	hmacKey       []byte
	iv            []byte
	block         cipher.Block
	hmac          hash.Hash
}

// NewCrypt returns a new *Crypt with the given keys.
func NewCrypt(encryptionKey, hmacKey []byte) (*Crypt, error) {
	if len(encryptionKey) != 32 {
		encryptionKey = passphraseToKey(encryptionKey)
	}
	if len(hmacKey) != 32 {
		hmacKey = passphraseToKey(hmacKey)
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	return &Crypt{
		encryptionKey: encryptionKey,
		hmacKey:       hmacKey,
		iv:            nil,
		block:         block,
		hmac:          hmac.New(sha256.New, hmacKey),
	}, nil
}

// Encrypt encrypts the given payload.
func (c *Crypt) Encrypt(payload []byte) ([]byte, error) {
	if c.iv == nil {
		// Initialize IV
		c.iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, c.iv); err != nil {
			return nil, fmt.Errorf("payloadcrypt: couldn't initialize IV: %v", err)
		}
	}
	ciphertext := make([]byte, aes.BlockSize+len(payload))
	copy(ciphertext[:aes.BlockSize], c.iv)
	stream := cipher.NewCFBEncrypter(c.block, c.iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], payload)
	c.incIV()
	c.hmac.Reset()
	c.hmac.Write(ciphertext)
	sum := c.hmac.Sum(nil)
	return append(ciphertext, sum...), nil
}

// Decrypt decrypts the given payload.
func (c *Crypt) Decrypt(payload []byte) ([]byte, error) {
	if len(payload) < aes.BlockSize {
		return nil, fmt.Errorf("payloadcrypt: invalid payload")
	}
	iv := payload[:aes.BlockSize]
	payload = payload[aes.BlockSize:]
	payloadLength := len(payload) - c.hmac.Size()
	if payloadLength <= 0 {
		return nil, fmt.Errorf("payloadcrypt: invalid payload")
	}
	encryptedPayload := payload[:payloadLength]
	sum := payload[payloadLength:]
	// Check the HMAC
	c.hmac.Reset()
	c.hmac.Write(append(iv, encryptedPayload...))
	if !hmac.Equal(sum, c.hmac.Sum(nil)) {
		return nil, fmt.Errorf("payloadcrypt: invalid HMAC")
	}
	stream := cipher.NewCFBDecrypter(c.block, iv)
	stream.XORKeyStream(encryptedPayload, encryptedPayload)
	return encryptedPayload, nil
}

func (c *Crypt) incIV() {
	incBytes(c.iv)
}

func incBytes(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func passphraseToKey(passphrase []byte) []byte {
	const oneMegabyte = 1024 * 1024
	h := sha256.New()
	passphraseLen := len(passphrase)
	// Write 1 MB to the hash
	repeat, remain := oneMegabyte/passphraseLen, oneMegabyte%passphraseLen
	for repeat > 0 {
		h.Write(passphrase)
		repeat--
	}
	if remain > 0 {
		h.Write(passphrase[:remain])
	}
	return h.Sum(nil)
}
