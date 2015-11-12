package payloadcrypt

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	c, err := NewCrypt([]byte("someKey"), []byte("someHMACKey"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := c.Encrypt([]byte("some message"))

	c2, err := NewCrypt([]byte("someKey"), []byte("someHMACKey"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := c2.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare([]byte("some message"), decrypted) != 0 {
		t.Error("Did not decrypt what was encrypted")
	}

	encrypted = c.Encrypt([]byte("another message"))
	decrypted, err = c2.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare([]byte("another message"), decrypted) != 0 {
		t.Error("Did not decrypt what was encrypted")
	}
}

func TestIncBytes(t *testing.T) {
	b := []byte{0, 1, 2, 3, 4, 5}
	incBytes(b)
	expected := []byte{1, 1, 2, 3, 4, 5}
	if bytes.Compare(b, expected) != 0 {
		t.Errorf("expected %v, got %v", expected, b)
	}

	b = []byte{255, 1, 2, 3, 4, 5}
	incBytes(b)
	expected = []byte{0, 2, 2, 3, 4, 5}
	if bytes.Compare(b, expected) != 0 {
		t.Errorf("expected %v, got %v", expected, b)
	}

	b = []byte{255, 255, 255, 255, 255, 255}
	incBytes(b)
	expected = []byte{0, 0, 0, 0, 0, 0}
	if bytes.Compare(b, expected) != 0 {
		t.Errorf("expected %v, got %v", expected, b)
	}
}
