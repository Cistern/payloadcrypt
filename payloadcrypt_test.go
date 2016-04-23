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
	encrypted, err := c.Encrypt([]byte("some message"))
	if err != nil {
		t.Fatal(err)
	}

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

	encrypted, err = c.Encrypt([]byte("another message"))
	if err != nil {
		t.Error(err)
	}
	decrypted, err = c2.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare([]byte("another message"), decrypted) != 0 {
		t.Error("Did not decrypt what was encrypted")
	}
}
