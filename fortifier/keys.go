package fortifier

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"hash"
	"syscall"

	"github.com/struqt/fortify/sss"
	"golang.org/x/term"
)

type CipherKeyKind string

func (s CipherKeyKind) String() string {
	return string(s)
}

const (
	CipherKeyKindSSS     CipherKeyKind = "sss"
	CipherKeyKindEd25519 CipherKeyKind = "ed25519"
	CipherKeyKindRSA     CipherKeyKind = "rsa"
)

type CipherKey interface {
	CipherKeyKind() CipherKeyKind
	NewSha256() hash.Hash
}

type CipherKeyData struct {
	kind   CipherKeyKind
	raw    []byte
	parts  []sss.Part
	blocks []pem.Block
}

func (k *CipherKeyData) NewSha256() hash.Hash {
	return hmac.New(sha256.New, k.raw)
}

func (k *CipherKeyData) CipherKeyKind() CipherKeyKind {
	return k.kind
}

func (f *Fortifier) SetupKey() (err error) {
	if len(f.key.raw) > 0 {
		return
	}
	switch f.key.kind {
	case CipherKeyKindEd25519:
		err = f.setupEd25519Key()
	case CipherKeyKindRSA:
		err = f.setupRsaKey()
	default:
		err = f.setupSssKey()
	}
	if err != nil {
		return
	}
	if f.block, err = aes.NewCipher(f.key.raw); err != nil {
		return
	}
	return
}

func enterPassphrase() []byte {
	fmt.Print("Enter passphrase: ")
	if passphrase, err := term.ReadPassword(syscall.Stdin); err != nil {
		fmt.Println("\nError reading passphrase:", err)
		return nil
	} else {
		fmt.Println()
		return passphrase
	}
}
