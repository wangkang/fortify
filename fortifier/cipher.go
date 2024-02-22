package fortifier

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"

	"github.com/struqt/fortify/sss"
	"golang.org/x/term"
)

type CipherKeyKind string

func (s CipherKeyKind) String() string {
	return string(s)
}

const (
	CipherKeyKindSSS CipherKeyKind = "sss"
	CipherKeyKindRSA CipherKeyKind = "rsa"
)

type CipherKey interface {
	CipherKeyKind() CipherKeyKind
	NewSha256() hash.Hash
}

type CipherKeyData struct {
	kind  CipherKeyKind
	raw   []byte
	parts []sss.Part
	bytes []byte
}

func (k *CipherKeyData) NewSha256() hash.Hash {
	return hmac.New(sha256.New, k.raw)
}

func (k *CipherKeyData) CipherKeyKind() CipherKeyKind {
	return k.kind
}

type CipherModeName string

func (s CipherModeName) String() string {
	return string(s)
}

type CipherMode struct {
	Name       CipherModeName
	SteamMaker func(block cipher.Block, iv []byte) cipher.Stream
}

const (
	CipherModeAes256CTR CipherModeName = "aes256-ctr"
	CipherModeAes256OFB CipherModeName = "aes256-ofb"
	CipherModeAes256CFB CipherModeName = "aes256-cfb"
)

func enterPassphrase() []byte {
	fmt.Print("Enter passphrase: ")
	if passphrase, err := term.ReadPassword(int(os.Stdin.Fd())); err != nil {
		fmt.Printf("\nError reading passphrase: %v\n", err)
		return nil
	} else {
		fmt.Println()
		return passphrase
	}
}
