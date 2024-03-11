package fortifier

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/wangkang/fortify/utils"
	"golang.org/x/crypto/ssh"
)

const rsaFortifier = "rsa_fortifier"

type MetadataRsa struct {
	Timestamp  time.Time `json:"timestamp"`
	Digest     string    `json:"digest"`
	Ciphertext string    `json:"ciphertext"`
}

func NewFortifierWithRsa(verbose bool, meta *Metadata, bytes []byte) *Fortifier {
	var m *MetadataRsa
	if meta != nil {
		m = meta.Rsa
	}
	return &Fortifier{
		meta:    &Metadata{Rsa: m},
		key:     &CipherKeyData{kind: CipherKeyKindRSA, bytes: bytes},
		verbose: verbose,
	}
}

func (f *Fortifier) setupRsaKey() error {
	if f.meta.Rsa == nil {
		return f.setupRsaPublicKey()
	} else {
		return f.setupRsaPrivateKey()
	}
}

func (f *Fortifier) setupRsaPublicKey() (err error) {
	var pub *rsa.PublicKey
	parsed, _, _, _, x := ssh.ParseAuthorizedKey(f.key.bytes)
	if x == nil {
		if parsedCryptoKey, ok := parsed.(ssh.CryptoPublicKey); ok {
			k := parsedCryptoKey.CryptoPublicKey()
			pub, _ = k.(*rsa.PublicKey)
		}
	}
	if pub == nil {
		blocks := f.decodePemFile()
		if len(blocks) == 0 {
			return fmt.Errorf("%s: pem file decoding failed", rsaFortifier)
		}
		block := &blocks[0]
		var k any
		switch block.Type {
		case "RSA PUBLIC KEY":
			if k, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				return fmt.Errorf("%s: not public key in PKCS #1, ASN.1 DER form -- %v", rsaFortifier, err)
			}
		case "PUBLIC KEY":
			return fmt.Errorf("%s: PKCS #8 public key is unsupported", rsaFortifier)
		}
		if k == nil {
			return fmt.Errorf("%s: unsupported key type %q", rsaFortifier, block.Type)
		}
		pub = k.(*rsa.PublicKey)
	}
	if pub == nil {
		return
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	var encrypted []byte
	if encrypted, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, raw, nil); err != nil {
		return
	}
	f.key.raw = raw
	f.meta.Key = CipherKeyKindRSA
	f.meta.Timestamp = time.Now()
	f.meta.Rsa = &MetadataRsa{
		Timestamp:  time.Now(),
		Digest:     utils.ComputeDigest(raw),
		Ciphertext: base64.URLEncoding.EncodeToString(encrypted),
	}
	return
}

func (f *Fortifier) setupRsaPrivateKey() (err error) {
	var pri *rsa.PrivateKey
	if pri, err = f.parseRsaPrivateKey(); err != nil {
		return
	}
	m := f.meta.Rsa
	var ciphertext []byte
	ciphertext, err = base64.URLEncoding.DecodeString(m.Ciphertext)
	if f.key.raw, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, pri, ciphertext, nil); err != nil {
		return fmt.Errorf("%s: decrypting secret key failed. %v", rsaFortifier, err)
	}
	actual := utils.ComputeDigest(f.key.raw)
	if m.Digest != actual {
		return fmt.Errorf("%s: digest mismatch. expect %q, actual %q", rsaFortifier, m.Digest, actual)
	}
	return
}

func (f *Fortifier) parseRsaPrivateKey() (*rsa.PrivateKey, error) {
	var k any
	var err error
	bytes := f.key.bytes
	if k, err = ssh.ParseRawPrivateKey(bytes); err != nil {
		var passphraseMissingError *ssh.PassphraseMissingError
		if errors.As(err, &passphraseMissingError) {
			k, err = ssh.ParseRawPrivateKeyWithPassphrase(bytes, enterPassphrase())
		}
	}
	if err != nil {
		blocks := f.decodePemFile()
		if len(blocks) == 0 {
			return nil, err
		}
		block := &blocks[0]
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			err = fmt.Errorf("%s: encrypted PKCS #8 private key is unsupported", rsaFortifier)
		}
	}
	if err != nil {
		return nil, err
	}
	if key, ok := k.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("%s: requiring *rsa.PrivateKey, not %v", rsaFortifier, reflect.TypeOf(k))
	} else {
		return key, nil
	}
}

func (f *Fortifier) decodePemFile() (blocks []pem.Block) {
	kb := f.key.bytes
	for {
		var blk *pem.Block
		blk, kb = pem.Decode(kb)
		if blk == nil || blk.Type == "" {
			break
		}
		blocks = append(blocks, *blk)
	}
	return
}
