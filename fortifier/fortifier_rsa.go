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
	"time"

	"github.com/struqt/fortify/utils"
)

type MetadataRsa struct {
	Timestamp  time.Time `json:"timestamp"`
	Digest     string    `json:"digest"`
	Ciphertext string    `json:"ciphertext"`
}

func NewFortifierWithRsa(meta *Metadata, blocks []pem.Block) *Fortifier {
	var m *MetadataRsa
	if meta != nil {
		m = meta.Rsa
	}
	return &Fortifier{
		meta: &Metadata{Rsa: m},
		key:  &CipherKeyData{kind: CipherKeyKindRSA, blocks: blocks},
	}
}

func (f *Fortifier) setupRsaKey() (err error) {
	if len(f.key.blocks) == 0 {
		return errors.New("no key for RSA")
	}
	m := f.meta.Rsa
	if m != nil {
		if err = f.setupRsaPrivateKey(); err != nil {
			return
		}
	} else {
		if err = f.setupRsaPublicKey(); err != nil {
			return
		}
	}
	return
}

func (f *Fortifier) setupRsaPublicKey() (err error) {
	p := f.key.blocks[0]
	if p.Type != "RSA PUBLIC KEY" {
		return fmt.Errorf("requiring RSA PUBLIC KEY, not %s", p.Type)
	}
	var k any
	if k, err = x509.ParsePKCS1PublicKey(p.Bytes); err != nil {
		return fmt.Errorf("not an RSA public key in PKCS #1, ASN.1 DER form -- %v", err)
	}
	pub := k.(*rsa.PublicKey)
	f.key.raw = make([]byte, 32)
	raw := f.key.raw
	if _, err = rand.Read(raw); err != nil {
		return
	}
	var encrypted []byte
	// if encrypted, err = rsa.EncryptPKCS1v15(rand.Reader, pub, raw); err != nil {
	if encrypted, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, raw, nil); err != nil {
		return
	}
	f.meta.Key = CipherKeyKindRSA
	f.meta.Rsa = &MetadataRsa{
		Timestamp:  time.Now(),
		Digest:     utils.ComputeDigest(raw),
		Ciphertext: base64.URLEncoding.EncodeToString(encrypted),
	}
	return
}

func (f *Fortifier) setupRsaPrivateKey() (err error) {
	p := f.key.blocks[0]
	if p.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("requiring RSA PRIVATE KEY, not %s", p.Type)
	}
	m := f.meta.Rsa
	var ciphertext []byte
	ciphertext, err = base64.URLEncoding.DecodeString(m.Ciphertext)
	var passphrase []byte
	var der []byte
	if p.Headers["Proc-Type"] == "4,ENCRYPTED" {
		passphrase = enterPassphrase()
		if len(passphrase) == 0 {
			return errors.New("passphrase is required")
		}
		if der, err = x509.DecryptPEMBlock(&p, passphrase); err != nil {
			return fmt.Errorf("decrypting RSA private key -- %v", err)
		}
	}
	if der == nil {
		der = p.Bytes
	}
	var k any
	if k, err = x509.ParsePKCS1PrivateKey(der); err != nil {
		return fmt.Errorf("not an RSA private key in PKCS #1, ASN.1 DER form -- %v", err)
	}
	pri := k.(*rsa.PrivateKey)
	if f.key.raw, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, pri, ciphertext, nil); err != nil {
		return fmt.Errorf("decrypting secret key failed. %v", err)
	}
	actual := utils.ComputeDigest(f.key.raw)
	if m.Digest != actual {
		return fmt.Errorf("digest mismatch: expect %s, actual %s", m.Digest, actual)
	}
	return
}
