package fortifier

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"time"

	"github.com/struqt/fortify/sss"
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
}

type CipherKeyData struct {
	kind  CipherKeyKind
	parts []sss.Part
	raw   []byte
}

type MetadataSss struct {
	Timestamp time.Time `json:"timestamp"`
	Parts     uint8     `json:"parts"`
	Threshold uint8     `json:"threshold"`
	Digest    string    `json:"digest"`
}

func NewFortifierWithSss(parts []sss.Part) *Fortifier {
	var ms *MetadataSss
	if len(parts) > 0 {
		ms = &MetadataSss{
			Timestamp: parts[0].Timestamp,
			Parts:     parts[0].Parts,
			Threshold: parts[0].Threshold,
			Digest:    parts[0].Digest,
		}
	} else {
		ms = &MetadataSss{Parts: 2, Threshold: 2}
	}
	return &Fortifier{
		meta: &Metadata{Sss: ms},
		key:  &CipherKeyData{kind: CipherKeyKindSSS, parts: parts, raw: nil},
	}
}

func (k *CipherKeyData) NewSha256() hash.Hash {
	return hmac.New(sha256.New, k.raw)
}

func (f *Fortifier) SetupKey() (err error) {
	if len(f.key.raw) > 0 {
		return
	}
	var raw []byte
	switch f.key.kind {
	case CipherKeyKindEd25519:
		return errors.New("TODO CipherKeyKindEd25519")
	case CipherKeyKindRSA:
		return errors.New("TODO CipherKeyKindRSA")
	default:
		if len(f.key.parts) > 0 {
			if raw, err = sss.Combine(f.key.parts); err != nil {
				return
			}
		} else {
			meta := f.meta
			raw = make([]byte, 32)
			_, _ = rand.Read(raw)
			var ps []sss.Part
			if ps, err = sss.Split(raw, meta.Sss.Parts, meta.Sss.Threshold); err != nil {
				return
			}
			if err = sss.AppendParts(ps, 0, 1, "fortified.key"); err != nil {
				return
			}
			defer sss.CloseAllFilesForWrite()
			meta.Sss.Digest = ps[0].Digest
			meta.Sss.Timestamp = ps[0].Timestamp
		}
		f.meta.Key = CipherKeyKindSSS
	}
	f.key.raw = raw
	if f.block, err = aes.NewCipher(raw); err != nil {
		return
	}
	return
}
