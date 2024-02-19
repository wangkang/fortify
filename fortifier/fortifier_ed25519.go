package fortifier

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"time"

	"github.com/struqt/fortify/utils"
)

type MetadataEd25519 struct {
	Timestamp  time.Time `json:"timestamp"`
	Digest     string    `json:"digest"`
	Ciphertext string    `json:"ciphertext"`
}

func NewFortifierWithEd25519(meta *Metadata, blocks []pem.Block) *Fortifier {
	var m *MetadataEd25519
	if meta != nil {
		m = meta.Ed25519
	}
	return &Fortifier{
		meta: &Metadata{Ed25519: m},
		key:  &CipherKeyData{kind: CipherKeyKindEd25519, blocks: blocks},
	}
}

func (f *Fortifier) setupEd25519Key() (err error) {
	var encrypted []byte
	f.meta.Key = CipherKeyKindEd25519
	f.meta.Ed25519 = &MetadataEd25519{
		Timestamp:  time.Now(),
		Digest:     utils.ComputeDigest(encrypted),
		Ciphertext: base64.URLEncoding.EncodeToString(encrypted),
	}
	return errors.New("TODO CipherKeyKindEd25519")
}
