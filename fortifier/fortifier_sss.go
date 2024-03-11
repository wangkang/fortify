package fortifier

import (
	"crypto/rand"
	"time"

	"github.com/wangkang/fortify/sss"
)

type MetadataSss struct {
	Timestamp time.Time `json:"timestamp"`
	Digest    string    `json:"digest"`
	Parts     uint8     `json:"parts"`
	Threshold uint8     `json:"threshold"`
}

func NewFortifierWithSss(verbose, truncate bool, parts []sss.Part) *Fortifier {
	var m *MetadataSss
	if len(parts) > 0 {
		m = &MetadataSss{
			Timestamp: parts[0].Timestamp,
			Digest:    parts[0].Digest,
			Parts:     parts[0].Parts,
			Threshold: parts[0].Threshold,
		}
	} else {
		m = &MetadataSss{Parts: 2, Threshold: 2}
	}
	return &Fortifier{
		meta:     &Metadata{Sss: m},
		key:      &CipherKeyData{kind: CipherKeyKindSSS, parts: parts},
		verbose:  verbose,
		truncate: truncate,
	}
}

func (f *Fortifier) setupSssKey() (err error) {
	f.meta.Key = CipherKeyKindSSS
	f.meta.Timestamp = time.Now()
	if len(f.key.parts) > 0 {
		if f.key.raw, err = sss.Combine(f.key.parts); err != nil {
			return
		}
	} else {
		f.key.raw = make([]byte, 32)
		raw := f.key.raw
		meta := f.meta
		if _, err = rand.Read(raw); err != nil {
			return
		}
		var ps []sss.Part
		if ps, err = sss.Split(raw, meta.Sss.Parts, meta.Sss.Threshold); err != nil {
			return
		}
		if err = sss.AppendParts(ps, 0, 1, "fortified.key", f.truncate); err != nil {
			return
		}
		defer sss.CloseAllFilesForWrite()
		meta.Sss.Digest = ps[0].Digest
		meta.Sss.Timestamp = ps[0].Timestamp
	}
	return
}
