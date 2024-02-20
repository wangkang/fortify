package fortifier

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"time"
)

type Encrypter interface {
	EncryptFile(in, out *os.File) error
}

type Decrypter interface {
	Decrypt(r io.Reader, w io.Writer, layout *FileLayout) error
	DecryptFile(in, out *os.File, layout *FileLayout) error
}

type Metadata struct {
	Timestamp time.Time      `json:"timestamp"`
	Key       CipherKeyKind  `json:"key"`
	Mode      CipherModeName `json:"mode"`
	Sss       *MetadataSss   `json:"sss"`
	Rsa       *MetadataRsa   `json:"rsa"`
}

type Fortifier struct {
	meta  *Metadata
	key   *CipherKeyData
	block cipher.Block
}

func NewEncrypter(mode CipherModeName, f *Fortifier) Encrypter {
	switch mode {
	case CipherModeAes256CTR:
		return NewAes256EncrypterCTR(f)
	case CipherModeAes256OFB:
		return NewAes256EncrypterOFB(f)
	case CipherModeAes256CFB:
		return NewAes256EncrypterCFB(f)
	default:
		return nil
	}
}

func NewDecrypter(mode CipherModeName, f *Fortifier) Decrypter {
	switch mode {
	case CipherModeAes256CTR:
		return NewAes256DecrypterCTR(f)
	case CipherModeAes256OFB:
		return NewAes256DecrypterOFB(f)
	case CipherModeAes256CFB:
		return NewAes256DecrypterCFB(f)
	default:
		return nil
	}
}

func (f *Fortifier) SetupKey() (err error) {
	if len(f.key.raw) > 0 {
		return
	}
	switch f.key.kind {
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
