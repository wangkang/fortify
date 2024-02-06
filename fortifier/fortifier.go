package fortifier

import (
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

type CipherModeName string

func (s CipherModeName) String() string {
	return string(s)
}

type CipherMode struct {
	Name       CipherModeName
	SteamMaker func(block cipher.Block, iv []byte) cipher.Stream
}

type Metadata struct {
	Timestamp time.Time      `json:"timestamp"`
	Key       CipherKeyKind  `json:"key"`
	Mode      CipherModeName `json:"mode"`
	Sss       *MetadataSss   `json:"sss"`
}

type Fortifier struct {
	meta  *Metadata
	key   *CipherKeyData
	block cipher.Block
}

const (
	CipherModeAes256CTR CipherModeName = "aes256-ctr"
	CipherModeAes256OFB CipherModeName = "aes256-ofb"
	CipherModeAes256CFB CipherModeName = "aes256-cfb"
)

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
