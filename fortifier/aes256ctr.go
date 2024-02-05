package fortifier

import (
	"crypto/cipher"
	"os"
)

type Aes256EncrypterCTR struct {
	Aes256StreamEncrypter
}

func NewAes256EncrypterCTR(f *Fortifier) *Aes256EncrypterCTR {
	return &Aes256EncrypterCTR{Aes256StreamEncrypter{f}}
}

func (f *Aes256EncrypterCTR) EncryptFile(in, out *os.File) error {
	f.meta.Mode = CipherModeAes256CTR
	return f.Aes256StreamEncrypter.EncryptFile(in, out,
		CipherMode{Name: CipherModeAes256CTR, SteamMaker: cipher.NewCTR})
}

type Aes256DecrypterCTR struct {
	Aes256StreamDecrypter
}

func NewAes256DecrypterCTR(f *Fortifier) *Aes256DecrypterCTR {
	return &Aes256DecrypterCTR{Aes256StreamDecrypter{f}}
}

func (f *Aes256DecrypterCTR) DecryptFile(in, out *os.File, layout *FileLayout) error {
	return f.Aes256StreamDecrypter.DecryptFile(in, out, layout,
		CipherMode{Name: CipherModeAes256CTR, SteamMaker: cipher.NewCTR})
}
