package fortifier

import (
	"crypto/cipher"
	"os"
)

type Aes256EncrypterOFB struct {
	Aes256StreamEncrypter
}

func NewAes256EncrypterOFB(f *Fortifier) *Aes256EncrypterOFB {
	return &Aes256EncrypterOFB{Aes256StreamEncrypter{f}}
}

func (f *Aes256EncrypterOFB) EncryptFile(in, out *os.File) error {
	f.meta.Mode = CipherModeAes256OFB
	return f.Aes256StreamEncrypter.EncryptFile(in, out,
		CipherMode{Name: CipherModeAes256OFB, SteamMaker: cipher.NewOFB})
}

type Aes256DecrypterOFB struct {
	Aes256StreamDecrypter
}

func NewAes256DecrypterOFB(f *Fortifier) *Aes256DecrypterOFB {
	return &Aes256DecrypterOFB{Aes256StreamDecrypter{f}}
}

func (f *Aes256DecrypterOFB) DecryptFile(in, out *os.File, layout *FileLayout) error {
	return f.Aes256StreamDecrypter.DecryptFile(in, out, layout,
		CipherMode{Name: CipherModeAes256OFB, SteamMaker: cipher.NewOFB})
}
