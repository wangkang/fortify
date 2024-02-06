package fortifier

import (
	"crypto/cipher"
	"io"
	"os"
)

type Aes256EncrypterCFB struct {
	Aes256StreamEncrypter
}

func NewAes256EncrypterCFB(f *Fortifier) *Aes256EncrypterCFB {
	return &Aes256EncrypterCFB{Aes256StreamEncrypter{f}}
}

func (f *Aes256EncrypterCFB) EncryptFile(in, out *os.File) error {
	f.meta.Mode = CipherModeAes256CFB
	return f.Aes256StreamEncrypter.EncryptFile(in, out,
		CipherMode{Name: CipherModeAes256CFB, SteamMaker: cipher.NewCFBEncrypter})
}

type Aes256DecrypterCFB struct {
	Aes256StreamDecrypter
}

func NewAes256DecrypterCFB(f *Fortifier) *Aes256DecrypterCFB {
	return &Aes256DecrypterCFB{Aes256StreamDecrypter{f}}
}

func (f *Aes256DecrypterCFB) Decrypt(r io.Reader, w io.Writer, layout *FileLayout) error {
	return f.Aes256StreamDecrypter.Decrypt(r, w, layout,
		CipherMode{Name: CipherModeAes256CFB, SteamMaker: cipher.NewCFBDecrypter})
}

func (f *Aes256DecrypterCFB) DecryptFile(in, out *os.File, layout *FileLayout) error {
	return f.Aes256StreamDecrypter.DecryptFile(in, out, layout,
		CipherMode{Name: CipherModeAes256CFB, SteamMaker: cipher.NewCFBDecrypter})
}
