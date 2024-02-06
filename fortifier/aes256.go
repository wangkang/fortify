package fortifier

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type Aes256StreamEncrypter struct {
	*Fortifier
}

func (f *Aes256StreamEncrypter) EncryptFile(in, out *os.File, mode CipherMode) (err error) {
	if err = f.SetupKey(); err != nil {
		return
	}
	iv := make([]byte, f.block.BlockSize())
	if _, err = rand.Read(iv); err != nil {
		return
	}
	ir := bufio.NewReaderSize(in, 128*1024)
	ow := bufio.NewWriterSize(out, 256*1024)
	layout := &FileLayout{}
	if err = layout.WriteHeadOut(ow, f.meta); err != nil {
		return
	}
	if _, err = ow.Write(iv); err != nil {
		return
	}
	check := f.key.NewSha256()
	check.Write(iv)
	stream := mode.SteamMaker(f.block, iv)
	writer := io.MultiWriter(check, cipher.StreamWriter{S: stream, W: ow})
	reader := ir
	fmt.Printf("%s O-->* %s [%s %s]\n", in.Name(), out.Name(), f.meta.Key, f.meta.Mode)
	started := time.Now()
	var cnt int64
	if cnt, err = io.Copy(writer, reader); err != nil {
		return
	}
	if err = ow.Flush(); err != nil {
		return
	}
	_ = out.Sync()
	var stat os.FileInfo
	if stat, err = out.Stat(); err != nil {
		return
	}
	fmt.Printf("%s O-->* %s %d bytes (%v) OK\n", in.Name(), out.Name(), stat.Size(), time.Since(started))
	return layout.WriteHeadPlaceHolders(out, f.key, check, cnt)
}

type Aes256StreamDecrypter struct {
	*Fortifier
}

func (f *Aes256StreamDecrypter) DecryptFile(in, out *os.File, layout *FileLayout, mode CipherMode) (err error) {
	ir := bufio.NewReaderSize(in, 128*1024)
	ow := bufio.NewWriterSize(out, 256*1024)
	meta := layout.Metadata()
	fmt.Printf("%s *-->O %s %d bytes [%s %s]\n", in.Name(), out.Name(), layout.dataLen, meta.Key, meta.Mode)
	started := time.Now()
	if err = f.Decrypt(ir, ow, layout, mode); err != nil {
		return
	}
	if err = ow.Flush(); err != nil {
		return
	}
	_ = out.Sync()
	var stat os.FileInfo
	if stat, err = out.Stat(); err != nil {
		return
	}
	fmt.Printf("%s *-->O %s %d bytes (%v) OK\n", in.Name(), out.Name(), stat.Size(), time.Since(started))
	return
}

func (f *Aes256StreamDecrypter) Decrypt(r io.Reader, w io.Writer, layout *FileLayout, mode CipherMode) (err error) {
	if err = f.SetupKey(); err != nil {
		return
	}
	expect := layout.metaSum
	actual := layout.makeChecksumHead(f.key)
	if !bytes.Equal(expect, actual) {
		return errors.New("invalid checksum of meta")
	}
	meta := layout.Metadata()
	if meta.Mode != mode.Name {
		return fmt.Errorf("requires cipher mode: %s", meta.Mode)
	}
	if meta.Sss.Digest != f.meta.Sss.Digest {
		return errors.New("mismatched key digest")
	}
	f.meta.Mode = meta.Mode
	f.meta.Timestamp = meta.Timestamp
	iv := make([]byte, f.block.BlockSize())
	if err = binary.Read(r, layoutByteOrder, iv); err != nil {
		return
	}
	check := f.key.NewSha256()
	stream := mode.SteamMaker(f.block, iv)
	var writer io.Writer
	if w != nil {
		writer = io.MultiWriter(w, check)
	} else {
		writer = check
	}
	reader := cipher.StreamReader{S: stream, R: r}
	check.Write(iv)
	var cnt int64
	if cnt, err = io.Copy(writer, reader); err != nil {
		return
	}
	if uint64(cnt) != layout.dataLen {
		return fmt.Errorf("expect data length is %d, not %d\n", layout.dataLen, cnt)
	}
	check.Write(layout.metaSum)
	sum := check.Sum(nil)
	if !bytes.Equal(layout.checksum, sum) {
		return errors.New("invalid checksum of file")
	}
	return
}
