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

const defaultReaderBufferSize = 128 * 1024
const defaultWriterBufferSize = 256 * 1024

type Aes256StreamEncrypter struct {
	*Fortifier
}

func (f *Aes256StreamEncrypter) EncryptFile(in, out *os.File, mode CipherMode) (err error) {
	if err = f.SetupKey(); err != nil {
		return
	}
	if f.verbose {
		var stat os.FileInfo
		if stat, err = in.Stat(); err != nil {
			return
		}
		fmt.Printf("%s O-->* %s %d bytes [%s %s]\n", in.Name(), out.Name(), stat.Size(), f.meta.Key, f.meta.Mode)
	}
	started := time.Now()
	layout := &FileLayout{metadata: f.meta}
	if err = f.Encrypt(in, out, layout, mode); err != nil {
		return
	}
	if f.verbose {
		fmt.Printf("%s O-->* %s %d bytes (%v) OK\n", in.Name(), out.Name(), layout.dataLength, time.Since(started))
	}
	return
}

func (f *Aes256StreamEncrypter) Encrypt(
	in io.Reader, out io.WriteSeeker, layout *FileLayout, mode CipherMode) (err error) {
	iv := make([]byte, f.block.BlockSize())
	if _, err = rand.Read(iv); err != nil {
		return
	}
	ow := bufio.NewWriterSize(out, defaultWriterBufferSize)
	if err = layout.WriteHeadOut(ow); err != nil {
		return
	}
	if _, err = ow.Write(iv); err != nil {
		return
	}
	check := f.key.NewSha256()
	check.Write(iv)
	stream := mode.SteamMaker(f.block, iv)
	writer := io.MultiWriter(check, cipher.StreamWriter{S: stream, W: ow})
	ir := bufio.NewReaderSize(in, defaultReaderBufferSize)
	var cnt int64
	if cnt, err = io.Copy(writer, ir); err != nil {
		return
	}
	if err = ow.Flush(); err != nil {
		return
	}
	if file, ok := out.(*os.File); ok {
		if err = file.Sync(); err != nil {
			return
		}
	}
	if err = layout.WriteHeadPlaceHolders(out, f.key, check, cnt); err != nil {
		return
	}
	return
}

type Aes256StreamDecrypter struct {
	*Fortifier
}

func (f *Aes256StreamDecrypter) DecryptFile(in, out *os.File, layout *FileLayout, mode CipherMode) (err error) {
	if err = f.SetupKey(); err != nil {
		return
	}
	if f.verbose {
		meta := layout.Metadata()
		fmt.Printf("%s *-->O %s %d bytes [%s %s]\n", in.Name(), out.Name(), layout.dataLength, meta.Key, meta.Mode)
	}
	started := time.Now()
	if err = f.Decrypt(in, out, layout, mode); err != nil {
		return
	}
	if f.verbose {
		var stat os.FileInfo
		if stat, err = out.Stat(); err != nil {
			return
		}
		fmt.Printf("%s *-->O %s %d bytes (%v) OK\n", in.Name(), out.Name(), stat.Size(), time.Since(started))
	}
	return
}

func (f *Aes256StreamDecrypter) Decrypt(in io.Reader, w io.Writer, layout *FileLayout, mode CipherMode) (err error) {
	if err = f.SetupKey(); err != nil {
		return
	}
	expect := layout.headChecksum
	actual := layout.makeChecksumHead(f.key)
	if !bytes.Equal(expect, actual) {
		return errors.New("invalid checksum of meta")
	}
	meta := layout.Metadata()
	if meta.Mode != mode.Name {
		return fmt.Errorf("requires cipher mode: %s", meta.Mode)
	}
	if f.meta.Sss != nil && meta.Sss.Digest != f.meta.Sss.Digest {
		return errors.New("mismatched key digest")
	}
	f.meta.Mode = meta.Mode
	f.meta.Timestamp = meta.Timestamp
	iv := make([]byte, f.block.BlockSize())
	ir := bufio.NewReaderSize(in, defaultReaderBufferSize)
	if err = binary.Read(ir, layoutByteOrder, iv); err != nil {
		return
	}
	check := f.key.NewSha256()
	stream := mode.SteamMaker(f.block, iv)
	var writer io.Writer
	var ow *bufio.Writer
	if w != nil {
		ow = bufio.NewWriterSize(w, defaultWriterBufferSize)
		writer = io.MultiWriter(ow, check)
	} else {
		writer = check
	}
	reader := cipher.StreamReader{S: stream, R: ir}
	check.Write(iv)
	var cnt int64
	if cnt, err = io.Copy(writer, reader); err != nil {
		return
	}
	if uint64(cnt) != layout.dataLength {
		return fmt.Errorf("expect data length is %d, not %d\n", layout.dataLength, cnt)
	}
	check.Write(layout.headChecksum)
	sum := check.Sum(nil)
	if !bytes.Equal(layout.checksum, sum) {
		return errors.New("invalid checksum of file")
	}
	if ow != nil {
		if err = ow.Flush(); err != nil {
			return
		}
	}
	if file, ok := w.(*os.File); ok {
		if err = file.Sync(); err != nil {
			return
		}
	}
	return
}
