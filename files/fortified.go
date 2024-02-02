package files

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"
)

const FortifiedFileMagicNumber = int32(0x40f1ed00)

type FortifiedFileHead struct {
	Timestamp time.Time `json:"timestamp"`
	Parts     uint8     `json:"parts"`
	Threshold uint8     `json:"threshold"`
	Digest    string    `json:"digest"`
}

type FortifiedWriter struct {
	key  []byte
	out  *os.File
	head *FortifiedFileHead
}

func NewFortifiedWriter(file *os.File, head *FortifiedFileHead) *FortifiedWriter {
	return &FortifiedWriter{out: file, head: head}
}

func (w *FortifiedWriter) WriteFile(in *os.File) (err error) {
	key := w.key
	if len(key) == 0 {
		key = w.randomKey256b()
		var ps []SssPart
		if ps, err = SssSplit(key, w.head.Parts, w.head.Threshold); err != nil {
			return
		}
		if err = SssAppendParts(ps, 0, 1, "fortified.key"); err != nil {
			return
		}
		defer SssCloseAllFilesForWrite()
		w.head.Digest = ps[0].Digest
		w.head.Timestamp = ps[0].Timestamp
	}
	if err = w.writeHeadV1(w.head); err != nil {
		return
	}
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return
	}
	if _, err = w.out.Write(iv); err != nil {
		return
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	writer := cipher.StreamWriter{S: stream, W: w.out}
	fmt.Printf("Encrypt: %s ----> %s\n", in.Name(), w.out.Name())
	started := time.Now()
	var cnt int64
	if cnt, err = io.Copy(writer, in); err != nil {
		return
	}
	fmt.Printf("Encrypt: %s ----> %s OK (%v)\n", in.Name(), w.out.Name(), time.Since(started))
	return w.writeTail(cnt)
}

func (w *FortifiedWriter) writeHeadV1(head *FortifiedFileHead) (err error) {
	var headJson []byte
	var headLen uint32
	if headJson, err = json.Marshal(head); err != nil {
		return
	}
	headLen = uint32(len(headJson) & 0xFFFFFFFF)
	dataStart := []byte{'<', '(', '[', '{'}
	magic := FortifiedFileMagicNumber | '1'
	dataLen := int64(0)
	items := []any{magic, dataLen, headLen, headJson, dataStart}
	for _, item := range items {
		if err = binary.Write(w.out, binary.BigEndian, item); err != nil {
			return
		}
	}
	return nil
}

func (w *FortifiedWriter) writeTail(cnt int64) (err error) {
	dataEnd := []byte{'}', ']', ')', '>'}
	if _, err = w.out.Write(dataEnd); err != nil {
		return
	}
	size := int64(reflect.TypeOf(FortifiedFileMagicNumber).Size())
	if _, err = w.out.Seek(size, io.SeekStart); err != nil {
		return
	}
	if err = binary.Write(w.out, binary.BigEndian, cnt); err != nil {
		return
	}
	return nil
}

func (w *FortifiedWriter) randomKey256b() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}
