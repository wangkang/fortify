package files

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"reflect"
	"time"
)

const FortifiedFileMagicNumber = int32(0x40F1ED00)

type FortifiedFileSss struct {
	Timestamp time.Time `json:"timestamp"`
	Parts     uint8     `json:"parts"`
	Threshold uint8     `json:"threshold"`
	Digest    string    `json:"digest"`
}

type FortifiedFileHead struct {
	Cipher string            `json:"cipher"`
	Sss    *FortifiedFileSss `json:"sss"`
}

type FortifiedWriter struct {
	key   []byte
	check hash.Hash
	out   *os.File
	head  *FortifiedFileHead
}

func NewFortifiedWriter(file *os.File, head *FortifiedFileHead) *FortifiedWriter {
	return &FortifiedWriter{out: file, head: head}
}

func (w *FortifiedWriter) WriteFile(in *os.File) (err error) {
	head := w.head
	if head == nil {
		head = &FortifiedFileHead{Sss: &FortifiedFileSss{Parts: 2, Threshold: 2}}
		w.head = head
	}
	key := w.key
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
		var ps []SssPart
		if ps, err = SssSplit(key, head.Sss.Parts, head.Sss.Threshold); err != nil {
			return
		}
		if err = SssAppendParts(ps, 0, 1, "fortified.key"); err != nil {
			return
		}
		defer SssCloseAllFilesForWrite()
		head.Sss.Digest = ps[0].Digest
		head.Sss.Timestamp = ps[0].Timestamp
		w.key = key
		w.check = hmac.New(sha256.New, key)
	}
	return w.writeCiphertextV1(in)
}

func (w *FortifiedWriter) writeCiphertextV1(in *os.File) (err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(w.key); err != nil {
		return
	}
	out := w.out
	iv := make([]byte, block.BlockSize())
	if _, err = rand.Read(iv); err != nil {
		return
	}
	stream := cipher.NewCTR(block, iv)
	w.head.Cipher = "aes256-ctr"
	var writeTail func(int64) error
	if err, writeTail = w.writeHeadV1(w.head); err != nil {
		return
	}
	if _, err = out.Write(iv); err != nil {
		return
	}
	w.check.Write(iv)
	writer := io.MultiWriter(w.check, cipher.StreamWriter{S: stream, W: out})
	fmt.Printf("Encrypt: %s ----> %s\n", in.Name(), out.Name())
	started := time.Now()
	var cnt int64
	if cnt, err = io.Copy(writer, in); err != nil {
		return
	}
	fmt.Printf("Encrypt: %s ----> %s OK (%v)\n", in.Name(), out.Name(), time.Since(started))
	return writeTail(cnt)
}

func (w *FortifiedWriter) writeHeadV1(head *FortifiedFileHead) (err error, writeTail func(int64) error) {
	var headJson []byte
	if headJson, err = json.Marshal(head); err != nil {
		return
	}
	magic := make([]byte, 4)
	checksum := make([]byte, 32)
	dataLen := make([]byte, 8)
	headLen := make([]byte, 4)
	encoder := binary.BigEndian
	encoder.PutUint32(magic, uint32(FortifiedFileMagicNumber|'1'))
	encoder.PutUint32(headLen, uint32(len(headJson)&0xFFFFFFFF))
	w.check.Write(magic)
	w.check.Write(headLen)
	w.check.Write(headJson)
	dataStart := []byte{'<', '(', '[', '{'}
	items := []any{magic, checksum, dataLen, headLen, headJson, dataStart}
	for _, item := range items {
		if err = binary.Write(w.out, encoder, item); err != nil {
			return
		}
	}
	return err, func(cnt int64) (err error) {
		dataEnd := []byte{'}', ']', ')', '>'}
		if _, err = w.out.Write(dataEnd); err != nil {
			return
		}
		size := int64(reflect.TypeOf(FortifiedFileMagicNumber).Size())
		if _, err = w.out.Seek(size, io.SeekStart); err != nil {
			return
		}
		encoder.PutUint64(dataLen, uint64(cnt))
		w.check.Write(dataLen)
		sum := w.check.Sum(nil)
		if _, err = w.out.Write(sum); err != nil {
			return
		}
		if _, err = w.out.Write(dataLen); err != nil {
			return
		}
		return
	}
}
