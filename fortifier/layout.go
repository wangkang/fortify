package fortifier

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"reflect"
	"time"
)

const FileMagicNumber = uint32(0x40F1ED00)

var layoutDataStart = "🔒fortified🔒"
var layoutByteOrder = binary.BigEndian

type FileLayout struct {
	magic     uint32
	checksum  []byte
	dataLen   uint64
	metaSum   []byte
	metaLen   uint32
	metaJson  []byte
	nonce     []byte
	dataStart []byte
	//
	version  rune
	metadata *Metadata
}

func (f *FileLayout) DataLen() uint64 {
	return f.dataLen
}

func (f *FileLayout) Version() rune {
	return f.version
}

func (f *FileLayout) Metadata() *Metadata {
	return f.metadata
}

func (f *FileLayout) String() string {
	return fmt.Sprintf("------------------------------\n"+
		"Magic: %X\nVersion: %c\nChecksum: %X\nData Length: %d\n"+
		"Meta Checksum: %X\nMeta Length: %d\nMeta JSON: %s\nData Start: %s\nNonce: %X\n"+
		"------------------------------",
		f.magic, f.Version(), f.checksum, f.dataLen, f.metaSum, f.metaLen, f.metaJson, f.dataStart, f.nonce,
	)
}

func (f *FileLayout) ReadHeadIn(in io.Reader) (err error) {
	endian := layoutByteOrder
	if err = binary.Read(in, endian, &f.magic); err != nil {
		return
	}
	if FileMagicNumber != (f.magic & 0x7FFFFF00) {
		return errors.New("not a fortified input file")
	}
	f.checksum = make([]byte, 32)
	if err = binary.Read(in, endian, f.checksum); err != nil {
		return
	}
	if err = binary.Read(in, endian, &f.dataLen); err != nil {
		return
	}
	f.metaSum = make([]byte, 32)
	if err = binary.Read(in, endian, f.metaSum); err != nil {
		return
	}
	if err = binary.Read(in, endian, &f.metaLen); err != nil {
		return
	}
	f.metaJson = make([]byte, f.metaLen)
	if err = binary.Read(in, endian, f.metaJson); err != nil {
		return
	}
	f.dataStart = make([]byte, len(layoutDataStart))
	if err = binary.Read(in, endian, f.dataStart); err != nil {
		return
	}
	f.nonce = make([]byte, 8)
	if err = binary.Read(in, endian, f.nonce); err != nil {
		return
	}
	//
	f.version = rune(0xFF & f.magic)
	f.metadata = &Metadata{}
	if err = json.Unmarshal(f.metaJson, f.metadata); err != nil {
		return
	}
	return
}

func (f *FileLayout) WriteHeadOut(out io.Writer, meta *Metadata) (err error) {
	meta.Timestamp = time.Now()
	if f.metaJson, err = json.Marshal(meta); err != nil {
		return
	}
	f.metaLen = uint32(len(f.metaJson) & 0xFFFFFFFF)
	f.magic = FileMagicNumber | '1'
	f.checksum = make([]byte, 32) // place hold
	f.dataLen = 0                 // place hold
	f.metaSum = make([]byte, 32)  // place hold
	f.dataStart = []byte(layoutDataStart)
	f.nonce = make([]byte, 8)
	if _, err = rand.Read(f.nonce); err != nil {
		return
	}
	items := []any{f.magic, f.checksum, f.dataLen, f.metaSum, f.metaLen, f.metaJson, f.dataStart, f.nonce}
	if out == nil {
		return
	}
	endian := layoutByteOrder
	for _, item := range items {
		if err = binary.Write(out, endian, item); err != nil {
			return
		}
	}
	return
}

func (f *FileLayout) WriteHeadPlaceHolders(
	out io.WriteSeeker, key *CipherKeyData, check hash.Hash, dataLen int64) (err error) {
	f.dataLen = uint64(dataLen)
	if err = f.makeChecksum(key, check); err != nil {
		return
	}
	if out == nil {
		return
	}
	size := int64(reflect.TypeOf(FileMagicNumber).Size())
	if _, err = out.Seek(size, io.SeekStart); err != nil {
		return
	}
	if _, err = out.Write(f.checksum); err != nil {
		return
	}
	if err = binary.Write(out, layoutByteOrder, f.dataLen); err != nil {
		return
	}
	if _, err = out.Write(f.metaSum); err != nil {
		return
	}
	return
}

func (f *FileLayout) makeChecksum(key *CipherKeyData, check hash.Hash) (err error) {
	f.metaSum = f.makeChecksumHead(key)
	check.Write(f.metaSum)
	f.checksum = check.Sum(nil)
	return
}

func (f *FileLayout) makeChecksumHead(key *CipherKeyData) []byte {
	endian := layoutByteOrder
	magic := make([]byte, 4)
	endian.PutUint32(magic, f.magic)
	dataLen := make([]byte, 8)
	endian.PutUint64(dataLen, f.dataLen)
	metaLen := make([]byte, 4)
	endian.PutUint32(metaLen, f.metaLen)
	check := key.NewSha256()
	check.Write(magic)
	check.Write(dataLen)
	check.Write(metaLen)
	check.Write(f.metaJson)
	check.Write(f.dataStart)
	check.Write(f.nonce)
	return check.Sum(nil)
}
