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
)

const FileMagicNumber = uint32(0x40F1ED00)

var layoutDataStart = "🔒fortified🔒"
var layoutByteOrder = binary.BigEndian

type FileLayout struct {
	magic          uint32
	checksum       []byte
	dataLength     uint64
	headChecksum   []byte
	metadataLength uint32
	metadataRaw    []byte
	dataStartMark  []byte
	nonce          []byte
	//
	version  rune
	metadata *Metadata
}

func (f *FileLayout) DataLength() uint64 {
	return f.dataLength
}

func (f *FileLayout) Version() rune {
	return f.version
}

func (f *FileLayout) Metadata() *Metadata {
	return f.metadata
}

func (f *FileLayout) String() string {
	return fmt.Sprintf("\nMagic: %X\nVersion: %c\nChecksum: %X\nData Length: %d\n"+
		"Head Checksum: %X\nMetadata Length: %d\nMetadata Raw: %s\nData Start Mark: %s\nNonce: %X\n",
		f.magic, f.Version(), f.checksum, f.dataLength, f.headChecksum,
		f.metadataLength, f.metadataRaw, f.dataStartMark, f.nonce,
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
	if err = binary.Read(in, endian, &f.dataLength); err != nil {
		return
	}
	f.headChecksum = make([]byte, 32)
	if err = binary.Read(in, endian, f.headChecksum); err != nil {
		return
	}
	if err = binary.Read(in, endian, &f.metadataLength); err != nil {
		return
	}
	f.metadataRaw = make([]byte, f.metadataLength)
	if err = binary.Read(in, endian, f.metadataRaw); err != nil {
		return
	}
	f.dataStartMark = make([]byte, len(layoutDataStart))
	if err = binary.Read(in, endian, f.dataStartMark); err != nil {
		return
	}
	f.nonce = make([]byte, 8)
	if err = binary.Read(in, endian, f.nonce); err != nil {
		return
	}
	//
	f.version = rune(0xFF & f.magic)
	f.metadata = &Metadata{}
	if err = json.Unmarshal(f.metadataRaw, f.metadata); err != nil {
		return
	}
	return
}

func (f *FileLayout) WriteHeadOut(out io.Writer) (err error) {
	f.magic = FileMagicNumber | '1'
	f.version = rune(0xFF & f.magic)
	if f.metadataRaw, err = json.Marshal(f.metadata); err != nil {
		return
	}
	f.metadataLength = uint32(len(f.metadataRaw) & 0xFFFFFFFF)
	f.checksum = make([]byte, 32)     // place hold
	f.dataLength = 0                  // place hold
	f.headChecksum = make([]byte, 32) // place hold
	f.dataStartMark = []byte(layoutDataStart)
	f.nonce = make([]byte, 8)
	if _, err = rand.Read(f.nonce); err != nil {
		return
	}
	items := []any{f.magic, f.checksum, f.dataLength, f.headChecksum,
		f.metadataLength, f.metadataRaw, f.dataStartMark, f.nonce}
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
	f.dataLength = uint64(dataLen)
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
	if err = binary.Write(out, layoutByteOrder, f.dataLength); err != nil {
		return
	}
	if _, err = out.Write(f.headChecksum); err != nil {
		return
	}
	return
}

func (f *FileLayout) makeChecksum(key *CipherKeyData, check hash.Hash) (err error) {
	f.headChecksum = f.makeChecksumHead(key)
	check.Write(f.headChecksum)
	f.checksum = check.Sum(nil)
	return
}

func (f *FileLayout) makeChecksumHead(key *CipherKeyData) []byte {
	endian := layoutByteOrder
	magic := make([]byte, 4)
	endian.PutUint32(magic, f.magic)
	dataLen := make([]byte, 8)
	endian.PutUint64(dataLen, f.dataLength)
	metaLen := make([]byte, 4)
	endian.PutUint32(metaLen, f.metadataLength)
	check := key.NewSha256()
	check.Write(magic)
	check.Write(dataLen)
	check.Write(metaLen)
	check.Write(f.metadataRaw)
	check.Write(f.dataStartMark)
	check.Write(f.nonce)
	return check.Sum(nil)
}
