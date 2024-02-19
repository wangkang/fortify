package files

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"os"

	"github.com/struqt/fortify/sss"
)

func PemDecodeFile(args []string) (blocks []pem.Block, err error) {
	size := len(args)
	if size == 0 {
		return
	}
	var kCloseFn func()
	var kf *os.File
	if kf, kCloseFn, err = OpenInputFile(args[0]); err != nil {
		return
	}
	defer kCloseFn()
	var kb []byte
	if kb, err = io.ReadAll(kf); err != nil {
		return
	}
	for {
		var blk *pem.Block
		blk, kb = pem.Decode(kb)
		if blk == nil || blk.Type == "" {
			break
		}
		blocks = append(blocks, *blk)
	}
	return
}

func SssCombineKeyFiles(args []string) (parts []sss.Part, err error) {
	size := len(args)
	if size == 0 {
		return nil, nil
	}
	kCloseFns := make([]func(), size)
	kParts := make([]sss.Part, size)
	for i, name := range args {
		var kf *os.File
		if kf, kCloseFns[i], err = OpenInputFile(name); err != nil {
			return
		}
		var kb []byte
		if kb, err = io.ReadAll(kf); err != nil {
			return
		}
		if err = json.Unmarshal(kb, &kParts[i]); err != nil {
			return
		}
	}
	defer func() {
		for _, kCloseFn := range kCloseFns {
			kCloseFn()
		}
	}()
	return kParts, nil
}
