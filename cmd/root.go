package cmd

import (
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
	"github.com/struqt/fortify/fortifier"
	"github.com/struqt/fortify/sss"
)

var root = &cobra.Command{Use: "fortify"}

func newFortifier(kind fortifier.CipherKeyKind, meta *fortifier.Metadata, args []string) (*fortifier.Fortifier, error) {
	switch kind {
	case fortifier.CipherKeyKindSSS:
		if parts, err := sss.CombineKeyFiles(args); err != nil {
			return nil, err
		} else {
			return fortifier.NewFortifierWithSss(parts), nil
		}
	case fortifier.CipherKeyKindRSA:
		if blocks, err := decodePemFile(args); err != nil {
			return nil, err
		} else {
			if 0 == len(blocks) {
				return nil, fmt.Errorf("not a pem formatted file: %s", args)
			}
			return fortifier.NewFortifierWithRsa(meta, blocks), nil
		}
	default:
		return nil, fmt.Errorf("unknown cipher key kind: %s", kind)
	}
}

func decodePemFile(args []string) (blocks []pem.Block, err error) {
	size := len(args)
	if size == 0 {
		return
	}
	var kCloseFn func()
	var kf *os.File
	if kf, kCloseFn, err = files.OpenInputFile(args[0]); err != nil {
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
