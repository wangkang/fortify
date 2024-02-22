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
		if kb, err := readKeyFile(args); err != nil {
			return nil, err
		} else {
			return fortifier.NewFortifierWithRsa(meta, kb), nil
		}
	default:
		return nil, fmt.Errorf("unknown cipher key kind: %s", kind)
	}
}

func readKeyFile(args []string) (kb []byte, err error) {
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
	if kb, err = io.ReadAll(kf); err != nil {
		return
	}
	return
}

func decodePemFile(kb []byte) (blocks []pem.Block, err error) {
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
