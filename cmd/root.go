package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/wangkang/fortify/files"
	"github.com/wangkang/fortify/fortifier"
	"github.com/wangkang/fortify/sss"
)

var root = &cobra.Command{Use: "fortify", Short: "Enhance file security through encryption"}
var ssss = &cobra.Command{Use: "sss", Short: "Shamir's secret sharing"}

func init() {
	root.AddCommand(ssss)
}

func newFortifier(
	kind fortifier.CipherKeyKind, meta *fortifier.Metadata, args []string,
) (*fortifier.Fortifier, []string, error) {
	switch kind {
	case fortifier.CipherKeyKindSSS:
		if parts, err := sss.CombineKeyFiles(args); err != nil {
			return nil, args, err
		} else {
			return fortifier.NewFortifierWithSss(flagVerbose, flagTruncate, parts), args[len(parts):], nil
		}
	case fortifier.CipherKeyKindRSA:
		if kb, err := readKeyFile(args); err != nil {
			return nil, args, err
		} else {
			return fortifier.NewFortifierWithRsa(flagVerbose, meta, kb), args[1:], nil
		}
	default:
		return nil, args, fmt.Errorf("unknown cipher key kind: %s", kind)
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
