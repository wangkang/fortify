package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
	"github.com/struqt/fortify/fortifier"
)

var root = &cobra.Command{Use: "fortify"}

func newFortifier(kind fortifier.CipherKeyKind, meta *fortifier.Metadata, args []string) (*fortifier.Fortifier, error) {
	switch kind {
	case fortifier.CipherKeyKindSSS:
		if parts, err := files.SssCombineKeyFiles(args); err != nil {
			return nil, err
		} else {
			return fortifier.NewFortifierWithSss(parts), nil
		}
	case fortifier.CipherKeyKindRSA:
		if blocks, err := files.PemDecodeFile(args); err != nil {
			return nil, err
		} else {
			return fortifier.NewFortifierWithRsa(meta, blocks), nil
		}
	case fortifier.CipherKeyKindEd25519:
		if blocks, err := files.PemDecodeFile(args); err != nil {
			return nil, err
		} else {
			return fortifier.NewFortifierWithEd25519(meta, blocks), nil
		}
	default:
		return nil, fmt.Errorf("unknown cipher key kind: %s", kind)
	}
}
