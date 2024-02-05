package files

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/struqt/fortify/fortifier"
	"github.com/struqt/fortify/sss"
)

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

func NewFortifier(kind fortifier.CipherKeyKind, args []string) (f *fortifier.Fortifier, err error) {
	switch kind {
	case fortifier.CipherKeyKindSSS:
		var parts []sss.Part
		if parts, err = SssCombineKeyFiles(args); err != nil {
			return
		}
		f = fortifier.NewFortifierWithSss(parts)
	case fortifier.CipherKeyKindEd25519:
		err = fmt.Errorf("todo cipher key kind: %s", kind)
		return
	case fortifier.CipherKeyKindRSA:
		err = fmt.Errorf("todo cipher key kind: %s", kind)
		return
	default:
		err = fmt.Errorf("unknown cipher key kind: %s", kind)
		return
	}
	return
}
