package sss

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/wangkang/fortify/files"
	"github.com/wangkang/fortify/shamir"
	"github.com/wangkang/fortify/utils"
)

func Combine(parts []Part) ([]byte, error) {
	var (
		secret []byte
		expect string
	)
	shares := make([][]byte, len(parts))
	for index, i := range parts {
		if share, err := base64.URLEncoding.DecodeString(i.Payload); err != nil {
			return secret, err
		} else {
			shares[index] = share
			if len(expect) == 0 {
				expect = i.Digest
			} else {
				if expect != i.Digest {
					fmt.Printf("Expect secret digest: %s\n", expect)
					fmt.Printf("Actual secret digest: %s\n", i.Digest)
					return secret, fmt.Errorf("secret digest mismatch in file %v", index+1)
				}
			}
		}
	}
	var err error
	if secret, err = shamir.Combine(shares); err != nil {
		return secret, err
	}
	return secret, nil
}

func CombineKeyFiles(args []string) (parts []Part, err error) {
	size := len(args)
	if size == 0 {
		return nil, nil
	}
	kCloseFns := make([]func(), size)
	kParts := make([]Part, size)
	count := 0
	for i, name := range args {
		var kf *os.File
		if kf, kCloseFns[i], err = files.OpenInputFile(name); err != nil {
			break
		}
		count++
		var kb []byte
		if kb, err = io.ReadAll(kf); err != nil {
			return
		}
		if err = json.Unmarshal(kb, &kParts[i]); err != nil {
			err = fmt.Errorf("not a valid sss key part\nCaused by: %v", err)
			return
		}
	}
	kCloseFns = kCloseFns[:count]
	defer func() {
		for _, kCloseFn := range kCloseFns {
			kCloseFn()
		}
	}()
	return kParts[:count], nil
}

func CombinePartFiles(in []string, out string, truncate, verbose bool) error {
	size := len(in)
	if size == 0 {
		return errors.New("no input files")
	}
	var output *os.File = nil
	var oCloseFn func()
	if len(out) > 0 {
		var err error
		if output, oCloseFn, err = files.OpenOutputFile(out, truncate); err != nil {
			return err
		}
	}
	defer oCloseFn()
	iFiles := make([]*os.File, size)
	iCloseFn := make([]func(), size)
	for i, path := range in {
		var err error
		if iFiles[i], iCloseFn[i], err = files.OpenInputFile(path); err != nil {
			return err
		}
	}
	defer func() {
		for _, closer := range iCloseFn {
			closer()
		}
		clear(iCloseFn)
		clear(iFiles)
	}()
	scanners := make([]*bufio.Scanner, size)
	for i, file := range iFiles {
		buf := make([]byte, maxScannerTokenSize)
		scanners[i] = bufio.NewScanner(file)
		scanners[i].Buffer(buf, maxScannerTokenSize)
		scanners[i].Split(bufio.ScanLines)
	}

	parts := make([]Part, size)
	count := 0
	for {
		var err error
		var lines [][]byte
		for _, scanner := range scanners {
			if scanner.Scan() {
				line := scanner.Bytes()
				lines = append(lines, line)
			}
			if err = scanner.Err(); err != nil {
				return err
			}
		}
		if len(lines) != size {
			break
		}
		if len(lines[0]) == 0 {
			continue
		}
		for i, line := range lines {
			if err := json.Unmarshal(line, &parts[i]); err != nil {
				return err
			}
		}
		threshold := parts[0].Threshold
		if len(parts) < int(threshold) {
			return errors.New(fmt.Sprintf("need %d input files", threshold))
		}
		block := parts[0].Block
		blocks := parts[0].Blocks
		if block != count+1 {
			return errors.New("block mismatch")
		}
		var secret []byte
		if secret, err = Combine(parts); err != nil {
			return err
		}
		expect := parts[0].Digest
		actual := utils.ComputeDigest(secret)
		if expect != actual {
			fmt.Printf("Expect secret digest: %s\n", expect)
			fmt.Printf("Actual secret digest: %s\n", actual)
			return errors.New("secret digest mismatch")
		}
		if count == 0 && verbose {
			fmt.Printf("Blocks count: %d\n", blocks)
		}
		if count == 0 && output != nil {
			var stat os.FileInfo
			if stat, err = output.Stat(); err != nil {
				return err
			}
			if stat.Size() > 0 {
				if truncate {
					if err = output.Truncate(0); err != nil {
						return err
					}
					fmt.Printf("Truncate output file: %s\n", out)
				} else {
					return errors.New("output file is not empty")
				}
			}
			if _, err = output.Write(secret); err != nil {
				return err
			}
		}
		count++
		if verbose {
			l := len(secret)
			w := len(fmt.Sprintf("%d", blocks))
			if output != nil {
				fmt.Printf("Block %*d/%d OK -- recovered %d bytes and appended them into %s\n", w, block, blocks, l, out)
			} else {
				fmt.Printf("Block %*d/%d OK -- recovered %d bytes\n", w, block, blocks, l)
			}
		}
	}
	return nil
}
