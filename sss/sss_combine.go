package sss

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/struqt/fortify/shamir"
	"github.com/struqt/fortify/utils"
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

func CombinePartFiles(in []string, out string, truncate bool) error {
	size := len(in)
	if size == 0 {
		return nil
	}

	var output *os.File = nil
	if len(out) > 0 {
		var err error
		if out, err = filepath.Abs(out); err != nil {
			return err
		}
		if output, err = os.OpenFile(out, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600); err != nil {
			return err
		}
		fmt.Printf("Open output file: %s\n", out)
	}
	defer func() {
		if output != nil {
			_ = output.Sync()
			_ = output.Close()
			fmt.Printf("Close output file: %s\n", output.Name())
		}
	}()
	inputs := make([]*os.File, size)
	for i, path := range in {
		var err error
		if path, err = filepath.Abs(path); err != nil {
			return err
		}
		var file *os.File
		if file, err = os.OpenFile(path, os.O_RDONLY, 0400); err != nil {
			return err
		}
		inputs[i] = file
		fmt.Printf("Open file: %v\n", path)
	}
	defer func() {
		for _, file := range inputs {
			_ = file.Close()
			fmt.Printf("Close file: %s\n", file.Name())
		}
	}()

	scanners := make([]*bufio.Scanner, size)
	for i, file := range inputs {
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
		if count == 0 {
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
		l := len(secret)
		w := len(fmt.Sprintf("%d", blocks))
		if output != nil {
			fmt.Printf("Block %*d/%d OK -- recovered %d bytes and appended them into %s\n", w, block, blocks, l, out)
		} else {
			fmt.Printf("Block %*d/%d OK -- recovered %d bytes\n", w, block, blocks, l)
		}
	}
	return nil
}
