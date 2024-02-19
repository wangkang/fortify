package sss

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/struqt/fortify/shamir"
	"github.com/struqt/fortify/utils"
)

func Split(secret []byte, parts, threshold uint8) ([]Part, error) {
	var err error
	var out [][]byte
	var outParts []Part
	out, err = shamir.Split(secret, int(parts), int(threshold))
	if err != nil {
		return outParts, err
	}
	digest := utils.ComputeDigest(secret)
	for index, i := range out {
		p := Part{
			Parts:     parts,
			Part:      index + 1,
			Payload:   base64.URLEncoding.EncodeToString(i),
			Timestamp: time.Now(),
			Threshold: threshold,
			Digest:    digest,
		}
		outParts = append(outParts, p)
	}
	return outParts, nil
}

func SplitIntoFiles(f string, parts, threshold uint8, prefix string) error {
	path, err := filepath.Abs(f)
	if err != nil {
		return err
	}
	var stat os.FileInfo
	if stat, err = os.Stat(path); err != nil {
		return err
	}
	if stat.IsDir() {
		return errors.New("not a file")
	}
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	blocks := int(math.Ceil(float64(stat.Size()) / float64(fileBlockSize)))
	reader := bufio.NewReader(file)
	buffer := make([]byte, fileBlockSize)
	var bytesRead, block int
	var ps []Part
	for {
		bytesRead, err = reader.Read(buffer)
		if err != nil {
			return err
		}
		secret := buffer[:bytesRead]
		ps, err = Split(secret, parts, threshold)
		if err != nil {
			return err
		}
		err = AppendParts(ps, block, blocks, prefix)
		if err != nil {
			return err
		}
		block++
		if bytesRead < fileBlockSize {
			break
		}
	}
	return nil
}

func AppendParts(ps []Part, block, blocks int, prefix string) error {
	size := len(ps)
	var wg sync.WaitGroup
	wg.Add(size)
	errCh := make(chan error, len(ps))
	for i, p := range ps {
		{
			path := fmt.Sprintf("%s_%d_%d.json", prefix, p.Parts, p.Part)
			file := OpenFileForWrite(path)
			if file == nil {
				return fmt.Errorf("can not open file: %s", path)
			}
			ps[i].file = file
			ps[i].Block = block + 1
			ps[i].Blocks = blocks
		}
		go func(wg *sync.WaitGroup, p Part) {
			defer wg.Done()
			if err := appendPart(&p, block); err != nil {
				errCh <- err
				return
			}
			//fmt.Printf("Part %d/%d: %s\n", p.Part, p.Parts, p.file.Name())
		}(&wg, ps[i])
	}
	go func() {
		wg.Wait()
		close(errCh)
	}()
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	w := len(fmt.Sprintf("%d", blocks))
	fmt.Printf("Block %*d/%d OK\n", w, block+1, blocks)
	return nil
}

func appendPart(p *Part, block int) (err error) {
	file := p.file
	if block == 0 {
		if err = file.Truncate(0); err != nil {
			return
		}
	}
	var content []byte
	content, err = json.Marshal(p)
	if err != nil {
		return
	}
	if block > 0 {
		_, err = file.WriteString("\n\n")
		if err != nil {
			return
		}
	}
	_, err = file.Write(content)
	if err != nil {
		return
	}
	return nil
}

var openedFilesForWrite = make(map[string]*os.File)
var openedFilesForWriteLock sync.Mutex

func OpenFileForWrite(path string) *os.File {
	openedFilesForWriteLock.Lock()
	defer openedFilesForWriteLock.Unlock()
	var err error
	if path, err = filepath.Abs(path); err != nil {
		return nil
	}
	file := openedFilesForWrite[path]
	if file != nil {
		return file
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return nil
	}
	fmt.Printf("Open: %v\n", path)
	openedFilesForWrite[path] = file
	return file
}

func CloseAllFilesForWrite() {
	openedFilesForWriteLock.Lock()
	defer openedFilesForWriteLock.Unlock()
	for k, file := range openedFilesForWrite {
		_ = file.Sync()
		_ = file.Close()
		openedFilesForWrite[k] = nil
		fmt.Printf("Close: %s\n", file.Name())
	}
	clear(openedFilesForWrite)
}
