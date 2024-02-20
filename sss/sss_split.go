package sss

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/struqt/fortify/files"
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

func SplitIntoFiles(in string, parts, threshold uint8, prefix string) error {
	file, closer, err := files.OpenInputFile(in)
	if err != nil {
		return err
	}
	defer closer()
	var stat os.FileInfo
	if stat, err = file.Stat(); err != nil {
		return err
	}
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
var openedFilesForWriteCloser = make(map[string]func())
var openedFilesForWriteLock sync.Mutex

func OpenFileForWrite(path string) *os.File {
	openedFilesForWriteLock.Lock()
	defer openedFilesForWriteLock.Unlock()
	file, _ := openedFilesForWrite[path]
	if file != nil {
		return file
	}
	var err error
	var closer func()
	if file, closer, err = files.OpenOutputFile(path, true); err != nil {
		return nil
	}
	openedFilesForWrite[path] = file
	openedFilesForWriteCloser[path] = closer
	return file
}

func CloseAllFilesForWrite() {
	openedFilesForWriteLock.Lock()
	defer openedFilesForWriteLock.Unlock()
	for _, closer := range openedFilesForWriteCloser {
		closer()
	}
	clear(openedFilesForWrite)
	clear(openedFilesForWriteCloser)
}
