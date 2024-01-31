package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/shamir"
)

func init() {
	random := &cobra.Command{Use: "random", Run: sssRandomCmd, Short: "Split a random byte array into secret shares"}
	random.Flags().Uint8P("parts", "p", 5, "Count of secret shares to split into")
	random.Flags().Uint8P("threshold", "t", 3, "Minimum secret share count for secret recovery")
	random.Flags().Uint16P("bytes", "b", 32, "Length of random byte array")

	split := &cobra.Command{Use: "split", Run: sssSplitCmd, Short: "Split a secret to several shares"}
	split.Flags().Uint8P("parts", "p", 5, "Total part count to split")
	split.Flags().Uint8P("threshold", "t", 3, "Minimum part count to recover the secret")
	split.Flags().StringP("file", "f", "", "File that contains the secret")

	combine := &cobra.Command{Use: "combine", Run: sssCombineCmd, Short: "Combine secret shares to recover the secret"}
	combine.Flags().StringSliceP("files", "f", nil, "JSON format files and each file contains one secret share")

	sss := &cobra.Command{Use: "sss", Short: "Shamir's secret sharing"}
	sss.AddCommand(random, split, combine)
	root.AddCommand(sss)
}

type sssPart struct {
	Payload   string    `json:"payload"`
	Threshold uint8     `json:"threshold"`
	Parts     uint8     `json:"parts"`
	Part      int       `json:"part"`
	Timestamp time.Time `json:"timestamp"`
	Digest    string    `json:"digest"`
	file      string
}

func sssRandomCmd(c *cobra.Command, _ []string) {
	bs, err := c.Flags().GetUint16("bytes")
	if err != nil || bs <= 0 {
		bs = 32
	}
	secret := make([]byte, bs)
	_, err = rand.Reader.Read(secret)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	parts, threshold := sssSplitArgs(c)
	sssSplitIntoFiles(secret, parts, threshold)
}

func sssSplitCmd(c *cobra.Command, _ []string) {
	file, err := c.Flags().GetString("file")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	file = strings.TrimSpace(file)
	if len(file) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", "No file specified")
		return
	}
	secret, path, err := sssReadFile(file)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	secret = bytes.TrimSpace(secret)
	fmt.Printf("Read %d byte(s) from %s\n", len(secret), path)
	parts, threshold := sssSplitArgs(c)
	sssSplitIntoFiles(secret, parts, threshold)
}

func sssCombineCmd(cmd *cobra.Command, _ []string) {
	var err error
	var files []string
	var parts []sssPart
	var secret []byte
	if files, err = cmd.Flags().GetStringSlice("files"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	if parts, err = sssReadPartFiles(files); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	for _, i := range parts {
		fmt.Printf("Part %d/%d: %s\n", i.Part, i.Parts, i.file)
	}
	if secret, err = sssCombine(parts); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	expect := parts[0].Digest
	actual := sssDigest(secret)
	fmt.Printf("Expect Secret Digest: %s\n", expect)
	fmt.Printf("Actual Secret Digest: %s\n", actual)
	if expect != actual {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", "Secret digest mismatch")
		return
	}
	fmt.Printf("OK\n")
}

func sssReadPartFiles(files []string) ([]sssPart, error) {
	parts := make([]sssPart, len(files))
	for i, file := range files {
		if content, _, err := sssReadFile(file); err != nil {
			return parts, err
		} else {
			if err = json.Unmarshal(content, &parts[i]); err != nil {
				return parts, err
			}
		}
		parts[i].file = file
	}
	return parts, nil
}

func sssReadFile(file string) ([]byte, string, error) {
	path, err := filepath.Abs(file)
	if err != nil {
		return nil, path, err
	}
	var stat os.FileInfo
	stat, err = os.Stat(path)
	if err != nil {
		return nil, path, err
	}
	if stat.IsDir() {
		return nil, path, errors.New("not a file")
	}
	var content []byte
	if content, err = os.ReadFile(file); err != nil {
		return nil, path, err
	}
	return content, path, nil
}

func sssSplitIntoFiles(secret []byte, parts, threshold uint8) {
	digest := sssDigest(secret)
	ps, err := sssSplit(secret, digest, parts, threshold)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	for i, p := range ps {
		fileName := fmt.Sprintf("sss_%d_%d.json", p.Parts, p.Part)
		var content []byte
		content, err = json.Marshal(p)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding for file %s: %v\n", fileName, err)
			return
		}
		err = os.WriteFile(fileName, content, 0600)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error writing to file %s: %v\n", fileName, err)
			return
		}
		fmt.Printf("Part %d/%d: %s\n", i+1, parts, fileName)
	}
	fmt.Printf("Secret Digest: %s\n", digest)
	fmt.Printf("OK\n")
}

func sssDigest(secret []byte) string {
	sha := sha512.New()
	sha.Write(secret)
	digest := base64.URLEncoding.EncodeToString(sha.Sum(nil))
	return digest
}

func sssSplit(secret []byte, digest string, parts, threshold uint8) ([]sssPart, error) {
	var err error
	var out [][]byte
	var outParts []sssPart
	out, err = shamir.Split(secret, int(parts), int(threshold))
	if err != nil {
		return outParts, err
	}
	for index, i := range out {
		p := sssPart{
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

func sssSplitArgs(c *cobra.Command) (parts, threshold uint8) {
	var err error
	parts, err = c.Flags().GetUint8("parts")
	if err != nil || parts <= 0 {
		parts = 5
	}
	threshold, err = c.Flags().GetUint8("threshold")
	if err != nil || threshold <= 0 {
		threshold = 3
	}
	return
}

func sssCombine(parts []sssPart) ([]byte, error) {
	var err error
	var shares [][]byte
	var secret []byte
	if shares, err = sssCollectSecretShares(parts); err != nil {
		return secret, err
	}
	if secret, err = shamir.Combine(shares); err != nil {
		return secret, err
	}
	return secret, nil
}

func sssCollectSecretShares(parts []sssPart) ([][]byte, error) {
	var expect string
	shares := make([][]byte, len(parts))
	for index, i := range parts {
		if share, err := base64.URLEncoding.DecodeString(i.Payload); err != nil {
			return shares, err
		} else {
			shares[index] = share
			if len(expect) == 0 {
				expect = i.Digest
			} else {
				if expect != i.Digest {
					return shares, errors.New("secret digest mismatch")
				}
			}
		}
	}
	return shares, nil
}
