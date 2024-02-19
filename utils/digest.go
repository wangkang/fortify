package utils

import (
	"crypto/sha512"
	"encoding/base64"
)

// ComputeDigest computes the digest of a byte slice.
func ComputeDigest(slice []byte) string {
	sha := sha512.New()
	sha.Write(slice)
	digest := base64.URLEncoding.EncodeToString(sha.Sum(nil))
	return digest
}
