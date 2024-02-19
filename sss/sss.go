package sss

import (
	"os"
	"time"
)

const fileBlockSize = 512 * 1024
const maxScannerTokenSize = 768 * 1024

type Part struct {
	Payload   string    `json:"payload"`
	Block     int       `json:"block"`
	Blocks    int       `json:"blocks"`
	Part      int       `json:"part"`
	Parts     uint8     `json:"parts"`
	Threshold uint8     `json:"threshold"`
	Digest    string    `json:"digest"`
	Timestamp time.Time `json:"timestamp"`
	file      *os.File
}
