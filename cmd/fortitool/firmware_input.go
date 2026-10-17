package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/mosajjal/fortitool/internal/l1"
	"github.com/mosajjal/fortitool/internal/qcow2"
)

const maxZIPDiskSize = 2 << 30

func decodeFirmwareContainer(raw []byte) ([]byte, string, error) {
	if bytes.HasPrefix(raw, []byte("PK\x03\x04")) || bytes.HasPrefix(raw, []byte("PK\x05\x06")) {
		image, err := decodeZIPDisk(raw, maxZIPDiskSize)
		return image, "zip", err
	}
	image, gzip, err := decodeOuter(raw)
	if gzip {
		return image, "gzip", err
	}
	return image, "none", err
}

func decodeZIPDisk(raw []byte, maxSize int64) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	if len(zr.File) != 1 || !zr.File[0].Mode().IsRegular() {
		return nil, fmt.Errorf("zip: expected exactly one regular QCOW2 disk")
	}
	member := zr.File[0]
	if member.Flags&1 != 0 {
		return nil, fmt.Errorf("zip: encrypted members are unsupported")
	}
	if maxSize <= 0 || member.UncompressedSize64 > uint64(maxSize) {
		return nil, fmt.Errorf("zip: disk exceeds %d byte limit", maxSize)
	}
	r, err := member.Open()
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	defer r.Close()
	image, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	if int64(len(image)) > maxSize {
		return nil, fmt.Errorf("zip: disk exceeds %d byte limit", maxSize)
	}
	if !qcow2.IsQCow2(image) {
		return nil, fmt.Errorf("zip: member is not a QCOW2 disk")
	}
	return image, nil
}

type firmwareLayer struct {
	Image    []byte
	Key      []byte
	State    string
	Identity string
}

func decodeFirmwareLayer(ctx context.Context, image []byte) (*firmwareLayer, error) {
	// Installation disks need no L1 header, but cleartext .out disks can
	// carry one. Preserve its identity when present.
	if qcow2.IsQCow2(image) {
		layer := &firmwareLayer{Image: image, State: "not applicable", Identity: "unknown"}
		if header, ok := l1.FindHeader(image); ok {
			layer.State, layer.Identity = "cleartext", header.Identity
		}
		return layer, nil
	}
	plain, key, encrypted, ok := l1.DecryptAuto(ctx, image)
	if !ok {
		return nil, fmt.Errorf("no valid L1 header or key found")
	}
	header, ok := l1.FindHeader(plain)
	if !ok {
		return nil, fmt.Errorf("decoded image has no validated L1 header")
	}
	state := "cleartext"
	if encrypted {
		state = "encrypted"
	}
	return &firmwareLayer{Image: plain, Key: key, State: state, Identity: header.Identity}, nil
}
