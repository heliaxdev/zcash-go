package zcash

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxCompactSize is the maximum allowed CompactSize value per Zcash consensus.
const MaxCompactSize uint64 = 0x02000000

// readCompactSize reads a Bitcoin/Zcash CompactSize integer from r, enforcing
// canonical encoding and the MaxCompactSize consensus bound.
func readCompactSize(r io.Reader) (uint64, error) {
	var flag [1]byte
	if _, err := io.ReadFull(r, flag[:]); err != nil {
		return 0, fmt.Errorf("failed to read CompactSize flag byte: %w", err)
	}
	var result uint64
	switch flag[0] {
	case 253:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, fmt.Errorf("failed to read CompactSize u16 body: %w", err)
		}
		n := uint64(binary.LittleEndian.Uint16(b[:]))
		if n < 253 {
			return 0, errors.New("zcash: non-canonical CompactSize (u16 form below 253)")
		}
		result = n
	case 254:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, fmt.Errorf("failed to read CompactSize u32 body: %w", err)
		}
		n := uint64(binary.LittleEndian.Uint32(b[:]))
		if n < 0x10000 {
			return 0, errors.New("zcash: non-canonical CompactSize (u32 form below 0x10000)")
		}
		result = n
	case 255:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, fmt.Errorf("failed to read CompactSize u64 body: %w", err)
		}
		n := binary.LittleEndian.Uint64(b[:])
		if n < 0x100000000 {
			return 0, errors.New("zcash: non-canonical CompactSize (u64 form below 0x100000000)")
		}
		result = n
	default:
		result = uint64(flag[0])
	}
	if result > MaxCompactSize {
		return 0, fmt.Errorf("zcash: CompactSize %d exceeds max %d", result, MaxCompactSize)
	}
	return result, nil
}

// writeCompactSize writes a CompactSize integer to w.
func writeCompactSize(w io.Writer, size uint64) error {
	switch {
	case size < 253:
		_, err := w.Write([]byte{byte(size)})
		return err
	case size <= 0xFFFF:
		var b [3]byte
		b[0] = 253
		binary.LittleEndian.PutUint16(b[1:], uint16(size))
		_, err := w.Write(b[:])
		return err
	case size <= 0xFFFFFFFF:
		var b [5]byte
		b[0] = 254
		binary.LittleEndian.PutUint32(b[1:], uint32(size))
		_, err := w.Write(b[:])
		return err
	default:
		var b [9]byte
		b[0] = 255
		binary.LittleEndian.PutUint64(b[1:], size)
		_, err := w.Write(b[:])
		return err
	}
}

// readU32LE reads a little-endian uint32.
func readU32LE(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("failed to read u32 little-endian: %w", err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// readU64LE reads a little-endian uint64.
func readU64LE(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("failed to read u64 little-endian: %w", err)
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// readI64LE reads a little-endian int64 (used for value balances).
func readI64LE(r io.Reader) (int64, error) {
	u, err := readU64LE(r)
	if err != nil {
		return 0, fmt.Errorf("failed to read i64 little-endian: %w", err)
	}
	return int64(u), nil
}

// readBytes reads exactly n bytes.
func readBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("failed to read %d bytes: %w", n, err)
	}
	return b, nil
}

// readByte reads a single byte.
func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("failed to read single byte: %w", err)
	}
	return b[0], nil
}

// readFixed32 reads a fixed 32-byte array.
func readFixed32(r io.Reader) ([32]byte, error) {
	var a [32]byte
	if _, err := io.ReadFull(r, a[:]); err != nil {
		return a, fmt.Errorf("failed to read 32-byte fixed array: %w", err)
	}
	return a, nil
}

// readFixed64 reads a fixed 64-byte array.
func readFixed64(r io.Reader) ([64]byte, error) {
	var a [64]byte
	if _, err := io.ReadFull(r, a[:]); err != nil {
		return a, fmt.Errorf("failed to read 64-byte fixed array: %w", err)
	}
	return a, nil
}

// readScript reads a CompactSize-prefixed byte slice (used for scriptSig and
// scriptPubKey). Mirrors zcash_transparent::address::Script::read which uses
// Vector<u8>.
func readScript(r io.Reader) ([]byte, error) {
	n, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read script length: %w", err)
	}
	b, err := readBytes(r, int(n))
	if err != nil {
		return nil, fmt.Errorf("failed to read script body (%d bytes): %w", n, err)
	}
	return b, nil
}
