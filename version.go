// Package zcash parses Zcash transactions (Sapling+ versions: V4 and V5).
//
// Pre-Sapling transaction versions (Sprout v1/v2 and Overwinter V3) are not
// supported and return ErrSkipped.
package zcash

import "errors"

// ErrSkipped is returned by Parse when the transaction version is not supported
// by this parser (i.e. pre-Sapling Sprout v1/v2 and Overwinter V3).
var ErrSkipped = errors.New("zcash: unsupported transaction version (pre-Sapling)")

// Version identifiers for a Zcash transaction.
type TxVersion int

const (
	// TxVersionSprout covers pre-Overwinter versions 1 and 2. Not supported.
	TxVersionSprout TxVersion = iota
	TxVersionV3               // Overwinter. Not supported.
	TxVersionV4               // Sapling .. Nu6.2
	TxVersionV5               // NU5 .. Nu6.2 (and beyond)
)

// Header / version_group_id constants (see zcash_protocol constants.rs).
const (
	v3TxVersion      uint32 = 3
	v3VersionGroupID uint32 = 0x03C48270
	v4TxVersion      uint32 = 4
	v4VersionGroupID uint32 = 0x892F2085
	v5TxVersion      uint32 = 5
	v5VersionGroupID uint32 = 0x26A7270A
	overwinteredBit  uint32 = 1 << 31
	versionMask      uint32 = 0x7FFFFFFF
)

// BranchId is the Zcash consensus branch id.
type BranchId uint32

// Known consensus branch ids (consensus.rs:744-766).
const (
	BranchIdSprout     BranchId = 0
	BranchIdOverwinter BranchId = 0x5BA81B19
	BranchIdSapling    BranchId = 0x76B809BB
	BranchIdBlossom    BranchId = 0x2BB40E60
	BranchIdHeartwood  BranchId = 0xF5B9230B
	BranchIdCanopy     BranchId = 0xE9FF75A6
	BranchIdNu5        BranchId = 0xC2D6D0B4
	BranchIdNu6        BranchId = 0xC8E71055
	BranchIdNu61       BranchId = 0x4DEC4DF0
	BranchIdNu62       BranchId = 0x5437F330
)

// branchIdFromU32 maps the on-wire u32 to a BranchId, returning false if unknown.
func branchIdFromU32(v uint32) (BranchId, bool) {
	switch v {
	case 0:
		return BranchIdSprout, true
	case 0x5BA81B19:
		return BranchIdOverwinter, true
	case 0x76B809BB:
		return BranchIdSapling, true
	case 0x2BB40E60:
		return BranchIdBlossom, true
	case 0xF5B9230B:
		return BranchIdHeartwood, true
	case 0xE9FF75A6:
		return BranchIdCanopy, true
	case 0xC2D6D0B4:
		return BranchIdNu5, true
	case 0xC8E71055:
		return BranchIdNu6, true
	case 0x4DEC4DF0:
		return BranchIdNu61, true
	case 0x5437F330:
		return BranchIdNu62, true
	default:
		return 0, false
	}
}
