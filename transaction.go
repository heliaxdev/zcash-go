package zcash

import (
	"fmt"
	"io"
)

// Transaction is a parsed Zcash transaction (Sapling+: V4 or V5).
type Transaction struct {
	Version           TxVersion
	ConsensusBranchID BranchId
	LockTime          uint32
	ExpiryHeight      uint32

	Transparent *TransparentBundle
	Sprout      *SproutBundle      // only present in v4
	Sapling     *SaplingBundle
	Orchard     *OrchardBundle     // only present in v5
}

// Parse reads a Zcash transaction from r. It returns [ErrSkipped] for
// unsupported pre-Sapling transaction versions (Sprout v1/v2, Overwinter V3).
func Parse(r io.Reader) (*Transaction, error) {
	header, err := readU32LE(r)
	if err != nil {
		return nil, err
	}
	overwintered := (header & overwinteredBit) != 0
	version := header & versionMask

	if !overwintered {
		// Pre-Overwinter Sprout v1/v2: not supported.
		return nil, fmt.Errorf("%w: sprout version %d", ErrSkipped, version)
	}

	vgid, err := readU32LE(r)
	if err != nil {
		return nil, err
	}

	switch {
	case version == v3TxVersion && vgid == v3VersionGroupID:
		// Overwinter V3: pre-Sapling, not supported.
		return nil, fmt.Errorf("%w: overwinter v3", ErrSkipped)
	case version == v4TxVersion && vgid == v4VersionGroupID:
		return parseV4(r)
	case version == v5TxVersion && vgid == v5VersionGroupID:
		return parseV5(r)
	default:
		return nil, fmt.Errorf("%w: unknown version %d group_id 0x%08x", ErrSkipped, version, vgid)
	}
}

func parseV4(r io.Reader) (*Transaction, error) {
	tx := &Transaction{Version: TxVersionV4}

	transparent, err := readTransparent(r)
	if err != nil {
		return nil, err
	}
	tx.Transparent = transparent

	tx.LockTime, err = readU32LE(r)
	if err != nil {
		return nil, err
	}
	tx.ExpiryHeight, err = readU32LE(r)
	if err != nil {
		return nil, err
	}

	// consensus_branch_id is not encoded in the v4 body; it is supplied by the
	// caller in the Rust API. For our structural parser we leave it as 0
	// (unknown) since the on-wire format does not commit to it here.
	tx.ConsensusBranchID = BranchId(0)

	// Sapling v4 components.
	sapling, err := readSaplingV4Components(r)
	if err != nil {
		return nil, err
	}
	tx.Sapling = sapling

	// Sprout joinsplits (v4 has_sprout == true).
	sprout, err := readSproutBundle(r)
	if err != nil {
		return nil, err
	}
	tx.Sprout = sprout

	return tx, nil
}

func parseV5(r io.Reader) (*Transaction, error) {
	tx := &Transaction{Version: TxVersionV5}

	branchRaw, err := readU32LE(r)
	if err != nil {
		return nil, err
	}
	bid, ok := branchIdFromU32(branchRaw)
	if !ok {
		return nil, fmt.Errorf("zcash: invalid consensus branch id 0x%08x", branchRaw)
	}
	tx.ConsensusBranchID = bid

	tx.LockTime, err = readU32LE(r)
	if err != nil {
		return nil, err
	}
	tx.ExpiryHeight, err = readU32LE(r)
	if err != nil {
		return nil, err
	}

	transparent, err := readTransparent(r)
	if err != nil {
		return nil, err
	}
	tx.Transparent = transparent

	sapling, err := readSaplingV5Bundle(r)
	if err != nil {
		return nil, err
	}
	tx.Sapling = sapling

	orchard, err := readOrchardV5Bundle(r)
	if err != nil {
		return nil, err
	}
	tx.Orchard = orchard

	return tx, nil
}
