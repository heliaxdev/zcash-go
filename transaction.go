package zcash

import (
	"fmt"
	"io"
)

// Transaction is a parsed Zcash transaction (Sapling+: V4, V5 or V6).
type Transaction struct {
	Version           TxVersion
	ConsensusBranchID BranchId
	LockTime          uint32
	ExpiryHeight      uint32

	Transparent *TransparentBundle
	Sprout      *SproutBundle // only present in v4
	Sapling     *SaplingBundle
	Orchard     *OrchardBundle  // only present in v5/v6
	Ironwood    *IronwoodBundle // only present in v6
}

// Parse reads a Zcash transaction from r. It returns [ErrSkipped] for
// unsupported pre-Sapling transaction versions (Sprout v1/v2, Overwinter V3).
func Parse(r io.Reader) (*Transaction, error) {
	header, err := readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read tx header: %w", err)
	}
	overwintered := (header & overwinteredBit) != 0
	version := header & versionMask

	if !overwintered {
		// Pre-Overwinter Sprout v1/v2: not supported.
		return nil, fmt.Errorf("%w: sprout version %d", ErrSkipped, version)
	}

	vgid, err := readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read tx version_group_id: %w", err)
	}

	switch {
	case version == v3TxVersion && vgid == v3VersionGroupID:
		// Overwinter V3: pre-Sapling, not supported.
		return nil, fmt.Errorf("%w: overwinter v3", ErrSkipped)
	case version == v4TxVersion && vgid == v4VersionGroupID:
		return parseV4(r)
	case version == v5TxVersion && vgid == v5VersionGroupID:
		return parseV5(r)
	case version == v6TxVersion && vgid == v6VersionGroupID:
		return parseV6(r)
	default:
		return nil, fmt.Errorf("%w: unknown version %d group_id 0x%08x", ErrSkipped, version, vgid)
	}
}

func parseV4(r io.Reader) (*Transaction, error) {
	tx := &Transaction{Version: TxVersionV4}

	transparent, err := readTransparent(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v4 transparent bundle: %w", err)
	}
	tx.Transparent = transparent

	tx.LockTime, err = readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v4 lock_time: %w", err)
	}
	tx.ExpiryHeight, err = readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v4 expiry_height: %w", err)
	}

	// consensus_branch_id is not encoded in the v4 body; it is supplied by the
	// caller in the Rust API. For our structural parser we leave it as 0
	// (unknown) since the on-wire format does not commit to it here.
	tx.ConsensusBranchID = BranchId(0)

	// Sapling v4 components.
	sapling, err := readSaplingV4Components(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v4 sapling bundle: %w", err)
	}
	tx.Sapling = sapling

	// Sprout joinsplits (v4 has_sprout == true).
	sprout, err := readSproutBundle(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v4 sprout bundle: %w", err)
	}
	tx.Sprout = sprout

	// binding_sig follows the sprout section and is present iff the sapling
	// bundle has any spends or outputs (mod.rs:873-881).
	if tx.Sapling != nil && (len(tx.Sapling.Spends) > 0 || len(tx.Sapling.Outputs) > 0) {
		tx.Sapling.BindingSig, err = readFixed64(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read v4 sapling binding sig: %w", err)
		}
	}

	return tx, nil
}

func parseV5(r io.Reader) (*Transaction, error) {
	tx := &Transaction{Version: TxVersionV5}

	branchRaw, err := readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v5 consensus_branch_id: %w", err)
	}
	bid, ok := branchIdFromU32(branchRaw)
	if !ok {
		return nil, fmt.Errorf("zcash: invalid consensus branch id 0x%08x", branchRaw)
	}
	tx.ConsensusBranchID = bid

	tx.LockTime, err = readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v5 lock_time: %w", err)
	}
	tx.ExpiryHeight, err = readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v5 expiry_height: %w", err)
	}

	transparent, err := readTransparent(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v5 transparent bundle: %w", err)
	}
	tx.Transparent = transparent

	sapling, err := readSaplingV5Bundle(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v5 sapling bundle: %w", err)
	}
	tx.Sapling = sapling

	orchard, err := readOrchardBundle(r, "orchard v5")
	if err != nil {
		return nil, fmt.Errorf("failed to read v5 orchard bundle: %w", err)
	}
	tx.Orchard = orchard

	return tx, nil
}

func parseV6(r io.Reader) (*Transaction, error) {
	tx := &Transaction{Version: TxVersionV6}

	branchRaw, err := readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 consensus_branch_id: %w", err)
	}
	bid, ok := branchIdFromU32(branchRaw)
	if !ok {
		return nil, fmt.Errorf("zcash: invalid consensus branch id 0x%08x", branchRaw)
	}
	tx.ConsensusBranchID = bid

	tx.LockTime, err = readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 lock_time: %w", err)
	}
	tx.ExpiryHeight, err = readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 expiry_height: %w", err)
	}

	transparent, err := readTransparent(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 transparent bundle: %w", err)
	}
	tx.Transparent = transparent

	sapling, err := readSaplingV5Bundle(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 sapling bundle: %w", err)
	}
	tx.Sapling = sapling

	orchard, err := readOrchardBundle(r, "orchard v6")
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 orchard bundle: %w", err)
	}
	tx.Orchard = orchard

	ironwood, err := readOrchardBundle(r, "ironwood v6")
	if err != nil {
		return nil, fmt.Errorf("failed to read v6 ironwood bundle: %w", err)
	}
	tx.Ironwood = ironwood

	return tx, nil
}
