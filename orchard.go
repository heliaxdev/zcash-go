package zcash

import (
	"fmt"
	"io"
)

// OrchardAction is an Orchard action description.
type OrchardAction struct {
	CvNet         [32]byte
	Nullifier     [32]byte
	Rk            [32]byte
	Cmx           [32]byte
	EphemeralKey  [32]byte
	EncCiphertext [EncCiphertextSize]byte
	OutCiphertext [OutCiphertextSize]byte
	SpendAuthSig  [64]byte
}

// OrchardBundle is the Orchard shielded bundle.
type OrchardBundle struct {
	Actions      []OrchardAction
	Flags        byte
	ValueBalance int64
	Anchor       [32]byte
	Proof        []byte
	BindingSig   [64]byte
}

// IronwoodAction is an Ironwood action description. The Ironwood pool (ZIP 229)
// reuses the Orchard action encoding unchanged.
type IronwoodAction = OrchardAction

// IronwoodBundle is the Ironwood shielded bundle. The Ironwood pool (ZIP 229)
// reuses the Orchard bundle encoding unchanged.
type IronwoodBundle = OrchardBundle

// readOrchardBundle reads an Orchard-protocol bundle (Orchard or Ironwood pool,
// whose wire encodings are identical). label identifies the pool and transaction
// version (e.g. "orchard v5", "ironwood v6") and is used in error messages.
// Returns nil when no actions are present.
func readOrchardBundle(r io.Reader, label string) (*OrchardBundle, error) {
	nActions, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s actions count: %w", label, err)
	}
	if nActions == 0 {
		return nil, nil
	}

	actions := make([]OrchardAction, nActions)
	for i := range actions {
		a := &actions[i]
		a.CvNet, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s action[%d] cv_net: %w", label, i, err)
		}
		a.Nullifier, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s action[%d] nullifier: %w", label, i, err)
		}
		a.Rk, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s action[%d] rk: %w", label, i, err)
		}
		a.Cmx, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s action[%d] cmx: %w", label, i, err)
		}
		a.EphemeralKey, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s action[%d] ephemeral key: %w", label, i, err)
		}
		if _, err = io.ReadFull(r, a.EncCiphertext[:]); err != nil {
			return nil, fmt.Errorf(
				"failed to read %s action[%d] enc_ciphertext: %w",
				label,
				i,
				err,
			)
		}
		if _, err = io.ReadFull(r, a.OutCiphertext[:]); err != nil {
			return nil, fmt.Errorf(
				"failed to read %s action[%d] out_ciphertext: %w",
				label,
				i,
				err,
			)
		}
	}

	var bundle OrchardBundle
	bundle.Flags, err = readByte(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s flags: %w", label, err)
	}
	bundle.ValueBalance, err = readI64LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s value_balance: %w", label, err)
	}
	bundle.Anchor, err = readFixed32(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s anchor: %w", label, err)
	}

	proofCount, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s proof length: %w", label, err)
	}
	bundle.Proof = make([]byte, proofCount)
	if _, err = io.ReadFull(r, bundle.Proof); err != nil {
		return nil, fmt.Errorf(
			"failed to read %s proof body (%d bytes): %w",
			label,
			proofCount,
			err,
		)
	}

	for i := range actions {
		actions[i].SpendAuthSig, err = readFixed64(r)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to read %s action[%d] spend auth sig: %w",
				label,
				i,
				err,
			)
		}
	}
	bundle.Actions = actions

	bundle.BindingSig, err = readFixed64(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s binding sig: %w", label, err)
	}
	return &bundle, nil
}
