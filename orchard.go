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
	Actions       []OrchardAction
	Flags         byte
	ValueBalance  int64
	Anchor        [32]byte
	Proof         []byte
	BindingSig    [64]byte
}

// readOrchardV5Bundle reads an Orchard bundle in the v5 transaction format.
// Returns nil when no actions are present.
func readOrchardV5Bundle(r io.Reader) (*OrchardBundle, error) {
	nActions, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 actions count: %w", err)
	}
	if nActions == 0 {
		return nil, nil
	}

	actions := make([]OrchardAction, nActions)
	for i := range actions {
		a := &actions[i]
		a.CvNet, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] cv_net: %w", i, err)
		}
		a.Nullifier, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] nullifier: %w", i, err)
		}
		a.Rk, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] rk: %w", i, err)
		}
		a.Cmx, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] cmx: %w", i, err)
		}
		a.EphemeralKey, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] ephemeral key: %w", i, err)
		}
		if _, err = io.ReadFull(r, a.EncCiphertext[:]); err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] enc_ciphertext: %w", i, err)
		}
		if _, err = io.ReadFull(r, a.OutCiphertext[:]); err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] out_ciphertext: %w", i, err)
		}
	}

	var bundle OrchardBundle
	bundle.Flags, err = readByte(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 flags: %w", err)
	}
	bundle.ValueBalance, err = readI64LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 value_balance: %w", err)
	}
	bundle.Anchor, err = readFixed32(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 anchor: %w", err)
	}

	proofCount, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 proof length: %w", err)
	}
	bundle.Proof = make([]byte, proofCount)
	if _, err = io.ReadFull(r, bundle.Proof); err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 proof body (%d bytes): %w", proofCount, err)
	}

	for i := range actions {
		actions[i].SpendAuthSig, err = readFixed64(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read orchard v5 action[%d] spend auth sig: %w", i, err)
		}
	}
	bundle.Actions = actions

	bundle.BindingSig, err = readFixed64(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchard v5 binding sig: %w", err)
	}
	return &bundle, nil
}
