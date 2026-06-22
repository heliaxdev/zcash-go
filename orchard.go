package zcash

import "io"

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
		return nil, err
	}
	if nActions == 0 {
		return nil, nil
	}

	actions := make([]OrchardAction, nActions)
	for i := range actions {
		a := &actions[i]
		a.CvNet, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		a.Nullifier, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		a.Rk, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		a.Cmx, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		a.EphemeralKey, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, a.EncCiphertext[:])
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, a.OutCiphertext[:])
		if err != nil {
			return nil, err
		}
	}

	var bundle OrchardBundle
	bundle.Flags, err = readByte(r)
	if err != nil {
		return nil, err
	}
	bundle.ValueBalance, err = readI64LE(r)
	if err != nil {
		return nil, err
	}
	bundle.Anchor, err = readFixed32(r)
	if err != nil {
		return nil, err
	}

	proofCount, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	bundle.Proof = make([]byte, proofCount)
	if _, err = io.ReadFull(r, bundle.Proof); err != nil {
		return nil, err
	}

	for i := range actions {
		actions[i].SpendAuthSig, err = readFixed64(r)
		if err != nil {
			return nil, err
		}
	}
	bundle.Actions = actions

	bundle.BindingSig, err = readFixed64(r)
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}
