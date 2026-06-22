package zcash

import (
	"errors"
	"fmt"
	"io"
)

// GrothProofSize is the size of a Sapling/Sprout Groth16 proof: π_A + π_B + π_C.
const GrothProofSize = 48 + 96 + 48 // 192

// EncCiphertextSize and OutCiphertextSize are Sapling/Orchard note ciphertext sizes.
const (
	EncCiphertextSize = 580
	OutCiphertextSize = 80
)

// SaplingSpend is a Sapling spend description.
type SaplingSpend struct {
	Cv           [32]byte
	Anchor       [32]byte // only present in v4
	Nullifier    [32]byte
	Rk           [32]byte
	Zkproof      [GrothProofSize]byte
	SpendAuthSig [64]byte
}

// SaplingOutput is a Sapling output description.
type SaplingOutput struct {
	Cv            [32]byte
	Cmu           [32]byte
	EphemeralKey  [32]byte
	EncCiphertext [EncCiphertextSize]byte
	OutCiphertext [OutCiphertextSize]byte
	Zkproof       [GrothProofSize]byte
}

// SaplingBundle is the Sapling shielded bundle.
type SaplingBundle struct {
	Spends       []SaplingSpend
	Outputs      []SaplingOutput
	ValueBalance int64
	Anchor       *[32]byte // shared spend anchor (present iff Spends non-empty)
	BindingSig   [64]byte  // present iff Spends|Outputs non-empty
}

var errCompactTooLarge = errors.New("zcash: compact size exceeds maximum")

// readSpendV4 reads a Sapling spend description in the v4 format.
func readSpendV4(r io.Reader) (SaplingSpend, error) {
	var s SaplingSpend
	var err error
	s.Cv, err = readFixed32(r)
	if err != nil {
		return s, fmt.Errorf("failed to read sapling v4 spend cv: %w", err)
	}
	s.Anchor, err = readFixed32(r)
	if err != nil {
		return s, fmt.Errorf("failed to read sapling v4 spend anchor: %w", err)
	}
	s.Nullifier, err = readFixed32(r)
	if err != nil {
		return s, fmt.Errorf("failed to read sapling v4 spend nullifier: %w", err)
	}
	s.Rk, err = readFixed32(r)
	if err != nil {
		return s, fmt.Errorf("failed to read sapling v4 spend rk: %w", err)
	}
	if _, err = io.ReadFull(r, s.Zkproof[:]); err != nil {
		return s, fmt.Errorf("failed to read sapling v4 spend zkproof: %w", err)
	}
	if _, err = io.ReadFull(r, s.SpendAuthSig[:]); err != nil {
		return s, fmt.Errorf("failed to read sapling v4 spend auth sig: %w", err)
	}
	return s, nil
}

// readOutputV4 reads a Sapling output description in the v4 format.
func readOutputV4(r io.Reader) (SaplingOutput, error) {
	var o SaplingOutput
	var err error
	o.Cv, err = readFixed32(r)
	if err != nil {
		return o, fmt.Errorf("failed to read sapling v4 output cv: %w", err)
	}
	o.Cmu, err = readFixed32(r)
	if err != nil {
		return o, fmt.Errorf("failed to read sapling v4 output cmu: %w", err)
	}
	o.EphemeralKey, err = readFixed32(r)
	if err != nil {
		return o, fmt.Errorf("failed to read sapling v4 output ephemeral key: %w", err)
	}
	if _, err = io.ReadFull(r, o.EncCiphertext[:]); err != nil {
		return o, fmt.Errorf("failed to read sapling v4 output enc_ciphertext: %w", err)
	}
	if _, err = io.ReadFull(r, o.OutCiphertext[:]); err != nil {
		return o, fmt.Errorf("failed to read sapling v4 output out_ciphertext: %w", err)
	}
	if _, err = io.ReadFull(r, o.Zkproof[:]); err != nil {
		return o, fmt.Errorf("failed to read sapling v4 output zkproof: %w", err)
	}
	return o, nil
}

// readSaplingV4Components reads the Sapling portion of a v4 transaction.
// has_sapling is true for v4 transactions.
func readSaplingV4Components(r io.Reader) (*SaplingBundle, error) {
	valueBalance, err := readI64LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v4 value_balance: %w", err)
	}
	nSpends, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v4 spends count: %w", err)
	}
	spends := make([]SaplingSpend, nSpends)
	for i := range spends {
		spends[i], err = readSpendV4(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v4 spend[%d]: %w", i, err)
		}
	}
	nOutputs, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v4 outputs count: %w", err)
	}
	outputs := make([]SaplingOutput, nOutputs)
	for i := range outputs {
		outputs[i], err = readOutputV4(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v4 output[%d]: %w", i, err)
		}
	}

	if len(spends) == 0 && len(outputs) == 0 {
		// binding_sig is absent in this case; bundle is effectively empty.
		return &SaplingBundle{ValueBalance: 0}, nil
	}

	bundle := &SaplingBundle{
		Spends:       spends,
		Outputs:      outputs,
		ValueBalance: valueBalance,
	}
	bundle.BindingSig, err = readFixed64(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v4 binding sig: %w", err)
	}
	return bundle, nil
}

// readSaplingV5Bundle reads a Sapling bundle in the v5 transaction format.
func readSaplingV5Bundle(r io.Reader) (*SaplingBundle, error) {
	nSpends, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v5 spends count: %w", err)
	}
	// read spends without witness data (cv, nullifier, rk)
	type spendV5 struct {
		Cv        [32]byte
		Nullifier [32]byte
		Rk        [32]byte
	}
	sd5 := make([]spendV5, nSpends)
	for i := range sd5 {
		sd5[i].Cv, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 spend[%d] cv: %w", i, err)
		}
		sd5[i].Nullifier, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 spend[%d] nullifier: %w", i, err)
		}
		sd5[i].Rk, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 spend[%d] rk: %w", i, err)
		}
	}

	nOutputs, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v5 outputs count: %w", err)
	}
	type outputV5 struct {
		Cv            [32]byte
		Cmu           [32]byte
		EphemeralKey  [32]byte
		EncCiphertext [EncCiphertextSize]byte
		OutCiphertext [OutCiphertextSize]byte
	}
	od5 := make([]outputV5, nOutputs)
	for i := range od5 {
		od5[i].Cv, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 output[%d] cv: %w", i, err)
		}
		od5[i].Cmu, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 output[%d] cmu: %w", i, err)
		}
		od5[i].EphemeralKey, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 output[%d] ephemeral key: %w", i, err)
		}
		if _, err = io.ReadFull(r, od5[i].EncCiphertext[:]); err != nil {
			return nil, fmt.Errorf(
				"failed to read sapling v5 output[%d] enc_ciphertext: %w",
				i,
				err,
			)
		}
		if _, err = io.ReadFull(r, od5[i].OutCiphertext[:]); err != nil {
			return nil, fmt.Errorf(
				"failed to read sapling v5 output[%d] out_ciphertext: %w",
				i,
				err,
			)
		}
	}

	bundle := &SaplingBundle{}
	if len(sd5) == 0 && len(od5) == 0 {
		return bundle, nil
	}

	bundle.ValueBalance, err = readI64LE(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v5 value_balance: %w", err)
	}

	if len(sd5) > 0 {
		var anchor [32]byte
		anchor, err = readFixed32(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 anchor: %w", err)
		}
		bundle.Anchor = &anchor
	}

	bundle.Spends = make([]SaplingSpend, len(sd5))
	for i := range sd5 {
		bundle.Spends[i].Cv = sd5[i].Cv
		bundle.Spends[i].Nullifier = sd5[i].Nullifier
		bundle.Spends[i].Rk = sd5[i].Rk
		bundle.Spends[i].Anchor = *bundle.Anchor
		if _, err = io.ReadFull(r, bundle.Spends[i].Zkproof[:]); err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 spend[%d] zkproof: %w", i, err)
		}
		if _, err = io.ReadFull(r, bundle.Spends[i].SpendAuthSig[:]); err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 spend[%d] auth sig: %w", i, err)
		}
	}

	bundle.Outputs = make([]SaplingOutput, len(od5))
	for i := range od5 {
		bundle.Outputs[i].Cv = od5[i].Cv
		bundle.Outputs[i].Cmu = od5[i].Cmu
		bundle.Outputs[i].EphemeralKey = od5[i].EphemeralKey
		bundle.Outputs[i].EncCiphertext = od5[i].EncCiphertext
		bundle.Outputs[i].OutCiphertext = od5[i].OutCiphertext
		if _, err = io.ReadFull(r, bundle.Outputs[i].Zkproof[:]); err != nil {
			return nil, fmt.Errorf("failed to read sapling v5 output[%d] zkproof: %w", i, err)
		}
	}

	bundle.BindingSig, err = readFixed64(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sapling v5 binding sig: %w", err)
	}
	return bundle, nil
}
