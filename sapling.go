package zcash

import (
	"errors"
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
		return s, err
	}
	s.Anchor, err = readFixed32(r)
	if err != nil {
		return s, err
	}
	s.Nullifier, err = readFixed32(r)
	if err != nil {
		return s, err
	}
	s.Rk, err = readFixed32(r)
	if err != nil {
		return s, err
	}
	_, err = io.ReadFull(r, s.Zkproof[:])
	if err != nil {
		return s, err
	}
	_, err = io.ReadFull(r, s.SpendAuthSig[:])
	return s, err
}

// readOutputV4 reads a Sapling output description in the v4 format.
func readOutputV4(r io.Reader) (SaplingOutput, error) {
	var o SaplingOutput
	var err error
	o.Cv, err = readFixed32(r)
	if err != nil {
		return o, err
	}
	o.Cmu, err = readFixed32(r)
	if err != nil {
		return o, err
	}
	o.EphemeralKey, err = readFixed32(r)
	if err != nil {
		return o, err
	}
	_, err = io.ReadFull(r, o.EncCiphertext[:])
	if err != nil {
		return o, err
	}
	_, err = io.ReadFull(r, o.OutCiphertext[:])
	if err != nil {
		return o, err
	}
	_, err = io.ReadFull(r, o.Zkproof[:])
	return o, err
}

// readSaplingV4Components reads the Sapling portion of a v4 transaction.
// has_sapling is true for v4 transactions.
func readSaplingV4Components(r io.Reader) (*SaplingBundle, error) {
	valueBalance, err := readI64LE(r)
	if err != nil {
		return nil, err
	}
	nSpends, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	spends := make([]SaplingSpend, nSpends)
	for i := range spends {
		spends[i], err = readSpendV4(r)
		if err != nil {
			return nil, err
		}
	}
	nOutputs, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	outputs := make([]SaplingOutput, nOutputs)
	for i := range outputs {
		outputs[i], err = readOutputV4(r)
		if err != nil {
			return nil, err
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
		return nil, err
	}
	return bundle, nil
}

// readSaplingV5Bundle reads a Sapling bundle in the v5 transaction format.
func readSaplingV5Bundle(r io.Reader) (*SaplingBundle, error) {
	nSpends, err := readCompactSize(r)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		sd5[i].Nullifier, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		sd5[i].Rk, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
	}

	nOutputs, err := readCompactSize(r)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		od5[i].Cmu, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		od5[i].EphemeralKey, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, od5[i].EncCiphertext[:])
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, od5[i].OutCiphertext[:])
		if err != nil {
			return nil, err
		}
	}

	bundle := &SaplingBundle{}
	if len(sd5) == 0 && len(od5) == 0 {
		return bundle, nil
	}

	bundle.ValueBalance, err = readI64LE(r)
	if err != nil {
		return nil, err
	}

	if len(sd5) > 0 {
		var anchor [32]byte
		anchor, err = readFixed32(r)
		if err != nil {
			return nil, err
		}
		bundle.Anchor = &anchor
	}

	bundle.Spends = make([]SaplingSpend, len(sd5))
	for i := range sd5 {
		bundle.Spends[i].Cv = sd5[i].Cv
		bundle.Spends[i].Nullifier = sd5[i].Nullifier
		bundle.Spends[i].Rk = sd5[i].Rk
		bundle.Spends[i].Anchor = *bundle.Anchor
		_, err = io.ReadFull(r, bundle.Spends[i].Zkproof[:])
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, bundle.Spends[i].SpendAuthSig[:])
		if err != nil {
			return nil, err
		}
	}

	bundle.Outputs = make([]SaplingOutput, len(od5))
	for i := range od5 {
		bundle.Outputs[i].Cv = od5[i].Cv
		bundle.Outputs[i].Cmu = od5[i].Cmu
		bundle.Outputs[i].EphemeralKey = od5[i].EphemeralKey
		bundle.Outputs[i].EncCiphertext = od5[i].EncCiphertext
		bundle.Outputs[i].OutCiphertext = od5[i].OutCiphertext
		_, err = io.ReadFull(r, bundle.Outputs[i].Zkproof[:])
		if err != nil {
			return nil, err
		}
	}

	bundle.BindingSig, err = readFixed64(r)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}
