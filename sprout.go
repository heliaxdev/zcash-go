package zcash

import (
	"fmt"
	"io"
)

// SproutCiphertextSize is the size of a Sprout note ciphertext.
const SproutCiphertextSize = 601

// NumSproutJSInputs and NumSproutJSOutputs are the fixed JS in/out counts.
const (
	NumSproutJSInputs  = 2
	NumSproutJSOutputs = 2
)

// SproutJoinSplit is a single Sprout JoinSplit description. Only the Groth16
// proof variant is supported (as used in Sapling+ v4 transactions).
type SproutJoinSplit struct {
	VpubOld      int64
	VpubNew      int64
	Anchor       [32]byte
	Nullifiers   [NumSproutJSInputs][32]byte
	Commitments  [NumSproutJSOutputs][32]byte
	EphemeralKey [32]byte
	RandomSeed   [32]byte
	Macs         [NumSproutJSInputs][32]byte
	Proof        [GrothProofSize]byte
	Ciphertexts  [NumSproutJSOutputs][SproutCiphertextSize]byte
}

// SproutBundle is the Sprout joinsplit bundle, only present in v4 transactions.
type SproutBundle struct {
	JoinSplits      []SproutJoinSplit
	JoinSplitPubKey [32]byte
	JoinSplitSig    [64]byte
}

// readSproutJoinSplit reads a Groth16-variant JoinSplit description.
func readSproutJoinSplit(r io.Reader) (SproutJoinSplit, error) {
	var js SproutJoinSplit
	var err error
	js.VpubOld, err = readI64LE(r)
	if err != nil {
		return js, fmt.Errorf("failed to read sprout joinsplit vpub_old: %w", err)
	}
	js.VpubNew, err = readI64LE(r)
	if err != nil {
		return js, fmt.Errorf("failed to read sprout joinsplit vpub_new: %w", err)
	}
	js.Anchor, err = readFixed32(r)
	if err != nil {
		return js, fmt.Errorf("failed to read sprout joinsplit anchor: %w", err)
	}
	for i := range js.Nullifiers {
		js.Nullifiers[i], err = readFixed32(r)
		if err != nil {
			return js, fmt.Errorf("failed to read sprout joinsplit nullifier[%d]: %w", i, err)
		}
	}
	for i := range js.Commitments {
		js.Commitments[i], err = readFixed32(r)
		if err != nil {
			return js, fmt.Errorf("failed to read sprout joinsplit commitment[%d]: %w", i, err)
		}
	}
	js.EphemeralKey, err = readFixed32(r)
	if err != nil {
		return js, fmt.Errorf("failed to read sprout joinsplit ephemeral key: %w", err)
	}
	js.RandomSeed, err = readFixed32(r)
	if err != nil {
		return js, fmt.Errorf("failed to read sprout joinsplit random seed: %w", err)
	}
	for i := range js.Macs {
		js.Macs[i], err = readFixed32(r)
		if err != nil {
			return js, fmt.Errorf("failed to read sprout joinsplit mac[%d]: %w", i, err)
		}
	}
	if _, err = io.ReadFull(r, js.Proof[:]); err != nil {
		return js, fmt.Errorf("failed to read sprout joinsplit groth proof: %w", err)
	}
	for i := range js.Ciphertexts {
		if _, err = io.ReadFull(r, js.Ciphertexts[i][:]); err != nil {
			return js, fmt.Errorf("failed to read sprout joinsplit ciphertext[%d]: %w", i, err)
		}
	}
	return js, nil
}

// readSproutBundle reads the v4 sprout joinsplit section. Returns nil if there
// are no joinsplits. `use_groth` is true for v4 (Sapling+) transactions.
func readSproutBundle(r io.Reader) (*SproutBundle, error) {
	nJS, err := readCompactSize(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sprout joinsplit count: %w", err)
	}
	if nJS == 0 {
		return nil, nil
	}
	bundle := &SproutBundle{
		JoinSplits: make([]SproutJoinSplit, nJS),
	}
	for i := range bundle.JoinSplits {
		bundle.JoinSplits[i], err = readSproutJoinSplit(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read sprout joinsplit[%d]: %w", i, err)
		}
	}
	bundle.JoinSplitPubKey, err = readFixed32(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sprout joinsplit pubkey: %w", err)
	}
	bundle.JoinSplitSig, err = readFixed64(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sprout joinsplit sig: %w", err)
	}
	return bundle, nil
}
