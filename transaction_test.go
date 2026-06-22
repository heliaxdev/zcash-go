package zcash

import (
	"bytes"
	"os"
	"testing"
)

const txVectorPath = "assets/zcash_tx.bin"

func TestParseVector(t *testing.T) {
	raw, err := os.ReadFile(txVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", txVectorPath, err)
	}

	tx, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Header assertions derived from the first bytes of the vector.
	if tx.Version != TxVersionV5 {
		t.Fatalf("version = %v, want V5", tx.Version)
	}
	if tx.ConsensusBranchID != BranchIdNu62 {
		t.Fatalf("branch id = 0x%08x, want Nu6.2 (0x%08x)", tx.ConsensusBranchID, BranchIdNu62)
	}
	if tx.LockTime != 0 {
		t.Errorf("lock_time = %d, want 0", tx.LockTime)
	}
	if tx.ExpiryHeight != 0x339b19 {
		t.Errorf("expiry_height = 0x%x, want 0x339b19", tx.ExpiryHeight)
	}
	if tx.Transparent != nil {
		t.Errorf("transparent bundle = %v, want nil", tx.Transparent)
	}
	if tx.Sprout != nil {
		t.Errorf("sprout bundle = %v, want nil (v5 has no sprout)", tx.Sprout)
	}
	if tx.Sapling == nil {
		t.Fatal("sapling bundle = nil, want non-nil")
	}
	if got := len(tx.Sapling.Spends); got != 0 {
		t.Errorf("sapling spends = %d, want 0", got)
	}
	if got := len(tx.Sapling.Outputs); got != 0 {
		t.Errorf("sapling outputs = %d, want 0", got)
	}
	if tx.Orchard == nil {
		t.Fatal("orchard bundle = nil, want non-nil")
	}
	if got, want := len(tx.Orchard.Actions), 5; got != want {
		t.Errorf("orchard actions = %d, want %d", got, want)
	}
	if tx.Orchard.Anchor == ([32]byte{}) {
		t.Error("orchard anchor = zero, want non-zero")
	}
	if tx.Orchard.BindingSig == ([64]byte{}) {
		t.Error("orchard binding sig = zero, want non-zero")
	}
	if len(tx.Orchard.Proof) == 0 {
		t.Error("orchard proof = empty, want non-empty")
	}
}

func TestRoundTripSerialize(t *testing.T) {
	raw, err := os.ReadFile(txVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", txVectorPath, err)
	}

	tx, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	var out bytes.Buffer
	if err := tx.Serialize(&out); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if !bytes.Equal(raw, out.Bytes()) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", out.Len(), len(raw))
	}
}
