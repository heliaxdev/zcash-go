package zcash

import (
	"bytes"
	"os"
	"testing"
)

const txVectorPath = "assets/zcash_tx.bin"
const txFailVectorPath = "assets/zcash_tx_fail.bin"

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

func TestParseV4FailVector(t *testing.T) {
	raw, err := os.ReadFile(txFailVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", txFailVectorPath, err)
	}

	tx, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Ground truth from zcash_tx_fail.txt (Rust librustzcash decode).
	if tx.Version != TxVersionV4 {
		t.Fatalf("version = %v, want V4", tx.Version)
	}
	if tx.LockTime != 0 {
		t.Errorf("lock_time = %d, want 0", tx.LockTime)
	}
	if tx.ExpiryHeight != 3396855 {
		t.Errorf("expiry_height = %d, want 3396855", tx.ExpiryHeight)
	}
	if tx.Transparent == nil {
		t.Fatal("transparent bundle = nil, want non-nil")
	}
	if got, want := len(tx.Transparent.Vin), 15; got != want {
		t.Errorf("transparent inputs = %d, want %d", got, want)
	}
	if got := len(tx.Transparent.Vout); got != 0 {
		t.Errorf("transparent outputs = %d, want 0", got)
	}
	if tx.Sprout != nil {
		t.Errorf("sprout bundle = %v, want nil", tx.Sprout)
	}
	if tx.Sapling == nil {
		t.Fatal("sapling bundle = nil, want non-nil")
	}
	if got := len(tx.Sapling.Spends); got != 0 {
		t.Errorf("sapling spends = %d, want 0", got)
	}
	if got, want := len(tx.Sapling.Outputs), 2; got != want {
		t.Errorf("sapling outputs = %d, want %d", got, want)
	}
	if got, want := tx.Sapling.ValueBalance, int64(-1885872241); got != want {
		t.Errorf("sapling value_balance = %d, want %d", got, want)
	}
	if tx.Sapling.BindingSig == ([64]byte{}) {
		t.Error("sapling binding sig = zero, want non-zero (outputs present)")
	}
	if tx.Orchard != nil {
		t.Errorf("orchard bundle = %v, want nil (v4 has no orchard)", tx.Orchard)
	}
}

func TestRoundTripSerialize(t *testing.T) {
	vectors := []struct {
		name string
		path string
	}{
		{"v5", txVectorPath},
		{"v4_fail", txFailVectorPath},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			raw, err := os.ReadFile(v.path)
			if err != nil {
				t.Fatalf("read %s: %v", v.path, err)
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
		})
	}
}
