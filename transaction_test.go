package zcash

import (
	"bytes"
	"os"
	"testing"
)

const txVectorPath = "assets/zcash_tx.bin"
const txFailVectorPath = "assets/zcash_tx_fail.bin"
const txV6VectorPath = "assets/zcash_tx_v6.bin"
const txV6Nu7VectorPath = "assets/zcash_tx_v6_nu7.bin"

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

func TestParseV6Vector(t *testing.T) {
	raw, err := os.ReadFile(txV6VectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", txV6VectorPath, err)
	}

	tx, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if tx.Version != TxVersionV6 {
		t.Fatalf("version = %v, want V6", tx.Version)
	}
	if tx.ConsensusBranchID != BranchIdNu63 {
		t.Fatalf("branch id = 0x%08x, want Nu6.3 (0x%08x)", tx.ConsensusBranchID, BranchIdNu63)
	}
	if tx.LockTime != 0 {
		t.Errorf("lock_time = %d, want 0", tx.LockTime)
	}
	if tx.ExpiryHeight != 1 {
		t.Errorf("expiry_height = %d, want 1", tx.ExpiryHeight)
	}
	if tx.Transparent != nil {
		t.Errorf("transparent bundle = %v, want nil", tx.Transparent)
	}
	if tx.Sprout != nil {
		t.Errorf("sprout bundle = %v, want nil (v6 has no sprout)", tx.Sprout)
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
	if got, want := len(tx.Orchard.Actions), 1; got != want {
		t.Errorf("orchard actions = %d, want %d", got, want)
	}
	// The v6 Orchard slot forbids the cross-address bit (bit 2).
	if got := tx.Orchard.Flags & 0b100; got != 0 {
		t.Errorf("orchard flags = 0b%05b, want bit 2 clear", tx.Orchard.Flags)
	}
	if tx.Orchard.ValueBalance != 162464361004284 {
		t.Errorf("orchard value_balance = %d, want 162464361004284", tx.Orchard.ValueBalance)
	}
	if tx.Orchard.BindingSig == ([64]byte{}) {
		t.Error("orchard binding sig = zero, want non-zero")
	}
	if got, want := len(tx.Orchard.Proof), 4992; got != want {
		t.Errorf("orchard proof len = %d, want %d", got, want)
	}

	if tx.Ironwood == nil {
		t.Fatal("ironwood bundle = nil, want non-nil")
	}
	if got, want := len(tx.Ironwood.Actions), 1; got != want {
		t.Errorf("ironwood actions = %d, want %d", got, want)
	}
	// The v6 Ironwood slot encodes enableCrossAddress in bit 2.
	if got := tx.Ironwood.Flags & 0b100; got == 0 {
		t.Errorf("ironwood flags = 0b%05b, want bit 2 set", tx.Ironwood.Flags)
	}
	if tx.Ironwood.ValueBalance != -544781819241992 {
		t.Errorf("ironwood value_balance = %d, want -544781819241992", tx.Ironwood.ValueBalance)
	}
	if tx.Ironwood.BindingSig == ([64]byte{}) {
		t.Error("ironwood binding sig = zero, want non-zero")
	}
	if got, want := len(tx.Ironwood.Proof), 4992; got != want {
		t.Errorf("ironwood proof len = %d, want %d", got, want)
	}
}

func TestParseV6Nu7Vector(t *testing.T) {
	raw, err := os.ReadFile(txV6Nu7VectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", txV6Nu7VectorPath, err)
	}

	tx, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// The vector is the v6 vector with only the consensus_branch_id patched,
	// so the wire format is unchanged from Nu6.3; only the epoch differs.
	if tx.Version != TxVersionV6 {
		t.Fatalf("version = %v, want V6", tx.Version)
	}
	if tx.ConsensusBranchID != BranchIdNu7 {
		t.Fatalf("branch id = 0x%08x, want Nu7 (0x%08x)", tx.ConsensusBranchID, BranchIdNu7)
	}
	if tx.Orchard == nil || tx.Ironwood == nil {
		t.Fatal("orchard/ironwood bundle = nil, want non-nil")
	}
	if got, want := len(tx.Orchard.Actions), 1; got != want {
		t.Errorf("orchard actions = %d, want %d", got, want)
	}
	if got, want := len(tx.Ironwood.Actions), 1; got != want {
		t.Errorf("ironwood actions = %d, want %d", got, want)
	}
}

func TestBranchIdFromU32(t *testing.T) {
	bid, ok := branchIdFromU32(0x77190AD9)
	if !ok || bid != BranchIdNu7 {
		t.Fatalf("branchIdFromU32(0x77190AD9) = %v, %v; want BranchIdNu7, true", bid, ok)
	}
	// NB: 0x77190AD8 was an earlier NU7 proposal id, since retired.
	if _, ok := branchIdFromU32(0x77190AD8); ok {
		t.Error("branchIdFromU32(0x77190AD8) accepted, want rejected (retired proposal)")
	}
}

func TestRoundTripSerialize(t *testing.T) {
	vectors := []struct {
		name string
		path string
	}{
		{"v5", txVectorPath},
		{"v4_fail", txFailVectorPath},
		{"v6", txV6VectorPath},
		{"v6_nu7", txV6Nu7VectorPath},
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
