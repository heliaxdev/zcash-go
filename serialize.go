package zcash

import (
	"encoding/binary"
	"io"
)

// Serialize writes the transaction back to its canonical binary encoding.
func (tx *Transaction) Serialize(w io.Writer) error {
	switch tx.Version {
	case TxVersionV4:
		return tx.serializeV4(w)
	case TxVersionV5:
		return tx.serializeV5(w)
	default:
		return errUnsupportedVersion
	}
}

var errUnsupportedVersion = errSkipped("zcash: unsupported transaction version")

type errSkipped string

func (e errSkipped) Error() string { return string(e) }

func writeU32LE(w io.Writer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func writeI64LE(w io.Writer, v int64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v))
	_, err := w.Write(b[:])
	return err
}

func writeFixed(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func writeScript(w io.Writer, s []byte) error {
	if err := writeCompactSize(w, uint64(len(s))); err != nil {
		return err
	}
	return writeFixed(w, s)
}

func (tx *Transaction) headerAndGroupID() (uint32, uint32, error) {
	switch tx.Version {
	case TxVersionV4:
		return overwinteredBit | v4TxVersion, v4VersionGroupID, nil
	case TxVersionV5:
		return overwinteredBit | v5TxVersion, v5VersionGroupID, nil
	default:
		return 0, 0, errUnsupportedVersion
	}
}

func (tx *Transaction) serializeV4(w io.Writer) error {
	header, vgid, err := tx.headerAndGroupID()
	if err != nil {
		return err
	}
	if err := writeU32LE(w, header); err != nil {
		return err
	}
	if err := writeU32LE(w, vgid); err != nil {
		return err
	}
	if err := writeTransparent(w, tx.Transparent); err != nil {
		return err
	}
	if err := writeU32LE(w, tx.LockTime); err != nil {
		return err
	}
	if err := writeU32LE(w, tx.ExpiryHeight); err != nil {
		return err
	}
	if err := writeSaplingV4Components(w, tx.Sapling); err != nil {
		return err
	}
	if err := writeSproutBundle(w, tx.Sprout); err != nil {
		return err
	}
	return nil
}

func (tx *Transaction) serializeV5(w io.Writer) error {
	header, vgid, err := tx.headerAndGroupID()
	if err != nil {
		return err
	}
	if err := writeU32LE(w, header); err != nil {
		return err
	}
	if err := writeU32LE(w, vgid); err != nil {
		return err
	}
	if err := writeU32LE(w, uint32(tx.ConsensusBranchID)); err != nil {
		return err
	}
	if err := writeU32LE(w, tx.LockTime); err != nil {
		return err
	}
	if err := writeU32LE(w, tx.ExpiryHeight); err != nil {
		return err
	}
	if err := writeTransparent(w, tx.Transparent); err != nil {
		return err
	}
	if err := writeSaplingV5Bundle(w, tx.Sapling); err != nil {
		return err
	}
	if err := writeOrchardV5Bundle(w, tx.Orchard); err != nil {
		return err
	}
	return nil
}

func writeTransparent(w io.Writer, b *TransparentBundle) error {
	if b == nil {
		if err := writeCompactSize(w, 0); err != nil {
			return err
		}
		return writeCompactSize(w, 0)
	}
	if err := writeCompactSize(w, uint64(len(b.Vin))); err != nil {
		return err
	}
	for i := range b.Vin {
		if err := writeTxIn(w, &b.Vin[i]); err != nil {
			return err
		}
	}
	if err := writeCompactSize(w, uint64(len(b.Vout))); err != nil {
		return err
	}
	for i := range b.Vout {
		if err := writeTxOut(w, &b.Vout[i]); err != nil {
			return err
		}
	}
	return nil
}

func writeTxIn(w io.Writer, in *TxIn) error {
	if err := writeFixed(w, in.Prevout.Hash[:]); err != nil {
		return err
	}
	if err := writeU32LE(w, in.Prevout.N); err != nil {
		return err
	}
	if err := writeScript(w, in.ScriptSig); err != nil {
		return err
	}
	return writeU32LE(w, in.Sequence)
}

func writeTxOut(w io.Writer, out *TxOut) error {
	if err := writeI64LE(w, out.Value); err != nil {
		return err
	}
	return writeScript(w, out.ScriptPubKey)
}

func writeSaplingV4Components(w io.Writer, b *SaplingBundle) error {
	if b == nil {
		if err := writeI64LE(w, 0); err != nil {
			return err
		}
		if err := writeCompactSize(w, 0); err != nil {
			return err
		}
		return writeCompactSize(w, 0)
	}
	if err := writeI64LE(w, b.ValueBalance); err != nil {
		return err
	}
	if err := writeCompactSize(w, uint64(len(b.Spends))); err != nil {
		return err
	}
	for i := range b.Spends {
		s := &b.Spends[i]
		if err := writeFixed(w, s.Cv[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.Anchor[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.Nullifier[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.Rk[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.Zkproof[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.SpendAuthSig[:]); err != nil {
			return err
		}
	}
	if err := writeCompactSize(w, uint64(len(b.Outputs))); err != nil {
		return err
	}
	for i := range b.Outputs {
		o := &b.Outputs[i]
		if err := writeFixed(w, o.Cv[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.Cmu[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.EphemeralKey[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.EncCiphertext[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.OutCiphertext[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.Zkproof[:]); err != nil {
			return err
		}
	}
	if len(b.Spends) > 0 || len(b.Outputs) > 0 {
		if err := writeFixed(w, b.BindingSig[:]); err != nil {
			return err
		}
	}
	return nil
}

func writeSaplingV5Bundle(w io.Writer, b *SaplingBundle) error {
	if b == nil {
		if err := writeCompactSize(w, 0); err != nil {
			return err
		}
		return writeCompactSize(w, 0)
	}
	if err := writeCompactSize(w, uint64(len(b.Spends))); err != nil {
		return err
	}
	for i := range b.Spends {
		s := &b.Spends[i]
		if err := writeFixed(w, s.Cv[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.Nullifier[:]); err != nil {
			return err
		}
		if err := writeFixed(w, s.Rk[:]); err != nil {
			return err
		}
	}
	if err := writeCompactSize(w, uint64(len(b.Outputs))); err != nil {
		return err
	}
	for i := range b.Outputs {
		o := &b.Outputs[i]
		if err := writeFixed(w, o.Cv[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.Cmu[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.EphemeralKey[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.EncCiphertext[:]); err != nil {
			return err
		}
		if err := writeFixed(w, o.OutCiphertext[:]); err != nil {
			return err
		}
	}
	if len(b.Spends) > 0 || len(b.Outputs) > 0 {
		if err := writeI64LE(w, b.ValueBalance); err != nil {
			return err
		}
	}
	if len(b.Spends) > 0 && b.Anchor != nil {
		if err := writeFixed(w, b.Anchor[:]); err != nil {
			return err
		}
	}
	for i := range b.Spends {
		if err := writeFixed(w, b.Spends[i].Zkproof[:]); err != nil {
			return err
		}
	}
	for i := range b.Spends {
		if err := writeFixed(w, b.Spends[i].SpendAuthSig[:]); err != nil {
			return err
		}
	}
	for i := range b.Outputs {
		if err := writeFixed(w, b.Outputs[i].Zkproof[:]); err != nil {
			return err
		}
	}
	if len(b.Spends) > 0 || len(b.Outputs) > 0 {
		if err := writeFixed(w, b.BindingSig[:]); err != nil {
			return err
		}
	}
	return nil
}

func writeOrchardV5Bundle(w io.Writer, b *OrchardBundle) error {
	if b == nil {
		return writeCompactSize(w, 0)
	}
	if err := writeCompactSize(w, uint64(len(b.Actions))); err != nil {
		return err
	}
	for i := range b.Actions {
		a := &b.Actions[i]
		if err := writeFixed(w, a.CvNet[:]); err != nil {
			return err
		}
		if err := writeFixed(w, a.Nullifier[:]); err != nil {
			return err
		}
		if err := writeFixed(w, a.Rk[:]); err != nil {
			return err
		}
		if err := writeFixed(w, a.Cmx[:]); err != nil {
			return err
		}
		if err := writeFixed(w, a.EphemeralKey[:]); err != nil {
			return err
		}
		if err := writeFixed(w, a.EncCiphertext[:]); err != nil {
			return err
		}
		if err := writeFixed(w, a.OutCiphertext[:]); err != nil {
			return err
		}
	}
	if _, err := w.Write([]byte{b.Flags}); err != nil {
		return err
	}
	if err := writeI64LE(w, b.ValueBalance); err != nil {
		return err
	}
	if err := writeFixed(w, b.Anchor[:]); err != nil {
		return err
	}
	if err := writeCompactSize(w, uint64(len(b.Proof))); err != nil {
		return err
	}
	if err := writeFixed(w, b.Proof); err != nil {
		return err
	}
	for i := range b.Actions {
		if err := writeFixed(w, b.Actions[i].SpendAuthSig[:]); err != nil {
			return err
		}
	}
	return writeFixed(w, b.BindingSig[:])
}

func writeSproutBundle(w io.Writer, b *SproutBundle) error {
	if b == nil {
		return writeCompactSize(w, 0)
	}
	if err := writeCompactSize(w, uint64(len(b.JoinSplits))); err != nil {
		return err
	}
	for i := range b.JoinSplits {
		js := &b.JoinSplits[i]
		if err := writeI64LE(w, js.VpubOld); err != nil {
			return err
		}
		if err := writeI64LE(w, js.VpubNew); err != nil {
			return err
		}
		if err := writeFixed(w, js.Anchor[:]); err != nil {
			return err
		}
		for j := range js.Nullifiers {
			if err := writeFixed(w, js.Nullifiers[j][:]); err != nil {
				return err
			}
		}
		for j := range js.Commitments {
			if err := writeFixed(w, js.Commitments[j][:]); err != nil {
				return err
			}
		}
		if err := writeFixed(w, js.EphemeralKey[:]); err != nil {
			return err
		}
		if err := writeFixed(w, js.RandomSeed[:]); err != nil {
			return err
		}
		for j := range js.Macs {
			if err := writeFixed(w, js.Macs[j][:]); err != nil {
				return err
			}
		}
		if err := writeFixed(w, js.Proof[:]); err != nil {
			return err
		}
		for j := range js.Ciphertexts {
			if err := writeFixed(w, js.Ciphertexts[j][:]); err != nil {
				return err
			}
		}
	}
	if err := writeFixed(w, b.JoinSplitPubKey[:]); err != nil {
		return err
	}
	return writeFixed(w, b.JoinSplitSig[:])
}
