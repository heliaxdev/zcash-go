package zcash

import "io"

// OutPoint points to a previous transaction output.
type OutPoint struct {
	Hash [32]byte // txid of the containing transaction
	N    uint32   // output index
}

// IsNull reports whether the outpoint is the null outpoint (all-zero hash, N=0xffffffff).
func (o OutPoint) IsNull() bool {
	for _, b := range o.Hash {
		if b != 0 {
			return false
		}
	}
	return o.N == 0xffffffff
}

// TxIn is a transparent transaction input.
type TxIn struct {
	Prevout   OutPoint
	ScriptSig []byte
	Sequence  uint32
}

// TxOut is a transparent transaction output.
type TxOut struct {
	Value        int64
	ScriptPubKey []byte
}

// TransparentBundle contains the transparent inputs and outputs of a tx.
// It is nil when both vin and vout are empty.
type TransparentBundle struct {
	Vin  []TxIn
	Vout []TxOut
}

func readOutPoint(r io.Reader) (OutPoint, error) {
	hash, err := readFixed32(r)
	if err != nil {
		return OutPoint{}, err
	}
	n, err := readU32LE(r)
	if err != nil {
		return OutPoint{}, err
	}
	return OutPoint{Hash: hash, N: n}, nil
}

func readTxIn(r io.Reader) (TxIn, error) {
	prevout, err := readOutPoint(r)
	if err != nil {
		return TxIn{}, err
	}
	script, err := readScript(r)
	if err != nil {
		return TxIn{}, err
	}
	seq, err := readU32LE(r)
	if err != nil {
		return TxIn{}, err
	}
	return TxIn{Prevout: prevout, ScriptSig: script, Sequence: seq}, nil
}

func readTxOut(r io.Reader) (TxOut, error) {
	value, err := readI64LE(r)
	if err != nil {
		return TxOut{}, err
	}
	script, err := readScript(r)
	if err != nil {
		return TxOut{}, err
	}
	return TxOut{Value: value, ScriptPubKey: script}, nil
}

// readTransparent reads the transparent bundle: CompactSize-prefixed vin and
// vout. Returns nil when both are empty.
func readTransparent(r io.Reader) (*TransparentBundle, error) {
	vinCount, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	if vinCount > MaxCompactSize {
		return nil, errCompactTooLarge
	}
	vin := make([]TxIn, vinCount)
	for i := range vin {
		vin[i], err = readTxIn(r)
		if err != nil {
			return nil, err
		}
	}

	voutCount, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	vout := make([]TxOut, voutCount)
	for i := range vout {
		vout[i], err = readTxOut(r)
		if err != nil {
			return nil, err
		}
	}

	if len(vin) == 0 && len(vout) == 0 {
		return nil, nil
	}
	return &TransparentBundle{Vin: vin, Vout: vout}, nil
}
