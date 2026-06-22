# zcash-go

A native Go parser for Zcash transactions (Sapling and later).

## Overview

This package deserializes Zcash transactions into structured Go types. It
mirrors the parsing logic of [`librustzcash`][librustzcash]
(`zcash_primitives::transaction`), reimplemented natively in Go without any
external dependencies.

Supported transaction versions:

- **V4** (Sapling .. Nu6.2) — transparent bundle, Sapling shielded bundle,
  Sprout joinsplits.
- **V5** (NU5 .. Nu6.2) — transparent bundle, Sapling shielded bundle, Orchard
  shielded bundle.

Pre-Sapling transactions (Sprout v1/v2 and Overwinter V3) are not supported and
return `ErrSkipped`.

Only deserialization is implemented; transaction txid computation (blake2b
digest tree) and cryptographic validity checks (curve points, field elements)
are out of scope. Structural validation (canonical CompactSize encoding, the
`0x02000000` consensus bound) is enforced.

## Usage

```go
package main

import (
	"fmt"
	"os"

	"github.com/heliaxdev/zcash-go"
)

func main() {
	raw, err := os.ReadFile("tx.bin")
	if err != nil {
		panic(err)
	}

	tx, err := zcash.Parse(bytes.NewReader(raw))
	if err != nil {
		if errors.Is(err, zcash.ErrSkipped) {
			fmt.Println("unsupported pre-Sapling transaction")
			return
		}
		panic(err)
	}

	fmt.Printf("version:            %v\n", tx.Version)
	fmt.Printf("consensus branch:   0x%08x\n", tx.ConsensusBranchID)
	fmt.Printf("lock_time:          %d\n", tx.LockTime)
	fmt.Printf("expiry_height:      %d\n", tx.ExpiryHeight)
	if tx.Transparent != nil {
		fmt.Printf("transparent inputs: %d\n", len(tx.Transparent.Vin))
		fmt.Printf("transparent outputs: %d\n", len(tx.Transparent.Vout))
	}
	if tx.Sapling != nil {
		fmt.Printf("sapling spends:     %d\n", len(tx.Sapling.Spends))
		fmt.Printf("sapling outputs:    %d\n", len(tx.Sapling.Outputs))
	}
	if tx.Orchard != nil {
		fmt.Printf("orchard actions:    %d\n", len(tx.Orchard.Actions))
	}
}
```

## Round-trip serialization

Parsed transactions can be re-serialized via `(*Transaction).Serialize`. The
output is byte-identical to the input for well-formed transactions, which is
used as the primary correctness oracle in the test suite.

## Reference

- [Zcash Protocol Specification][protocol] — §7.1 Transaction Encoding and
  Consensus, §4.4 Spend Descriptions, §4.5 Output Descriptions.
- [ZIP 225][zip-225] — Version 5 Transaction Format.
- [librustzcash][librustzcash] — the canonical Rust implementation this parser
  follows.

[librustzcash]: https://github.com/zcash/librustzcash
[protocol]: https://zips.z.cash/protocol/protocol.pdf
[zip-225]: https://zips.z.cash/zip-0225

## License

MIT.
