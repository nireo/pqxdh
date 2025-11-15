# pqxdh

This package implements the Post-Quantum Extended Diffie-Hellman key exchange protocol. It just has a single dependency other than the standard library. It also contains the XEdDSA implementation which allows conversion from a X25519 key exchange key to a ed25519 signing key.

The only downside of this approach is that the users need some other channel to ensure the initial identity key of the key exchange initiator. This is because there is no way of knowing if a malicious server has replaced the bundle content with their own keys. 

The PQXDH is built on top of X3DH, however it adds one-time MLKEM keys and a last resort key MLKEM key. If one were to strip that out, this library then contains a fully feature X3DH implementation.

## Examples

Basic key exchange:

```go
package main

import (
	"bytes"
	"log"

	"github.com/nireo/pqxdh"
)

func main() {
	alice, err := pqxdh.NewPQXDHState()
	if err != nil {
		log.Fatalf("alice state init failed: %s", err)
	}
	bob, err := pqxdh.NewPQXDHState()
	if err != nil {
		log.Fatalf("bob state init failed: %s", err)
	}

	if err = bob.GenerateOneTimeKEMKeys(1); err != nil {
		log.Fatalf("generateOneTimeKEMKeys: %v", err)
	}

	if err = bob.GenerateOneTimePrekeys(1); err != nil {
		log.Fatalf("generateOneTimePrekeys: %v", err)
	}

	var kemID pqxdh.KEMID
	for id := range bob.OneTimeKEMKeys {
		kemID = id
		break
	}
	var otpkID uint32
	for id := range bob.OneTimePreKeys {
		otpkID = id
		break
	}

	bundle, err := bob.MakeBundleWithIDs(kemID, &otpkID)
	if err != nil {
		log.Fatalf("failed to make bundle: %s", err)
	}
	h, err := bundle.Hash()
	if err != nil {
		log.Fatalf("failed to hash bundle: %s", err)
	}
	bundle.BundleHash = h

	rkA, init, err := alice.KeyExchange(bundle)
	if err != nil {
		log.Fatalf("failed to initialize key exchange: %s", err)
	}

	res, err := bob.ReceiveInitMessage(init)
	if err != nil {
		log.Fatalf("failed to receive key exchange: %s", err)
	}

	if !bytes.Equal(rkA, res.RootKey) {
		log.Fatalf("mistmatch between shared secret")
	}

	log.Printf("key exchange completed with\n\tshared secret: %x\n\tadditional data: %x", res.RootKey, res.AD)
}
```
