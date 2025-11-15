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
