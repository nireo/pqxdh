package pqxdh

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha512"
	"testing"
)

func TestKDFDeterministic(t *testing.T) {
	out1, err1 := pqxdhKDF([]byte("km"), protocolInfo)
	if err1 != nil {
		t.Fatalf("pqxdhKDF: %v", err1)
	}
	out2, err2 := pqxdhKDF([]byte("km"), protocolInfo)
	if err2 != nil {
		t.Fatalf("pqxdhKDF(2): %v", err2)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatalf("outputs differ")
	}
	if len(out1) != sha512.New().Size() {
		t.Fatalf("unexpected length: %d", len(out1))
	}
	out3, err3 := pqxdhKDF([]byte("km"), "other")
	if err3 != nil {
		t.Fatalf("pqxdhKDF other: %v", err3)
	}
	if bytes.Equal(out1, out3) {
		t.Fatalf("outputs equal for different info")
	}
}

func TestBundleHashAndSignatures(t *testing.T) {
	receiver, err := NewPQXDHState(1)
	if err != nil {
		t.Fatalf("NewPQXDHState: %v", err)
	}
	if err := receiver.generateOneTimeKEMKeys(1); err != nil {
		t.Fatalf("generateOneTimeKEMKeys: %v", err)
	}
	if err := receiver.generateOneTimePrekeys(1); err != nil {
		t.Fatalf("generateOneTimePrekeys: %v", err)
	}
	var kemID idKEM
	var encap *mlkem.EncapsulationKey1024
	for id, k := range receiver.oneTimeKEMKeys {
		kemID = id
		encap = k.encap
		break
	}
	var otpkID uint32
	var otpk *oneTimePreKey
	for id, k := range receiver.oneTimePrekeys {
		otpkID = id
		otpk = k
		break
	}
	b, err := receiver.makeBundle(kemID, encap, &otpkID, otpk)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	h, err := b.hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	b.bundleHash = h
	ok, err := b.isHashValid()
	if err != nil {
		t.Fatalf("isHashValid err: %v", err)
	}
	if !ok {
		t.Fatalf("hash invalid")
	}
	if err := b.verifyBundleSignatures(); err != nil {
		t.Fatalf("verifyBundleSignatures: %v", err)
	}
	b.spkSig[0] ^= 1
	if err := b.verifyBundleSignatures(); err == nil {
		t.Fatalf("expected signature error")
	}
}

func TestKeyExchangeWithOneTimeKeys(t *testing.T) {
	alice, err := NewPQXDHState(1)
	if err != nil {
		t.Fatalf("NewPQXDHState alice: %v", err)
	}
	bob, err := NewPQXDHState(2)
	if err != nil {
		t.Fatalf("NewPQXDHState bob: %v", err)
	}
	if err := bob.generateOneTimeKEMKeys(1); err != nil {
		t.Fatalf("generateOneTimeKEMKeys: %v", err)
	}
	if err := bob.generateOneTimePrekeys(1); err != nil {
		t.Fatalf("generateOneTimePrekeys: %v", err)
	}
	var kemID idKEM
	var encap *mlkem.EncapsulationKey1024
	for id, k := range bob.oneTimeKEMKeys {
		kemID = id
		encap = k.encap
		break
	}
	var otpkID uint32
	var otpk *oneTimePreKey
	for id, k := range bob.oneTimePrekeys {
		otpkID = id
		otpk = k
		break
	}
	bundle, err := bob.makeBundle(kemID, encap, &otpkID, otpk)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	h, err := bundle.hash()
	if err != nil {
		t.Fatalf("bundle hash: %v", err)
	}
	bundle.bundleHash = h
	rkA, init, err := alice.keyExchange(bundle)
	if err != nil {
		t.Fatalf("alice.keyExchange: %v", err)
	}
	res, err := bob.recvKeyExchange(init)
	if err != nil {
		t.Fatalf("bob.recvKeyExchange: %v", err)
	}
	if !bytes.Equal(rkA, res.rootKey) {
		t.Fatalf("root keys differ")
	}
	if !bytes.Equal(init.ad, res.ad) {
		t.Fatalf("additional data differ")
	}
	if _, ok := bob.oneTimeKEMKeys[kemID]; ok {
		t.Fatalf("one-time KEM not consumed")
	}
	if _, ok := bob.oneTimePrekeys[otpkID]; ok {
		t.Fatalf("one-time prekey not consumed")
	}
}

func TestKeyExchangeWithLastResortKEM(t *testing.T) {
	alice, err := NewPQXDHState(1)
	if err != nil {
		t.Fatalf("NewPQXDHState alice: %v", err)
	}
	bob, err := NewPQXDHState(2)
	if err != nil {
		t.Fatalf("NewPQXDHState bob: %v", err)
	}
	bundle, err := bob.makeBundle(bob.lastResortKEMid, bob.lastResortKEMencap, nil, nil)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	h, err := bundle.hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	bundle.bundleHash = h
	rkA, init, err := alice.keyExchange(bundle)
	if err != nil {
		t.Fatalf("alice.keyExchange: %v", err)
	}
	res, err := bob.recvKeyExchange(init)
	if err != nil {
		t.Fatalf("bob.recvKeyExchange: %v", err)
	}
	if !bytes.Equal(rkA, res.rootKey) {
		t.Fatalf("root keys differ")
	}
	if !bytes.Equal(init.ad, res.ad) {
		t.Fatalf("additional data differ")
	}
	if !bob.lastResortKEMid.eq(init.targetEncapID) {
		t.Fatalf("wrong KEM id used")
	}
}

func TestKeyExchangeRejectsBadBundleHash(t *testing.T) {
	alice, err := NewPQXDHState(1)
	if err != nil {
		t.Fatalf("NewPQXDHState alice: %v", err)
	}
	bob, err := NewPQXDHState(2)
	if err != nil {
		t.Fatalf("NewPQXDHState bob: %v", err)
	}
	bundle, err := bob.makeBundle(bob.lastResortKEMid, bob.lastResortKEMencap, nil, nil)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	bundle.bundleHash = []byte("bad")
	_, _, err = alice.keyExchange(bundle)
	if err == nil {
		t.Fatalf("expected error for bad bundle hash")
	}
}
