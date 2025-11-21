package pqxdh

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
	"time"
)

func TestKDFDeterministic(t *testing.T) {
	out1, err1 := kdf([]byte("km"), protocolInfo)
	if err1 != nil {
		t.Fatalf("pqxdhKDF: %v", err1)
	}
	out2, err2 := kdf([]byte("km"), protocolInfo)
	if err2 != nil {
		t.Fatalf("pqxdhKDF(2): %v", err2)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatalf("outputs differ")
	}
	if len(out1) != 32 {
		t.Fatalf("unexpected length: %d", len(out1))
	}
	out3, err3 := kdf([]byte("km"), "other")
	if err3 != nil {
		t.Fatalf("pqxdhKDF other: %v", err3)
	}
	if bytes.Equal(out1, out3) {
		t.Fatalf("outputs equal for different info")
	}
}

func TestBundleHashAndSignatures(t *testing.T) {
	receiver, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState: %v", err)
	}
	if err = receiver.GenerateOneTimeKEMKeys(1); err != nil {
		t.Fatalf("generateOneTimeKEMKeys: %v", err)
	}
	if err = receiver.GenerateOneTimePrekeys(1); err != nil {
		t.Fatalf("generateOneTimePrekeys: %v", err)
	}
	var kemID KEMID
	var encap *mlkem.EncapsulationKey1024
	for id, k := range receiver.OneTimeKEMKeys {
		kemID = id
		encap = k.Encap
		break
	}
	var otpkID uint32
	var otpk *OneTimePrekey
	for id, k := range receiver.OneTimePreKeys {
		otpkID = id
		otpk = k
		break
	}
	b, err := receiver.MakeBundle(kemID, encap, &otpkID, otpk)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	h, err := b.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	b.BundleHash = h
	ok, err := b.IsHashValid()
	if err != nil {
		t.Fatalf("isHashValid err: %v", err)
	}
	if !ok {
		t.Fatalf("hash invalid")
	}
	if err := b.VerifyBundleSignatures(); err != nil {
		t.Fatalf("verifyBundleSignatures: %v", err)
	}
	b.SignedPrekeySig[0] ^= 1
	if err := b.VerifyBundleSignatures(); err == nil {
		t.Fatalf("expected signature error")
	}
}

func TestKeyExchangeWithOneTimeKeys(t *testing.T) {
	alice, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState alice: %v", err)
	}
	bob, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState bob: %v", err)
	}
	if err = bob.GenerateOneTimeKEMKeys(1); err != nil {
		t.Fatalf("generateOneTimeKEMKeys: %v", err)
	}
	if err = bob.GenerateOneTimePrekeys(1); err != nil {
		t.Fatalf("generateOneTimePrekeys: %v", err)
	}
	var kemID KEMID
	var encap *mlkem.EncapsulationKey1024
	for id, k := range bob.OneTimeKEMKeys {
		kemID = id
		encap = k.Encap
		break
	}
	var otpkID uint32
	var otpk *OneTimePrekey
	for id, k := range bob.OneTimePreKeys {
		otpkID = id
		otpk = k
		break
	}
	bundle, err := bob.MakeBundle(kemID, encap, &otpkID, otpk)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	h, err := bundle.Hash()
	if err != nil {
		t.Fatalf("bundle hash: %v", err)
	}
	bundle.BundleHash = h
	rkA, init, err := alice.KeyExchange(bundle)
	if err != nil {
		t.Fatalf("alice.keyExchange: %v", err)
	}
	res, err := bob.ReceiveInitMessage(init)
	if err != nil {
		t.Fatalf("bob.recvKeyExchange: %v", err)
	}
	if !bytes.Equal(rkA, res.RootKey) {
		t.Fatalf("root keys differ")
	}
	if !bytes.Equal(init.AD, res.AD) {
		t.Fatalf("additional data differ")
	}
	if _, ok := bob.OneTimeKEMKeys[kemID]; ok {
		t.Fatalf("one-time KEM not consumed")
	}
	if _, ok := bob.OneTimePreKeys[otpkID]; ok {
		t.Fatalf("one-time prekey not consumed")
	}
}

func TestKeyExchangeWithLastResortKEM(t *testing.T) {
	alice, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState alice: %v", err)
	}
	bob, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState bob: %v", err)
	}
	bundle, err := bob.MakeBundle(bob.LastResortKEMid, bob.LastResortKEMencap, nil, nil)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	h, err := bundle.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	bundle.BundleHash = h
	rkA, init, err := alice.KeyExchange(bundle)
	if err != nil {
		t.Fatalf("alice.keyExchange: %v", err)
	}
	res, err := bob.ReceiveInitMessage(init)
	if err != nil {
		t.Fatalf("bob.recvKeyExchange: %v", err)
	}
	if !bytes.Equal(rkA, res.RootKey) {
		t.Fatalf("root keys differ")
	}
	if !bytes.Equal(init.AD, res.AD) {
		t.Fatalf("additional data differ")
	}
	if !bob.LastResortKEMid.Equals(init.TargetEncapID) {
		t.Fatalf("wrong KEM id used")
	}
}

func TestKeyExchangeRejectsBadBundleHash(t *testing.T) {
	alice, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState alice: %v", err)
	}
	bob, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState bob: %v", err)
	}
	bundle, err := bob.MakeBundle(bob.LastResortKEMid, bob.LastResortKEMencap, nil, nil)
	if err != nil {
		t.Fatalf("makeBundle: %v", err)
	}
	bundle.BundleHash = []byte("bad")
	_, _, err = alice.KeyExchange(bundle)
	if err == nil {
		t.Fatalf("expected error for bad bundle hash")
	}
}

func bundlesEqual(a, b *Bundle) bool {
	if a == nil || b == nil {
		return a == b
	}

	if a.Version != b.Version {
		return false
	}
	if !bytes.Equal(a.SigningPub, b.SigningPub) {
		return false
	}
	if !bytes.Equal(a.EncapID[:], b.EncapID[:]) {
		return false
	}
	if a.Encap == nil || b.Encap == nil {
		if a.Encap != b.Encap {
			return false
		}
	} else if !bytes.Equal(a.Encap.Bytes(), b.Encap.Bytes()) {
		return false
	}
	if !bytes.Equal(a.EncapSig, b.EncapSig) {
		return false
	}

	// OTPK (optional)
	if (a.OTPKID == nil) != (b.OTPKID == nil) {
		return false
	}
	if a.OTPKID != nil && b.OTPKID != nil && *a.OTPKID != *b.OTPKID {
		return false
	}
	if (a.OTPK == nil) != (b.OTPK == nil) {
		return false
	}
	if a.OTPK != nil && b.OTPK != nil && !bytes.Equal(a.OTPK.Bytes(), b.OTPK.Bytes()) {
		return false
	}
	if !bytes.Equal(a.OTPKSig, b.OTPKSig) {
		return false
	}

	if a.IdentityPK == nil || b.IdentityPK == nil {
		if a.IdentityPK != b.IdentityPK {
			return false
		}
	} else if !bytes.Equal(a.IdentityPK.Bytes(), b.IdentityPK.Bytes()) {
		return false
	}

	if a.SignedPrekeyPK == nil || b.SignedPrekeyPK == nil {
		if a.SignedPrekeyPK != b.SignedPrekeyPK {
			return false
		}
	} else if !bytes.Equal(a.SignedPrekeyPK.Bytes(), b.SignedPrekeyPK.Bytes()) {
		return false
	}
	if !bytes.Equal(a.SignedPrekeySig, b.SignedPrekeySig) {
		return false
	}

	if !bytes.Equal(a.BundleHash, b.BundleHash) {
		return false
	}

	return true
}

func TestBundleMarshalUnmarshal_NoOTPK(t *testing.T) {
	state, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState() error = %v", err)
	}

	// Use the last-resort KEM as the Encap for this bundle, no OTPK.
	bundle, err := state.MakeBundleWithIDs(state.LastResortKEMid, nil)
	if err != nil {
		t.Fatalf("MakeBundleWithIDs() error = %v", err)
	}

	// Compute & set BundleHash
	hash, err := bundle.Hash()
	if err != nil {
		t.Fatalf("bundle.Hash() error = %v", err)
	}
	bundle.BundleHash = hash

	// Marshal
	data, err := bundle.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal into a new Bundle
	var got Bundle
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	// Check all fields that should survive round-trip
	if !bundlesEqual(bundle, &got) {
		t.Fatalf("bundles not equal after round-trip")
	}

	// Sanity: signatures should still verify
	if err := got.VerifyBundleSignatures(); err != nil {
		t.Fatalf("VerifyBundleSignatures() after round-trip error = %v", err)
	}
}

func TestBundleMarshalUnmarshal_WithOTPK(t *testing.T) {
	state, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState() error = %v", err)
	}

	// Manually create a one-time prekey (don't rely on GenerateOneTimePrekeys,
	// so tests don't depend on its implementation details).
	otpPriv, err := defaultCurve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() for OTPK error = %v", err)
	}
	otpPub := otpPriv.PublicKey()

	pkSig, _, err := Sign(state.Identity.SK, otpPub.Bytes())
	if err != nil {
		t.Fatalf("Sign() for OTPK error = %v", err)
	}

	otpkIDVal := uint32(42)
	otpk := &OneTimePrekey{
		SK:        otpPriv,
		PK:        otpPub,
		PKSig:     pkSig,
		CreatedAt: time.Now().Unix(),
		UsedAt:    nil,
	}

	// Bundle using last resort KEM and this OTPK
	bundle, err := state.MakeBundle(state.LastResortKEMid, state.LastResortKEMencap, &otpkIDVal, otpk)
	if err != nil {
		t.Fatalf("MakeBundle() error = %v", err)
	}

	// Compute & set BundleHash
	hash, err := bundle.Hash()
	if err != nil {
		t.Fatalf("bundle.Hash() error = %v", err)
	}
	bundle.BundleHash = hash

	// Marshal
	data, err := bundle.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal into a new Bundle
	var got Bundle
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	// Check round-trip equality
	if !bundlesEqual(bundle, &got) {
		t.Fatalf("bundles not equal after round-trip with OTPK")
	}

	// Signatures should verify (signed-prekey, ML-KEM key, OTPK)
	if err := got.VerifyBundleSignatures(); err != nil {
		t.Fatalf("VerifyBundleSignatures() after round-trip with OTPK error = %v", err)
	}
}

func TestBundleUnmarshalBinary_Truncated(t *testing.T) {
	state, err := NewPQXDHState()
	if err != nil {
		t.Fatalf("NewPQXDHState() error = %v", err)
	}

	bundle, err := state.MakeBundleWithIDs(state.LastResortKEMid, nil)
	if err != nil {
		t.Fatalf("MakeBundleWithIDs() error = %v", err)
	}

	hash, err := bundle.Hash()
	if err != nil {
		t.Fatalf("bundle.Hash() error = %v", err)
	}
	bundle.BundleHash = hash

	data, err := bundle.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Truncate one byte from the end
	truncated := data[:len(data)-1]

	var got Bundle
	if err := got.UnmarshalBinary(truncated); err == nil {
		t.Fatalf("expected error from UnmarshalBinary() on truncated data, got nil")
	}
}
