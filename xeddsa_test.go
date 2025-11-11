package pqxdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"math/big"
	"testing"
)

func fixedZ(seed byte) []byte {
	z := make([]byte, 64)
	for i := range z {
		z[i] = seed + byte(i)
	}
	return z
}

func pMinusOneLE() []byte {
	pm1 := new(big.Int).Sub(p25519, big.NewInt(1))
	return bigToLe(pm1, 32)
}

func TestSignVerify_RoundTrip(t *testing.T) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("xeddsa round trip test")

	sig, A, err := SignWithZ(priv, msg, fixedZ(0x42))
	if err != nil {
		t.Fatalf("SignWithZ: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("got signature len=%d, want 64", len(sig))
	}
	if len(A) != 32 {
		t.Fatalf("got A len=%d, want 32", len(A))
	}

	if ok := VerifyWithX25519(priv.PublicKey(), msg, sig); !ok {
		t.Fatalf("VerifyWithX25519 failed on a valid signature")
	}

	if ok := VerifyWithA(A, msg, sig); !ok {
		t.Fatalf("VerifyWithA failed on a valid signature")
	}

	msg2 := append([]byte(nil), msg...)
	msg2[0] ^= 0x01
	if ok := VerifyWithX25519(priv.PublicKey(), msg2, sig); ok {
		t.Fatalf("VerifyWithX25519 should fail on a modified message")
	}

	badSig := append([]byte(nil), sig...)
	badSig[10] ^= 0x80
	if ok := VerifyWithA(A, msg, badSig); ok {
		t.Fatalf("VerifyWithA should fail on a modified signature")
	}

	AwithSign := append([]byte(nil), A...)
	AwithSign[31] |= 0x80
	if ok := VerifyWithA(AwithSign, msg, sig); ok {
		t.Fatalf("VerifyWithA should fail if A's sign bit is set")
	}
}

func TestEd25519PublicKeyFromX25519_AgreesWithSignOutputA(t *testing.T) {
	curve := ecdh.X25519()

	for i := range 8 {
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		_, AfromSign, err := SignWithZ(priv, []byte("map check"), fixedZ(byte(i)))
		if err != nil {
			t.Fatalf("SignWithZ: %v", err)
		}

		u := priv.PublicKey().Bytes()
		AfromU, err := Ed25519PublicKeyFromX25519(u)
		if err != nil {
			t.Fatalf("Ed25519PublicKeyFromX25519: %v", err)
		}

		if !bytes.Equal(AfromSign, AfromU) {
			t.Fatalf("A mismatch\nfrom Sign: %x\nfrom map : %x", AfromSign, AfromU)
		}
	}
}

func TestSign_RandomizedOutputsDiffer(t *testing.T) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("same message, different signatures expected")
	sig1, A1, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	sig2, A2, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}

	if !bytes.Equal(A1, A2) {
		t.Fatalf("A changed across signatures for same key")
	}
	if bytes.Equal(sig1, sig2) {
		t.Fatalf("two signatures on same message are identical; expected randomized R")
	}

	if !VerifyWithA(A1, msg, sig1) || !VerifyWithA(A2, msg, sig2) {
		t.Fatalf("randomized signatures should verify")
	}
}

func TestEd25519PublicKeyFromX25519_InvalidInputs(t *testing.T) {
	if _, err := Ed25519PublicKeyFromX25519(make([]byte, 31)); err == nil {
		t.Fatalf("expected error for 31-byte input")
	}
	if _, err := Ed25519PublicKeyFromX25519(make([]byte, 33)); err == nil {
		t.Fatalf("expected error for 33-byte input")
	}

	u := pMinusOneLE()
	if _, err := Ed25519PublicKeyFromX25519(u); err == nil {
		t.Fatalf("expected error for u == -1 mod p")
	}
}

func TestMontgomeryUToEdwardsY_EdgeCases(t *testing.T) {
	y := montgomeryUToEdwardsY(make([]byte, 32))
	if y == nil {
		t.Fatalf("expected y for u=0")
	}
	want := pMinusOneLE()
	if !bytes.Equal(y, want) {
		t.Fatalf("u=0 produced y=%x, want p-1=%x", y, want)
	}

	if res := montgomeryUToEdwardsY(pMinusOneLE()); res != nil {
		t.Fatalf("expected nil for u == -1 mod p, got %x", res)
	}
}

func TestClampX25519_Bits(t *testing.T) {
	in := bytes.Repeat([]byte{0xFF}, 32)
	out := clampX25519(in)

	if out[0]&0x07 != 0 {
		t.Fatalf("clamp: low 3 bits of byte 0 not cleared: %08b", out[0])
	}

	if out[31]&0x80 != 0 {
		t.Fatalf("clamp: high bit of byte 31 not cleared: %08b", out[31])
	}
	if out[31]&0x40 == 0 {
		t.Fatalf("clamp: bit 6 of byte 31 not set: %08b", out[31])
	}

	if !bytes.Equal(in, bytes.Repeat([]byte{0xFF}, 32)) {
		t.Fatalf("input slice modified by clampX25519")
	}
}

func TestSignWithZ_Errors(t *testing.T) {
	msg := []byte("msg")
	if _, _, err := SignWithZ(nil, msg, fixedZ(0)); err == nil {
		t.Fatalf("expected error on nil private key")
	}

	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, _, err := SignWithZ(priv, msg, make([]byte, 63)); err == nil {
		t.Fatalf("expected error on Z length != 64")
	}
}

func TestVerifyWithX25519_InvalidInputs(t *testing.T) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("hi")
	sig, _, err := SignWithZ(priv, msg, fixedZ(7))
	if err != nil {
		t.Fatalf("SignWithZ: %v", err)
	}

	if ok := VerifyWithX25519(nil, msg, sig); ok {
		t.Fatalf("expected false for nil public key")
	}

	if ok := VerifyWithX25519(priv.PublicKey(), msg, sig[:63]); ok {
		t.Fatalf("expected false for non-64-byte signature")
	}
}
