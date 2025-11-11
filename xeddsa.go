package pqxdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"filippo.io/edwards25519"
)

// ErrInvalidX25519PublicKey is returned when the X25519 public key can't be mapped to a valid Edwards point.
var ErrInvalidX25519PublicKey = errors.New("xeddsa: invalid X25519 public key")

// p = 2^255 - 19
var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	p.Sub(p, big.NewInt(19))
	return p
}()

// VerifyWithX25519 verifies an XEd25519 signature using X25519 public key.
// It deterministically maps the Montgomery u-coordinate to an Ed25519 public key A
// (with sign bit cleared).
func VerifyWithX25519(pub *ecdh.PublicKey, msg, sig []byte) bool {
	if pub == nil || len(sig) != 64 {
		return false
	}

	A, err := Ed25519PublicKeyFromX25519(pub.Bytes())
	if err != nil {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(A), msg, sig)
}

// VerifyWithA verifies an XEd25519 signature given the Ed25519-compatible public key A
// (i.e., the 32-byte key with the sign bit cleared) returned by Sign.
func VerifyWithA(A, msg, sig []byte) bool {
	if len(A) != 32 || len(sig) != 64 {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(A), msg, sig)
}

// Ed25519PublicKeyFromX25519 maps a 32-byte X25519 public key (Montgomery u)
// to a 32-byte Ed25519 public key A (compressed Edwards y with sign bit 0).
// A is suitable for crypto/ed25519.Verify(A, msg, sig).
func Ed25519PublicKeyFromX25519(uMont []byte) ([]byte, error) {
	if len(uMont) != 32 {
		return nil, ErrInvalidX25519PublicKey
	}

	// Compute y = (u - 1) / (u + 1) mod p.
	y := montgomeryUToEdwardsY(uMont)
	if y == nil {
		return nil, ErrInvalidX25519PublicKey
	}

	A := make([]byte, 32)
	copy(A, y)
	A[31] &^= 0x80 // force sign bit to 0

	if _, err := new(edwards25519.Point).SetBytes(A); err != nil {
		return nil, ErrInvalidX25519PublicKey
	}

	return A, nil
}

// montgomeryUToEdwardsY returns y = (u-1)/(u+1) mod p encoded little-endian.
// Returns nil if u == -1 (mod p) or the inverse doesn't exist.
func montgomeryUToEdwardsY(uLe []byte) []byte {
	u := leToBig(uLe)
	p := new(big.Int).Set(p25519)

	u.Mod(u, p)
	one := big.NewInt(1)

	up1 := new(big.Int).Add(u, one)
	up1.Mod(up1, p)
	if up1.Sign() == 0 {
		// u == -1 mod p → denominator is 0 → not on the map
		return nil
	}

	um1 := new(big.Int).Sub(u, one)
	um1.Mod(um1, p)

	inv := new(big.Int).ModInverse(up1, p)
	if inv == nil {
		return nil
	}

	y := new(big.Int).Mul(um1, inv)
	y.Mod(y, p)
	return bigToLe(y, 32)
}

func leToBig(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

func bigToLe(x *big.Int, size int) []byte {
	be := x.Bytes()
	le := make([]byte, size)
	for i := 0; i < len(be) && i < size; i++ {
		le[i] = be[len(be)-1-i]
	}
	return le
}

// Sign signs msg with the given Go stdlib ECDH X25519 private key.
// It returns a 64-byte Ed25519-compatible signature (R || s) and the 32-byte
// Ed25519 public key A (with sign bit cleared), suitable for crypto/ed25519.Verify.
// Per XEdDSA, signatures are randomized.
func Sign(priv *ecdh.PrivateKey, msg []byte) (sig []byte, A []byte, err error) {
	Z := make([]byte, 64)
	if _, err := rand.Read(Z); err != nil {
		return nil, nil, err
	}

	return SignWithZ(priv, msg, Z)
}

// SignWithZ is like Sign but lets callers provide the 64-byte secret random Z
// required by XEdDSA.
func SignWithZ(priv *ecdh.PrivateKey, msg, Z []byte) (sig []byte, A []byte, err error) {
	if priv == nil {
		return nil, nil, errors.New("xeddsa: nil private key")
	}
	sk := priv.Bytes()
	if len(sk) != 32 {
		return nil, nil, errors.New("xeddsa: expected 32-byte X25519 private key")
	}
	if len(Z) != 64 {
		return nil, nil, errors.New("xeddsa: Z must be 64 bytes")
	}

	// derive the Montgomery scalar k by applying X25519 clamping to sk.
	kClamped := clampX25519(sk)

	// calculate_key_pair(k): E = kB, A.y = E.y, A.s = 0; a = +/- k (mod q).
	kScalar := scalarFromLittle256(kClamped) // reduce mod l (q) in constant-time
	E := edwards25519.NewGeneratorPoint().ScalarBaseMult(kScalar)
	Eenc := E.Bytes() // Ed25519 compressed point (y || signbit)
	Aenc := make([]byte, 32)
	copy(Aenc, Eenc)
	Aenc[31] &^= 0x80 // force sign bit to 0
	A = Aenc

	a := edwards25519.NewScalar().Set(kScalar)
	if (Eenc[31] & 0x80) != 0 {
		// if E.s == 1 then a = -k (mod q).
		a.Negate(a)
	}

	// r = H1(a || M || Z) mod q (domain-separated SHA-512)
	r := hash1ToScalar(append(append(a.Bytes(), msg...), Z...))

	// R = rB
	R := edwards25519.NewGeneratorPoint().ScalarBaseMult(r)
	Renc := R.Bytes()

	// h = H(R || A || M) mod q  (plain SHA-512 per spec)
	h := hashToScalar(bytes.Join([][]byte{Renc, Aenc, msg}, nil))

	// s = r + h*a (mod q)
	s := edwards25519.NewScalar().MultiplyAdd(h, a, r)

	// sig = R || s
	sig = append(append(make([]byte, 0, 64), Renc...), s.Bytes()...)
	return sig, A, nil
}

// clampX25519 applies RFC7748 clamping to a 32-byte X25519 private key.
// This mirrors crypto/ecdh's internal x25519ScalarMult clamping.
func clampX25519(in []byte) []byte {
	out := make([]byte, 32)
	copy(out, in)
	out[0] &^= 7 // clear bits 0..2
	out[31] &^= 0x80
	out[31] |= 0x40
	return out
}

// scalarFromLittle256 interprets a 32-byte little-endian integer and reduces it mod l.
// It uses SetUniformBytes with a 64-byte input (value || zero pad) to stay constant-time.
func scalarFromLittle256(x32 []byte) *edwards25519.Scalar {
	var x64 [64]byte
	copy(x64[:32], x32)
	s, _ := edwards25519.NewScalar().SetUniformBytes(x64[:])
	return s
}

// hash1ToScalar computes SHA-512 over (prefix || X) where prefix is 32 bytes:
// 0xFF repeated except first byte 0xFE for hash_1, then reduces mod l.
func hash1ToScalar(x []byte) *edwards25519.Scalar {
	prefix := bytes.Repeat([]byte{0xFF}, 32)
	prefix[0] = 0xFE // 2^256 - 1 - 1 in little-endian domain separation
	h := sha512.Sum512(append(prefix, x...))
	s, _ := edwards25519.NewScalar().SetUniformBytes(h[:])
	return s
}

// hashToScalar computes SHA-512(X) and reduces mod l.
func hashToScalar(x []byte) *edwards25519.Scalar {
	h := sha512.Sum512(x)
	s, _ := edwards25519.NewScalar().SetUniformBytes(h[:])
	return s
}
