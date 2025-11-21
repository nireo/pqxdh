// Package pqxdh implements the Post-Quantum Extended Diffie-Hellman based on the Signal specification.
// It corrently includes implementation of the XEdDSA to sign content using the identity keys of parties
// without having to rely on an extra keypair for signing and verifying.
//
// The descriptions of both algorithms can be found here:
//   - https://signal.org/docs/specifications/pqxdh/
//   - https://signal.org/docs/specifications/xeddsa/
package pqxdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// PQXDHVersion has a version for backwards compatibility and proper versioning
type PQXDHVersion uint8

var defaultCurve = ecdh.X25519()

const (
	protocolInfo = "PCH_CURVE25519_SHA-512_MLKEM-1024"

	tagECx25519     byte = 0x01
	tagMLKEM1024Pub byte = 0xA3
	tagMLKEM768Pub  byte = 0xA4

	pqxdhV1 PQXDHVersion = 1
)

var (
	ErrTLVTruncated  = errors.New("truncated TLV")
	ErrTLVLenOverrun = errors.New("TLV length overrun")
	ErrTLVTrailing   = errors.New("trailing bytes after TLV")
	ErrBadTag        = errors.New("unexpected tag")
)

func encodeTLV(tag byte, v []byte) []byte {
	if len(v) > 0xFFFF {
		panic("value too large for 2-byte length")
	}

	out := make([]byte, 1+2+len(v))
	out[0] = tag
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(v)))
	copy(out[3:], v)

	return out
}

func decodeTLV(b []byte) (tag byte, val []byte, rest []byte, err error) {
	if len(b) < 3 {
		return 0, nil, nil, ErrTLVTruncated
	}
	tag = b[0]
	n := int(binary.LittleEndian.Uint16(b[1:3]))
	if len(b) < 3+n {
		return 0, nil, nil, ErrTLVLenOverrun
	}

	val = b[3 : 3+n]
	rest = b[3+n:]
	return
}

func EncodeEC(pk *ecdh.PublicKey) []byte {
	return encodeTLV(tagECx25519, pk.Bytes())
}

func EncodeKEM1024(pk *mlkem.EncapsulationKey1024) []byte {
	return encodeTLV(tagMLKEM1024Pub, pk.Bytes())
}

func DecodeECX25519(b []byte) (*ecdh.PublicKey, error) {
	tag, val, rest, err := decodeTLV(b)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, ErrTLVTrailing
	}

	if tag != tagECx25519 {
		return nil, fmt.Errorf("%w: got 0x%02x want 0x%02x", ErrBadTag, tag, tagECx25519)
	}

	if len(val) != 32 {
		return nil, fmt.Errorf("bad X25519 public key length: got %d want 32", len(val))
	}

	pk, err := ecdh.X25519().NewPublicKey(val)
	if err != nil {
		return nil, fmt.Errorf("X25519 NewPublicKey: %w", err)
	}

	return pk, nil
}

func DecodeKEM1024(b []byte) (*mlkem.EncapsulationKey1024, error) {
	tag, val, rest, err := decodeTLV(b)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, ErrTLVTrailing
	}

	if tag != tagMLKEM1024Pub {
		return nil, fmt.Errorf("%w: got 0x%02x want 0x%02x", ErrBadTag, tag, tagMLKEM1024Pub)
	}

	if len(val) != mlkem.EncapsulationKeySize1024 {
		return nil, fmt.Errorf(
			"bad ML-KEM-1024 public key length: got %d want %d",
			len(val), mlkem.EncapsulationKeySize1024,
		)
	}

	pk, err := mlkem.NewEncapsulationKey1024(val)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM NewEncapsulationKey1024: %w", err)
	}

	return pk, nil
}

// KEMID is a server-addressable id for a KEM key
type KEMID [16]byte

// Equals checks if a given kemID is equivalent to this
func (id KEMID) Equals(other KEMID) bool {
	return bytes.Equal(id[:], other[:])
}

// OneTimeKEMKey contains a single-use KEM key that is supposed to be used only once per pqxdh run
// the user however has a last-resort mlkem key such that the post-quantum security is preserved
//
// Since the XEdDSA signatures are based on a random Z we want to store the signature which is then
// used to reconstruct the bundle hash.
type OneTimeKEMKey struct {
	// mlkem keys
	Decap *mlkem.DecapsulationKey1024
	Encap *mlkem.EncapsulationKey1024

	EncapSig  []byte
	CreatedAt int64
	UsedAt    *time.Time
}

// OneTimePrekey are elliptic curve keys that should be used (if available) for each pqxdh run.
// similar to the one time kem keys they should only be used one and then discarded. the receiver
// uses the private key in their key exchange and the iniator uses the public key when initiating
// the key exhange.
//
// Since the XEdDSA signatures are based on a random Z we want to store the signature which is then
// used to reconstruct the bundle hash.
type OneTimePrekey struct {
	SK *ecdh.PrivateKey
	PK *ecdh.PublicKey

	PKSig     []byte
	CreatedAt int64
	UsedAt    *time.Time
}

// Identity contains the identity for a given local user. The identity keys should stay the same
type Identity struct {
	// identity static DH (X25519)
	PK *ecdh.PublicKey
	SK *ecdh.PrivateKey

	// a XEdDSA verification key derived from the sk and only user for ed25519 verify.
	SigningPub ed25519.PublicKey
}

// Bundle contains all of the information needed for the iniator to begin key exhange. all of the
// information in this struct is public meaning that in real usage this is populated by a server.
type Bundle struct {
	SigningPub ed25519.PublicKey
	Encap      *mlkem.EncapsulationKey1024 // public KEM key (either last-resort or one-time use)
	EncapSig   []byte                      // signed by Bob’s identity signing key
	EncapID    KEMID                       // id to reference in init

	// classical one-time (optional; server deletes after handing out)
	OTPKID  *uint32
	OTPK    *ecdh.PublicKey // optional public X25519 key
	OTPKSig []byte

	IdentityPK      *ecdh.PublicKey // identity key
	SignedPrekeyPK  *ecdh.PublicKey // signed prekey
	SignedPrekeySig []byte          // identity key signature of signed prekey

	Version    PQXDHVersion
	BundleHash []byte
}

// State represents a user in pqxdh a user can initiate a key exchange or it accept key exchange
// requests to create a shared secret. this struct constains private key which should obviously kept secret.
type State struct {
	Identity Identity

	// classical signed prekey
	SignedPrekeySK  *ecdh.PrivateKey
	SignedPrekeyPK  *ecdh.PublicKey
	SignedPrekeySig []byte

	// classical one-time prekeys (many; keyed by server-visible id)
	OneTimePreKeys map[uint32]*OneTimePrekey

	// PQ one-time KEM keys (many; keyed by idKEM)
	OneTimeKEMKeys map[KEMID]*OneTimeKEMKey

	// PQ signed prekey (last resort) secret half lives locally
	LastResortKEMdecap *mlkem.DecapsulationKey1024
	LastResortKEMencap *mlkem.EncapsulationKey1024
	LastResortKEMid    KEMID
	LastResortSig      []byte

	Version   PQXDHVersion
	CreatedAt int64
}

type InitMessage struct {
	BundleHash []byte
	AD         []byte

	IdentityPK    *ecdh.PublicKey
	EphemeralPK   *ecdh.PublicKey
	OTPKUsedID    *uint32
	TargetEncapID KEMID
	EncapCT       []byte

	Payload []byte
}

// NewPQXDHState constructs a PQXDH state by generating needed keys
func NewPQXDHState() (*State, error) {
	ikSK, err := defaultCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	spkSK, err := defaultCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	spkSig, A, err := Sign(ikSK, spkSK.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	decap, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}

	var kemID KEMID
	if _, err = rand.Read(kemID[:]); err != nil {
		return nil, err
	}

	lastResortSig, _, err := Sign(ikSK, decap.EncapsulationKey().Bytes())
	if err != nil {
		return nil, err
	}

	return &State{
		Identity: Identity{
			SigningPub: ed25519.PublicKey(A),
			PK:         ikSK.PublicKey(),
			SK:         ikSK,
		},
		SignedPrekeySK:     spkSK,
		SignedPrekeyPK:     spkSK.PublicKey(),
		SignedPrekeySig:    spkSig,
		OneTimePreKeys:     make(map[uint32]*OneTimePrekey),
		OneTimeKEMKeys:     make(map[KEMID]*OneTimeKEMKey),
		LastResortKEMdecap: decap,
		LastResortKEMencap: decap.EncapsulationKey(),
		LastResortKEMid:    kemID,
		LastResortSig:      lastResortSig,
		Version:            pqxdhV1,
		CreatedAt:          time.Now().Unix(),
	}, nil
}

// GenerateOneTimeKEMKeys generates MLKEM keys that must only be used once. If the state does not contain
// enough of these then the last-resort MLKEM key must be used. The encapsulation key should be sent to
// a server and the decapsulation key kept private. Also the server needs the ID of the key.
func (ps *State) GenerateOneTimeKEMKeys(n int) error {
	for range n {
		decap, err := mlkem.GenerateKey1024()
		if err != nil {
			return err
		}
		encap := decap.EncapsulationKey()

		// create a random identifier for the kem key that the server can use
		var id KEMID
		_, err = rand.Read(id[:])
		if err != nil {
			return err
		}

		encapSig, _, err := Sign(ps.Identity.SK, encap.Bytes())
		if err != nil {
			return fmt.Errorf("failed to sign encapsulation key: %w", err)
		}

		ps.OneTimeKEMKeys[id] = &OneTimeKEMKey{
			Decap:     decap,
			Encap:     encap,
			EncapSig:  encapSig,
			CreatedAt: time.Now().Unix(),
			UsedAt:    nil,
		}
	}

	return nil
}

// randomUint32 generates a random uint32 using a cryptographic random number generator.
func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// GenerateOneTimePrekeys generates optional one-time prekeys that can be used in a single PQXDH run. They
// are optional, but they increase the security of the protocol. Obviously, only the ID and public key should
// be sent to the server.
func (ps *State) GenerateOneTimePrekeys(n int) error {
	for range n {
		otpPriv, err := defaultCurve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate otp: %w", err)
		}
		pk := otpPriv.PublicKey()

		// this ID is given in the initial message such that the receiver can determinte the correct private key.
		id, err := randomUint32()
		if err != nil {
			return err
		}

		pksig, _, err := Sign(ps.Identity.SK, pk.Bytes())
		if err != nil {
			return fmt.Errorf("failed to sign encapsulation key: %w", err)
		}

		// the private key needs to stored in-case the process actually uses the one-time public key such that
		// we can perform the key exchange on the receiver end.
		ps.OneTimePreKeys[id] = &OneTimePrekey{
			SK:        otpPriv,
			PK:        pk,
			PKSig:     pksig,
			CreatedAt: time.Now().Unix(),
			UsedAt:    nil,
		}
	}

	return nil
}

// IsHashValid that the content of the bundleHash match the content in the bundle when hashed.
func (b *Bundle) IsHashValid() (bool, error) {
	got, err := b.Hash()
	if err != nil {
		return false, err
	}

	return bytes.Equal(got, b.BundleHash), nil
}

// Hash hashes the content of the bundle
func (b *Bundle) Hash() ([]byte, error) {
	h := sha512.New()

	if b.Encap == nil || b.IdentityPK == nil || b.SignedPrekeyPK == nil {
		return nil, errors.New("required fields are nil for hashing")
	}

	h.Write([]byte{byte(b.Version)})
	h.Write(b.IdentityPK.Bytes())

	h.Write(b.SignedPrekeyPK.Bytes())
	h.Write(b.SignedPrekeySig)

	h.Write(b.Encap.Bytes())
	h.Write(b.EncapID[:])
	h.Write(b.EncapSig)

	if b.OTPK != nil {
		h.Write(b.OTPK.Bytes())
		h.Write(b.OTPKSig)
	}

	return h.Sum(nil), nil
}

// findMLKEM finds for a given id the MLKEM key. it also checks the last resort kem key otherwise defaulting to the
// one time kem keys. it returns an error only when nothing is found.
func (ps *State) findMLKEM(id KEMID) (*mlkem.DecapsulationKey1024, *mlkem.EncapsulationKey1024, error) {
	if id.Equals(ps.LastResortKEMid) {
		return ps.LastResortKEMdecap, ps.LastResortKEMencap, nil
	}

	if kp, ok := ps.OneTimeKEMKeys[id]; ok {
		return kp.Decap, kp.Encap, nil
	} else {
		return nil, nil, fmt.Errorf("kem key not found with id: %x", id)
	}
}

// findOtpk find for a given id the one-time pre key it returns an error when nothing is found.
func (ps *State) findOtpk(id uint32) (*OneTimePrekey, error) {
	if k, ok := ps.OneTimePreKeys[id]; ok {
		return k, nil
	}

	return nil, fmt.Errorf("one time prekey id [%d] not found", id)
}

// MakeBundleWithIDs creates a bundle just from given IDs. This can be used when the keys have not yet been fetched.
// to make the exposed API cleaner.
func (ps *State) MakeBundleWithIDs(encapID KEMID, otpkID *uint32) (*Bundle, error) {
	bundle := &Bundle{
		SigningPub:      ps.Identity.SigningPub,
		IdentityPK:      ps.Identity.PK,
		SignedPrekeyPK:  ps.SignedPrekeyPK,
		SignedPrekeySig: ps.SignedPrekeySig,
		Version:         pqxdhV1,
	}

	if otpkID != nil {
		otpk, ok := ps.OneTimePreKeys[*otpkID]
		if !ok {
			return nil, fmt.Errorf("one-time prekey with id %d not found", *otpkID)
		}
		bundle.OTPKID = otpkID
		bundle.OTPK = otpk.PK
		bundle.OTPKSig = otpk.PKSig
	}

	if encapID.Equals(ps.LastResortKEMid) {
		bundle.EncapSig = ps.LastResortSig
		bundle.EncapID = ps.LastResortKEMid
		bundle.Encap = ps.LastResortKEMencap
	} else if k, ok := ps.OneTimeKEMKeys[encapID]; ok {
		bundle.EncapSig = k.EncapSig
		bundle.Encap = k.Encap
		bundle.EncapID = encapID
	} else {
		return nil, fmt.Errorf("MLKEM not found for KEM id %x", encapID)
	}

	return bundle, nil
}

// MakeBundle constructs a given bundle from a pqxdh state. It can be used for both testing and then
// when we want as the receiver construct a bundle to check the bundle hash. the only error this will
// return is when either kemID or otpkID are not found.
func (ps *State) MakeBundle(encapID KEMID, encap *mlkem.EncapsulationKey1024, otpkID *uint32, otpk *OneTimePrekey) (*Bundle, error) {
	bundle := &Bundle{
		SigningPub:      ps.Identity.SigningPub,
		IdentityPK:      ps.Identity.PK,
		SignedPrekeyPK:  ps.SignedPrekeyPK,
		SignedPrekeySig: ps.SignedPrekeySig,
		Version:         pqxdhV1,
	}

	if otpkID != nil && otpk != nil {
		bundle.OTPKID = otpkID
		bundle.OTPK = otpk.PK
		bundle.OTPKSig = otpk.PKSig
	}

	if encap == nil {
		return nil, errors.New("encapsulation key is nil")
	}

	bundle.Encap = encap
	bundle.EncapID = encapID

	// choose correct stored signature
	if encapID.Equals(ps.LastResortKEMid) {
		bundle.EncapSig = ps.LastResortSig
	} else if k, ok := ps.OneTimeKEMKeys[encapID]; ok {
		bundle.EncapSig = k.EncapSig
	} else {
		return nil, fmt.Errorf("no stored signature for KEM id %x", encapID)
	}

	return bundle, nil
}

func kdf(km []byte, info string) ([]byte, error) {
	// HKDF salt = A zero-filled byte sequence with length equal to the hash
	// output length
	hash := sha512.New
	salt := make([]byte, 32)
	f := slices.Repeat([]byte{0xFF}, 32)

	inputKeyMaterial := append(f, km...)
	hkdfKey, err := hkdf.Key(hash, inputKeyMaterial, salt, info, 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf.Key failed: %s", err)
	}

	return hkdfKey, nil
}

// VerifyBundleSignatures verifies that the bundle keys were signed using the given identity key.
// For signing it uses the XEdDSA implementation to convert a identity DH key to a signing key.
// It throws an error if one of the signatures is invalid.
func (b *Bundle) VerifyBundleSignatures() error {
	if b == nil {
		return errors.New("nil bundle")
	}

	if b.SigningPub == nil || len(b.SigningPub) != ed25519.PublicKeySize {
		return errors.New("missing or bad signingPub")
	}

	if b.SignedPrekeyPK == nil || len(b.SignedPrekeySig) != ed25519.SignatureSize {
		return errors.New("missing signed-prekey or signature")
	}

	if !ed25519.Verify(b.SigningPub, b.SignedPrekeyPK.Bytes(), b.SignedPrekeySig) {
		return errors.New("invalid signature on signed-prekey")
	}

	if b.Encap == nil || len(b.EncapSig) != ed25519.SignatureSize {
		return errors.New("missing ML-KEM key or signature")
	}
	if !ed25519.Verify(b.SigningPub, b.Encap.Bytes(), b.EncapSig) {
		return errors.New("invalid signature on ML-KEM key")
	}

	if b.OTPK != nil {
		if len(b.OTPKSig) != ed25519.SignatureSize {
			return errors.New("missing one-time prekey signature")
		}
		if !ed25519.Verify(b.SigningPub, b.OTPK.Bytes(), b.OTPKSig) {
			return errors.New("invalid signature on one-time prekey")
		}
	}

	return nil
}

// additionalDataAsInitiator constructs the additional data as the party initiating the key exchange.
// We cannot use this on the receiver end as the order of the elements needs to be the same. such that
// both parties have the same additional data.
func (ps *State) additionalDataAsInitiator(bundle *Bundle) []byte {
	ad := make([]byte, 0, 32*2+mlkem.EncapsulationKeySize1024)
	ad = append(ad, ps.Identity.PK.Bytes()...)    // IK_A
	ad = append(ad, bundle.IdentityPK.Bytes()...) // IK_B

	ad = append(ad, bundle.Encap.Bytes()...) // PQPK_B
	ad = append(ad, bundle.BundleHash...)
	return ad
}

// additionalDataAsReceiver calculates the additional data from the receiver side. It ensures that the
// order of elements is the same as on the initiator side.
func (ps *State) additionalDataAsReceiver(
	encap *mlkem.EncapsulationKey1024,
	idpk *ecdh.PublicKey,
	bundleHash []byte,
) []byte {
	ad := make([]byte, 0, 32*2+mlkem.EncapsulationKeySize1024+len(bundleHash))
	ad = append(ad, idpk.Bytes()...)           // IK_A
	ad = append(ad, ps.Identity.PK.Bytes()...) // IK_B
	ad = append(ad, encap.Bytes()...)          // PQPK_B
	ad = append(ad, bundleHash...)

	return ad
}

// KeyExchange consumes a bundle and returns derived secret and a initial message that will be sent to the
// receiver. The initial message contains all of the data that the receiver needs in order to complete
// the key exchange process. This method also ensures that the signatures and information provided in the bundle
// is trustworthy by using the identity key to verify signatures and calculating a bundle hash and comparing the hash
// to the content.
func (ps *State) KeyExchange(bundle *Bundle) ([]byte, *InitMessage, error) {
	if bundle == nil {
		return nil, nil, errors.New("nil bundle")
	}
	if bundle.IdentityPK == nil || bundle.SignedPrekeyPK == nil || bundle.Encap == nil {
		return nil, nil, errors.New("bundle missing required keys")
	}

	bhash, err := bundle.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("bundle hash compute failed: %w", err)
	}

	if !bytes.Equal(bhash, bundle.BundleHash) {
		return nil, nil, errors.New("bundle hash not okay")
	}

	err = bundle.VerifyBundleSignatures()
	if err != nil {
		return nil, nil, err
	}

	// DH1 = IK_A x SPK_B
	dh1, err := ps.Identity.SK.ECDH(bundle.SignedPrekeyPK)
	if err != nil {
		return nil, nil, fmt.Errorf("DH1 (IK_AxSPK_B) failed: %w", err)
	}

	// generate the ephemeral key only used for this session
	ephPriv, err := defaultCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ephemeral key gen failed: %w", err)
	}

	// DH2 = EK_A x IK_B
	dh2, err := ephPriv.ECDH(bundle.IdentityPK)
	if err != nil {
		return nil, nil, fmt.Errorf("DH2 (EK_AxIK_B) failed: %w", err)
	}

	// DH3 = EK_A x SPK_B
	dh3, err := ephPriv.ECDH(bundle.SignedPrekeyPK)
	if err != nil {
		return nil, nil, fmt.Errorf("DH3 (EK_AxSPK_B) failed: %w", err)
	}

	// Optional DH4 = EK_A x OPK_B
	var dh4 []byte
	if bundle.OTPK != nil {
		dh4, err = ephPriv.ECDH(bundle.OTPK)
		if err != nil {
			return nil, nil, fmt.Errorf("DH4 (EK_AxOPK_B) failed: %w", err)
		}
	}

	pqSS, ct := bundle.Encap.Encapsulate()

	var km []byte
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	if len(dh4) > 0 {
		km = append(km, dh4...)
	}
	km = append(km, pqSS...)

	rootKey, err := kdf(km, protocolInfo)
	if err != nil {
		return nil, nil, err
	}

	initContent := &InitMessage{
		// hash of the bundle that alice used to derive the shared secret
		BundleHash:    bhash,
		AD:            ps.additionalDataAsInitiator(bundle),
		IdentityPK:    ps.Identity.PK,
		TargetEncapID: bundle.EncapID,
		EncapCT:       ct,
		EphemeralPK:   ephPriv.PublicKey(),
	}

	if bundle.OTPKID != nil && bundle.OTPK != nil {
		initContent.OTPKUsedID = bundle.OTPKID
	}

	return rootKey, initContent, nil
}

// checkBundleAsReceiver calculates the bundle hash based on what alice has used. it will also
// be added into the additional information so it needs to match.
func (ps *State) checkBundleAsReceiver(
	usedBundleHash []byte,
	kemUsed *mlkem.EncapsulationKey1024,
	kemID KEMID, otpkID *uint32,
	otpk *OneTimePrekey,
) ([]byte, error) {
	bundle, err := ps.MakeBundle(kemID, kemUsed, otpkID, otpk)
	if err != nil {
		return nil, fmt.Errorf("failed to construct bundle: %s", err)
	}

	hash, err := bundle.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate bundle hash %s", err)
	}

	if !bytes.Equal(hash, usedBundleHash) {
		return nil, errors.New("bundle hash didn't match")
	}

	return hash, nil
}

// KeyExchangeResult contains the result of the key exchange on one side. The information here can be then fed
// to for example the double ratchet algorithm.
type KeyExchangeResult struct {
	RootKey []byte
	AD      []byte
}

// ReceiveInitMessage handles the receiver end in a key exchange process. It validates a given bundle and that the
// keys used in the bundle do infact exist. It validates the bundle signature and that the content of the bundle is
// signed by the identity key provided in the bundle.
//
// This method takes care of removing the used one-time MLKEM and one-time prekeys if needed. It returns the final
// shared secret and the additional data which then be used to encrypt data securely between the two parties.
func (ps *State) ReceiveInitMessage(init *InitMessage) (*KeyExchangeResult, error) {
	if init == nil {
		return nil, errors.New("nil init")
	}

	if init.IdentityPK == nil || init.EphemeralPK == nil {
		return nil, errors.New("init missing identity or ephemeral key")
	}

	// the function needs the decap and encap so we call it here and pass it through functions.
	// not the cleanest approach.
	// TODO: make the bundle checking a bit more sane.
	decap, encap, err := ps.findMLKEM(init.TargetEncapID)
	if err != nil {
		return nil, fmt.Errorf("failed to find used KEM key: %s", err)
	}

	if len(init.EncapCT) != mlkem.CiphertextSize1024 {
		return nil, fmt.Errorf("bad KEM ciphertext: got %d, want %d",
			len(init.EncapCT), mlkem.CiphertextSize1024)
	}

	var otpk *OneTimePrekey
	if init.OTPKUsedID != nil {
		otpk, err = ps.findOtpk(*init.OTPKUsedID)
		if err != nil {
			return nil, fmt.Errorf("one time private key used but not found: %s", err)
		}
	}

	// validate that the bundle content is correct. this obviously cannot validate the server that provided the bundle
	// did not forge it to create a key exchange here with the receiver. the security is based on the fact that the party
	// can through some other channel verify the authenticity of the identity key that provided the bundle.
	bundleHash, err := ps.checkBundleAsReceiver(init.BundleHash, encap, init.TargetEncapID, init.OTPKUsedID, otpk)
	if err != nil {
		return nil, err
	}

	dh1, err := ps.SignedPrekeySK.ECDH(init.IdentityPK)
	if err != nil {
		return nil, fmt.Errorf("DH1 SPK_BxIK_A failed: %w", err)
	}

	dh2, err := ps.Identity.SK.ECDH(init.EphemeralPK)
	if err != nil {
		return nil, fmt.Errorf("DH1 IK_BxEPH failed: %w", err)
	}

	dh3, err := ps.SignedPrekeySK.ECDH(init.EphemeralPK)
	if err != nil {
		return nil, fmt.Errorf("DH1 SPK_BxEPH failed: %w", err)
	}

	var dh4 []byte
	if otpk != nil {
		dh4, err = otpk.SK.ECDH(init.EphemeralPK)
		if err != nil {
			return nil, fmt.Errorf("DH1 OTPKxEPH failed: %w", err)
		}
	}

	pqSS, err := decap.Decapsulate(init.EncapCT)
	if err != nil {
		return nil, fmt.Errorf("kem decapsulation failed: %w", err)
	}

	var km []byte
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	if len(dh4) > 0 {
		km = append(km, dh4...)
	}
	km = append(km, pqSS...)

	rootKey, err := kdf(km, protocolInfo)
	if err != nil {
		return nil, err
	}

	ps.consumeKEMIfOneTime(init.TargetEncapID)
	ps.consumeOTPKIfUsed(init.OTPKUsedID)

	return &KeyExchangeResult{
		RootKey: rootKey,
		AD:      ps.additionalDataAsReceiver(encap, init.IdentityPK, bundleHash),
	}, nil
}

func (ps *State) consumeKEMIfOneTime(id KEMID) {
	if id.Equals(ps.LastResortKEMid) {
		return
	}

	if k, ok := ps.OneTimeKEMKeys[id]; ok {
		now := time.Now()
		k.UsedAt = &now
		delete(ps.OneTimeKEMKeys, id)
	}
}

// consumeOTPKIfUsed consumes a given id if it has been used. It changes the
func (ps *State) consumeOTPKIfUsed(id *uint32) {
	if id == nil {
		return
	}

	if k, ok := ps.OneTimePreKeys[*id]; ok {
		now := time.Now()
		k.UsedAt = &now
		delete(ps.OneTimePreKeys, *id)
	}
}

// MarshalBinary implements encoding.BinaryMarshaler for Bundle.
func (b *Bundle) MarshalBinary() ([]byte, error) {
	if b == nil {
		return nil, errors.New("nil bundle")
	}

	if len(b.SigningPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad signingPub length: got %d want %d", len(b.SigningPub), ed25519.PublicKeySize)
	}
	if b.IdentityPK == nil {
		return nil, errors.New("nil IdentityPK")
	}
	if b.SignedPrekeyPK == nil {
		return nil, errors.New("nil SignedPrekeyPK")
	}
	if len(b.SignedPrekeySig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("bad SignedPrekeySig length: got %d want %d", len(b.SignedPrekeySig), ed25519.SignatureSize)
	}
	if b.Encap == nil {
		return nil, errors.New("nil Encap")
	}
	if len(b.EncapSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("bad EncapSig length: got %d want %d", len(b.EncapSig), ed25519.SignatureSize)
	}

	hasOTPK := b.OTPK != nil || b.OTPKID != nil || b.OTPKSig != nil
	if hasOTPK {
		if b.OTPK == nil || b.OTPKID == nil {
			return nil, errors.New("inconsistent OTPK presence (need OTPK and OTPKID)")
		}
		if len(b.OTPKSig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("bad OTPKSig length: got %d want %d", len(b.OTPKSig), ed25519.SignatureSize)
		}
	}

	if len(b.BundleHash) == 0 {
		h, err := b.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to compute bundle hash: %w", err)
		}
		b.BundleHash = h
	}

	// Rough capacity estimate to avoid reallocations.
	capacity := 1 + // Version
		ed25519.PublicKeySize + // SigningPub
		len(b.EncapID) +
		mlkem.EncapsulationKeySize1024 +
		ed25519.SignatureSize + // EncapSig
		1 + // hasOTPK flag
		(4 + 32 + ed25519.SignatureSize) + // OTPK fields (worst case)
		32 + // IdentityPK
		32 + // SignedPrekeyPK
		ed25519.SignatureSize + // SignedPrekeySig
		2 + len(b.BundleHash) // BundleHash length + bytes

	buf := bytes.NewBuffer(make([]byte, 0, capacity))

	if err := buf.WriteByte(byte(b.Version)); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.SigningPub); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.EncapID[:]); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.Encap.Bytes()); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.EncapSig); err != nil {
		return nil, err
	}

	if hasOTPK {
		if err := buf.WriteByte(1); err != nil {
			return nil, err
		}

		var idBytes [4]byte
		binary.LittleEndian.PutUint32(idBytes[:], *b.OTPKID)
		if _, err := buf.Write(idBytes[:]); err != nil {
			return nil, err
		}

		if _, err := buf.Write(b.OTPK.Bytes()); err != nil {
			return nil, err
		}

		if _, err := buf.Write(b.OTPKSig); err != nil {
			return nil, err
		}
	} else {
		if err := buf.WriteByte(0); err != nil {
			return nil, err
		}
	}

	if _, err := buf.Write(b.IdentityPK.Bytes()); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.SignedPrekeyPK.Bytes()); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.SignedPrekeySig); err != nil {
		return nil, err
	}

	var bhLenBytes [2]byte
	binary.LittleEndian.PutUint16(bhLenBytes[:], uint16(len(b.BundleHash)))
	if _, err := buf.Write(bhLenBytes[:]); err != nil {
		return nil, err
	}

	if _, err := buf.Write(b.BundleHash); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (b *Bundle) UnmarshalBinary(data []byte) error {
	if b == nil {
		return errors.New("nil bundle receiver")
	}

	readBytes := func(p []byte, offset *int) error {
		if *offset+len(p) > len(data) {
			return fmt.Errorf("bundle truncated: need %d bytes at %d, have %d",
				len(p), *offset, len(data)-*offset)
		}
		copy(p, data[*offset:*offset+len(p)])
		*offset += len(p)
		return nil
	}

	offset := 0

	if offset >= len(data) {
		return errors.New("bundle truncated before version")
	}
	b.Version = PQXDHVersion(data[offset])
	offset++

	sp := make([]byte, ed25519.PublicKeySize)
	if err := readBytes(sp, &offset); err != nil {
		return err
	}
	b.SigningPub = sp

	var encapID KEMID
	if err := readBytes(encapID[:], &offset); err != nil {
		return err
	}

	encapBytes := make([]byte, mlkem.EncapsulationKeySize1024)
	if err := readBytes(encapBytes, &offset); err != nil {
		return err
	}
	encap, err := mlkem.NewEncapsulationKey1024(encapBytes)
	if err != nil {
		return fmt.Errorf("NewEncapsulationKey1024 failed: %w", err)
	}

	encapSig := make([]byte, ed25519.SignatureSize)
	if err := readBytes(encapSig, &offset); err != nil {
		return err
	}

	if offset >= len(data) {
		return errors.New("bundle truncated before hasOTPK flag")
	}
	hasOTPK := data[offset]
	offset++

	var (
		otpkID  *uint32
		otpk    *ecdh.PublicKey
		otpkSig []byte
	)

	if hasOTPK == 1 {
		var idBytes [4]byte
		if err := readBytes(idBytes[:], &offset); err != nil {
			return err
		}
		id := binary.LittleEndian.Uint32(idBytes[:])
		otpkID = &id

		otpkBytes := make([]byte, 32)
		if err := readBytes(otpkBytes, &offset); err != nil {
			return err
		}
		pk, err := ecdh.X25519().NewPublicKey(otpkBytes)
		if err != nil {
			return fmt.Errorf("X25519 NewPublicKey for OTPK failed: %w", err)
		}
		otpk = pk

		otpkSig = make([]byte, ed25519.SignatureSize)
		if err := readBytes(otpkSig, &offset); err != nil {
			return err
		}
	} else if hasOTPK != 0 {
		return fmt.Errorf("invalid hasOTPK flag: %d", hasOTPK)
	}

	idpkBytes := make([]byte, 32)
	if err := readBytes(idpkBytes, &offset); err != nil {
		return err
	}
	idpk, err := ecdh.X25519().NewPublicKey(idpkBytes)
	if err != nil {
		return fmt.Errorf("X25519 NewPublicKey for IdentityPK failed: %w", err)
	}

	spkBytes := make([]byte, 32)
	if err := readBytes(spkBytes, &offset); err != nil {
		return err
	}
	spk, err := ecdh.X25519().NewPublicKey(spkBytes)
	if err != nil {
		return fmt.Errorf("X25519 NewPublicKey for SignedPrekeyPK failed: %w", err)
	}

	spkSig := make([]byte, ed25519.SignatureSize)
	if err := readBytes(spkSig, &offset); err != nil {
		return err
	}

	var bhLenBytes [2]byte
	if err := readBytes(bhLenBytes[:], &offset); err != nil {
		return err
	}
	bhLen := int(binary.LittleEndian.Uint16(bhLenBytes[:]))
	if bhLen < 0 {
		return fmt.Errorf("negative bundle hash length: %d", bhLen)
	}
	if offset+bhLen > len(data) {
		return fmt.Errorf("bundle truncated: need %d bytes for hash, have %d", bhLen, len(data)-offset)
	}
	bundleHash := make([]byte, bhLen)
	if err := readBytes(bundleHash, &offset); err != nil {
		return err
	}

	if offset != len(data) {
		return fmt.Errorf("trailing %d bytes after bundle", len(data)-offset)
	}

	b.SigningPub = sp
	b.Encap = encap
	b.EncapSig = encapSig
	b.EncapID = encapID

	b.OTPKID = otpkID
	b.OTPK = otpk
	b.OTPKSig = otpkSig

	b.IdentityPK = idpk
	b.SignedPrekeyPK = spk
	b.SignedPrekeySig = spkSig

	b.BundleHash = bundleHash

	return nil
}
