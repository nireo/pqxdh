package pqxdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// pqxdhVersion has a version for backwards compatibility and proper versioning
type pqxdhVersion uint8

const (
	protocolInfo = "PCH_CURVE25519_SHA-512_CRYSTALS-KYBER-1024"

	tagECx25519     byte = 0x01
	tagMLKEM1024Pub byte = 0xA3

	pqxdhV1 pqxdhVersion = 1
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
	binary.BigEndian.PutUint16(out[1:3], uint16(len(v)))
	copy(out[3:], v)
	return out
}

func decodeTLV(b []byte) (tag byte, val []byte, rest []byte, err error) {
	if len(b) < 3 {
		return 0, nil, nil, ErrTLVTruncated
	}
	tag = b[0]
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) < 3+n {
		return 0, nil, nil, ErrTLVLenOverrun
	}
	val = b[3 : 3+n]
	rest = b[3+n:]
	return
}

func encodeEC(pk *ecdh.PublicKey) []byte {
	return encodeTLV(tagECx25519, pk.Bytes())
}

func encodeKEM1024(pk *mlkem.EncapsulationKey1024) []byte {
	return encodeTLV(tagMLKEM1024Pub, pk.Bytes())
}

func decodeECX25519(b []byte) (*ecdh.PublicKey, error) {
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

func decodeKEM1024(b []byte) (*mlkem.EncapsulationKey1024, error) {
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

// idKEM is a server-addressable id for a KEM key
type idKEM [16]byte

func (id idKEM) eq(other idKEM) bool {
	return bytes.Equal(id[:], other[:])
}

// oneTimeKEMKey contains a single-use KEm key that is supposed to be used only once per pqxdh run
// the user however has a last-resort mlkem key such that the post-quantum security is preserved
type oneTimeKEMKey struct {
	// mlkem keys
	decap *mlkem.DecapsulationKey1024
	encap *mlkem.EncapsulationKey1024

	// metadata
	createdAt int64
	usedAt    *int64
}

// oneTimePreKey are elliptic curve keys that should be used (if available) for each pqxdh run.
// similar to the one time kem keys they should only be used one and then discarded. the receiver
// uses the private key in their key exchange and the iniator uses the public key when initiating
// the key exhange.
type oneTimePreKey struct {
	sk *ecdh.PrivateKey
	pk *ecdh.PublicKey

	// metadata
	createdAt int64
	usedAt    *int64
}

// pqxdhIdentity contains the identity for a given local user. The identity keys should stay the same
type pqxdhIdentity struct {
	// identity signing keys (ed25519)
	signingPub  ed25519.PublicKey
	signingPriv ed25519.PrivateKey

	// identity static DH (X25519)
	pk *ecdh.PublicKey
	sk *ecdh.PrivateKey
}

// pqxdhBundle contains all of the information needed for the iniator to begin key exhange. all of the
// information in this struct is public meaning that in real usage this is populated by a server.
type pqxdhBundle struct {
	signingPub ed25519.PublicKey
	encap      *mlkem.EncapsulationKey1024 // public KEM key (either last-resort or one-time use)
	encapSig   []byte                      // signed by Bob’s identity signing key
	encapID    idKEM                       // id to reference in init

	// classical one-time (optional; server deletes after handing out)
	otpkID  *uint32
	otpk    *ecdh.PublicKey // optional public X25519 key
	otpkSig []byte

	idpk   *ecdh.PublicKey // identity key
	spkpk  *ecdh.PublicKey // signed prekey
	spkSig []byte          // identity key signature of signed prekey

	version    pqxdhVersion
	bundleHash []byte
}

// pqxdhState represents a user in pqxdh a user can initiate a key exchange or it accept key exchange
// requests to create a shared secret. this struct constains private key which should obviously kept secret.
type pqxdhState struct {
	identity pqxdhIdentity

	// classical signed prekey
	signedPrekeySK  *ecdh.PrivateKey
	signedPrekeyPK  *ecdh.PublicKey
	signedPrekeySig []byte

	// classical one-time prekeys (many; keyed by server-visible id)
	oneTimePrekeys map[uint32]*oneTimePreKey

	// PQ one-time KEM keys (many; keyed by idKEM)
	oneTimeKEMKeys map[idKEM]*oneTimeKEMKey

	// PQ signed prekey (last resort) secret half lives locally
	lastResortKEMdecap *mlkem.DecapsulationKey1024
	lastResortKEMencap *mlkem.EncapsulationKey1024
	lastResortKEMid    idKEM

	// optional: metadata
	deviceID  uint32
	version   pqxdhVersion
	createdAt int64
}

type pqxdhInit struct {
	bundleHash []byte
	ad         []byte

	idpk          *ecdh.PublicKey
	ephKey        *ecdh.PublicKey
	otpkUsedID    *uint32
	targetEncapID idKEM
	encapCT       []byte

	payload []byte
}

func NewPQXDHState(deviceID uint32) (*pqxdhState, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	curve := ecdh.X25519()
	ikSK, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	spkSK, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	spkSig := ed25519.Sign(signPriv, spkSK.PublicKey().Bytes())

	decap, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}

	var kemID idKEM
	if _, err := rand.Read(kemID[:]); err != nil {
		return nil, err
	}

	return &pqxdhState{
		identity: pqxdhIdentity{
			signingPub:  signPub,
			signingPriv: signPriv,
			pk:          ikSK.PublicKey(),
			sk:          ikSK,
		},
		signedPrekeySK:     spkSK,
		signedPrekeyPK:     spkSK.PublicKey(),
		signedPrekeySig:    spkSig,
		oneTimePrekeys:     make(map[uint32]*oneTimePreKey),
		oneTimeKEMKeys:     make(map[idKEM]*oneTimeKEMKey),
		lastResortKEMdecap: decap,
		lastResortKEMencap: decap.EncapsulationKey(),
		lastResortKEMid:    kemID,
		deviceID:           deviceID,
		version:            pqxdhV1,
		createdAt:          time.Now().Unix(),
	}, nil
}

func (ps *pqxdhState) generateOneTimeKEMKeys(n int) error {
	for range n {
		decap, err := mlkem.GenerateKey1024()
		if err != nil {
			return err
		}

		// create a random identifier for the kem key that the server can use
		var id idKEM
		_, err = rand.Read(id[:])
		if err != nil {
			return err
		}

		ps.oneTimeKEMKeys[id] = &oneTimeKEMKey{
			decap:     decap,
			encap:     decap.EncapsulationKey(),
			createdAt: time.Now().Unix(),
			usedAt:    nil,
		}
	}

	return nil
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func (ps *pqxdhState) generateOneTimePrekeys(n int) error {
	curve := ecdh.X25519()

	for range n {
		otpPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate otp: %w", err)
		}

		id, err := randomUint32()
		if err != nil {
			return err
		}

		ps.oneTimePrekeys[id] = &oneTimePreKey{
			sk:        otpPriv,
			pk:        otpPriv.PublicKey(),
			createdAt: time.Now().Unix(),
			usedAt:    nil,
		}
	}

	return nil
}

// ensureHash returns a boolean telling if the value of the bundleHash field matches
// the hashed content.
func (b *pqxdhBundle) isHashValid() (bool, error) {
	got, err := b.hash()
	if err != nil {
		return false, err
	}

	return bytes.Equal(got, b.bundleHash), nil
}

// hash hashes the content of the bundle
func (b *pqxdhBundle) hash() ([]byte, error) {
	h := sha256.New()

	if b.encap == nil || b.idpk == nil || b.spkpk == nil {
		return nil, errors.New("required fields are nil for hashing")
	}

	h.Write([]byte{byte(b.version)})
	h.Write(b.idpk.Bytes())

	h.Write(b.spkpk.Bytes())
	h.Write(b.spkSig)

	h.Write(b.encap.Bytes())
	h.Write(b.encapID[:])
	h.Write(b.encapSig)

	if b.otpk != nil {
		h.Write(b.otpk.Bytes())
		h.Write(b.otpkSig)
	}

	return h.Sum(nil), nil
}

// findKEM finds for a given id the kem key. it also checks the last resort kem key otherwise defaulting to the
// one time kem keys. it returns an error only when nothing is found.
func (ps *pqxdhState) findKEM(id idKEM) (*mlkem.DecapsulationKey1024, *mlkem.EncapsulationKey1024, error) {
	if id.eq(ps.lastResortKEMid) {
		return ps.lastResortKEMdecap, ps.lastResortKEMencap, nil
	}

	if kp, ok := ps.oneTimeKEMKeys[id]; ok {
		return kp.decap, kp.encap, nil
	} else {
		return nil, nil, fmt.Errorf("kem key not found with id: %x", id)
	}
}

func (ps *pqxdhState) findOtpk(id uint32) (*oneTimePreKey, error) {
	if k, ok := ps.oneTimePrekeys[id]; ok {
		return k, nil
	}

	return nil, fmt.Errorf("one time prekey id [%d] not found", id)
}

// makeBundle constructs a given bundle from a pqxdh state. It can be used for both testing and then
// when we want as the receiver construct a bundle to check the bundle hash. the only error this will
// return is when either kemID or otpkID are not found.
func (ps *pqxdhState) makeBundle(encapID idKEM, encap *mlkem.EncapsulationKey1024, otpkID *uint32, otpk *oneTimePreKey) (*pqxdhBundle, error) {
	bundle := &pqxdhBundle{
		signingPub: ps.identity.signingPub,
		idpk:       ps.identity.pk,
		spkpk:      ps.signedPrekeyPK,
		spkSig:     ps.signedPrekeySig,

		version: pqxdhV1,
	}

	if otpkID != nil && otpk != nil {
		bundle.otpkID = otpkID
		bundle.otpk = otpk.pk
		bundle.otpkSig = ed25519.Sign(ps.identity.signingPriv, otpk.pk.Bytes())
	}

	if encap == nil {
		return nil, errors.New("encapsulation key is nil")
	}

	bundle.encap = encap
	bundle.encapID = encapID
	bundle.encapSig = ed25519.Sign(ps.identity.signingPriv, encap.Bytes())

	return bundle, nil
}

func pqxdhKDF(km []byte, info string) ([]byte, error) {
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

// verifyBundleSignatures verifies that the
func (b *pqxdhBundle) verifyBundleSignatures() error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if b.signingPub == nil || len(b.signingPub) != ed25519.PublicKeySize {
		return errors.New("missing or bad signingPub")
	}

	if b.spkpk == nil || len(b.spkSig) != ed25519.SignatureSize {
		return errors.New("missing signed-prekey or signature")
	}
	if !ed25519.Verify(b.signingPub, b.spkpk.Bytes(), b.spkSig) {
		return errors.New("invalid signature on signed-prekey")
	}

	if b.encap == nil || len(b.encapSig) != ed25519.SignatureSize {
		return errors.New("missing ML-KEM key or signature")
	}
	if !ed25519.Verify(b.signingPub, b.encap.Bytes(), b.encapSig) {
		return errors.New("invalid signature on ML-KEM key")
	}

	if b.otpk != nil {
		if len(b.otpkSig) != ed25519.SignatureSize {
			return errors.New("missing one-time prekey signature")
		}
		if !ed25519.Verify(b.signingPub, b.otpk.Bytes(), b.otpkSig) {
			return errors.New("invalid signature on one-time prekey")
		}
	}

	return nil
}

func (ps *pqxdhState) additionalDataAsInitiator(bundle *pqxdhBundle) []byte {
	ad := make([]byte, 0, 32*2+mlkem.EncapsulationKeySize1024)
	ad = append(ad, ps.identity.pk.Bytes()...) // IK_A
	ad = append(ad, bundle.idpk.Bytes()...)    // IK_B

	ad = append(ad, bundle.encap.Bytes()...) // PQPK_B
	ad = append(ad, bundle.bundleHash...)
	return ad
}

func (ps *pqxdhState) additionalDataAsReceiver(
	encap *mlkem.EncapsulationKey1024,
	idpk *ecdh.PublicKey,
	bundleHash []byte,
) []byte {
	ad := make([]byte, 0, 32*2+mlkem.EncapsulationKeySize1024+len(bundleHash))
	ad = append(ad, idpk.Bytes()...)           // IK_A
	ad = append(ad, ps.identity.pk.Bytes()...) // IK_B
	ad = append(ad, encap.Bytes()...)          // PQPK_B
	ad = append(ad, bundleHash...)

	return ad
}

// keyExchange consumes a bundle and returns derived secret material.
func (ps *pqxdhState) keyExchange(bundle *pqxdhBundle) ([]byte, *pqxdhInit, error) {
	if bundle == nil {
		return nil, nil, errors.New("nil bundle")
	}
	if bundle.idpk == nil || bundle.spkpk == nil || bundle.encap == nil {
		return nil, nil, errors.New("bundle missing required keys")
	}

	bhash, err := bundle.hash()
	if err != nil {
		return nil, nil, fmt.Errorf("bundle hash compute failed: %w", err)
	}

	if !bytes.Equal(bhash, bundle.bundleHash) {
		return nil, nil, errors.New("bundle hash not okay")
	}

	err = bundle.verifyBundleSignatures()
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.X25519()

	// DH1 = IK_A x SPK_B
	dh1, err := ps.identity.sk.ECDH(bundle.spkpk)
	if err != nil {
		return nil, nil, fmt.Errorf("DH1 (IK_AxSPK_B) failed: %w", err)
	}

	// generate the ephemeral key only used for this session
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ephemeral key gen failed: %w", err)
	}

	// DH2 = EK_A x IK_B
	dh2, err := ephPriv.ECDH(bundle.idpk)
	if err != nil {
		return nil, nil, fmt.Errorf("DH2 (EK_AxIK_B) failed: %w", err)
	}

	// DH3 = EK_A x SPK_B
	dh3, err := ephPriv.ECDH(bundle.spkpk)
	if err != nil {
		return nil, nil, fmt.Errorf("DH3 (EK_AxSPK_B) failed: %w", err)
	}

	// Optional DH4 = EK_A x OPK_B
	var dh4 []byte
	if bundle.otpk != nil {
		dh4, err = ephPriv.ECDH(bundle.otpk)
		if err != nil {
			return nil, nil, fmt.Errorf("DH4 (EK_AxOPK_B) failed: %w", err)
		}
	}

	pqSS, ct := bundle.encap.Encapsulate()

	var km []byte
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	if len(dh4) > 0 {
		km = append(km, dh4...)
	}
	km = append(km, pqSS...)

	rootKey, err := pqxdhKDF(km, protocolInfo)
	if err != nil {
		return nil, nil, err
	}

	initContent := &pqxdhInit{
		// hash of the bundle that alice used to derive the shared secret
		bundleHash:    bhash,
		ad:            ps.additionalDataAsInitiator(bundle),
		idpk:          ps.identity.pk,
		targetEncapID: bundle.encapID,
		encapCT:       ct,
		ephKey:        ephPriv.PublicKey(),
	}

	if bundle.otpkID != nil && bundle.otpk != nil {
		initContent.otpkUsedID = bundle.otpkID
	}

	return rootKey, initContent, nil
}

// checkBundleAsReceiver calculates the bundle hash based on what alice has used. it will also
// be added into the additional information so it needs to match.
func (ps *pqxdhState) checkBundleAsReceiver(
	usedBundleHash []byte,
	kemUsed *mlkem.EncapsulationKey1024,
	kemID idKEM, otpkID *uint32,
	otpk *oneTimePreKey,
) ([]byte, error) {
	bundle, err := ps.makeBundle(kemID, kemUsed, otpkID, otpk)
	if err != nil {
		return nil, fmt.Errorf("failed to construct bundle: %s", err)
	}

	hash, err := bundle.hash()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate bundle hash %s", err)
	}

	if !bytes.Equal(hash, usedBundleHash) {
		return nil, errors.New("bundle hash didn't match")
	}

	return hash, nil
}

type pqxdhResult struct {
	rootKey []byte
	ad      []byte
}

func (ps *pqxdhState) recvKeyExchange(init *pqxdhInit) (*pqxdhResult, error) {
	if init == nil {
		return nil, errors.New("nil init")
	}

	if init.idpk == nil || init.ephKey == nil {
		return nil, errors.New("init missing identity or ephemeral key")
	}

	// the function needs the decap and encap so we call it here and pass it through functions.
	// not the cleanest approach.
	// TODO: make the bundle checking a bit more sane.
	decap, encap, err := ps.findKEM(init.targetEncapID)
	if err != nil {
		return nil, fmt.Errorf("failed to find used KEM key: %s", err)
	}

	if len(init.encapCT) != mlkem.CiphertextSize1024 {
		return nil, fmt.Errorf("bad KEM ciphertext: got %d, want %d",
			len(init.encapCT), mlkem.CiphertextSize1024)
	}

	var otpk *oneTimePreKey
	if init.otpkUsedID != nil {
		otpk, err = ps.findOtpk(*init.otpkUsedID)
		if err != nil {
			return nil, fmt.Errorf("one time private key used but not found: %s", err)
		}
	}

	bundleHash, err := ps.checkBundleAsReceiver(init.bundleHash, encap, init.targetEncapID, init.otpkUsedID, otpk)
	if err != nil {
		return nil, err
	}

	dh1, err := ps.signedPrekeySK.ECDH(init.idpk)
	if err != nil {
		return nil, fmt.Errorf("DH1 SPK_BxIK_A failed: %w", err)
	}

	dh2, err := ps.identity.sk.ECDH(init.ephKey)
	if err != nil {
		return nil, fmt.Errorf("DH1 IK_BxEPH failed: %w", err)
	}

	dh3, err := ps.signedPrekeySK.ECDH(init.ephKey)
	if err != nil {
		return nil, fmt.Errorf("DH1 SPK_BxEPH failed: %w", err)
	}

	var dh4 []byte
	if otpk != nil {
		dh4, err = otpk.sk.ECDH(init.ephKey)
		if err != nil {
			return nil, fmt.Errorf("DH1 OTPKxEPH failed: %w", err)
		}
	}

	pqSS, err := decap.Decapsulate(init.encapCT)
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

	rootKey, err := pqxdhKDF(km, protocolInfo)
	if err != nil {
		return nil, err
	}

	ps.consumeKEMIfOneTime(init.targetEncapID)
	ps.consumeOTPKIfUsed(init.otpkUsedID)

	return &pqxdhResult{
		rootKey: rootKey,
		ad:      ps.additionalDataAsReceiver(encap, init.idpk, bundleHash),
	}, nil
}

func (ps *pqxdhState) consumeKEMIfOneTime(id idKEM) {
	if id.eq(ps.lastResortKEMid) {
		return
	}

	if k, ok := ps.oneTimeKEMKeys[id]; ok {
		now := time.Now().Unix()
		k.usedAt = &now
		delete(ps.oneTimeKEMKeys, id)
	}
}

func (ps *pqxdhState) consumeOTPKIfUsed(id *uint32) {
	if id == nil {
		return
	}

	if k, ok := ps.oneTimePrekeys[*id]; ok {
		now := time.Now().Unix()
		k.usedAt = &now
		delete(ps.oneTimePrekeys, *id)
	}
}
