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

var curve = ecdh.X25519()

const (
	protocolInfo = "PCH_CURVE25519_SHA-512_CRYSTALS-KYBER-1024"

	tagECx25519     byte = 0x01
	tagMLKEM1024Pub byte = 0xA3

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

// KEMID is a server-addressable id for a KEM key
type KEMID [16]byte

func (id KEMID) Equals(other KEMID) bool {
	return bytes.Equal(id[:], other[:])
}

// OneTimeKEMKey contains a single-use KEM key that is supposed to be used only once per pqxdh run
// the user however has a last-resort mlkem key such that the post-quantum security is preserved
type OneTimeKEMKey struct {
	// mlkem keys
	decap *mlkem.DecapsulationKey1024
	encap *mlkem.EncapsulationKey1024

	encapSig  []byte
	createdAt int64
	usedAt    *int64
}

// OneTimePrekey are elliptic curve keys that should be used (if available) for each pqxdh run.
// similar to the one time kem keys they should only be used one and then discarded. the receiver
// uses the private key in their key exchange and the iniator uses the public key when initiating
// the key exhange.
type OneTimePrekey struct {
	sk *ecdh.PrivateKey
	pk *ecdh.PublicKey

	pksig []byte
	// metadata
	createdAt int64
	usedAt    *int64
}

// Identity contains the identity for a given local user. The identity keys should stay the same
type Identity struct {
	// identity static DH (X25519)
	pk *ecdh.PublicKey
	sk *ecdh.PrivateKey

	// a XEdDSA verification key derived from the sk and only user for ed25519 verify.
	signingPub ed25519.PublicKey
}

// Bundle contains all of the information needed for the iniator to begin key exhange. all of the
// information in this struct is public meaning that in real usage this is populated by a server.
type Bundle struct {
	signingPub ed25519.PublicKey
	encap      *mlkem.EncapsulationKey1024 // public KEM key (either last-resort or one-time use)
	encapSig   []byte                      // signed by Bob’s identity signing key
	encapID    KEMID                       // id to reference in init

	// classical one-time (optional; server deletes after handing out)
	otpkID  *uint32
	otpk    *ecdh.PublicKey // optional public X25519 key
	otpkSig []byte

	idpk   *ecdh.PublicKey // identity key
	spkpk  *ecdh.PublicKey // signed prekey
	spkSig []byte          // identity key signature of signed prekey

	version    PQXDHVersion
	bundleHash []byte
}

// State represents a user in pqxdh a user can initiate a key exchange or it accept key exchange
// requests to create a shared secret. this struct constains private key which should obviously kept secret.
type State struct {
	identity Identity

	// classical signed prekey
	signedPrekeySK  *ecdh.PrivateKey
	signedPrekeyPK  *ecdh.PublicKey
	signedPrekeySig []byte

	// classical one-time prekeys (many; keyed by server-visible id)
	oneTimePrekeys map[uint32]*OneTimePrekey

	// PQ one-time KEM keys (many; keyed by idKEM)
	oneTimeKEMKeys map[KEMID]*OneTimeKEMKey

	// PQ signed prekey (last resort) secret half lives locally
	lastResortKEMdecap *mlkem.DecapsulationKey1024
	lastResortKEMencap *mlkem.EncapsulationKey1024
	lastResortKEMid    KEMID
	lastResortSig      []byte

	version   PQXDHVersion
	createdAt int64
}

type InitMessage struct {
	bundleHash []byte
	ad         []byte

	idpk          *ecdh.PublicKey
	ephKey        *ecdh.PublicKey
	otpkUsedID    *uint32
	targetEncapID KEMID
	encapCT       []byte

	payload []byte
}

// NewPQXDHState constructs a PQXDH state by generating needed keys
func NewPQXDHState() (*State, error) {
	ikSK, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	spkSK, err := curve.GenerateKey(rand.Reader)
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
		identity: Identity{
			signingPub: ed25519.PublicKey(A),
			pk:         ikSK.PublicKey(),
			sk:         ikSK,
		},
		signedPrekeySK:     spkSK,
		signedPrekeyPK:     spkSK.PublicKey(),
		signedPrekeySig:    spkSig,
		oneTimePrekeys:     make(map[uint32]*OneTimePrekey),
		oneTimeKEMKeys:     make(map[KEMID]*OneTimeKEMKey),
		lastResortKEMdecap: decap,
		lastResortKEMencap: decap.EncapsulationKey(),
		lastResortKEMid:    kemID,
		lastResortSig:      lastResortSig,
		version:            pqxdhV1,
		createdAt:          time.Now().Unix(),
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

		encapSig, _, err := Sign(ps.identity.sk, encap.Bytes())
		if err != nil {
			return fmt.Errorf("failed to sign encapsulation key: %w", err)
		}

		ps.oneTimeKEMKeys[id] = &OneTimeKEMKey{
			decap:     decap,
			encap:     encap,
			encapSig:  encapSig,
			createdAt: time.Now().Unix(),
			usedAt:    nil,
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
		otpPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate otp: %w", err)
		}
		pk := otpPriv.PublicKey()

		// this ID is given in the initial message such that the receiver can determinte the correct private key.
		id, err := randomUint32()
		if err != nil {
			return err
		}

		pksig, _, err := Sign(ps.identity.sk, pk.Bytes())
		if err != nil {
			return fmt.Errorf("failed to sign encapsulation key: %w", err)
		}

		// the private key needs to stored in-case the process actually uses the one-time public key such that
		// we can perform the key exchange on the receiver end.
		ps.oneTimePrekeys[id] = &OneTimePrekey{
			sk:        otpPriv,
			pk:        pk,
			pksig:     pksig,
			createdAt: time.Now().Unix(),
			usedAt:    nil,
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

	return bytes.Equal(got, b.bundleHash), nil
}

// Hash hashes the content of the bundle
func (b *Bundle) Hash() ([]byte, error) {
	h := sha512.New()

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

// findMLKEM finds for a given id the MLKEM key. it also checks the last resort kem key otherwise defaulting to the
// one time kem keys. it returns an error only when nothing is found.
func (ps *State) findMLKEM(id KEMID) (*mlkem.DecapsulationKey1024, *mlkem.EncapsulationKey1024, error) {
	if id.Equals(ps.lastResortKEMid) {
		return ps.lastResortKEMdecap, ps.lastResortKEMencap, nil
	}

	if kp, ok := ps.oneTimeKEMKeys[id]; ok {
		return kp.decap, kp.encap, nil
	} else {
		return nil, nil, fmt.Errorf("kem key not found with id: %x", id)
	}
}

// findOtpk find for a given id the one-time pre key it returns an error when nothing is found.
func (ps *State) findOtpk(id uint32) (*OneTimePrekey, error) {
	if k, ok := ps.oneTimePrekeys[id]; ok {
		return k, nil
	}

	return nil, fmt.Errorf("one time prekey id [%d] not found", id)
}

// MakeBundle constructs a given bundle from a pqxdh state. It can be used for both testing and then
// when we want as the receiver construct a bundle to check the bundle hash. the only error this will
// return is when either kemID or otpkID are not found.
func (ps *State) MakeBundle(encapID KEMID, encap *mlkem.EncapsulationKey1024, otpkID *uint32, otpk *OneTimePrekey) (*Bundle, error) {
	bundle := &Bundle{
		signingPub: ps.identity.signingPub,
		idpk:       ps.identity.pk,
		spkpk:      ps.signedPrekeyPK,
		spkSig:     ps.signedPrekeySig,
		version:    pqxdhV1,
	}

	if otpkID != nil && otpk != nil {
		bundle.otpkID = otpkID
		bundle.otpk = otpk.pk
		bundle.otpkSig = otpk.pksig
	}

	if encap == nil {
		return nil, errors.New("encapsulation key is nil")
	}

	bundle.encap = encap
	bundle.encapID = encapID

	// choose correct stored signature
	if encapID.Equals(ps.lastResortKEMid) {
		bundle.encapSig = ps.lastResortSig
	} else if k, ok := ps.oneTimeKEMKeys[encapID]; ok {
		bundle.encapSig = k.encapSig
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

// additionalDataAsInitiator constructs the additional data as the party initiating the key exchange.
// We cannot use this on the receiver end as the order of the elements needs to be the same. such that
// both parties have the same additional data.
func (ps *State) additionalDataAsInitiator(bundle *Bundle) []byte {
	ad := make([]byte, 0, 32*2+mlkem.EncapsulationKeySize1024)
	ad = append(ad, ps.identity.pk.Bytes()...) // IK_A
	ad = append(ad, bundle.idpk.Bytes()...)    // IK_B

	ad = append(ad, bundle.encap.Bytes()...) // PQPK_B
	ad = append(ad, bundle.bundleHash...)
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
	ad = append(ad, ps.identity.pk.Bytes()...) // IK_B
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
	if bundle.idpk == nil || bundle.spkpk == nil || bundle.encap == nil {
		return nil, nil, errors.New("bundle missing required keys")
	}

	bhash, err := bundle.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("bundle hash compute failed: %w", err)
	}

	if !bytes.Equal(bhash, bundle.bundleHash) {
		return nil, nil, errors.New("bundle hash not okay")
	}

	err = bundle.VerifyBundleSignatures()
	if err != nil {
		return nil, nil, err
	}

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

	rootKey, err := kdf(km, protocolInfo)
	if err != nil {
		return nil, nil, err
	}

	initContent := &InitMessage{
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

	if init.idpk == nil || init.ephKey == nil {
		return nil, errors.New("init missing identity or ephemeral key")
	}

	// the function needs the decap and encap so we call it here and pass it through functions.
	// not the cleanest approach.
	// TODO: make the bundle checking a bit more sane.
	decap, encap, err := ps.findMLKEM(init.targetEncapID)
	if err != nil {
		return nil, fmt.Errorf("failed to find used KEM key: %s", err)
	}

	if len(init.encapCT) != mlkem.CiphertextSize1024 {
		return nil, fmt.Errorf("bad KEM ciphertext: got %d, want %d",
			len(init.encapCT), mlkem.CiphertextSize1024)
	}

	var otpk *OneTimePrekey
	if init.otpkUsedID != nil {
		otpk, err = ps.findOtpk(*init.otpkUsedID)
		if err != nil {
			return nil, fmt.Errorf("one time private key used but not found: %s", err)
		}
	}

	// validate that the bundle content is correct. this obviously cannot validate the server that provided the bundle
	// did not forge it to create a key exchange here with the receiver. the security is based on the fact that the party
	// can through some other channel verify the authenticity of the identity key that provided the bundle.
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

	rootKey, err := kdf(km, protocolInfo)
	if err != nil {
		return nil, err
	}

	ps.consumeKEMIfOneTime(init.targetEncapID)
	ps.consumeOTPKIfUsed(init.otpkUsedID)

	return &KeyExchangeResult{
		RootKey: rootKey,
		AD:      ps.additionalDataAsReceiver(encap, init.idpk, bundleHash),
	}, nil
}

func (ps *State) consumeKEMIfOneTime(id KEMID) {
	if id.Equals(ps.lastResortKEMid) {
		return
	}

	if k, ok := ps.oneTimeKEMKeys[id]; ok {
		now := time.Now().Unix()
		k.usedAt = &now
		delete(ps.oneTimeKEMKeys, id)
	}
}

func (ps *State) consumeOTPKIfUsed(id *uint32) {
	if id == nil {
		return
	}

	if k, ok := ps.oneTimePrekeys[*id]; ok {
		now := time.Now().Unix()
		k.usedAt = &now
		delete(ps.oneTimePrekeys, *id)
	}
}
