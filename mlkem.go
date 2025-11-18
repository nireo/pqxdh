package pqxdh

import "crypto/mlkem"

type KEMType uint8

const (
	KEM1024 KEMType = iota
	KEM768
)

type KEMEncap interface {
	Bytes() []byte
	Encapsulate() (sharedSecret, ciphertext []byte)
}

type KEMDecap interface {
	Bytes() []byte
	EncapsulationKey() KEMEncap
	Decapsulate(ciphertext []byte) (sharedSecret []byte, err error)
}

type kemParams struct {
	kemType        KEMType
	tagPub         byte
	protocolInfo   string
	encapKeySize   int
	ciphertextSize int
}

var kemParams1024 = kemParams{
	kemType:        KEM1024,
	tagPub:         tagMLKEM1024Pub,
	protocolInfo:   "PCH_CURVE25519_SHA-512_MLKEM-1024",
	encapKeySize:   mlkem.EncapsulationKeySize1024,
	ciphertextSize: mlkem.CiphertextSize1024,
}

var kemParams768 = kemParams{
	kemType:        KEM768,
	tagPub:         tagMLKEM768Pub,
	protocolInfo:   "PCH_CURVE25519_SHA-512_MLKEM-768",
	encapKeySize:   mlkem.EncapsulationKeySize768,
	ciphertextSize: mlkem.CiphertextSize768,
}

type (
	mlkem1024Decap struct{ *mlkem.DecapsulationKey1024 }
	mlkem1024Encap struct{ *mlkem.EncapsulationKey1024 }
)

func (d mlkem1024Decap) Bytes() []byte { return d.DecapsulationKey1024.Bytes() }
func (d mlkem1024Decap) EncapsulationKey() KEMEncap {
	return mlkem1024Encap{d.DecapsulationKey1024.EncapsulationKey()}
}

func (d mlkem1024Decap) Decapsulate(ct []byte) ([]byte, error) {
	return d.DecapsulationKey1024.Decapsulate(ct)
}

func (e mlkem1024Encap) Bytes() []byte { return e.EncapsulationKey1024.Bytes() }
func (e mlkem1024Encap) Encapsulate() ([]byte, []byte) {
	return e.EncapsulationKey1024.Encapsulate()
}

type (
	mlkem768Decap struct{ *mlkem.DecapsulationKey768 }
	mlkem768Encap struct{ *mlkem.EncapsulationKey768 }
)

func (d mlkem768Decap) Bytes() []byte { return d.DecapsulationKey768.Bytes() }
func (d mlkem768Decap) EncapsulationKey() KEMEncap {
	return mlkem768Encap{d.DecapsulationKey768.EncapsulationKey()}
}

func (d mlkem768Decap) Decapsulate(ct []byte) ([]byte, error) {
	return d.DecapsulationKey768.Decapsulate(ct)
}

func (e mlkem768Encap) Bytes() []byte { return e.EncapsulationKey768.Bytes() }
func (e mlkem768Encap) Encapsulate() ([]byte, []byte) {
	return e.EncapsulationKey768.Encapsulate()
}

func generateKEMKey(t KEMType) (KEMDecap, error) {
	switch t {
	case KEM768:
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, err
		}
		return mlkem768Decap{dk}, nil
	case KEM1024:
		fallthrough
	default:
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, err
		}
		return mlkem1024Decap{dk}, nil
	}
}
