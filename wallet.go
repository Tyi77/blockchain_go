package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const walletFile = "wallet.dat"
const addressChecksumLen = 4

// Wallet stores private and public keys
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// NewWallet creates and returns a Wallet
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

// walletData is used to serialize wallet since ecdsa.PrivateKey cannot be serialized natively by gob
type walletData struct {
	PrivateKeyD []byte
	PrivateKeyX []byte
	PrivateKeyY []byte
	PublicKey   []byte
}

// GobEncode implements the gob.GobEncoder interface
func (w Wallet) GobEncode() ([]byte, error) {
	wd := walletData{
		PrivateKeyD: w.PrivateKey.D.Bytes(),
		PrivateKeyX: w.PrivateKey.X.Bytes(),
		PrivateKeyY: w.PrivateKey.Y.Bytes(),
		PublicKey:   w.PublicKey,
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(wd)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GobDecode implements the gob.GobDecoder interface
func (w *Wallet) GobDecode(data []byte) error {
	var wd walletData
	dec := gob.NewDecoder(bytes.NewReader(data))
	err := dec.Decode(&wd)
	if err != nil {
		return err
	}
	w.PublicKey = wd.PublicKey
	w.PrivateKey.Curve = elliptic.P256()
	w.PrivateKey.D = new(big.Int).SetBytes(wd.PrivateKeyD)
	w.PrivateKey.X = new(big.Int).SetBytes(wd.PrivateKeyX)
	w.PrivateKey.Y = new(big.Int).SetBytes(wd.PrivateKeyY)
	return nil
}

// GetAddress returns wallet address
func (w Wallet) GetAddress() []byte {
	pubKeyHash := HashPubKey(w.PublicKey)

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)

	return address
}

// HashPubKey hashes public key
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

// ValidateAddress check if address if valid
func ValidateAddress(address string) bool {
	pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

// Checksum generates a checksum for a public key
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}
