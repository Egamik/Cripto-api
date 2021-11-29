package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

func HashString(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	shash := hex.EncodeToString(h.Sum(nil))
	return shash
}

func GenKeyPair() (string, string) {
	bitSize := 2048
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	pvtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pub_bytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pub_bytes,
		},
	)
	return string(pubPEM), string(pvtPEM)
}
