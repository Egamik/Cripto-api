package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type CA struct {
	caCert   *x509.Certificate
	caPvtKey *rsa.PrivateKey
	caPEM    *bytes.Buffer
	Serial   int64
}

func (ca *CA) nextSerial() int64 {
	next := ca.Serial + 1
	ca.Serial = next
	return next
}

func (ca *CA) CreateNewCert(name string) (*x509.Certificate, *bytes.Buffer) {
	serialNumber := ca.nextSerial()
	serial := big.NewInt(serialNumber)
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		RawIssuer: []byte(ca.caPEM.Bytes()),
		IsCA:      false,
	}
	// Generates RSA keypair
	certPvt, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil
	}

	// Creates signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.caCert, &certPvt.PublicKey, ca.caPvtKey)
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPvtKeyPEM := new(bytes.Buffer)
	pem.Encode(certPvtKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPvt),
	})

	return cert, certPEM
}

// Sets up the Certificate Authority with its own cert
func (ca *CA) CaSetup() *x509.Certificate {
	ca.Serial = 0
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "YMCA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		RawIssuer: nil,
		IsCA:      true,
	}
	// Creates CA RSA key pair
	caPvtKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}

	ca.caCert = caCert
	ca.caPvtKey = caPvtKey

	// Creates CA self signed certificate
	// DER bytes
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPvtKey.PublicKey, caPvtKey)
	if err != nil {
		return nil
	}
	// cifra PEM
	ca.caPEM = new(bytes.Buffer)
	pem.Encode(ca.caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})

	caPvtPEM := new(bytes.Buffer)
	pem.Encode(caPvtPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPvtKey),
	})

	return caCert
}
