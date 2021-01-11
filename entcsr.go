package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func pubKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func main() {
	certName := os.Args[1]
	keySize, er := rsa.GenerateKey(rand.Reader, 4096)

	// Certificate template
	crtTpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Entando"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365), // one year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// certificate
	crt, er := x509.CreateCertificate(rand.Reader, &crtTpl, &crtTpl, pubKey(keySize), keySize)
	if er != nil {
		log.Fatal("Failed to create certificate: %s", er)
	}

	crtFile, er := os.Create(certName + "-cert.crt")
	if er != nil {
		log.Fatal("Error writing buffer to file: %s", er)
	}
	pem.Encode(crtFile, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	crtFile.Close()

	if er != nil {
		panic(er)
	}
	derKey := x509.MarshalPKCS1PrivateKey(keySize)
	keyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derKey,
	}

	keyFile, er := os.Create(certName + "-key.key")
	if er != nil {
		panic(er)
	}
	pem.Encode(keyFile, &keyBlock)
	keyFile.Close()

	commonName := "spid-signing-cert"
	emailAddress := "email@email.com"
	org := "orgName"
	orgUnit := "OPS"
	city := "Cagliari"
	state := "Italia"
	country := "IT"

	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Locality:           []string{city},
		Organization:       []string{org},
		OrganizationalUnit: []string{orgUnit},
		Province:           []string{state},
	}

	asn1Parser, er := asn1.Marshal(subject.ToRDNSequence())
	if er != nil {
		panic(er)
	}

	// Certificate signing request template
	csr := x509.CertificateRequest{
		RawSubject:         asn1Parser,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA512WithRSA,
	}

	// Create certificate signing request
	bytes, er := x509.CreateCertificateRequest(rand.Reader, &csr, keySize)
	if er != nil {
		panic(er)
	}
	csrFile, er := os.Create(certName + "-cert-sign-request.csr")
	if er != nil {
		panic(er)
	}

	pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes})
	csrFile.Close()
}
