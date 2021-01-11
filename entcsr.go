package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
)

func main() {
	certName := os.Args[1]
	keySize, er := rsa.GenerateKey(rand.Reader, 4096)

	if er != nil {
		panic(er)
	}
	derKey := x509.MarshalPKCS1PrivateKey(keySize)
	keyBlock := pem.Block{
		Type: "RSA PRIVATE KEY",
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
		CommonName: commonName,
		Country: []string{country},
		Locality: []string{city},
		Organization: []string{org},
		OrganizationalUnit: []string{orgUnit},
		Province: []string{state},
	}

	asn1Parser, er := asn1.Marshal(subject.ToRDNSequence())
	if er != nil {
		panic(er)
	}
	csr := x509.CertificateRequest{
		RawSubject: asn1Parser,
		EmailAddresses: []string{emailAddress},
		SignatureAlgorithm: x509.SHA512WithRSA,
	}

	bytes, er := x509.CreateCertificateRequest(rand.Reader, &csr, keySize)
	if er != nil {
		panic(er)
	}
	csrFile, er := os.Create(certName + "-cert.csr")
	if er != nil {
		panic(er)
	}

	pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes})
	csrFile.Close()
}