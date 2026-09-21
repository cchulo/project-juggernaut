package pki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return nil, errors.New("pki: no PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ParseCert parses one PEM certificate.
func ParseCert(certPEM []byte) (*x509.Certificate, error) { return parseCert(certPEM) }
