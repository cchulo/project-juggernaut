// Package pki is the internal certificate authority for gateway ↔ pod mutual
// TLS. The controller creates one CA per cluster, issues a server certificate
// per session pod (URI SAN spiffe://<domain>/session/<pod>) and one client
// certificate for the gateway (spiffe://<domain>/gateway). Each side verifies
// the other's chain and identity; no network position is trusted.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// CA is a signing authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Bundle is a PEM-encoded certificate, key and CA.
type Bundle struct {
	CertPEM []byte
	KeyPEM  []byte
	CAPEM   []byte
}

// NewCA creates a P-256 CA valid for 10 years.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LoadCA parses PEM material.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("pki: CA PEM is incomplete")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// PEM encodes the CA.
func (ca *CA) PEM() (certPEM, keyPEM []byte, err error) {
	kd, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// IssueServer issues a pod certificate: SPIFFE URI plus optional IP SANs.
func (ca *CA) IssueServer(spiffeID string, ips []net.IP, ttl time.Duration) (*Bundle, error) {
	return ca.issue(spiffeID, ips, ttl, x509.ExtKeyUsageServerAuth)
}

// IssueClient issues the gateway's client certificate.
func (ca *CA) IssueClient(spiffeID string, ttl time.Duration) (*Bundle, error) {
	return ca.issue(spiffeID, nil, ttl, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issue(spiffeID string, ips []net.IP, ttl time.Duration, usage x509.ExtKeyUsage) (*Bundle, error) {
	u, err := url.Parse(spiffeID)
	if err != nil || u.Scheme != "spiffe" {
		return nil, fmt.Errorf("pki: %q is not a spiffe URI", spiffeID)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: u.Path},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		URIs:         []*url.URL{u},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}),
		CAPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}),
	}, nil
}

// SessionID is the SPIFFE URI of a session pod.
func SessionID(trustDomain, pod string) string { return "spiffe://" + trustDomain + "/session/" + pod }

// GatewayID is the SPIFFE URI of the gateway.
func GatewayID(trustDomain string) string { return "spiffe://" + trustDomain + "/gateway" }
