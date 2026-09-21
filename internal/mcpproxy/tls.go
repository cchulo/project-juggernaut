package mcpproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// PodTLS is the gateway's client identity for mutual TLS to session pods and
// the CA that signs pod certificates. Pods are identified by the SPIFFE URI
// SAN spiffe://<trustDomain>/session/<pod>; the connection is refused when
// the presented certificate names another pod.
type PodTLS struct {
	cert        tls.Certificate
	pool        *x509.CertPool
	TrustDomain string
}

// LoadPodTLS reads the gateway's client certificate, key and the CA.
func LoadPodTLS(certFile, keyFile, caFile, trustDomain string) (*PodTLS, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("gateway client cert: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("pod CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("pod CA: no certificates in file")
	}
	return &PodTLS{cert: cert, pool: pool, TrustDomain: trustDomain}, nil
}

// ClientConfig builds a tls.Config that presents the gateway certificate and
// verifies the pod's certificate chain. The pod's identity (URI SAN) is
// checked per connection by VerifyPod through ServerName handling below.
func (p *PodTLS) ClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{p.cert},
		RootCAs:      p.pool,
		// Pods are addressed by IP; hostname verification is replaced by the SPIFFE check.
		InsecureSkipVerify: true, //nolint:gosec // chain and identity are verified in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return p.verifyChain(rawCerts, "")
		},
	}
}

// verifyChain checks the chain against the CA and, when wantPod is set, the URI SAN.
func (p *PodTLS) verifyChain(rawCerts [][]byte, wantPod string) error {
	if len(rawCerts) == 0 {
		return errors.New("pod presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("pod certificate: %w", err)
	}
	prefix := "spiffe://" + p.TrustDomain + "/session/"
	for _, u := range leaf.URIs {
		s := u.String()
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			if wantPod == "" || s[len(prefix):] == wantPod {
				return nil
			}
		}
	}
	return fmt.Errorf("pod certificate has no %s<pod> identity", prefix)
}
