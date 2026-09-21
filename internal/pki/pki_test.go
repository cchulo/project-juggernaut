package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	ca, err := NewCA("juggernaut pod CA")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := ca.PEM()
	if _, err := LoadCA(certPEM, keyPEM); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	b, err := ca.IssueServer(SessionID("juggernaut", "jira-abcd1234"), nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.CAPEM)
	leaf := mustParse(t, b.CertPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://juggernaut/session/jira-abcd1234" {
		t.Fatalf("URI SAN: %v", leaf.URIs)
	}
	other, _ := NewCA("other")
	ob, _ := other.IssueServer(SessionID("juggernaut", "jira-abcd1234"), nil, time.Hour)
	if _, err := mustParse(t, ob.CertPEM).Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("a certificate from another CA must not verify")
	}
}

func mustParse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	c, err := parseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
