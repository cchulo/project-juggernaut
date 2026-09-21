package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestMutualTLSHandshake proves the certificate shapes the controller issues
// let a gateway client and a pod server authenticate each other, and that a
// certificate from another CA or for another identity is rejected.
func TestMutualTLSHandshake(t *testing.T) {
	ca, _ := NewCA("test CA")
	pod, _ := ca.IssueServer(SessionID("juggernaut", "jira-1"), []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	gw, _ := ca.IssueClient(GatewayID("juggernaut"), time.Hour)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pod.CAPEM)

	serverCert, _ := tls.X509KeyPair(pod.CertPEM, pod.KeyPEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			for _, u := range chains[0][0].URIs {
				if u.String() == GatewayID("juggernaut") {
					return nil
				}
			}
			return fmt.Errorf("not the gateway")
		},
	}
	srv.StartTLS()
	defer srv.Close()

	dial := func(certPEM, keyPEM []byte, wantPod string) error {
		cert, _ := tls.X509KeyPair(certPEM, keyPEM)
		tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, InsecureSkipVerify: true,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				leaf, _ := x509.ParseCertificate(raw[0])
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
					return err
				}
				for _, u := range leaf.URIs {
					if u.String() == SessionID("juggernaut", wantPod) {
						return nil
					}
				}
				return fmt.Errorf("wrong pod identity")
			}}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		resp, err := c.Get(srv.URL)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	if err := dial(gw.CertPEM, gw.KeyPEM, "jira-1"); err != nil {
		t.Fatalf("gateway ↔ pod handshake: %v", err)
	}
	if err := dial(gw.CertPEM, gw.KeyPEM, "jira-2"); err == nil {
		t.Fatal("the gateway must refuse a pod presenting another pod's identity")
	}
	imposter, _ := ca.IssueServer(SessionID("juggernaut", "jira-9"), nil, time.Hour) // a pod cert used as a client cert
	if err := dial(imposter.CertPEM, imposter.KeyPEM, "jira-1"); err == nil {
		t.Fatal("a pod certificate must not be accepted as the gateway")
	}
	other, _ := NewCA("other")
	rogue, _ := other.IssueClient(GatewayID("juggernaut"), time.Hour)
	if err := dial(rogue.CertPEM, rogue.KeyPEM, "jira-1"); err == nil {
		t.Fatal("a client certificate from another CA must be refused")
	}
}
