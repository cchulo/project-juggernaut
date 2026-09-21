package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/pki"
)

// PodPKI issues the certificates for podAuth mtls from a CA kept in a Secret
// in the system namespace. It never hands the CA key to anyone: pods get a
// leaf and the CA certificate; the gateway gets a client leaf and the CA certificate.
type PodPKI struct {
	Client          client.Client
	SystemNamespace string
	Cfg             config.MTLS
	ca              *pki.CA
}

// Ensure loads or creates the CA and the gateway client certificate Secret.
func (p *PodPKI) Ensure(ctx context.Context) error {
	sec := &corev1.Secret{}
	err := p.Client.Get(ctx, client.ObjectKey{Namespace: p.SystemNamespace, Name: p.Cfg.CASecretName}, sec)
	switch {
	case apierrors.IsNotFound(err):
		ca, err := pki.NewCA("juggernaut pod CA")
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := ca.PEM()
		if err != nil {
			return err
		}
		sec = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: p.SystemNamespace, Name: p.Cfg.CASecretName},
			Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": certPEM, "ca.key": keyPEM}}
		if err := p.Client.Create(ctx, sec); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create pod CA: %w", err)
		}
		p.ca = ca
	case err != nil:
		return err
	default:
		ca, err := pki.LoadCA(sec.Data["ca.crt"], sec.Data["ca.key"])
		if err != nil {
			return fmt.Errorf("load pod CA: %w", err)
		}
		p.ca = ca
	}
	return p.ensureGatewayCert(ctx)
}

// ensureGatewayCert issues (or renews within 7 days of expiry) the gateway's client certificate.
func (p *PodPKI) ensureGatewayCert(ctx context.Context) error {
	name := p.Cfg.GatewaySecretName
	sec := &corev1.Secret{}
	err := p.Client.Get(ctx, client.ObjectKey{Namespace: p.SystemNamespace, Name: name}, sec)
	if err == nil {
		if c, perr := pki.ParseCert(sec.Data["tls.crt"]); perr == nil && time.Until(c.NotAfter) > 7*24*time.Hour {
			return nil
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	b, err := p.ca.IssueClient(pki.GatewayID(p.Cfg.TrustDomain), 90*24*time.Hour)
	if err != nil {
		return err
	}
	sec = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: p.SystemNamespace, Name: name}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": b.CertPEM, "tls.key": b.KeyPEM, "ca.crt": b.CAPEM}}
	if err := p.Client.Create(ctx, sec); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return p.Client.Update(ctx, sec)
		}
		return err
	}
	return nil
}

// IssueForPod adds a server certificate for the pod to its per-session Secret.
func (p *PodPKI) IssueForPod(ctx context.Context, secret *corev1.Secret, podName string, ttl time.Duration) error {
	if _, ok := secret.Data["tls.crt"]; ok {
		return nil
	}
	b, err := p.ca.IssueServer(pki.SessionID(p.Cfg.TrustDomain, podName), nil, ttl)
	if err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data["tls.crt"] = b.CertPEM
	secret.Data["tls.key"] = b.KeyPEM
	secret.Data["ca.crt"] = b.CAPEM
	return p.Client.Update(ctx, secret)
}
