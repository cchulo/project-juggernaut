package core

import (
	"context"
	"strings"
	"testing"
)

func TestSessionIDs(t *testing.T) {
	a, b := NewMcpSessionID(), NewMcpSessionID()
	if a == b || !IsMcpSessionID(a) || len(a) != len("jg_")+26 || IsMcpSessionID("jg_short") || IsMcpSessionID("xx_"+a[3:]) {
		t.Fatalf("ids: %s %s", a, b)
	}
	if UserHash("alice@example.com") == UserHash("bob@example.com") || len(UserHash("x")) != 8 {
		t.Fatal("user hash must be 8 hex chars and differ per subject")
	}
	k := PodKey{Subject: "alice@example.com", ServerType: "jira"}
	if !strings.HasPrefix(k.Name(), "jira-") || strings.Contains(k.Name(), "@") {
		t.Fatalf("pod name must not leak the subject: %s", k.Name())
	}
}

func TestSealerAndMAC(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	s, err := NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := s.Seal("pod-token")
	if ct == "pod-token" {
		t.Fatal("seal must not be identity")
	}
	if pt, err := s.Open(ct); err != nil || pt != "pod-token" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := s.Open(ct[:len(ct)-2] + "AA"); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
	mk := DeriveMACKey(key, "routing")
	m1 := MAC(mk, "a", "b")
	if !MACEqual(m1, MAC(mk, "a", "b")) || MACEqual(m1, MAC(mk, "ab", "")) || MACEqual(m1, MAC(DeriveMACKey(key, "other"), "a", "b")) {
		t.Fatal("MAC must depend on parts, boundaries and purpose")
	}
	if !MACEqual(nil, nil) || MACEqual(nil, m1) {
		t.Fatal("nil handling")
	}
}

func TestPrincipalHelpers(t *testing.T) {
	p := &Principal{Subject: "s", Groups: []string{"eng"}, Scopes: []string{"juggernaut:mcp"}}
	if !p.InGroup("eng") || p.InGroup("ops") || !p.HasScope("juggernaut:mcp") || p.HasScope("x") {
		t.Fatal("principal helpers")
	}
	ctx := WithPrincipal(context.Background(), p)
	if PrincipalFrom(ctx) != p || PrincipalFrom(context.Background()) != nil {
		t.Fatal("context round trip")
	}
	g := NewGrants("s", []string{"b", "a", "a", ""}, []string{"g"}, false, 3, true)
	if len(g.ServerTypes) != 2 || g.ServerTypes[0] != "a" || !g.Allows("b") || g.Allows("c") || !g.InGroup("g") {
		t.Fatalf("grants: %+v", g)
	}
	if !HasPrefixFold("Cursor 1.0", "cursor") || HasPrefixFold("cur", "cursor") {
		t.Fatal("prefix fold")
	}
}
