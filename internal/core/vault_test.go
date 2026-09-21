package core

import "testing"

func TestVaultRoundTrip(t *testing.T) {
	salt := NewSalt()
	params := ArgonParams{Time: 1, Memory: 8 * 1024, Threads: 1} // fast for tests
	k := DeriveUserKey("correct horse", salt, params)
	e, err := SealEntry(k, salt, params, "alice", "atlassian", map[string]string{"JIRA_API_TOKEN": "abc", "JIRA_USERNAME": "a@x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Names) != 2 || string(e.Ciphertext) == `{"JIRA_API_TOKEN":"abc"` {
		t.Fatalf("entry shape: %+v", e)
	}
	got, err := OpenEntry(k, "alice", "atlassian", e)
	if err != nil || got["JIRA_API_TOKEN"] != "abc" {
		t.Fatalf("open: %v %v", got, err)
	}
	if _, err := OpenEntry(DeriveUserKey("wrong", salt, params), "alice", "atlassian", e); err != ErrVaultKey {
		t.Fatalf("wrong key must fail with ErrVaultKey, got %v", err)
	}
	if _, err := OpenEntry(k, "bob", "atlassian", e); err != ErrVaultKey {
		t.Fatal("entry must be bound to its subject")
	}
	if _, err := OpenEntry(k, "alice", "github", e); err != ErrVaultKey {
		t.Fatal("entry must be bound to its adapter")
	}
}

func TestSealToPod(t *testing.T) {
	kp, _ := NewPodKeyPair()
	blob, err := SealToPod(kp.Public, map[string]string{"X": "1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := kp.OpenFromClient(blob)
	if err != nil || got["X"] != "1" {
		t.Fatalf("open: %v %v", got, err)
	}
	other, _ := NewPodKeyPair()
	if _, err := other.OpenFromClient(blob); err == nil {
		t.Fatal("another pod's key must not open the blob")
	}
}
