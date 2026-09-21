package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cchulo/project-juggernaut/internal/cli"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// tokenAndSubject logs in (device flow) unless JUGGERNAUT_ACCESS_TOKEN is set,
// and reads the subject from the token's payload (the gateway validates it; we
// only need the subject to bind the sealed entries).
func tokenAndSubject(issuer, clientID, scope string) (string, string, error) {
	tok := os.Getenv("JUGGERNAUT_ACCESS_TOKEN")
	if tok == "" {
		if issuer == "" {
			return "", "", fmt.Errorf("--issuer or JUGGERNAUT_ISSUER is required (or set JUGGERNAUT_ACCESS_TOKEN)")
		}
		var err error
		tok, err = deviceLogin(issuer, clientID, scope)
		if err != nil {
			return "", "", err
		}
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("token is not a JWT; cannot read the subject")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Sub == "" {
		return "", "", fmt.Errorf("token has no sub claim")
	}
	return tok, claims.Sub, nil
}

func secretsCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: juggernaut secrets init|set|list|delete|rotate")
	}
	fs := flag.NewFlagSet("secrets "+args[0], flag.ExitOnError)
	gatewayURL := fs.String("gateway", os.Getenv("JUGGERNAUT_GATEWAY"), "gateway public URL")
	issuer := fs.String("issuer", os.Getenv("JUGGERNAUT_ISSUER"), "OIDC issuer for the device-flow login")
	clientID := fs.String("client-id", "mcp-client", "public client with device flow enabled")
	passphrase := fs.String("passphrase", os.Getenv("JUGGERNAUT_VAULT_PASSPHRASE"), "vault passphrase (init/rotate, or when the key is not cached)")
	noCache := fs.Bool("no-cache-key", false, "do not keep the derived key on disk; ask for the passphrase every time")
	_ = fs.Parse(args[1:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	switch args[0] {
	case "init":
		if *passphrase == "" {
			return fmt.Errorf("--passphrase is required for init")
		}
		if _, err := cli.InitVault(*passphrase, !*noCache); err != nil {
			return err
		}
		fmt.Println("vault created; add credentials with: juggernaut secrets set <adapter> NAME=value ...")
		return nil
	}

	vault, err := cli.LoadVault()
	if err != nil {
		return err
	}
	key, err := vault.UserKey(*passphrase)
	if err != nil {
		return err
	}
	defer core.Zero(key)
	if *gatewayURL == "" {
		return fmt.Errorf("--gateway or JUGGERNAUT_GATEWAY is required")
	}
	tok, subject, err := tokenAndSubject(*issuer, *clientID, "openid juggernaut:mcp")
	if err != nil {
		return err
	}
	g := &cli.Gateway{URL: *gatewayURL, Token: tok}

	switch args[0] {
	case "set":
		rest := fs.Args()
		if len(rest) < 2 {
			return fmt.Errorf("usage: juggernaut secrets set <adapter> NAME=value [NAME=value ...]")
		}
		values := map[string]string{}
		for _, kv := range rest[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("expected NAME=value, got %q", kv)
			}
			values[k] = v
		}
		if err := cli.SetSecrets(ctx, g, vault, key, subject, rest[0], values); err != nil {
			return err
		}
		fmt.Printf("sealed %d value(s) for %s; the gateway stores ciphertext only\n", len(values), rest[0])
	case "list":
		entries, err := g.List(ctx)
		if err != nil {
			return err
		}
		for _, e := range entries {
			fmt.Printf("%-16s %v  (updated %s)\n", e.Adapter, e.Entry.Names, e.Entry.UpdatedAt.Format(time.RFC3339))
		}
	case "delete":
		if len(fs.Args()) != 1 {
			return fmt.Errorf("usage: juggernaut secrets delete <adapter>")
		}
		return g.Delete(ctx, fs.Args()[0])
	case "rotate":
		if *passphrase == "" {
			return fmt.Errorf("--passphrase (the NEW passphrase) is required; set JUGGERNAUT_VAULT_OLD_PASSPHRASE when the old key is not cached")
		}
		oldKey := key
		if old := os.Getenv("JUGGERNAUT_VAULT_OLD_PASSPHRASE"); old != "" {
			oldKey = core.DeriveUserKey(old, vault.Salt, vault.Argon)
		}
		return cli.Rotate(ctx, g, vault, oldKey, subject, *passphrase, !*noCache)
	default:
		return fmt.Errorf("unknown secrets command %q", args[0])
	}
	return nil
}

func connectCmd(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	gatewayURL := fs.String("gateway", os.Getenv("JUGGERNAUT_GATEWAY"), "gateway public URL")
	issuer := fs.String("issuer", os.Getenv("JUGGERNAUT_ISSUER"), "OIDC issuer for the device-flow login")
	clientID := fs.String("client-id", "mcp-client", "public client with device flow enabled")
	listen := fs.String("listen", "127.0.0.1:8090", "loopback address MCP clients connect to")
	passphrase := fs.String("passphrase", os.Getenv("JUGGERNAUT_VAULT_PASSPHRASE"), "vault passphrase when the key is not cached")
	_ = fs.Parse(args)
	if *gatewayURL == "" {
		return fmt.Errorf("--gateway or JUGGERNAUT_GATEWAY is required")
	}
	if !strings.HasPrefix(*listen, "127.0.0.1:") && !strings.HasPrefix(*listen, "localhost:") && !strings.HasPrefix(*listen, "[::1]:") {
		return fmt.Errorf("the companion only listens on loopback")
	}
	vault, err := cli.LoadVault()
	if err != nil {
		return err
	}
	key, err := vault.UserKey(*passphrase)
	if err != nil {
		return err
	}
	tok, subject, err := tokenAndSubject(*issuer, *clientID, "openid juggernaut:mcp")
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	comp := cli.NewCompanion(&cli.Gateway{URL: *gatewayURL, Token: tok}, subject, key, "X-Juggernaut-Sealed-Secrets-", log)
	if err := comp.Refresh(context.Background()); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "companion listening on http://%s/mcp for %s → %s\n", *listen, subject, *gatewayURL)
	srv := &http.Server{Addr: *listen, Handler: comp, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
