// Command juggernaut is the operator CLI: validate and inspect juggernaut.yaml,
// print the JSON Schema, and (later milestones) migrate configs and log in to
// the admin UI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/cchulo/project-juggernaut/internal/adapters/all"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		file := fs.String("f", "juggernaut.yaml", "config file")
		_ = fs.Parse(os.Args[2:])
		l, err := config.LoadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			os.Exit(1)
		}
		fmt.Printf("OK %s (hash %s): %d server types, %d groups\n", *file, l.Hash, len(l.Config.Servers), len(l.Config.Authorization.Groups))
	case "render":
		fs := flag.NewFlagSet("render", flag.ExitOnError)
		file := fs.String("f", "juggernaut.yaml", "config file")
		_ = fs.Parse(os.Args[2:])
		l, err := config.LoadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			os.Exit(1)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(l.Config)
	case "schema":
		_, _ = os.Stdout.Write(config.SchemaJSON())
	case "adapters":
		fmt.Printf("%-10s %v\n", "identity", registry.Identity.Types())
		fmt.Printf("%-10s %v\n", "policy", registry.Policy.Types())
		fmt.Printf("%-10s %v\n", "broker", registry.Broker.Types())
		fmt.Printf("%-10s %v\n", "provision", registry.Provision.Types())
		fmt.Printf("%-10s %v\n", "routing", registry.Routing.Types())
		fmt.Printf("%-10s %v\n", "egress", registry.Egress.Types())
		fmt.Printf("%-10s %v\n", "directory", registry.Directory.Types())
		fmt.Printf("%-10s %v\n", "audit", registry.Audit.Types())
	case "version":
		fmt.Println(version.Version)
	case "config":
		fmt.Fprintln(os.Stderr, "config migrate: nothing to migrate for", config.APIVersion)
	case "secrets":
		if err := secretsCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "connect":
		if err := connectCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "admin":
		if len(os.Args) < 3 || os.Args[2] != "login" {
			usage()
			os.Exit(2)
		}
		fs := flag.NewFlagSet("admin login", flag.ExitOnError)
		issuer := fs.String("issuer", os.Getenv("JUGGERNAUT_ISSUER"), "OIDC issuer (e.g. https://kc/realms/juggernaut)")
		clientID := fs.String("client-id", "juggernaut-admin-ui", "public client with device flow enabled")
		scope := fs.String("scope", "openid profile juggernaut:users.admin", "scopes to request")
		_ = fs.Parse(os.Args[3:])
		if *issuer == "" {
			fmt.Fprintln(os.Stderr, "--issuer or JUGGERNAUT_ISSUER is required")
			os.Exit(2)
		}
		tok, err := deviceLogin(*issuer, *clientID, *scope)
		if err != nil {
			fmt.Fprintln(os.Stderr, "login failed:", err)
			os.Exit(1)
		}
		fmt.Println(tok)
	default:
		usage()
		os.Exit(2)
	}
}

// deviceLogin runs the OAuth 2.0 device authorization grant (RFC 8628) and
// prints the access token for use against the admin API:
//
//	curl -H "Authorization: Bearer $(juggernaut admin login)" http://127.0.0.1:24680/admin/api/users
func deviceLogin(issuer, clientID, scope string) (string, error) {
	var disc struct {
		DeviceEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint  string `json:"token_endpoint"`
	}
	if err := getJSON(strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", &disc); err != nil {
		return "", err
	}
	if disc.DeviceEndpoint == "" {
		return "", fmt.Errorf("issuer does not advertise a device authorization endpoint")
	}
	var dev struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri_complete"`
		VerificationURL string `json:"verification_uri"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
	if err := postForm(disc.DeviceEndpoint, url.Values{"client_id": {clientID}, "scope": {scope}}, &dev); err != nil {
		return "", err
	}
	link := dev.VerificationURI
	if link == "" {
		link = dev.VerificationURL + " (code " + dev.UserCode + ")"
	}
	fmt.Fprintf(os.Stderr, "Open %s and approve the login.\n", link)
	interval := time.Duration(max(dev.Interval, 5)) * time.Second
	deadline := time.Now().Add(time.Duration(dev.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		var tok struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		err := postForm(disc.TokenEndpoint, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dev.DeviceCode}, "client_id": {clientID},
		}, &tok)
		if err != nil {
			return "", err
		}
		switch tok.Error {
		case "":
			if tok.AccessToken != "" {
				return tok.AccessToken, nil
			}
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		default:
			return "", fmt.Errorf("%s", tok.Error)
		}
	}
	return "", fmt.Errorf("device code expired")
}

func getJSON(u string, v any) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func postForm(u string, form url.Values, v any) error {
	resp, err := http.PostForm(u, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: juggernaut <command>

  validate -f juggernaut.yaml   validate against the schema and semantic rules
  render   -f juggernaut.yaml   print the defaulted config as JSON
  schema                        print the JSON Schema
  adapters                      list the adapter types compiled into this binary
  config migrate                rewrite an older config version (no-op today)
  admin login --issuer URL      obtain an admin token via the device flow (prints it)
  secrets init|set|list|delete|rotate   your sealed third-party credentials (see docs/SECURITY.md)
  connect --gateway URL         local companion: MCP clients use http://127.0.0.1:8090/mcp with no credentials in their config
  version`)
}
