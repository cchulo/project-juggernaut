package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// ProtectedResourceMetadata is the RFC 9728 document served at
// /.well-known/oauth-protected-resource.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// PRMPath is the well-known path.
const PRMPath = "/.well-known/oauth-protected-resource"

// PRMHandler serves the metadata document for the configured identity provider.
func PRMHandler(store *config.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := store.Get().Config
		doc := ProtectedResourceMetadata{
			Resource:               strings.TrimRight(c.Gateway.PublicURL, "/") + "/mcp",
			AuthorizationServers:   []string{c.Identity.Issuer},
			ScopesSupported:        []string{c.Identity.Scopes.MCP, c.Identity.Scopes.Admin},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "Juggernaut MCP Gateway",
			ResourceDocumentation:  "https://github.com/cchulo/project-juggernaut",
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

// PRMURL returns the absolute metadata URL for challenges.
func PRMURL(c *config.Config) string {
	return strings.TrimRight(c.Gateway.PublicURL, "/") + PRMPath
}
