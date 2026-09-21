// Package keycloak is the Directory adapter for the admin UI: it talks to the
// Keycloak Admin REST API with a dedicated service account that holds only the
// realm-management roles view-users, manage-users, query-users, query-groups
// and view-realm. Configured by identity.keycloakAdmin.
package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "keycloak"

func init() { registry.Directory.Register(Type, New) }

type (
	User            = contracts.User
	KeycloakSession = contracts.IdPSession
	Group           = contracts.Group
)

// New builds the adapter from identity.keycloakAdmin.
func New(ctx *core.Context) (contracts.Directory, error) {
	return NewKeycloak(ctx.Cfg().Identity, ctx.Secrets.Get)
}

// Keycloak implements Directory with gocloak.
type Keycloak struct {
	cfg    config.KeycloakAdmin
	client *gocloak.GoCloak
	secret func(*config.SecretRef) (string, error)

	mu    sync.Mutex
	tok   *gocloak.JWT
	tokAt time.Time
	// groups cache: name → id
	groupIDs map[string]string
	groupsAt time.Time
}

// NewKeycloak builds the client. baseURL defaults to the issuer's origin.
func NewKeycloak(id config.Identity, secret func(*config.SecretRef) (string, error)) (*Keycloak, error) {
	if id.KeycloakAdmin == nil {
		return nil, fmt.Errorf("identity.keycloakAdmin is not configured")
	}
	cfg := *id.KeycloakAdmin
	base := cfg.BaseURL
	if base == "" {
		// issuer is <base>/realms/<realm>
		if i := strings.Index(id.Issuer, "/realms/"); i > 0 {
			base = id.Issuer[:i]
		} else {
			return nil, fmt.Errorf("identity.keycloakAdmin.baseURL is required when the issuer is not <base>/realms/<realm>")
		}
	}
	return &Keycloak{cfg: cfg, client: gocloak.NewClient(base, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms")),
		secret: secret, groupIDs: map[string]string{}}, nil
}

// token logs the service account in and caches the token until shortly before expiry.
func (k *Keycloak) token(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.tok != nil && time.Since(k.tokAt) < time.Duration(k.tok.ExpiresIn-30)*time.Second {
		return k.tok.AccessToken, nil
	}
	sec, err := k.secret(&k.cfg.ClientSecretRef)
	if err != nil {
		return "", err
	}
	tok, err := k.client.LoginClient(ctx, k.cfg.ClientID, sec, k.cfg.Realm)
	if err != nil {
		return "", fmt.Errorf("keycloak service account login: %w", err)
	}
	k.tok, k.tokAt = tok, time.Now()
	return tok.AccessToken, nil
}

func (k *Keycloak) ListUsers(ctx context.Context, search string, first, max int) ([]User, error) {
	tok, err := k.token(ctx)
	if err != nil {
		return nil, err
	}
	params := gocloak.GetUsersParams{First: gocloak.IntP(first), Max: gocloak.IntP(max), BriefRepresentation: gocloak.BoolP(true)}
	if search != "" {
		params.Search = gocloak.StringP(search)
	}
	users, err := k.client.GetUsers(ctx, tok, k.cfg.Realm, params)
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(users))
	for _, u := range users {
		out = append(out, fromKC(u))
	}
	return out, nil
}

func (k *Keycloak) GetUser(ctx context.Context, id string) (*User, error) {
	tok, err := k.token(ctx)
	if err != nil {
		return nil, err
	}
	u, err := k.client.GetUserByID(ctx, tok, k.cfg.Realm, id)
	if err != nil {
		return nil, err
	}
	out := fromKC(u)
	groups, err := k.client.GetUserGroups(ctx, tok, k.cfg.Realm, id, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, gocloak.PString(g.Name))
	}
	return &out, nil
}

func (k *Keycloak) CreateUser(ctx context.Context, u User, temporaryPassword string, sendResetEmail bool) (*User, error) {
	tok, err := k.token(ctx)
	if err != nil {
		return nil, err
	}
	kc := gocloak.User{Username: &u.Username, Enabled: gocloak.BoolP(true)}
	if u.Email != "" {
		kc.Email = &u.Email
	}
	if u.FirstName != "" {
		kc.FirstName = &u.FirstName
	}
	if u.LastName != "" {
		kc.LastName = &u.LastName
	}
	id, err := k.client.CreateUser(ctx, tok, k.cfg.Realm, kc)
	if err != nil {
		return nil, err
	}
	if len(u.Groups) > 0 {
		if err := k.SetGroups(ctx, id, u.Groups); err != nil {
			return nil, err
		}
	}
	if temporaryPassword != "" {
		if err := k.client.SetPassword(ctx, tok, id, k.cfg.Realm, temporaryPassword, true); err != nil {
			return nil, err
		}
	} else if sendResetEmail && u.Email != "" {
		_ = k.client.ExecuteActionsEmail(ctx, tok, k.cfg.Realm, gocloak.ExecuteActionsEmail{UserID: &id, Actions: &[]string{"UPDATE_PASSWORD"}})
	}
	return k.GetUser(ctx, id)
}

func (k *Keycloak) UpdateUser(ctx context.Context, id string, enabled *bool, email, firstName, lastName *string) error {
	tok, err := k.token(ctx)
	if err != nil {
		return err
	}
	u := gocloak.User{ID: &id, Enabled: enabled, Email: email, FirstName: firstName, LastName: lastName}
	return k.client.UpdateUser(ctx, tok, k.cfg.Realm, u)
}

// SetGroups makes the user's memberships exactly `groups` (only groups known to Keycloak).
func (k *Keycloak) SetGroups(ctx context.Context, id string, groups []string) error {
	tok, err := k.token(ctx)
	if err != nil {
		return err
	}
	ids, err := k.groupIndex(ctx, tok)
	if err != nil {
		return err
	}
	current, err := k.client.GetUserGroups(ctx, tok, k.cfg.Realm, id, gocloak.GetGroupsParams{})
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, g := range groups {
		if _, ok := ids[g]; !ok {
			return fmt.Errorf("unknown group %q", g)
		}
		want[g] = true
	}
	have := map[string]bool{}
	for _, g := range current {
		name := gocloak.PString(g.Name)
		have[name] = true
		if !want[name] {
			if err := k.client.DeleteUserFromGroup(ctx, tok, k.cfg.Realm, id, gocloak.PString(g.ID)); err != nil {
				return err
			}
		}
	}
	for g := range want {
		if !have[g] {
			if err := k.client.AddUserToGroup(ctx, tok, k.cfg.Realm, id, ids[g]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *Keycloak) ResetPassword(ctx context.Context, id, value string, temporary bool) error {
	tok, err := k.token(ctx)
	if err != nil {
		return err
	}
	if value == "" {
		return k.client.ExecuteActionsEmail(ctx, tok, k.cfg.Realm, gocloak.ExecuteActionsEmail{UserID: &id, Actions: &[]string{"UPDATE_PASSWORD"}})
	}
	return k.client.SetPassword(ctx, tok, id, k.cfg.Realm, value, temporary)
}

func (k *Keycloak) Sessions(ctx context.Context, id string) ([]KeycloakSession, error) {
	tok, err := k.token(ctx)
	if err != nil {
		return nil, err
	}
	ss, err := k.client.GetUserSessions(ctx, tok, k.cfg.Realm, id)
	if err != nil {
		return nil, err
	}
	out := make([]KeycloakSession, 0, len(ss))
	for _, s := range ss {
		ks := KeycloakSession{ID: gocloak.PString(s.ID), IPAddress: gocloak.PString(s.IPAddress)}
		if s.Start != nil {
			ks.Start = time.UnixMilli(*s.Start)
		}
		if s.LastAccess != nil {
			ks.LastAccess = time.UnixMilli(*s.LastAccess)
		}
		if s.Clients != nil {
			for _, c := range *s.Clients {
				ks.Clients = append(ks.Clients, c)
			}
		}
		out = append(out, ks)
	}
	return out, nil
}

func (k *Keycloak) Logout(ctx context.Context, id string) error {
	tok, err := k.token(ctx)
	if err != nil {
		return err
	}
	return k.client.LogoutAllSessions(ctx, tok, k.cfg.Realm, id)
}

func (k *Keycloak) Groups(ctx context.Context) ([]Group, error) {
	tok, err := k.token(ctx)
	if err != nil {
		return nil, err
	}
	gs, err := k.client.GetGroups(ctx, tok, k.cfg.Realm, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, Group{ID: gocloak.PString(g.ID), Name: gocloak.PString(g.Name), Path: gocloak.PString(g.Path)})
	}
	return out, nil
}

func (k *Keycloak) groupIndex(ctx context.Context, tok string) (map[string]string, error) {
	k.mu.Lock()
	fresh := time.Since(k.groupsAt) < 5*time.Minute && len(k.groupIDs) > 0
	k.mu.Unlock()
	if fresh {
		return k.groupIDs, nil
	}
	gs, err := k.client.GetGroups(ctx, tok, k.cfg.Realm, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	idx := map[string]string{}
	for _, g := range gs {
		idx[gocloak.PString(g.Name)] = gocloak.PString(g.ID)
	}
	k.mu.Lock()
	k.groupIDs, k.groupsAt = idx, time.Now()
	k.mu.Unlock()
	return idx, nil
}

func fromKC(u *gocloak.User) User {
	out := User{ID: gocloak.PString(u.ID), Username: gocloak.PString(u.Username), Email: gocloak.PString(u.Email),
		FirstName: gocloak.PString(u.FirstName), LastName: gocloak.PString(u.LastName)}
	if u.Enabled != nil {
		out.Enabled = *u.Enabled
	}
	if u.CreatedTimestamp != nil {
		out.CreatedAt = time.UnixMilli(*u.CreatedTimestamp)
	}
	return out
}

// StatusOf maps gocloak errors to HTTP codes.
func (k *Keycloak) StatusOf(err error) int {
	var apiErr *gocloak.APIError
	if asAPIError(err, &apiErr) && apiErr.Code != 0 {
		return apiErr.Code
	}
	return http.StatusBadGateway
}

func asAPIError(err error, target **gocloak.APIError) bool {
	e, ok := err.(*gocloak.APIError)
	if ok {
		*target = e
	}
	return ok
}

var _ contracts.Directory = (*Keycloak)(nil)
