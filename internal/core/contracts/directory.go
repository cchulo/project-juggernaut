package contracts

import (
	"context"
	"time"
)

// User is the admin-listener view of a directory user.
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email,omitempty"`
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Enabled   bool      `json:"enabled"`
	Groups    []string  `json:"groups,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// IdPSession is one identity-provider session of a user.
type IdPSession struct {
	ID         string    `json:"id"`
	Clients    []string  `json:"clients,omitempty"`
	Start      time.Time `json:"start"`
	LastAccess time.Time `json:"lastAccess"`
	IPAddress  string    `json:"ipAddress,omitempty"`
}

// Group is a directory group.
type Group struct {
	ID   string `json:"keycloakId"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// Directory is the user-administration surface the admin UI needs. The
// reference adapter talks to the Keycloak Admin REST API with a service
// account holding only the roles the UI needs.
type Directory interface {
	ListUsers(ctx context.Context, search string, first, max int) ([]User, error)
	GetUser(ctx context.Context, id string) (*User, error)
	CreateUser(ctx context.Context, u User, temporaryPassword string, sendResetEmail bool) (*User, error)
	UpdateUser(ctx context.Context, id string, enabled *bool, email, firstName, lastName *string) error
	SetGroups(ctx context.Context, id string, groups []string) error
	ResetPassword(ctx context.Context, id, value string, temporary bool) error
	Sessions(ctx context.Context, id string) ([]IdPSession, error)
	Logout(ctx context.Context, id string) error
	Groups(ctx context.Context) ([]Group, error)
	// StatusOf maps an adapter error to an HTTP status for the API.
	StatusOf(err error) int
}
