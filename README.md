# Juggernaut

Juggernaut is a **self-hosted**, open-source, Kubernetes-native MCP (Model Context Protocol) gateway.

It runs **one isolated MCP server pod per (user, server type)**, brokers OAuth 2.0 on the front door
(the gateway is an MCP-spec OAuth 2.0 protected resource), and passes a **per-user token** to the MCP
servers hosted behind it so upstream actions (Jira, GitHub, internal APIs) are attributed to the
calling person, not to a shared service identity.

Juggernaut is designed for people running their own cluster: a laptop (kind, k3s, OrbStack) or a
managed cluster (EKS, GKE, AKS) with no cloud-specific dependency in the core. Identity comes from
your own OIDC provider (Keycloak is the reference; Entra ID, Okta, Dex and others are pluggable).

The repository is being built up in milestones. See `docs/DESIGN.md` for the full design and
`docs/SELF-HOSTING.md` for how to run it on your own hardware.

## Status

Pre-alpha scaffold. Nothing here is production-ready yet.

