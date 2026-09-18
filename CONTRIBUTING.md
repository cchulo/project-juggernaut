# Contributing

## Layout

See `docs/DESIGN.md` §13. Go code follows standard `cmd/` + `internal/` layout; the admin UI is
in `ui/admin`; Kubernetes packaging is in `charts/` and `deploy/`.

## Milestones

Work lands in milestone branches (`docs/DESIGN.md` §12). Each milestone has a demo checklist in its
pull request; a milestone is done when the checklist passes on a kind cluster.

## Local checks

```sh
make fmt vet test
make validate-example
```

## Dependencies

Only permissively licensed dependencies (Apache-2.0, MIT, BSD, MPL-2.0). No source-available (FSL, BSL,
SSPL) components in the core; optional integrations with such components must be plugins the operator
opts into.
