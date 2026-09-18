# syntax=docker/dockerfile:1
# The wrapper is a static binary. It is either baked into a server image (COPY
# --from=ghcr.io/cchulo/juggernaut-wrapper /juggernaut-wrapper /) or copied into
# the session pod by an init container from this image.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags '-s -w' -o /out/juggernaut-wrapper ./cmd/juggernaut-wrapper

FROM scratch
COPY --from=build /out/juggernaut-wrapper /juggernaut-wrapper
ENTRYPOINT ["/juggernaut-wrapper"]
