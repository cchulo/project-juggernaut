# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags '-s -w' -o /out/juggernaut-gateway ./cmd/juggernaut-gateway && \
    CGO_ENABLED=0 go build -ldflags '-s -w' -o /out/juggernaut ./cmd/juggernaut

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/juggernaut-gateway /juggernaut-gateway
COPY --from=build /out/juggernaut /juggernaut
USER 65532:65532
EXPOSE 8080 9090 24680
ENTRYPOINT ["/juggernaut-gateway"]
