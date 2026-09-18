# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags '-s -w' -o /out/juggernaut-egress ./cmd/juggernaut-egress

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/juggernaut-egress /juggernaut-egress
USER 65532:65532
EXPOSE 3128
ENTRYPOINT ["/juggernaut-egress"]
