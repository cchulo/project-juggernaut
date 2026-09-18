# syntax=docker/dockerfile:1
# Example stdio MCP server image with the wrapper baked in, used by the
# milestone-0 Compose demo. It runs the reference "everything" server from the
# TypeScript SDK; swap it for your own server. No npx at runtime: dependencies
# are installed at build time so the session pod needs no package registry access.
FROM node:22-slim AS deps
WORKDIR /app
RUN npm install --omit=dev @modelcontextprotocol/server-everything@2025.9.25 && npm cache clean --force

FROM ghcr.io/cchulo/juggernaut-wrapper:latest AS wrapper

FROM node:22-slim
WORKDIR /app
COPY --from=deps /app/node_modules /app/node_modules
COPY --from=wrapper /juggernaut-wrapper /juggernaut-wrapper
USER 65532:65532
ENTRYPOINT ["/juggernaut-wrapper"]
