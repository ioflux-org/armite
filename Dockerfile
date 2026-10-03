# syntax=docker/dockerfile:1

# Build: a static binary, so the runtime image needs no libc for it.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/provisio ./cmd/provisio

# Run: Node, because storage accounts are served by Azurite, a Node
# program Provisio starts and restarts itself; non-root (the image's
# "node" user). The CA, leaf certificate, signing key and state key are
# generated in /app/certs at first boot; everything created through the
# API - Azurite's blobs included - lives in /app/state, unreadable
# without the key in /app/certs: keep or discard the two together.
FROM node:22-alpine
RUN npm install -g azurite@3.37.0 && npm cache clean --force
WORKDIR /app
COPY --from=build /out/provisio /app/provisio
RUN mkdir -p /app/certs /app/state && chown -R node:node /app
USER node
VOLUME /app/certs /app/state
# Published ports cannot reach the loopback interface: bind them all.
ENV PROVISIO_LISTEN_ADDR=0.0.0.0:8443 PROVISIO_IMDS_ADDR=0.0.0.0:8081
EXPOSE 8443 8081
ENTRYPOINT ["/app/provisio"]
