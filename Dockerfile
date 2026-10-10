# syntax=docker/dockerfile:1

# Build: a static binary, so the runtime image needs no libc for it.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/armite ./cmd/armite

# Run: Node, because storage accounts are served by Azurite, a Node
# program Armite starts and restarts itself; non-root (the image's
# "node" user). /data is the home directory: the CA, leaf certificate,
# signing key and state key generated at first boot, and state/ with
# everything created through the API, Azurite's blobs included. One
# volume; delete state/ inside it to start over with the same CA.
FROM node:22-alpine
RUN npm install -g azurite@3.37.0 && npm cache clean --force
WORKDIR /app
COPY --from=build /out/armite /app/armite
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
# Published ports cannot reach the loopback interface: bind them all.
ENV ARMITE_HOME=/data ARMITE_LISTEN_ADDR=0.0.0.0:8443 ARMITE_IMDS_ADDR=0.0.0.0:8081
EXPOSE 8443 8081
ENTRYPOINT ["/app/armite"]
