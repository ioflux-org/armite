# syntax=docker/dockerfile:1

# Build: a static binary, so the runtime image needs no libc for it.
# The build stage runs on the builder's own platform and cross-compiles
# for the target (Go needs no emulation for that); a multi-arch image is
# one `docker buildx build --platform linux/amd64,linux/arm64`.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" -o /out/armite ./cmd/armite

# Azurite: installed on the builder's platform too, because npm under
# QEMU emulation (the arm64 half of a multi-arch build) crashes Node;
# Azurite is pure JavaScript, so the install copies across platforms.
FROM --platform=$BUILDPLATFORM node:25-alpine AS azurite
RUN npm install -g azurite@3.37.0 && npm cache clean --force

# Run: Node, because storage accounts are served by Azurite, a Node
# program Armite starts and restarts itself; non-root (the image's
# "node" user). /data is the home directory: the CA, leaf certificate,
# signing key and state key generated at first boot, and state/ with
# everything created through the API, Azurite's blobs included. One
# volume; delete state/ inside it to start over with the same CA.
FROM node:25-alpine
COPY --from=azurite /usr/local/lib/node_modules/azurite /usr/local/lib/node_modules/azurite
# The commands npm would have linked; COPY would flatten the symlinks.
RUN ln -s ../lib/node_modules/azurite/dist/src/blob/main.js /usr/local/bin/azurite-blob && \
    ln -s ../lib/node_modules/azurite/dist/src/azurite.js /usr/local/bin/azurite
WORKDIR /app
COPY --from=build /out/armite /app/armite
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
# Published ports cannot reach the loopback interface: bind them all.
ENV ARMITE_HOME=/data ARMITE_LISTEN_ADDR=0.0.0.0:8443 ARMITE_IMDS_ADDR=0.0.0.0:8081 \
    ARMITE_CONTAINER=1
EXPOSE 8443 8081
ENTRYPOINT ["/app/armite"]
