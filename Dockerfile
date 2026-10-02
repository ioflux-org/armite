# syntax=docker/dockerfile:1

# Build: a static binary, so the runtime image needs no libc.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/provisio ./cmd/provisio \
    && mkdir -p /out/certs /out/state

# Run: distroless, no shell, non-root. The CA, leaf certificate, signing
# key and state key are generated in /app/certs at first boot; mount it
# to read ca.pem from the host and to keep the CA stable across restarts.
# Resources, role assignments and secrets persist in /app/state, which
# is unreadable without the key in /app/certs: keep or discard the two
# together.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/provisio /app/provisio
COPY --from=build --chown=nonroot:nonroot /out/certs /app/certs
COPY --from=build --chown=nonroot:nonroot /out/state /app/state
VOLUME /app/certs /app/state
# Published ports cannot reach the loopback interface: bind them all.
ENV PROVISIO_LISTEN_ADDR=0.0.0.0:8443 PROVISIO_IMDS_ADDR=0.0.0.0:8081
EXPOSE 8443 8081
ENTRYPOINT ["/app/provisio"]
