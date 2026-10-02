# Running Provisio in Docker

## Build

```bash
docker build -t provisio:dev .
```

Multi-stage: a static Go binary in a distroless image, about 18 MB, no
shell, running as a non-root user.

## Run

The server generates its CA, leaf certificate, signing key and state
key in `/app/certs` at first boot, and persists everything created
through the API in `/app/state`. Mount host directories on both so you
can read `ca.pem` and keep your resources across runs, and run as your
own user so the files are yours:

```bash
mkdir -p certs state
docker run --rm --name provisio \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \
  -v "$PWD/certs:/app/certs" -v "$PWD/state:/app/state" \
  provisio:dev
```

The CA is generated once and reused on every start, so trust it once.
`8443` serves ARM, the login endpoint and every vault; `8081` is IMDS for
managed-identity clients. The state files are encrypted with the key in
`certs/`, so keep or discard the two directories together; see
[persistence.md](persistence.md).

To use a configuration file, mount it and name it:

```bash
docker run --rm --name provisio \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \
  -v "$PWD/certs:/app/certs" -v "$PWD/state:/app/state" \
  -v "$PWD/provisio.yaml:/app/provisio.yaml:ro" \
  -e PROVISIO_CONFIG=/app/provisio.yaml \
  provisio:dev
```

### With compose

```bash
docker compose up -d
docker compose cp provisio:/app/certs/ca.pem ./ca.pem
```

Both directories are named volumes; `docker compose down -v` removes
them and starts over.

## Reaching it

Every client talks to Provisio by hostname, so the hostnames must point
at the published ports. On the host, add to `/etc/hosts` (on WSL2, set
`generateHosts = false` in `/etc/wsl.conf` first, or the file is
rewritten):

```text
127.0.0.1  management.localhost
127.0.0.1  login.localhost
127.0.0.1  kv-demo.vault.localhost
```

One line per vault name you create. Then trust the CA, per client:

| client                         | how                                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| curl                           | `--cacert certs/ca.pem`                                                                  |
| az                             | `REQUESTS_CA_BUNDLE=$PWD/certs/ca.pem` and `az config set core.instance_discovery=false` |
| Node SDK                       | `NODE_EXTRA_CA_CERTS=certs/ca.pem`                                                       |
| Terraform (and any Go program) | `SSL_CERT_FILE=$PWD/certs/ca.pem`                                                        |

Managed-identity clients set `AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081`.

## Configuration

| variable               | default                              | image                          |
| ---------------------- | ------------------------------------ | ------------------------------ |
| `PROVISIO_LISTEN_ADDR` | `127.0.0.1:8443`                     | `0.0.0.0:8443`                 |
| `PROVISIO_IMDS_ADDR`   | `127.0.0.1:8081`                     | `0.0.0.0:8081`                 |
| `PROVISIO_CERT_DIR`    | `certs`                              | `/app/certs`                   |
| `PROVISIO_STATE_DIR`   | `state`                              | `/app/state`                   |
| `PROVISIO_STATE_KEY`   | unset (generated into the cert dir)  | unset                          |
| `PROVISIO_CONFIG`      | unset (`./provisio.yaml` if present) | unset; mount a file and set it |

The image binds all interfaces because Docker's published ports cannot
reach a container's loopback interface; publish on `127.0.0.1` as above
to keep the emulator off your network. The port clients use, the
hostnames and the vault suffix do not change with the bind address.

## From another container

A client container does not share the host's `/etc/hosts` or port
publishing. Put both on the same compose network and add the hostnames
as `extra_hosts` entries pointing at the `provisio` service, and mount
the CA the same way.
