# Running Armite in Docker

<video controls muted playsinline preload="metadata" style="width:100%;border-radius:8px"
  src="/demo/docker.mp4"></video>

## Pull

Every release publishes the image to GitHub's registry for `linux/amd64`
and `linux/arm64`, tagged with the version, the minor and `latest`:

```bash
docker pull ghcr.io/ioflux-org/armite:latest
docker run -d --name armite -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \
  -v armite:/data ghcr.io/ioflux-org/armite:latest
docker exec armite /app/armite version
```

The named volume `armite` is the home directory described under Run;
`docker cp armite:/data/ca.pem ./ca.pem` reads the CA out of it.

## Build

```bash
docker build -t armite:dev .
```

Multi-stage: a static Go binary on `node:22-alpine` with Azurite
installed, running as the image's non-root `node` user. About 110 MB to
pull; `docker images` reports about 680 MB unpacked, most of it
Azurite's dependencies. Node is there because storage accounts are
served by Azurite, a Node program Armite starts inside the container;
nothing to install.

## Run

`/data` is the server's home directory (`ARMITE_HOME`): the CA, leaf
certificate, signing key and state key generated at first boot, and -
because an explicit home is self-contained - `state/` with everything
created through the API. Mount a host
directory on it so you can read `ca.pem` and keep your resources across
runs, and run as your own user so the files are yours:

```bash
mkdir -p armite-data
docker run --rm --name armite \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \
  -v "$PWD/armite-data:/data" \
  armite:dev
```

The CA is generated once and reused on every start, so trust it once
(`armite-data/ca.pem`). `8443` serves ARM, the login endpoint, every
vault and every storage account; `8081` is IMDS for managed-identity
clients. The state files are encrypted with `state.key` next to them;
delete `state/` alone to start over with the same CA, the whole
directory to start over completely; see
[persistence.md](persistence.md). Azurite's blobs live under
`state/azurite`, unencrypted.

A configuration file goes where the server looks for it, the home
directory:

```bash
docker run --rm --name armite \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \
  -v "$PWD/armite-data:/data" \
  -v "$PWD/armite.yaml:/data/armite.yaml:ro" \
  armite:dev
```

### With compose

```bash
docker compose up -d
docker compose cp armite:/data/ca.pem ./ca.pem
```

The directory is a named volume, `armite_data`. To start over but
keep the CA, stop the stack and empty the state inside it; `docker
compose down -v` removes the volume and starts over completely:

```bash
docker compose stop
docker run --rm -v armite_data:/data alpine rm -rf /data/state
docker compose start
```

## Reaching it

Every client talks to Armite by hostname, so the hostnames must
resolve to the host the ports are published on - a resolver fix, or the
`/etc/hosts` lines `docker compose exec armite /app/armite hosts`
prints, see [dns.md](dns.md). Then trust the CA, per client:

| client                         | how                                                                                |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| curl                           | `--cacert ./ca.pem` (the copy read out above)                                      |
| az                             | `REQUESTS_CA_BUNDLE=$PWD/ca.pem` and `az config set core.instance_discovery=false` |
| Node SDK                       | `NODE_EXTRA_CA_CERTS=$PWD/ca.pem`                                                  |
| Terraform (and any Go program) | `SSL_CERT_FILE=$PWD/ca.pem`                                                        |

Managed-identity clients set `AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081`.

## Configuration

| variable             | default                             | image                          |
| -------------------- | ----------------------------------- | ------------------------------ |
| `ARMITE_LISTEN_ADDR` | `127.0.0.1:8443`                    | `0.0.0.0:8443`                 |
| `ARMITE_IMDS_ADDR`   | `127.0.0.1:8081`                    | `0.0.0.0:8081`                 |
| `ARMITE_HOME`        | `~/.armite`                         | `/data`                        |
| `ARMITE_STATE_DIR`   | the data directory (see config.md)  | unset (`/data/state`)          |
| `ARMITE_STATE_KEY`   | unset (generated into the cert dir) | unset                          |
| `ARMITE_CONFIG`      | unset (`./armite.yaml` if present)  | unset; mount a file and set it |
| `ARMITE_LOG_FORMAT`  | `text`                              | unset; `json` for a collector  |
| `ARMITE_CONTAINER`   | unset                               | `1`: hints say `docker cp`     |

The image binds all interfaces because Docker's published ports cannot
reach a container's loopback interface; publish on `127.0.0.1` as above
to keep the emulator off your network. The port clients use, the
hostnames and the vault suffix do not change with the bind address.

## From another container

A client container does not share the host's `/etc/hosts` or port
publishing. Put both on the same compose network and add the hostnames
as `extra_hosts` entries pointing at the `armite` service, and mount
the CA the same way.
