# Install

Four ways to get Armite. Only storage accounts need anything else
(Azurite, at the end of this page).

## The image

```bash
docker pull ghcr.io/ioflux-org/armite:latest    # or :0.2.0, :0.2
```

linux/amd64 and linux/arm64, Azurite inside. `0.2.0` never changes,
`0.2` follows the newest patch of that minor, `latest` the newest
release. Running it is in [Running in Docker](./docker.md).

## A release archive

Every release on [the releases page](https://github.com/ioflux-org/armite/releases)
carries `armite_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) for
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64,
plus `armite_<version>_checksums.txt`.

```bash
V=0.2.0 OS=linux ARCH=amd64        # Apple silicon: OS=darwin ARCH=arm64
curl -LO https://github.com/ioflux-org/armite/releases/download/v$V/armite_${V}_${OS}_${ARCH}.tar.gz
curl -LO https://github.com/ioflux-org/armite/releases/download/v$V/armite_${V}_checksums.txt
sha256sum --ignore-missing -c armite_${V}_checksums.txt   # macOS: shasum -a 256 --ignore-missing -c
tar -xzf armite_${V}_${OS}_${ARCH}.tar.gz
sudo install armite_${V}_${OS}_${ARCH}/armite /usr/local/bin/
armite version
```

The binaries are not code-signed. On macOS a browser download is
quarantined and refused on first run; `xattr -d com.apple.quarantine
armite` clears it (curl does not set the attribute). On Windows,
extract the zip with `Expand-Archive`, put `armite.exe` on your PATH,
and if SmartScreen's "Windows protected your PC" appears on first run,
choose "More info", then "Run anyway".

## go install

```bash
go install github.com/ioflux-org/armite/cmd/armite@latest   # or @v0.2.0
```

Needs Go 1.26. `armite version` reads the version from the module's
build info, so it reports the tag you installed.

## From source

```bash
git clone https://github.com/ioflux-org/armite && cd armite && go run ./cmd/armite
```

## Storage accounts

Need Azurite. With Node.js installed, `armite azurite install` puts a
pinned copy where the server finds it, no PATH changes; `npm install -g
azurite` works too. The image has it already. Without it, storage
accounts are off and everything else works.

## Upgrading

Pull the new image, run `go install` again, or replace the binary. Your
`~/.armite` and your data directory stay where they are, and nothing
needs migrating.

Coming from 0.1: Microsoft Graph is served on a new hostname. With a
hosts file, add `127.0.0.1  graph.localhost` (`armite hosts` prints it
and `armite doctor` checks it); with a wildcard resolver there is
nothing to do. Then register the cloud in az again so it learns the
Graph endpoint: the `az cloud` lines in
[Getting started](./getting-started.md).

Next: [Getting started](./getting-started.md).
