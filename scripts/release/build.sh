#!/usr/bin/env bash
# Builds the release archives for one version: a static binary per
# platform, tar.gz (zip for Windows), and a checksum file, into dist/.
#   ./scripts/release/build.sh v0.1.0
set -euo pipefail
cd "$(dirname "$0")/../.."
V="${1:?usage: build.sh vX.Y.Z}"
rm -rf dist && mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    os=${target%/*}; arch=${target#*/}
    name="armite_${V#v}_${os}_${arch}"
    bin=armite; [ "$os" = windows ] && bin=armite.exe
    mkdir -p "dist/$name"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X main.version=$V" -o "dist/$name/$bin" ./cmd/armite
    cp LICENSE README.md "dist/$name/"
    if [ "$os" = windows ]; then
        (cd dist && python3 -m zipfile -c "$name.zip" "$name") # zip(1) is not everywhere; python3 is
    else
        tar -C dist -czf "dist/$name.tar.gz" "$name"
    fi
    rm -r "dist/$name"
done
(cd dist && sha256sum ./* > "armite_${V#v}_checksums.txt")
ls -l dist
