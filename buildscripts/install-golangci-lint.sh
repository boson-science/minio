#!/usr/bin/env bash
set -euo pipefail

version=2.15.0
os=$(go env GOHOSTOS)
arch=$(go env GOHOSTARCH)
case "$os/$arch" in
linux/amd64) sha=9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea ;;
linux/arm64) sha=b4d8f17068b35ee6060cc2f69a16fb48740d706fbba81661c318649c114a6998 ;;
darwin/amd64) sha=767b899a28285e88ded2823d5dcc4bc5ef681173eb2d80f029a7b17ee4ece3b8 ;;
darwin/arm64) sha=d1e409481a8ca846c4bc97e781eb5cb1bd5c23353a0b3977a1cbda1b1b6447d5 ;;
*)
	echo "Unsupported golangci-lint platform: $os/$arch" >&2
	exit 1
	;;
esac

destination=$1
archive="golangci-lint-${version}-${os}-${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/$archive" "https://github.com/golangci/golangci-lint/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$sha" "$tmp/$archive" | shasum -a 256 -c -
tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$destination"
install -m 0755 "$tmp/golangci-lint-${version}-${os}-${arch}/golangci-lint" "$destination/golangci-lint"
