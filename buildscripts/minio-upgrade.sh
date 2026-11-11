#!/usr/bin/env bash
set -euo pipefail

# Use a unique Compose project so cleanup only removes this test's resources.
export COMPOSE_PROJECT_NAME="minio-upgrade-${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}"
compose=(docker compose -f buildscripts/upgrade-tests/compose.yml)
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/minio-upgrade.XXXXXX")
mc() { "${MC_TEST_CLIENT:?pinned test client required}" --config-dir "$work/mc-config" "$@"; }
old_tag=RELEASE.2019-12-19T22-52-26Z
old_commit=586614c73f902085465d07a1f854ca6c1efb9845
old_builder='golang@sha256:66a3f6817c129f48c9cc9b96816a1c0b6dcb399393196e3581d9367b55ab29f2'
old_image="minio-upgrade-${GITHUB_RUN_ID:-$$}:old"
new_image="minio-upgrade-${GITHUB_RUN_ID:-$$}:current"

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		MINIO_IMAGE="$new_image" "${compose[@]}" logs --no-color >"$work/compose.log" 2>&1 || true
		echo "Upgrade test failed; logs and Compose volumes retained for diagnosis: $work ($COMPOSE_PROJECT_NAME)" >&2
		MINIO_IMAGE="$new_image" "${compose[@]}" down --remove-orphans || true
	else
		MINIO_IMAGE="$new_image" "${compose[@]}" down -v --remove-orphans || true
	fi
}
trap cleanup EXIT

verify_checksum_mc() {
	local expected got
	expected=$(mc cat "$1" | sha256sum)
	got=$(mc cat "$2" | sha256sum)
	[[ $expected == "$got" ]] || {
		echo "checksum mismatch: $1 and $2" >&2
		return 1
	}
}

add_alias() {
	local i
	for i in $(seq 1 60); do
		if mc alias set minio http://127.0.0.1:9000 minioadmin minioadmin &&
			curl -fsS --max-time 5 http://127.0.0.1:9000/minio/health/ready >/dev/null; then
			return
		fi
		sleep 5
	done
	echo 'MinIO did not become ready within five minutes' >&2
	return 1
}

# Rebuild the exact upstream 2019 source using its Go 1.13 toolchain. The
# upstream Docker Hub image and matching Quay tag are no longer available.
git clone --quiet --depth 1 --branch "$old_tag" https://github.com/minio/minio.git "$work/old-source"
[[ "$(git -C "$work/old-source" rev-parse HEAD)" == "$old_commit" ]]
mkdir -p "$work/image/dockerscripts"
docker run --rm --user "$(id -u):$(id -g)" \
	-v "$work/old-source:/src:ro" -v "$work/image:/out" -w /src \
	-e CGO_ENABLED=0 -e GOPATH=/tmp/gopath -e GOCACHE=/tmp/gocache -e GOPROXY=https://proxy.golang.org \
	"$old_builder" go build -mod=readonly -o /out/minio .
cp "${MC_TEST_CLIENT:?pinned test client required}" "$work/image/mc"
cp Dockerfile.ci "$work/image/Dockerfile"
cp dockerscripts/docker-entrypoint.sh "$work/image/dockerscripts/"
docker build -t "$old_image" "$work/image"

# Match the existing upgrade test's non-race candidate image build.
make build
cp ./minio "$work/image/minio"
docker build -t "$new_image" "$work/image"

MINIO_IMAGE="$old_image" "${compose[@]}" up -d
add_alias
mc mb minio/minio-test/
mc cp ./minio minio/minio-test/to-read/
mc cp /etc/hosts minio/minio-test/to-read/hosts
mc anonymous set download minio/minio-test
verify_checksum_mc ./minio minio/minio-test/to-read/minio
old_sum=$(curl -fsS http://127.0.0.1:9000/minio-test/to-read/hosts | sha256sum)
MINIO_IMAGE="$old_image" "${compose[@]}" stop

MINIO_IMAGE="$new_image" "${compose[@]}" up -d
add_alias
echo 'Object listing immediately after upgrade:'
mc ls --recursive --json minio/minio-test/ || true
mc stat minio/minio-test/to-read/minio || true
mc admin heal --json -r minio/minio-test >/dev/null
new_sum=$(curl -fsS http://127.0.0.1:9000/minio-test/to-read/hosts | sha256sum)
[[ $old_sum == "$new_sum" ]] || {
	echo 'checksum mismatch after upgrade and heal' >&2
	exit 1
}
verify_checksum_mc ./minio minio/minio-test/to-read/minio
verify_checksum_mc /etc/hosts minio/minio-test/to-read/hosts
