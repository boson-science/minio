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
		# Capture reads through each backend before stopping the test cluster.
		# This distinguishes a node-specific 404 from a cluster-wide failure.
		if [ -f "$work/mc-config/config.json" ]; then
			(
				set +e
				for node in minio1 minio2 minio3 minio4; do
					printf '\n=== %s ===\n' "$node"
					timeout 30s "${MC_TEST_CLIENT:?}" --config-dir "$work/mc-config" stat "$node/minio-test/to-read/minio"
					timeout 30s "${MC_TEST_CLIENT:?}" --config-dir "$work/mc-config" cat "$node/minio-test/to-read/minio" | sha256sum
					printf 'read exit status: %s\n' "${PIPESTATUS[0]}"
				done
			) >"$work/node-reads.log" 2>&1
		fi
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
	local i node id ip ready
	# The 2019 readiness endpoint can return 200 before storage initializes.
	# Check authenticated access to each backend, not just the nginx balance.
	for node in minio1 minio2 minio3 minio4; do
		id=$("${compose[@]}" ps -q "$node")
		ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$id")
		ready=false
		for i in $(seq 1 60); do
			if mc alias set "$node" "http://$ip:9000" minioadmin minioadmin && mc ls "$node/" >/dev/null; then
				ready=true
				break
			fi
			sleep 5
		done
		if [ "$ready" != true ]; then
			echo "$node did not accept authenticated requests within five minutes" >&2
			return 1
		fi
	done
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

export MINIO_IMAGE="$old_image"
"${compose[@]}" up -d
add_alias
mc mb minio/minio-test/
mc cp ./minio minio/minio-test/to-read/
mc cp /etc/hosts minio/minio-test/to-read/hosts
# The 2019 cluster can accept writes before every node has finished starting.
# Retry the actual policy operation, but fail if it never succeeds.
policy_ready=false
for i in $(seq 1 60); do
	if mc anonymous set download minio/minio-test; then
		policy_ready=true
		break
	fi
	sleep 5
done
if [ "$policy_ready" != true ]; then
	echo 'Anonymous policy could not be set within five minutes' >&2
	exit 1
fi
verify_checksum_mc ./minio minio/minio-test/to-read/minio
old_sum=$(curl -fsS http://127.0.0.1:9000/minio-test/to-read/hosts | sha256sum)
"${compose[@]}" stop

export MINIO_IMAGE="$new_image"
"${compose[@]}" up -d
add_alias
echo 'Object listing immediately after upgrade:'
mc ls --recursive --json minio/minio-test/ || true
mc stat minio/minio-test/to-read/minio || true
echo 'Verify both objects before healing:'
verify_checksum_mc ./minio minio/minio-test/to-read/minio
verify_checksum_mc /etc/hosts minio/minio-test/to-read/hosts
mc admin heal --json -r minio/minio-test | tee "$work/heal.jsonl"
new_sum=$(curl -fsS http://127.0.0.1:9000/minio-test/to-read/hosts | sha256sum)
[[ $old_sum == "$new_sum" ]] || {
	echo 'checksum mismatch after upgrade and heal' >&2
	exit 1
}
verify_checksum_mc ./minio minio/minio-test/to-read/minio
verify_checksum_mc /etc/hosts minio/minio-test/to-read/hosts
