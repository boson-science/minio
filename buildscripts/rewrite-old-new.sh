#!/bin/bash -e

set -E
set -o pipefail
set -x

WORK_DIR="$(mktemp -d "$PWD/.verify-rewrite.XXXXXX")"
MINIO_CONFIG_DIR="$WORK_DIR/.minio"
MINIO_OLD=("$WORK_DIR/minio-old" --config-dir "$MINIO_CONFIG_DIR" server)
MINIO=("$PWD/minio" --config-dir "$MINIO_CONFIG_DIR" server)

if [ ! -x "$PWD/minio" ]; then
	echo "minio executable binary not found in current directory"
	exit 1
fi

# The upstream archive no longer serves this binary. Build the exact tagged
# source with its Go 1.15 generation, in an isolated pinned builder image.
function build_old_release() {
	local source_dir="$WORK_DIR/old-source"
	local old_builder='golang@sha256:ea080cc817b02a946461d42c02891bf750e3916c52f7ea8187bccde8f312b59f'
	git clone --quiet --depth 1 --branch RELEASE.2020-10-28T08-16-50Z https://github.com/minio/minio.git "$source_dir"
	test "$(git -C "$source_dir" rev-parse HEAD)" = f53c5a020ea0be454983bad3fda5c51ddc1f06f4
	docker run --rm --user "$(id -u):$(id -g)" \
		-v "$source_dir:/src:ro" -v "$WORK_DIR:/out" -w /src \
		-e CGO_ENABLED=0 -e GOPATH=/tmp/gopath -e GOCACHE=/tmp/gocache -e GOPROXY=https://proxy.golang.org \
		"$old_builder" go build -mod=readonly -o /out/minio-old .
}

function cleanup() {
	local status=$?
	if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	if [ "$status" -eq 0 ]; then
		purge "$WORK_DIR"
	else
		echo "Legacy rewrite diagnostics retained in $WORK_DIR" >&2
	fi
}
trap cleanup EXIT

function verify_rewrite() {
	start_port=$1

	export MINIO_ACCESS_KEY=minio
	export MINIO_SECRET_KEY=minio123
	export MC_HOST_minio="http://minio:minio123@127.0.0.1:${start_port}/"
	unset MINIO_KMS_AUTO_ENCRYPTION # do not auto-encrypt objects
	export MINIO_CI_CD=1

	# The workflow supplies a pinned client rather than building mc from HEAD.
	install -m 0755 "${MC_TEST_CLIENT:?pinned test client required}" "$WORK_DIR/mc"

	"${MINIO_OLD[@]}" --address ":$start_port" "${WORK_DIR}/xl{1...16}" >"${WORK_DIR}/server1.log" 2>&1 &
	pid=$!
	disown $pid

	timeout 15m "${WORK_DIR}/mc" ready minio/

	if ! ps -p ${pid} 1>&2 >/dev/null; then
		echo "server1 log:"
		cat "${WORK_DIR}/server1.log"
		echo "FAILED"
		exit 1
	fi

	"${WORK_DIR}/mc" mb minio/healing-rewrite-bucket --quiet --with-lock
	"${WORK_DIR}/mc" cp \
		buildscripts/verify-build.sh \
		minio/healing-rewrite-bucket/ \
		--disable-multipart --quiet

	"${WORK_DIR}/mc" cp \
		buildscripts/verify-build.sh \
		minio/healing-rewrite-bucket/ \
		--disable-multipart --quiet

	"${WORK_DIR}/mc" cp \
		buildscripts/verify-build.sh \
		minio/healing-rewrite-bucket/ \
		--disable-multipart --quiet

	kill "$pid"
	wait "$pid" || true
	pid=
	sleep 3

	"${MINIO[@]}" --address ":$start_port" "${WORK_DIR}/xl{1...16}" >"${WORK_DIR}/server1.log" 2>&1 &
	pid=$!
	disown $pid

	timeout 15m "${WORK_DIR}/mc" ready minio/

	if ! ps -p ${pid} 1>&2 >/dev/null; then
		echo "server1 log:"
		cat "${WORK_DIR}/server1.log"
		echo "FAILED"
		exit 1
	fi

	if ! ./s3-check-md5 \
		-debug \
		-versions \
		-access-key minio \
		-secret-key minio123 \
		-endpoint "http://127.0.0.1:${start_port}/" 2>&1 | grep INTACT; then
		echo "server1 log:"
		cat "${WORK_DIR}/server1.log"
		echo "FAILED"
		mkdir -p "$WORK_DIR/inspects"
		(
			cd "$WORK_DIR/inspects"
			"${WORK_DIR}/mc" admin inspect minio/healing-rewrite-bucket/verify-build.sh/**
		) || true

		exit 1
	fi

	go run ./buildscripts/heal-manual.go "127.0.0.1:${start_port}" "minio" "minio123"
	sleep 1

	if ! ./s3-check-md5 \
		-debug \
		-versions \
		-access-key minio \
		-secret-key minio123 \
		-endpoint http://127.0.0.1:${start_port}/ 2>&1 | grep INTACT; then
		echo "server1 log:"
		cat "${WORK_DIR}/server1.log"
		echo "FAILED"
		mkdir -p "$WORK_DIR/inspects"
		(
			cd "$WORK_DIR/inspects"
			"${WORK_DIR}/mc" admin inspect minio/healing-rewrite-bucket/verify-build.sh/**
		) || true

		exit 1
	fi

	kill "$pid"
	wait "$pid" || true
	pid=
}

function main() {
	build_old_release

	start_port=$(shuf -i 10000-65000 -n 1)

	verify_rewrite ${start_port}
}

function purge() {
	rm -rf "$1"
}

main "$@"
