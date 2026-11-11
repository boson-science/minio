#!/bin/bash
#

set -e
set -E
set -o pipefail

if [ ! -x "$PWD/minio" ]; then
	echo "minio executable binary not found in current directory"
	exit 1
fi

WORK_DIR="$PWD/.verify-$RANDOM"

export MINT_MODE=core
export MINT_DATA_DIR="$WORK_DIR/data"
export SERVER_ENDPOINT="127.0.0.1:9000"
export MC_HOST_verify="http://minio:minio123@${SERVER_ENDPOINT}/"
export MC_HOST_verify_ipv6="http://minio:minio123@[::1]:9000/"
export ACCESS_KEY="minio"
export SECRET_KEY="minio123"
export ENABLE_HTTPS=0
export GO111MODULE=on
export GOGC=25
export ENABLE_ADMIN=1
export MINIO_CI_CD=1

MINIO_CONFIG_DIR="$WORK_DIR/.minio"
MINIO=("$PWD/minio" --config-dir "$MINIO_CONFIG_DIR")

FILE_1_MB="$MINT_DATA_DIR/datafile-1-MB"
FILE_65_MB="$MINT_DATA_DIR/datafile-65-MB"

FUNCTIONAL_TESTS="$WORK_DIR/functional-tests.sh"

function start_minio_fs() {
	export MINIO_ROOT_USER=$ACCESS_KEY
	export MINIO_ROOT_PASSWORD=$SECRET_KEY
	"${MINIO[@]}" server "${WORK_DIR}/fs-disk" >"$WORK_DIR/fs-minio.log" 2>&1 &

	"${WORK_DIR}/mc" ready verify
}

function start_minio_erasure() {
	"${MINIO[@]}" server "${WORK_DIR}/erasure-disk1" "${WORK_DIR}/erasure-disk2" "${WORK_DIR}/erasure-disk3" "${WORK_DIR}/erasure-disk4" >"$WORK_DIR/erasure-minio.log" 2>&1 &

	"${WORK_DIR}/mc" ready verify
}

function start_minio_erasure_sets() {
	export MINIO_ENDPOINTS="${WORK_DIR}/erasure-disk-sets{1...32}"
	"${MINIO[@]}" server >"$WORK_DIR/erasure-minio-sets.log" 2>&1 &

	"${WORK_DIR}/mc" ready verify
}

function start_minio_pool_erasure_sets() {
	export MINIO_ROOT_USER=$ACCESS_KEY
	export MINIO_ROOT_PASSWORD=$SECRET_KEY
	export MINIO_ENDPOINTS="http://127.0.0.1:9000${WORK_DIR}/pool-disk-sets{1...4} http://127.0.0.1:9001${WORK_DIR}/pool-disk-sets{5...8}"
	"${MINIO[@]}" server --address ":9000" >"$WORK_DIR/pool-minio-9000.log" 2>&1 &
	"${MINIO[@]}" server --address ":9001" >"$WORK_DIR/pool-minio-9001.log" 2>&1 &

	"${WORK_DIR}/mc" ready verify
}

function start_minio_pool_erasure_sets_ipv6() {
	export MINIO_ROOT_USER=$ACCESS_KEY
	export MINIO_ROOT_PASSWORD=$SECRET_KEY
	export MINIO_ENDPOINTS="http://[::1]:9000${WORK_DIR}/pool-disk-sets-ipv6{1...4} http://[::1]:9001${WORK_DIR}/pool-disk-sets-ipv6{5...8}"
	"${MINIO[@]}" server --address="[::1]:9000" >"$WORK_DIR/pool-minio-ipv6-9000.log" 2>&1 &
	"${MINIO[@]}" server --address="[::1]:9001" >"$WORK_DIR/pool-minio-ipv6-9001.log" 2>&1 &

	"${WORK_DIR}/mc" ready verify_ipv6
}

function start_minio_dist_erasure() {
	export MINIO_ROOT_USER=$ACCESS_KEY
	export MINIO_ROOT_PASSWORD=$SECRET_KEY
	export MINIO_ENDPOINTS="http://127.0.0.1:9000${WORK_DIR}/dist-disk1 http://127.0.0.1:9001${WORK_DIR}/dist-disk2 http://127.0.0.1:9002${WORK_DIR}/dist-disk3 http://127.0.0.1:9003${WORK_DIR}/dist-disk4"
	for i in $(seq 0 3); do
		"${MINIO[@]}" server --address ":900${i}" >"$WORK_DIR/dist-minio-900${i}.log" 2>&1 &
	done

	"${WORK_DIR}/mc" ready verify
}

function run_test_fs() {
	start_minio_fs

	(cd "$WORK_DIR" && "$FUNCTIONAL_TESTS")
	rv=$?

	pkill minio
	sleep 3

	if [ "$rv" -ne 0 ]; then
		cat "$WORK_DIR/fs-minio.log"
	fi
	rm -f "$WORK_DIR/fs-minio.log"

	return "$rv"
}

function run_test_erasure_sets() {
	start_minio_erasure_sets

	(cd "$WORK_DIR" && "$FUNCTIONAL_TESTS")
	rv=$?

	pkill minio
	sleep 3

	if [ "$rv" -ne 0 ]; then
		cat "$WORK_DIR/erasure-minio-sets.log"
	fi
	rm -f "$WORK_DIR/erasure-minio-sets.log"

	return "$rv"
}

function run_test_pool_erasure_sets() {
	start_minio_pool_erasure_sets

	(cd "$WORK_DIR" && "$FUNCTIONAL_TESTS")
	rv=$?

	pkill minio
	sleep 3

	if [ "$rv" -ne 0 ]; then
		for i in $(seq 0 1); do
			echo "server$i log:"
			cat "$WORK_DIR/pool-minio-900$i.log"
		done
	fi

	for i in $(seq 0 1); do
		rm -f "$WORK_DIR/pool-minio-900$i.log"
	done

	return "$rv"
}

function run_test_pool_erasure_sets_ipv6() {
	start_minio_pool_erasure_sets_ipv6

	export SERVER_ENDPOINT="[::1]:9000"

	(cd "$WORK_DIR" && "$FUNCTIONAL_TESTS")
	rv=$?

	pkill minio
	sleep 3

	if [ "$rv" -ne 0 ]; then
		for i in $(seq 0 1); do
			echo "server$i log:"
			cat "$WORK_DIR/pool-minio-ipv6-900$i.log"
		done
	fi

	for i in $(seq 0 1); do
		rm -f "$WORK_DIR/pool-minio-ipv6-900$i.log"
	done

	return "$rv"
}

function run_test_erasure() {
	start_minio_erasure

	(cd "$WORK_DIR" && "$FUNCTIONAL_TESTS")
	rv=$?

	pkill minio
	sleep 3

	if [ "$rv" -ne 0 ]; then
		cat "$WORK_DIR/erasure-minio.log"
	fi
	rm -f "$WORK_DIR/erasure-minio.log"

	return "$rv"
}

function run_test_dist_erasure() {
	start_minio_dist_erasure

	(cd "$WORK_DIR" && "$FUNCTIONAL_TESTS")
	rv=$?

	pkill minio
	sleep 3

	if [ "$rv" -ne 0 ]; then
		echo "server1 log:"
		cat "$WORK_DIR/dist-minio-9000.log"
		echo "server2 log:"
		cat "$WORK_DIR/dist-minio-9001.log"
		echo "server3 log:"
		cat "$WORK_DIR/dist-minio-9002.log"
		echo "server4 log:"
		cat "$WORK_DIR/dist-minio-9003.log"
	fi

	rm -f "$WORK_DIR/dist-minio-9000.log" "$WORK_DIR/dist-minio-9001.log" "$WORK_DIR/dist-minio-9002.log" "$WORK_DIR/dist-minio-9003.log"

	return "$rv"
}

function purge() {
	rm -rf "$1"
}

function __init__() {
	echo "Initializing environment"
	mkdir -p "$WORK_DIR"
	mkdir -p "$MINIO_CONFIG_DIR"
	mkdir -p "$MINT_DATA_DIR"

	if [ -n "${MC_TEST_CLIENT:-}" ]; then
		install -m 0755 "$MC_TEST_CLIENT" "$WORK_DIR/mc"
	else
		GOBIN="$WORK_DIR" go install github.com/minio/mc@77f82e18b5401a65958f1619df6ebb994634bd88
	fi

	dd if=/dev/urandom of="$FILE_1_MB" bs=1048576 count=1 status=none || return 1
	dd if=/dev/urandom of="$FILE_65_MB" bs=1048576 count=65 status=none || return 1
	# Check the fixture contents before the client suite runs. An empty input can
	# make mc od panic and would also invalidate all the object-copy tests.
	printf 'Fixture sizes (bytes): 1 MiB=%s, 65 MiB=%s\n' "$(wc -c <"$FILE_1_MB")" "$(wc -c <"$FILE_65_MB")"
	test "$(wc -c <"$FILE_1_MB")" -eq 1048576 || return 1
	test "$(wc -c <"$FILE_65_MB")" -eq 68157440 || return 1

	## version is purposefully set to '3' for minio to migrate configuration file
	echo '{"version": "3", "credential": {"accessKey": "minio", "secretKey": "minio123"}, "region": "us-east-1"}' >"$MINIO_CONFIG_DIR/config.json"

	if ! wget -q -O "$FUNCTIONAL_TESTS" https://raw.githubusercontent.com/minio/mc/77f82e18b5401a65958f1619df6ebb994634bd88/functional-tests.sh; then
		echo "failed to download pinned mc functional tests"
		exit 1
	fi

	sed -i 's|-sS|-sSg|g' "$FUNCTIONAL_TESTS"
	chmod a+x "$FUNCTIONAL_TESTS"
}

function main() {
	echo "Testing in FS setup"
	if ! run_test_fs; then
		echo "FAILED"
		wc -c "$FILE_1_MB" "$FILE_65_MB" || true
		purge "$WORK_DIR"
		exit 1
	fi

	echo "Testing in Erasure setup"
	if ! run_test_erasure; then
		echo "FAILED"
		purge "$WORK_DIR"
		exit 1
	fi

	echo "Testing in Distributed Erasure setup"
	if ! run_test_dist_erasure; then
		echo "FAILED"
		purge "$WORK_DIR"
		exit 1
	fi

	echo "Testing in Erasure setup as sets"
	if ! run_test_erasure_sets; then
		echo "FAILED"
		purge "$WORK_DIR"
		exit 1
	fi

	echo "Testing in Distributed Eraure expanded setup"
	if ! run_test_pool_erasure_sets; then
		echo "FAILED"
		purge "$WORK_DIR"
		exit 1
	fi

	echo "Testing in Distributed Erasure expanded setup with ipv6"
	if ! run_test_pool_erasure_sets_ipv6; then
		echo "FAILED"
		purge "$WORK_DIR"
		exit 1
	fi

	purge "$WORK_DIR"
}

(__init__ "$@" && main "$@")
rv=$?
purge "$WORK_DIR"
exit "$rv"
