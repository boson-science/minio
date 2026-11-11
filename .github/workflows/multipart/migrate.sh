#!/bin/bash

set -euxo pipefail

## change working directory
cd .github/workflows/multipart/

function cleanup() {
	docker compose -f docker-compose-site1.yaml rm -s -f || true
	docker compose -f docker-compose-site2.yaml rm -s -f || true
	for volume in $(docker volume ls -q | grep minio); do
		docker volume rm ${volume} || true
	done

	docker system prune -f || true
	docker volume prune -f || true
	docker volume rm $(docker volume ls -q -f dangling=true) || true
}

cleanup

test -x ./mc
test -x ./s3-check-md5

export RELEASE=RELEASE.2023-08-29T23-07-35Z

docker compose -f docker-compose-site1.yaml up -d
docker compose -f docker-compose-site2.yaml up -d

sleep 30s

./mc alias set site1 http://site1-nginx:9001 minioadmin minioadmin --api s3v4
./mc alias set site2 http://site2-nginx:9002 minioadmin minioadmin --api s3v4

timeout 10m ./mc ready site1/
timeout 10m ./mc ready site2/

./mc admin replicate add site1 site2
./mc mb site1/testbucket/
./mc cp -r --quiet /usr/bin site1/testbucket/

sleep 5

check_site() {
	local site="$1" output
	output=$(./s3-check-md5 -versions -access-key minioadmin -secret-key minioadmin -endpoint "http://${site}-nginx:900$2" -bucket testbucket 2>&1) || return 1
	printf '%s\n' "$output"
	grep -q 'INTACT' <<<"$output" || return 1
	! grep -Eq 'FAILED|CORRUPTED' <<<"$output"
}

check_site site1 1
check_site site2 2

./mc cp -r --quiet /usr/bin site1/testbucket/

sleep 5

# A mismatch before healing is reported but remains recoverable by the upgrade.
check_site site1 1 || echo "site1 requires healing after the second copy"
check_site site2 2 || echo "site2 requires healing after the second copy"

export RELEASE=${1}

docker compose -f docker-compose-site1.yaml up -d
docker compose -f docker-compose-site2.yaml up -d

timeout 10m ./mc ready site1/
timeout 10m ./mc ready site2/

site1_healed=0
site2_healed=0
for i in $(seq 1 10); do
	# mc admin heal -r --remove when used against a LB endpoint
	# behaves flaky, let this run 10 times before giving up
	if ./mc admin heal -r --remove --json site1/ >/dev/null; then site1_healed=1; fi
	if ./mc admin heal -r --remove --json site2/ >/dev/null; then site2_healed=1; fi
done

test "$site1_healed" -eq 1
test "$site2_healed" -eq 1
check_site site1 1
check_site site2 2

# Add user group test
./mc admin user add site1 site-replication-issue-user site-replication-issue-password
./mc admin group add site1 site-replication-issue-group site-replication-issue-user

max_wait_attempts=30
wait_interval=5

attempt=1
while true; do
	if diff <(./mc admin group info site1 site-replication-issue-group) <(./mc admin group info site2 site-replication-issue-group); then
		echo "Outputs are consistent."
		break
	fi

	remaining_attempts=$((max_wait_attempts - attempt))
	if ((attempt >= max_wait_attempts)); then
		echo "Outputs remain inconsistent after $max_wait_attempts attempts. Exiting with error."
		exit 1
	else
		echo "Outputs are inconsistent. Waiting for $wait_interval seconds (attempt $attempt/$max_wait_attempts)."
		sleep $wait_interval
	fi

	((attempt += 1))
done

status=$(./mc admin group info site1 site-replication-issue-group --json | jq .groupStatus | tr -d '"')

if [[ $status == "enabled" ]]; then
	echo "Success"
else
	echo "Expected status: enabled, actual status: $status"
	exit 1
fi

cleanup

## change working directory
cd ../../../
