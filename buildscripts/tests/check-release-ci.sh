#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export GITHUB_REPOSITORY=test/repo
export TEST_SHA=0123456789abcdef0123456789abcdef01234567
cat >"$tmp/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
*'/jobs'*)
	if [[ "${TEST_CASE:-}" == missing_job ]]; then
		printf '%s\n' '{"jobs":[{"name":"Analyze (go)","status":"completed","conclusion":"success"}]}'
	else
		printf '%s\n' '{"jobs":[{"name":"Analyze (go)","status":"completed","conclusion":"success"},{"name":"Analyze (actions)","status":"completed","conclusion":"success"}]}'
	fi ;;
*'/actions/runs '*)
	conclusion=success
	[[ "${TEST_CASE:-}" == codeql_failed ]] && conclusion=failure
	printf '{"workflow_runs":[{"id":20,"name":"CodeQL","head_sha":"%s","created_at":"2026-01-01T00:00:00Z","status":"completed","conclusion":"%s"}]}\n' "$TEST_SHA" "$conclusion" ;;
*)
	case "${TEST_CASE:-}:$*" in
	missing:*go-cross.yml*) printf '%s\n' '{"workflow_runs":[]}' ;;
	pending:*go-cross.yml*) printf '{"workflow_runs":[{"id":1,"head_sha":"%s","created_at":"2026-01-01T00:00:00Z","status":"completed","conclusion":"success"},{"id":2,"head_sha":"%s","created_at":"2026-01-02T00:00:00Z","status":"in_progress","conclusion":null}]}' "$TEST_SHA" "$TEST_SHA" ;;
	failure:*go-cross.yml*) printf '{"workflow_runs":[{"id":1,"head_sha":"%s","created_at":"2026-01-01T00:00:00Z","status":"completed","conclusion":"failure"}]}' "$TEST_SHA" ;;
	stale:*go-cross.yml*) printf '%s\n' '{"workflow_runs":[{"id":1,"head_sha":"ffffffffffffffffffffffffffffffffffffffff","created_at":"2026-01-01T00:00:00Z","status":"completed","conclusion":"success"}]}' ;;
	missing_vuln:*vulncheck.yml*) printf '%s\n' '{"workflow_runs":[]}' ;;
	*) printf '{"workflow_runs":[{"id":1,"head_sha":"%s","event":"workflow_dispatch","created_at":"2026-01-01T00:00:00Z","status":"completed","conclusion":"success"}]}' "$TEST_SHA" ;;
	esac ;;
esac
MOCK
chmod +x "$tmp/gh"
export PATH="$tmp:$PATH"
TEST_CASE=success bash "$root/buildscripts/check-release-ci.sh" "$TEST_SHA" >/dev/null
for TEST_CASE in missing pending failure stale missing_job missing_vuln codeql_failed; do
	export TEST_CASE
	if bash "$root/buildscripts/check-release-ci.sh" "$TEST_SHA" >/dev/null; then
		echo "release CI gate unexpectedly passed: $TEST_CASE" >&2
		exit 1
	fi
done
echo 'release CI gate tests passed'
