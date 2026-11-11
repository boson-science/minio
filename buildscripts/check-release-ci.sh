#!/usr/bin/env bash
set -euo pipefail

sha=${1:?commit SHA required}
repo=${GITHUB_REPOSITORY:?repository required}
[[ $sha =~ ^[0-9a-f]{40}$ ]] || {
	echo 'Expected a full commit SHA' >&2
	exit 1
}

# Every suite is dispatched explicitly on the candidate commit. The newest
# run must pass: a newer failure or still-running rerun supersedes an older pass.
workflows=(
	go-cross.yml go-lint.yml go.yml go-healing.yml go-resiliency.yml
	helm-lint.yml iam-integrations.yaml mint.yml replication.yaml root-disable.yml
	shfmt.yml typos.yml upgrade-ci-cd.yaml
)
for workflow in "${workflows[@]}"; do
	result=$(gh api --method GET "repos/$repo/actions/workflows/$workflow/runs" \
		-f head_sha="$sha" -f event=workflow_dispatch -f per_page=100 |
		jq -r --arg sha "$sha" '[.workflow_runs[] | select(.head_sha == $sha)] | sort_by(.created_at, .id) | last | if . == null then "missing" else "\(.status):\(.conclusion // "pending")" end')
	printf '%s: %s\n' "$workflow" "$result"
	[[ $result == completed:success ]] || exit 1
done

result=$(gh api --method GET "repos/$repo/actions/workflows/vulncheck.yml/runs" \
	-f head_sha="$sha" -f per_page=100 |
	jq -r --arg sha "$sha" '[.workflow_runs[] | select(.head_sha == $sha and (.event == "push" or .event == "workflow_dispatch"))] | sort_by(.created_at, .id) | last | if . == null then "missing" else "\(.status):\(.conclusion // "pending")" end')
printf 'vulncheck.yml: %s\n' "$result"
[[ $result == completed:success ]] || exit 1

codeql=$(gh api --method GET "repos/$repo/actions/runs" -f head_sha="$sha" -f per_page=100 |
	jq -r --arg sha "$sha" '[.workflow_runs[] | select(.head_sha == $sha and .path == "dynamic/github-code-scanning/codeql")] | sort_by(.created_at, .id) | last | if . == null then "missing" else "\(.id):\(.status):\(.conclusion // "pending")" end')
printf 'CodeQL: %s\n' "$codeql"
[[ $codeql =~ ^[0-9]+:completed:success$ ]] || exit 1
run_id=${codeql%%:*}
gh api --method GET "repos/$repo/actions/runs/$run_id/jobs" -f per_page=100 |
	jq -e '(.jobs | any(.name == "Analyze (go)" and .status == "completed" and .conclusion == "success")) and (.jobs | any(.name == "Analyze (actions)" and .status == "completed" and .conclusion == "success"))' >/dev/null
