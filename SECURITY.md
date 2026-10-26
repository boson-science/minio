# Security Policy

This repository is an independent, community-maintained fork of MinIO. It is
not affiliated with MinIO, Inc. Please do not report issues in this fork to
MinIO, Inc.

## Supported Versions

Security fixes go into the latest release, published on the
[releases page](https://github.com/boson-science/minio/releases/latest). When a
security update is released, upgrade to it. Backports onto earlier releases are
published as `RELEASE.<time>.hotfix.<commit>` tags when needed (see
[RELEASING.md](RELEASING.md)).

## Reporting a Vulnerability

Report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/boson-science/minio/security/advisories/new)
for this repository. Please do not open a public issue. Vulnerabilities in the
embedded web console can be reported here or at
[boson-science/console](https://github.com/boson-science/console/security/advisories/new).

Include a description of the issue, its impact (for example DoS,
authentication bypass or information disclosure), the steps to reproduce it,
and any assumptions the exploit makes (such as needing valid credentials).

## Disclosure Process

1. A maintainer confirms and reproduces the report, then replies to accept or
   decline it with a reason.
2. Similar code paths are audited for the same problem.
3. A fix with a regression test is prepared in the advisory's private fork and
   recorded in `security/advisory-matrix.json`.
4. The fix is merged and released. The GitHub security advisory is published
   with that release. Reporters are credited only if they ask to be.
