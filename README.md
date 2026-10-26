> [!IMPORTANT]
> **This is an independent, community-maintained fork of MinIO focused on security patches.**
> Upstream [minio/minio](https://github.com/minio/minio) is no longer maintained. This fork
> continues from its final source and ships fixes for security vulnerabilities and critical bugs.
> It is not affiliated with or endorsed by MinIO, Inc.
>
> - Security fixes are tracked in [Security Advisories](https://github.com/boson-science/minio/security/advisories). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
> - Releases follow upstream's `RELEASE.<time>` scheme. See [RELEASING.md](RELEASING.md).
> - The embedded web console comes from [boson-science/console](https://github.com/boson-science/console).

# MinIO (community fork)

[![fork of minio/minio](https://img.shields.io/badge/fork%20of-minio%2Fminio-orange)](https://github.com/minio/minio) [![focus: security patches](https://img.shields.io/badge/focus-security%20patches-critical)](https://github.com/boson-science/minio/security/advisories) [![container: ghcr.io/boson-science/minio](https://img.shields.io/badge/container-ghcr.io%2Fboson--science%2Fminio-2496ED?logo=docker&logoColor=white)](https://github.com/boson-science/minio/pkgs/container/minio) [![license AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue)](LICENSE)

[![MinIO](https://raw.githubusercontent.com/minio/minio/master/.github/logo.svg?sanitize=true)](https://github.com/minio/minio)

MinIO is a high-performance, S3-compatible object storage server released under the GNU AGPL v3.0 license.

- S3 API compatible – works with existing S3 tools and SDKs
- Built for analytics and AI/ML data pipelines
- High performance for demanding storage workloads

## Why this fork exists

MinIO, Inc. stopped maintaining the community edition, leaving deployed servers without security updates.
This fork exists to keep those deployments patched. Its scope is deliberately narrow:

- **Security fixes** for vulnerabilities in the server and the embedded console
- **Critical bug fixes** and dependency updates needed to keep builds secure
- **No new features** beyond what is needed to keep the community edition usable, such as restoring SSO in the console

All changes are released under the AGPLv3, like the original source. The AGPLv3 provides no warranty;
support is best-effort through [GitHub issues](https://github.com/boson-science/minio/issues).

## Getting MinIO

You have two options:

1. **Container image** published by this fork to the GitHub Container Registry and signed with cosign:
   `ghcr.io/boson-science/minio:<RELEASE tag>`. See [Releases](https://github.com/boson-science/minio/releases).
2. **Build from source** as described below.

Upstream's legacy binaries (`dl.min.io`, `minio/minio` images on Docker Hub and Quay) no longer receive
updates and do not include this fork's security fixes.

## Install from Source

Use the following commands to compile and run a standalone MinIO server from source.
If you do not have a working Golang environment, please follow [How to install Golang](https://golang.org/doc/install). Minimum version required is [go1.24](https://golang.org/dl/#stable)

```sh
git clone https://github.com/boson-science/minio.git
cd minio
go build -o minio .
```

`go install github.com/minio/minio@latest` installs the unmaintained upstream source, not this fork.

You can alternatively run `go build` and use the `GOOS` and `GOARCH` environment variables to control the OS and architecture target.
For example:

```
env GOOS=linux GOARCH=arm64 go build
```

Start MinIO by running `./minio server PATH` where `PATH` is any empty folder on your local filesystem.

The MinIO deployment starts using default root credentials `minioadmin:minioadmin`.
You can test the deployment using the MinIO Console, an embedded web-based object browser built into MinIO Server.
Point a web browser running on the host machine to <http://127.0.0.1:9000> and log in with the root credentials.
You can use the Browser to create buckets, upload objects, and browse the contents of the MinIO server.

You can also connect using any S3-compatible tool, such as the MinIO Client `mc` commandline tool:

```sh
mc alias set local http://localhost:9000 minioadmin minioadmin
mc admin info local
```

See [Test using MinIO Client `mc`](#test-using-minio-client-mc) for more information on using the `mc` commandline tool.
For application developers, any S3 SDK works; the open-source [minio-go](https://github.com/minio/minio-go) and [minio-py](https://github.com/minio/minio-py) SDKs are also available.

> [!NOTE]
> Production environments using compiled-from-source MinIO binaries do so at their own risk.
> The AGPLv3 license provides no warranties nor liabilities for any such usage.

## Build Docker Image

You can use the `docker build .` command to build a Docker image on your local host machine.
You must first [build MinIO](#install-from-source) and ensure the `minio` binary exists in the project root.

The following command builds the Docker image using the default `Dockerfile` in the root project directory with the repository and image tag `myminio:minio`

```sh
docker build -t myminio:minio .
```

Use `docker image ls` to confirm the image exists in your local repository.
You can run the server using standard Docker invocation:

```sh
docker run -p 9000:9000 -p 9001:9001 myminio:minio server /tmp/minio --console-address :9001
```

Complete documentation for building Docker containers, managing custom images, or loading images into orchestration platforms is out of scope for this documentation.
You can modify the `Dockerfile` and `dockerscripts/docker-entrypoint.sh` as-needed to reflect your specific image requirements.

See the [MinIO Container](https://docs.min.io/community/minio-object-store/operations/deployments/baremetal-deploy-minio-as-a-container.html#deploy-minio-container) documentation for more guidance on running MinIO within a Container image.

## Install using Helm Charts

There are two paths for installing MinIO onto Kubernetes infrastructure:

- Use the [MinIO Operator](https://github.com/minio/operator)
- Use the community-maintained [Helm charts](helm/minio)

See the [MinIO Documentation](https://docs.min.io/community/minio-object-store/operations/deployments/kubernetes.html) for guidance on deploying using the Operator.
The Community Helm chart has instructions in the folder-level README.

## Test MinIO Connectivity

### Test using MinIO Console

MinIO Server comes with an embedded web based object browser.
Point your web browser to <http://127.0.0.1:9000> to ensure your server has started successfully.

> [!NOTE]
> MinIO runs console on random port by default, if you wish to choose a specific port use `--console-address` to pick a specific interface and port.

### Test using MinIO Client `mc`

`mc` provides a modern alternative to UNIX commands like ls, cat, cp, mirror, diff etc. It supports filesystems and Amazon S3 compatible cloud storage services.

The following commands set a local alias, validate the server information, create a bucket, copy data to that bucket, and list the contents of the bucket.

```sh
mc alias set local http://localhost:9000 minioadmin minioadmin
mc admin info
mc mb data
mc cp ~/Downloads/mydata data/
mc ls data/
```

Follow the MinIO Client [Quickstart Guide](https://docs.min.io/community/minio-object-store/reference/minio-mc.html#quickstart) for further instructions.

## Explore Further

- [The MinIO documentation website](https://docs.min.io/community/minio-object-store/index.html)
- [MinIO Erasure Code Overview](https://docs.min.io/community/minio-object-store/operations/concepts/erasure-coding.html)
- [Use `mc` with MinIO Server](https://docs.min.io/community/minio-object-store/reference/minio-mc.html)
- [Use `minio-go` SDK with MinIO Server](https://github.com/minio/minio-go)

## Contribute to MinIO Project

Please follow the [Contributor's Guide](CONTRIBUTING.md). Report security issues privately through [SECURITY.md](SECURITY.md), not public issues.

## License

- MinIO source is licensed under the [GNU AGPLv3](LICENSE).
- MinIO [documentation](docs) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- [License Compliance](COMPLIANCE.md)
