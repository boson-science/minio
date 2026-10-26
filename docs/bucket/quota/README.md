# Bucket Quota Configuration Quickstart Guide

![quota](bucketquota.png)

Buckets can be configured to have `Hard` quota - it disallows writes to the bucket after configured quota limit is reached.

## Prerequisites

- Install MinIO - [MinIO Quickstart Guide](https://docs.min.io/community/minio-object-store/operations/deployments/baremetal-deploy-minio-on-redhat-linux.html#procedure).
- [Use `mc` with MinIO Server](https://docs.min.io/community/minio-object-store/reference/minio-mc.html#quickstart)

## Set bucket quota configuration

### Set a hard quota of 1GB for a bucket `mybucket` on MinIO object storage

```sh
mc admin bucket quota myminio/mybucket --hard 1gb
```

### Verify the quota configured on `mybucket` on MinIO

```sh
mc admin bucket quota myminio/mybucket
```

### Clear bucket quota configuration for `mybucket` on MinIO

```sh
mc admin bucket quota myminio/mybucket --clear
```
