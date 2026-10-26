# How to monitor MinIO server with Grafana

[Grafana](https://grafana.com/) allows you to query, visualize, alert on and understand your metrics no matter where they are stored. Create, explore, and share dashboards with your team and foster a data driven culture.

## Prerequisites

- Prometheus and MinIO configured as explained in [document here](https://github.com/minio/minio/blob/master/docs/metrics/prometheus/README.md).
- Grafana installed as explained [here](https://grafana.com/grafana/download).

## MinIO Grafana Dashboard

Visualize MinIO metrics with the Grafana dashboard in this directory: [minio-dashboard.json](minio-dashboard.json).

Refer to the dashboard [json file here](minio-dashboard.json).

![Grafana](grafana-minio.png)

Node level Replication metrics can be viewed in the Grafana dashboard using [json file here](replication/minio-replication-node.json)

![Grafana](replication/grafana-replication-node.png)

Cluster level Replication metrics can be viewed in the Grafana dashboard using [json file here](replication/minio-replication-cluster.json)

![Grafana](replication/grafana-replication-cluster.png)

Bucket metrics can be viewed in the Grafana dashboard using [json file here](bucket/minio-bucket.json)

![Grafana](bucket/grafana-bucket.png)

Node metrics can be viewed in the Grafana dashboard using [json file here](node/minio-node.json)

![Grafana](node/grafana-node.png)

Note: All these dashboards are provided as an example and need basis they should be customized as well as new graphs should be added.
