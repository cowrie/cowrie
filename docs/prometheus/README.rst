How to Send Cowrie output to a Prometheus
=============================================

This guide will show you how to stand up a complete monitoring stack in Docker:

1. Prometheus
2. Cowrie
3. node-exporter (host-level metrics)
4. cAdvisor (container-level metrics)

All containers will join a user-defined Docker network so they can find one another by name.

1. Create the Docker network
=============================

.. code-block:: bash

    docker network create cowrie-net


2. Run Prometheus
==================

Create a volume for Prometheus’s TSDB

.. code-block:: bash

    docker volume create prometheus-data


For configuration file you can

Copy the example config into `/etc/prometheus` on your host

.. code-block:: bash

    sudo mkdir -p /etc/prometheus
    sudo cp ./docs/prometheus/prometheus.yaml /etc/prometheus/prometheus.yaml


Or from ~/cowrie call docker run with updated path

.. code-block:: bash

    -v ./docs/prometheus/prometheus.yaml:/etc/prometheus/prometheus.yaml:ro \

3. Launch Prometheus on `cowrie-net`
======================================

.. code-block:: bash

    docker run -d \
      --name prometheus \
      --network cowrie-net \
      -p 9090:9090 \
      -v /etc/prometheus/prometheus.yaml:/etc/prometheus/prometheus.yaml:ro \
      -v prometheus-data:/prometheus \
      prom/prometheus \
      --config.file=/etc/prometheus/prometheus.yaml

Verify it’s running at http://localhost:9090/targets


3. Run Cowrie with Prometheus metrics
======================================

.. code-block:: bash

    docker run
      --name cowrie \
      --network cowrie-net \
      -p 2222:2222 \
      -p 9000:9000 \
      -e COWRIE_OUTPUT_PROMETHEUS_ENABLED=yes \
      cowrie/cowrie:latest

---

4. Run node-exporter (host metrics)
======================================

.. code-block:: bash

    docker run -d \
      --name node-exporter \
      --network cowrie-net \
      --pid host \
      -v /:/host:ro \
      -p 9100:9100 \
      quay.io/prometheus/node-exporter:latest \
      --path.rootfs /host

---

5. Run cAdvisor (container metrics)
======================================

.. code-block:: bash

    docker run -d \
      --name cadvisor \
      --network cowrie-net \
      --privileged \
      -v /:/rootfs:ro \
      -v /var/run:/var/run:rw \
      -v /sys:/sys:ro \
      -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
      -v /var/lib/docker/:/var/lib/docker:ro \
      -p 8080:8080 \
      gcr.io/cadvisor/cadvisor:latest

Run cowrie with prometheus locally
===================================

Add the following entries in ``etc/cowrie.cfg`` under the Output Plugins section::

    [output_prometheus]
    enabled = true
    port = 9000
    debug = false

Ensure your `prometheus.yaml` has:

.. code-block:: yaml

    global:
      scrape_interval: 5s
    scrape_configs:
      - job_name: 'cowrie'
        static_configs:
          - targets: [
            'localhost:9000',
          ]
      - job_name: 'scrapers'
        static_configs:
          - targets: [
            'node-exporter:9100',
            'cadvisor:8080'
          ]
        metric_relabel_configs:
          - source_labels: [ cowrie ]
            regex: '^cowrie$'
            action: keep
          - action: drop
            regex: '.*'


Reload Prometheus if needed, then visit **Status → Targets** to confirm all three are UP.
