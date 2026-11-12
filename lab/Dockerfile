# SPDX-License-Identifier: MIT OR Apache-2.0
# One image for every node of the anycast lab except ClickHouse: routers
# (BIRD), PoPs (BIRD + XDP + agent + health check), customer server, clients,
# bots, NATS, PostgreSQL, the API and the workers. Sentinel binaries and the
# XDP object are bind-mounted from build/lab (built by the dev image).
FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bird2 iproute2 iputils-ping curl jq python3 procps ethtool tcpdump ca-certificates \
        openssl libelf1t64 zlib1g postgresql-17 bsdutils \
    && rm -rf /var/lib/apt/lists/*
COPY install-nats.sh /tmp/install-nats.sh
RUN sh /tmp/install-nats.sh && rm /tmp/install-nats.sh

ENV PATH=/opt/sentinel/bin:/usr/lib/postgresql/17/bin:$PATH
CMD ["sleep", "infinity"]
