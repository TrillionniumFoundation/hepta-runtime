FROM ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-jsonschema ripgrep git build-essential pkg-config openssh-client ca-certificates procps util-linux && rm -rf /var/lib/apt/lists/*
RUN install -d -m 0700 -o 1000 -g 1000 /home/hepta-qualification
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
WORKDIR /home/hepta-qualification
USER 1000:1000
