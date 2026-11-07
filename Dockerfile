FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# nft is only called when the nftables backend is switched on.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . && mkdir -p /var/lib/sshguard /etc/sshguard

COPY deploy/config.docker.toml /etc/sshguard/config.toml

# Root inside the container is needed to talk to the kernel firewall; compose drops every
# capability except NET_ADMIN and makes the filesystem read-only.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import json,time; d=json.load(open('/var/lib/sshguard/status.json')); assert time.time()-d['updated']<60"]

ENTRYPOINT ["sshguard"]
CMD ["run", "-c", "/etc/sshguard/config.toml"]
