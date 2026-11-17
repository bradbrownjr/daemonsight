# The DaemonSight hub: the web UI that receives uploads from collectors and
# shows every host. Collectors are installed natively on each Linux host;
# see docs/DESIGN.md "Hub" for why they don't run in containers.
#
#   docker run -d --name daemonsight -p 192.168.1.20:8466:8466 \
#     -v /mnt/user/appdata/daemonsight:/data ghcr.io/bradbrownjr/daemonsight:edge
FROM python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ARG REVISION=local
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/daemonsight/venv/bin:$PATH \
    DAEMONSIGHT_CONFIG=/data/config.toml

RUN useradd --system --uid 10001 --user-group --home-dir /data --no-create-home \
        --shell /usr/sbin/nologin daemonsight \
    && install -d -m 0750 -o daemonsight -g daemonsight /data

COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/daemonsight/venv \
    && /opt/daemonsight/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

COPY pyproject.toml README.md LICENSE /tmp/src/
COPY src /tmp/src/src
RUN /opt/daemonsight/venv/bin/pip install --no-cache-dir --no-deps /tmp/src \
    && rm -rf /tmp/src /tmp/requirements.txt \
    && echo "${REVISION}" | cut -c1-7 > /opt/daemonsight/REVISION

COPY packaging/docker/hub.toml /etc/daemonsight/hub.toml
COPY --chmod=0755 packaging/docker/entrypoint.sh /usr/local/bin/daemonsight-entrypoint

USER 10001:10001
WORKDIR /data
VOLUME /data
EXPOSE 8466
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8466/healthz', timeout=4)"
ENTRYPOINT ["daemonsight-entrypoint"]
CMD ["web"]
