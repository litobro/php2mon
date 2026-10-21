FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /bin/uv
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -d /app sensor \
    && mkdir -p /app /tls /state && chown sensor /tls /state
WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/usr/local UV_COMPILE_BYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY php2mon ./php2mon
RUN uv sync --frozen --no-dev
COPY docker/sensor-entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER sensor
ENTRYPOINT ["/entrypoint.sh"]
