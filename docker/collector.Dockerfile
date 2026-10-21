FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /bin/uv
RUN useradd -r -u 10001 -d /app collector \
    && mkdir -p /app /geoip && chown collector /geoip
WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/usr/local UV_COMPILE_BYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --extra collector
COPY php2mon ./php2mon
RUN uv sync --frozen --no-dev --extra collector
USER collector
ENTRYPOINT ["python", "-m", "php2mon.feeds"]
