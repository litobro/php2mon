FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /bin/uv
RUN useradd -r -u 10001 -d /app dashboard \
    && mkdir -p /app && chown dashboard /app
WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/usr/local UV_COMPILE_BYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --extra dashboard
COPY php2mon ./php2mon
RUN uv sync --frozen --no-dev --extra dashboard
USER dashboard
EXPOSE 8000
ENTRYPOINT ["uvicorn", "--factory", "php2mon.web.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
