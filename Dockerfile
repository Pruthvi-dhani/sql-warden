# sql-warden as a container: the HTTP server, for agents that connect with a token.
#
#   docker build -t sql-warden .
#   docker build -t sql-warden --build-arg EXTRAS=snowflake .     # with the Snowflake engine
#   docker run -p 8000:8000 -v "$PWD/warden.yaml:/etc/sql-warden/warden.yaml:ro" sql-warden
#
# It listens on 0.0.0.0, which sql-warden allows only with an auth section and
# server.allowed_hosts in the config. Put a proxy that terminates TLS in front of it.
# /healthz, /readyz and /metrics answer without a token; route only /mcp to the outside.

ARG PYTHON=3.12

FROM python:${PYTHON}-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1
WORKDIR /app
ARG EXTRAS=""
# Dependencies first, from the lock file alone, so a code change doesn't reinstall them.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project ${EXTRAS:+--extra $EXTRAS}
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable ${EXTRAS:+--extra $EXTRAS}

FROM python:${PYTHON}-slim
# A user of its own, with no shell and no home: nothing it runs needs either.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin warden
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    SQL_WARDEN_CONFIG=/etc/sql-warden/warden.yaml
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["sql-warden"]
CMD ["serve", "--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
