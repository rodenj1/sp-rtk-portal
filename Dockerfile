# syntax=docker/dockerfile:1
#
# The Portal image. Deployed by homelab-talos (namespace sp-rtk-portal) as
# uid 1000 with a read-only root filesystem: nothing here writes outside /tmp.
#
#   docker build -t sp-rtk-portal .
#   docker run --rm -p 8000:8000 -e PORTAL_DATABASE_URL=... sp-rtk-portal
#
# Configuration is the PORTAL_* environment (see README.md).

ARG PYTHON_VERSION=3.12

FROM ghcr.io/astral-sh/uv:0.11.14 AS uv

FROM python:${PYTHON_VERSION}-slim-bookworm AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first, so source edits don't invalidate this layer.
COPY pyproject.toml uv.lock ./
COPY protocol/pyproject.toml protocol/README.md protocol/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-workspace
COPY . .
# --no-editable: the venv holds real copies of sp-rtk-portal and the protocol
# package, so the runtime stage needs only /app/.venv.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

FROM python:${PYTHON_VERSION}-slim-bookworm
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORTAL_HOST=0.0.0.0 \
    PORTAL_PORT=8000
RUN groupadd --gid 1000 portal \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin portal
COPY --from=build /app/.venv /app/.venv
USER 1000:1000
EXPOSE 8000
# The Kubernetes probes run this inside the container (an exec probe), so the
# NetworkPolicy need not admit kubelet traffic to the Portal's port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['PORTAL_PORT'], timeout=4)"]
CMD ["sp-rtk-portal"]
