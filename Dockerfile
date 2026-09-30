# The multi-platform manifest digest was resolved for python:3.12.12-slim-bookworm.
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS builder
WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.11.7
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
ENV UV_PROJECT_ENVIRONMENT=/opt/dragons
RUN uv sync --locked --no-dev --no-editable --no-config --python /usr/local/bin/python

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
COPY --from=builder /opt/dragons /opt/dragons
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
WORKDIR /target
ENTRYPOINT ["/opt/dragons/bin/dragonscan"]
CMD ["--help"]
