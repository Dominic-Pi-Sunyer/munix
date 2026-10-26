# The demo agent's image for `munix run`: Python plus the agent's runtime dependencies, and nothing else.
#
#   docker build -t munix-demo-agent demo/agent
#
# Building downloads packages from PyPI, so it needs the owner's approval. The build context is only this
# directory; no source is copied in. Munix mounts it read-only at /agent when it runs the container, and sets
# the command itself (the Munix shim is PID 1 and owns the container's stdio), so there is no ENTRYPOINT or CMD.
FROM python:3.12-slim

# The versions locked in uv.lock for the two direct dependencies in pyproject.toml. pip resolves the rest;
# to see the full lock, run `uv export --frozen --no-hashes --no-dev --no-emit-project` in this directory.
ARG OPENAI_VERSION=1.109.1
ARG MCP_VERSION=1.30.0

# No bytecode (the root file system is read-only at run time) and unbuffered output.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install "openai==${OPENAI_VERSION}" "mcp[cli]==${MCP_VERSION}"

# The agent never runs as root.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin agent
USER agent
