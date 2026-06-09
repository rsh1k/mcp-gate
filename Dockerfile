# mcp-gate container image.
#
# Design goals: small, non-root, no build toolchain in the final image, and a
# sane default that prints help. mcp-gate's core has ZERO runtime dependencies,
# so the runtime layer is just Python + the package. PyYAML is included so YAML
# policies work out of the box; drop it if you only use JSON policies.
#
# Build:
#   docker build -t mcp-gate:latest .
#
# Run the proxy in front of an upstream stdio MCP server. Because stdio uses
# stdin/stdout, run with -i (interactive) and no TTY so the JSON-RPC stream is
# clean. Mount your policy and a volume for the audit log:
#
#   docker run --rm -i \
#     -v "$PWD/policy.yaml:/etc/mcp-gate/policy.yaml:ro" \
#     -v "mcp-gate-audit:/var/lib/mcp-gate" \
#     mcp-gate:latest run \
#       --policy /etc/mcp-gate/policy.yaml \
#       --audit  /var/lib/mcp-gate/audit.jsonl \
#       --fail closed \
#       -- <your upstream MCP server command>
#
# Validate a policy without running anything:
#   docker run --rm -v "$PWD/policy.yaml:/p.yaml:ro" mcp-gate:latest check --policy /p.yaml

# ---- build stage ----------------------------------------------------------
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY mcpgate ./mcpgate
# Build a wheel so the final stage installs a clean artifact, not the source tree.
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

# ---- runtime stage --------------------------------------------------------
FROM python:3.12-slim AS runtime

# Create a non-root user. The proxy never needs root; running as root on the
# tool-call path is exactly the kind of excess privilege this tool exists to
# discourage.
RUN useradd --create-home --uid 10001 mcpgate \
    && mkdir -p /var/lib/mcp-gate /etc/mcp-gate \
    && chown -R mcpgate:mcpgate /var/lib/mcp-gate /etc/mcp-gate

COPY --from=build /dist/*.whl /tmp/
# Install with the yaml extra so YAML policies work; --no-cache keeps it small.
RUN pip install --no-cache-dir /tmp/*.whl pyyaml \
    && rm -f /tmp/*.whl

USER mcpgate
WORKDIR /home/mcpgate

# The audit log is the one piece of durable state; make it an explicit volume so
# operators don't lose evidence when the container is recreated.
VOLUME ["/var/lib/mcp-gate"]

# OCI labels for registries (GHCR / Docker Hub) — fill in your repo URL.
LABEL org.opencontainers.image.title="mcp-gate" \
      org.opencontainers.image.description="Runtime policy-enforcement proxy for MCP tool calls" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/rsh1k/mcp-gate"

ENTRYPOINT ["mcp-gate"]
CMD ["--help"]
