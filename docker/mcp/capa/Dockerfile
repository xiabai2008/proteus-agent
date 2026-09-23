# Capa MCP Server
# Binary capability detection

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Capa MCP Server - Binary capability detection"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m mcpuser

RUN sed -ri "s|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g" /etc/apt/sources.list.d/debian.sources && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install capa
ARG CAPA_VERSION=7.0.1
RUN curl -sL "https://gh-proxy.com/https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip" -o /tmp/capa.zip && \
    cd /tmp && unzip capa.zip && \
    mv capa /usr/local/bin/capa && \
    chmod +x /usr/local/bin/capa && \
    rm -rf /tmp/*

# Note: capa --version may fail on non-x86_64 during build (e.g., ARM64 Mac)
RUN capa --version || echo "Skipping version check (non-x86_64 build host)"

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
COPY --chown=mcpuser:mcpuser . .
RUN mkdir -p /app/output /app/rules /app/samples && chown -R mcpuser:mcpuser /app

USER mcpuser

ENV CAPA_OUTPUT_DIR=/app/output
ENV CAPA_RULES_DIR=/app/rules
ENV CAPA_TIMEOUT=300
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
