# SearchSploit MCP Server
# Exploit-DB offline search

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="SearchSploit MCP Server - Exploit-DB search"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m mcpuser

RUN sed -ri "s|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g" /etc/apt/sources.list.d/debian.sources && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install exploit-db from git (not available as apt package in debian:trixie)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    cp /opt/exploitdb/.searchsploit_rc /root/ && \
    sed -i 's|/opt/exploitdb|/opt/exploitdb|g' /root/.searchsploit_rc

RUN searchsploit --help > /dev/null || true

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
COPY --chown=mcpuser:mcpuser . .
RUN mkdir -p /app/output && chown -R mcpuser:mcpuser /app

USER mcpuser

ENV SEARCHSPLOIT_OUTPUT_DIR=/app/output
ENV EXPLOITDB_PATH=/usr/share/exploitdb
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
