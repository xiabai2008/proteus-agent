# Binwalk MCP Server
# Firmware analysis and extraction tool

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Binwalk MCP Server - Firmware analysis and extraction"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Create non-root user
RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m mcpuser

# Install extraction dependencies
RUN sed -ri "s|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g" /etc/apt/sources.list.d/debian.sources && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    git \
    p7zip-full \
    unzip \
    xz-utils \
    gzip \
    bzip2 \
    tar \
    cpio \
    lz4 \
    zstd \
    xxd \
    squashfs-tools \
    mtd-utils \
    cabextract \
    arj \
    lhasa \
    && rm -rf /var/lib/apt/lists/*

# Install binwalk from source
RUN git clone --depth 1 https://gh-proxy.com/https://github.com/OSPG/binwalk.git /tmp/binwalk && \
    cd /tmp/binwalk && \
    pip install --no-cache-dir . && \
    rm -rf /tmp/binwalk

# Verify binwalk installation
RUN binwalk --help > /dev/null || echo "binwalk installed"

WORKDIR /app

COPY --chown=mcpuser:mcpuser requirements.txt ./

RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

COPY --chown=mcpuser:mcpuser . .

RUN mkdir -p /app/output /app/uploads && chown -R mcpuser:mcpuser /app

USER mcpuser

# Environment variables
ENV BINWALK_OUTPUT_DIR=/app/output
ENV BINWALK_UPLOAD_DIR=/app/uploads
ENV BINWALK_TIMEOUT=300
ENV BINWALK_MAX_CONCURRENT=2
ENV BINWALK_MAX_FILE_SIZE=104857600
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
