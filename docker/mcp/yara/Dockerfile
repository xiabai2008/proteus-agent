# YARA MCP Server
# Malware detection and pattern matching

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="YARA MCP Server - Malware detection and pattern matching"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Create non-root user
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

# Install YARA and dependencies
RUN sed -i "s|dl-cdn.alpinelinux.org|mirrors.tuna.tsinghua.edu.cn|g" /etc/apk/repositories && apk add --no-cache \
    ca-certificates \
    tini \
    yara \
    git \
    && rm -rf /var/cache/apk/*

# Verify YARA installation
RUN yara --version

WORKDIR /app

COPY --chown=mcpuser:mcpuser requirements.txt ./

RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

COPY --chown=mcpuser:mcpuser . .

RUN mkdir -p /app/output /app/rules /app/samples && chown -R mcpuser:mcpuser /app

USER mcpuser

# Download common YARA rulesets
RUN git clone --depth 1 https://gh-proxy.com/https://github.com/Yara-Rules/rules.git /tmp/yara-rules && \
    cp -r /tmp/yara-rules/malware /app/rules/malware && \
    cp -r /tmp/yara-rules/crypto /app/rules/crypto && \
    cp -r /tmp/yara-rules/packers /app/rules/packers && \
    cp -r /tmp/yara-rules/cve_rules /app/rules/cve_rules 2>/dev/null || true && \
    rm -rf /tmp/yara-rules

# Create index file for all rules
RUN find /app/rules -name "*.yar" -o -name "*.yara" | \
    sed 's/^/include "/' | sed 's/$/"/' > /app/rules/index.yar || true

# Environment variables
ENV YARA_RULES_DIR=/app/rules
ENV YARA_OUTPUT_DIR=/app/output
ENV YARA_TIMEOUT=300
ENV YARA_MAX_CONCURRENT=2
ENV YARA_MAX_FILE_SIZE=104857600
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "server.py"]
