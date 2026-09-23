# proteus 自建构建（2026-09-23）：官方 Dockerfile 用 uv + ghcr base 镜像 +
# BuildKit bind mount，与本地网络/缓存耦合深；这里是等价的最小构建——
# python:3.12-slim（本地已缓存）+ 钉版依赖 + --no-deps 装本体。
#
# 为什么钉 mcp==1.18.0 且 --no-deps：pyproject 声明 mcp>=1.6.0 过松，
# pip 全新解析会挑到旧版并撞 pydantic 约束（实测 ResolutionImpossible）；
# 直接装"经过验证的组合"再 --no-deps 装本体，绕开解析器（2026-09-23）。
# PyPI 走清华镜像：构建期直连 files.pythonhosted.org 会读超时（同日实测）。
FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple \
      "mcp==1.18.0" "httpx>=0.28.1" \
 && pip install --no-cache-dir --no-deps \
      -i https://pypi.tuna.tsinghua.edu.cn/simple . \
 && python -c "from cyberchef_api_mcp_server.server import main; print('adapter ok')"

CMD ["cyberchef-api-mcp-server"]
