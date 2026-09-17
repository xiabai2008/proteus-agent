"""授权本地演示靶子：简易 HTTP 服务（仅供 XPentest 本地闭环验证）。

端点：
- /           首页（含标题，暴露技术栈提示）
- /robots.txt 路径信息
- /health     健康检查（200）
- /admin      受保护路径（401，提示认证机制）
- /debug      版本信息（模拟敏感信息泄漏）
运行：python examples/target.py --port 8080
"""
import argparse
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = """<html><head><title>Demo Portal - Flask/2.3</title></head>
<body><h1>Welcome</h1><a href="/admin">Admin</a></body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /debug\n"

DEBUG = ("app: demo-portal v1.4.2\n"
         "framework: flask 2.3.0\n"
         "debug_mode: false\n")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._send(200, "text/html", PAGE)
        elif self.path == "/robots.txt":
            self._send(200, "text/plain", ROBOTS)
        elif self.path == "/health":
            self._send(200, "application/json", '{"status":"ok"}')
        elif self.path == "/admin":
            self._send(401, "text/plain", "401 Unauthorized: session required")
        elif self.path == "/debug":
            self._send(200, "text/plain", DEBUG)
        else:
            self._send(404, "text/plain", "404 Not Found")

    def _send(self, code: int, ctype: str, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "demo-portal")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    print(f"演示靶子: http://127.0.0.1:{args.port}（Ctrl+C 退出）")
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
