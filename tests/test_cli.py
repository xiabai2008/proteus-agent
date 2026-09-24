"""CLI 入口（`python -m penagent`）跨进程行为约束。

覆盖 R-42 第 2 项：**重定向/管道下 stdout 默认是块缓冲**（几 KB 才刷一次），
`python -m penagent run ... > log`、`| tee` 或后台运行时，进度要到进程结束才
一次性出现——长任务里日志文件长时间为空，看不出走到哪一步。`cli.main()` 开头
把 stdout/stderr 一并改成行缓冲，一次覆盖全部 print。

为什么必须起子进程：缓冲行为只在**非 tty**（管道/文件）下才与终端不同，而
pytest 自己的捕获会替换 sys.stdout，测不到真实的缓冲语义。
"""
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 子进程脚本：把 missions 子命令换成一个"先打印再长睡"的假实现，且**不显式
# flush**——那一行能出现在管道里，只能是行缓冲自己刷出去的。
# `cli.main()` 内部 `set_defaults(fn=cmd_missions)` 在解析器构造时按全局名取值，
# 故在 main() 之前替换模块属性即可生效。
CHILD = textwrap.dedent(
    """
    import sys, time
    import penagent.cli as cli

    def fake(args):
        print("progress-now")
        time.sleep(30)
        return 0

    cli.cmd_missions = fake
    sys.exit(cli.main(["missions"]))
    """
)


def test_progress_line_visible_while_piped():
    """管道下 print 的进度行要在进程结束前可见（否则仍处于块缓冲）。"""
    proc = subprocess.Popen([sys.executable, "-c", CHILD],
                            cwd=str(PROJECT_ROOT),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    seen: list[str] = []
    got_line = threading.Event()

    def _read() -> None:
        line = proc.stdout.readline()      # 子进程不退，块缓冲就永远读不到
        if line:
            seen.append(line.strip())
        got_line.set()

    try:
        threading.Thread(target=_read, daemon=True).start()
        assert got_line.wait(10), (
            "管道下 10 秒内读不到进度行——stdout 退回块缓冲了"
            "（cli.main 的 line_buffering 失效）")
        assert seen == ["progress-now"]
    finally:
        proc.kill()
        proc.wait(timeout=10)
        proc.stdout.close()
        proc.stderr.close()