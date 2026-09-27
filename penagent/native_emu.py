"""native_emu —— 真机执行题目自带的判定器（ELF + Unicorn），把"门"变成可调用的 oracle。

为什么要有这个工具（2026-09-27 真机实测，见 docs/修复待办清单.md R-45）：
一次 CTF 会话（黄鹤杯「云栈密令」，HarmonyOS .hap 内的 ARM64 libcloudseal.so）
里，模型需要"执行题目自带的 checker 来验证 flag"。它手搓 Unicorn 装载，
把整个 .so 往 0x10000 一放 —— 于是代码用 adrp/adr 指到的 .rodata 绝对地址
（该题在 0x2c0，而 .text 在 0x1067c）没被映射，每次都在 `UC_ERR_READ_UNMAPPED
pc=0x10838` 上失败。它把"我模拟不出来"写成"作者埋了死路、判定器不可满足"，
交了一个**过不了 checker** 的 flag。工具缺口是其中的关键一环：ELF 的
**装载语义**（vaddr ≠ 文件偏移、段各自映射）是机械知识，不该让模型每题重推。

本工具把这件事做成一次调用：

    native_emu(elf=<路径>, func=CloudSeal_NativeCheck,
               args="str:flag{...},len,hex:<16字节key>,len", expect=1,
               dump="sp-0x70:16")

装载按 program header 走（PT_LOAD：p_offset → p_vaddr，页对齐，与内核加载器
同口径），导出符号从 .dynsym / .symtab 解析（也接受 `func=0x1067c` 直接给地址），
参数支持 `int:` / `str:` / `hex:` / `len`（上一个缓冲区的长度），返回结构化
verdict：`accept`（ret == expect）/ `reject`（ret != expect）。

**判定器拒绝只说明这次输入没被接受，不代表门不可满足**——输出里固定带这条
提示，避免模型再把失败归因给题目。

安全边界：被执行的代码跑在 Unicorn 纯模拟器里（无 syscall、无网络、无宿主
文件系统访问），指令数与墙钟都有上界；参数只接受字符串/十六进制/整数，命令
不经 shell。因此 `dangerous=False`、可在 ctf-* 模式 auto_approve。
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

#: 支持的机器类型（e_machine）→ (unicorn arch/mode 名, 参数寄存器名列表, 返回寄存器)
_ARCHS = {
    0xB7: ("aarch64", ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"], "x0"),
    0x3E: ("x86_64", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"], "rax"),
}

_PAGE = 0x1000
_STACK_BASE = 0x200000
_STACK_SIZE = 0x100000
_ARG_BASE = 0x400000          # 参数缓冲区（str/hex）起始地址
_SENTINEL = 0x300000          # 返回落点：emu 跑到这里即停（ret 之后）
_MAX_ARG_BYTES = 1 << 20
_DEFAULT_MAX_INSNS = 5_000_000
_WALL_LIMIT_SECONDS = 20.0


def _align(value: int, page: int = _PAGE) -> int:
    return (value + page - 1) & ~(page - 1)


class _Elf:
    """最小 ELF64 解析：段表 + 符号表（只取本工具要用的字段）。"""

    def __init__(self, raw: bytes, path: str):
        if len(raw) < 64 or raw[:4] != b"\x7fELF":
            raise ValueError(f"{path} 不是 ELF 文件")
        if raw[4] != 2:
            raise ValueError("只支持 64 位 ELF（EI_CLASS=ELFCLASS64）")
        self.raw = raw
        self.path = path
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", raw, 16)
        self.e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
        self.e_shoff = struct.unpack_from("<Q", raw, 0x28)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", raw, 0x36)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from(
            "<HHH", raw, 0x3A)
        self.segments: list[tuple[int, int, int]] = []   # (p_offset, p_vaddr, p_filesz)
        for i in range(e_phnum):
            off = self.e_phoff + i * e_phentsize
            p_type, _flags = struct.unpack_from("<II", raw, off)
            p_offset, p_vaddr, _pa, p_filesz, _memsz = struct.unpack_from(
                "<QQQQQ", raw, off + 8)
            if p_type == 1 and p_filesz:
                self.segments.append((p_offset, p_vaddr, p_filesz))
        if not self.segments:
            raise ValueError("ELF 没有可装载段（PT_LOAD）")
        self.arch, self.arg_regs, self.ret_reg = self._arch()
        self.symbols = self._symbols()

    def _arch(self):
        if self.e_machine not in _ARCHS:
            known = ", ".join(f"{m:#x}({n})" for m, (n, _, _) in _ARCHS.items())
            raise ValueError(f"暂不支持的 e_machine={self.e_machine:#x}；"
                             f"已支持：{known}")
        return _ARCHS[self.e_machine]

    def _sections(self):
        """(名字, 类型, offset, size, link, entsize) 列表（无节头时为空）。"""
        out = []
        if not self.e_shoff or not self.e_shnum:
            return out
        names_off = 0
        if self.e_shstrndx:
            base = self.e_shoff + self.e_shstrndx * self.e_shentsize
            names_off = struct.unpack_from("<Q", self.raw, base + 0x18)[0]
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            name_off, sh_type, _f, _a, offset, size, link, _info, _al, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", self.raw, base)
            end = self.raw.find(b"\0", names_off + name_off) if names_off else -1
            name = (self.raw[names_off + name_off:end].decode("utf-8", "replace")
                    if end > 0 else "")
            out.append((name, sh_type, offset, size, link, entsize))
        return out

    def _symbols(self) -> dict[str, int]:
        """导出/静态符号名 → vaddr（.dynsym 优先，回退 .symtab）。"""
        syms: dict[str, int] = {}
        sections = self._sections()
        for want, strtab in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
            sym = next((s for s in sections if s[0] == want), None)
            strs = next((s for s in sections if s[0] == strtab), None)
            if not sym or not strs:
                continue
            _n, _t, soff, ssize, _l, _e = sym
            _n2, _t2, stroff, strsize, _l2, _e2 = strs
            for k in range(0, ssize, 24):       # Elf64_Sym 固定 24 字节
                if k + 24 > ssize:
                    break
                name_off, info, _other, shndx, value, _size = struct.unpack_from(
                    "<IBBHQQ", self.raw, soff + k)
                if not name_off or shndx == 0:      # SHN_UNDEF：未定义符号，跳过
                    continue
                end = self.raw.find(b"\0", stroff + name_off)
                name = self.raw[stroff + name_off:end].decode("utf-8", "replace")
                if name and name not in syms:
                    syms[name] = value
            if syms:
                break
        return syms

    def vaddr_to_offset(self, vaddr: int) -> int:
        for p_offset, p_vaddr, p_filesz in self.segments:
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        raise ValueError(f"vaddr {vaddr:#x} 不落在任何 PT_LOAD 段内")

    def map_into(self, mu) -> None:
        """按 PT_LOAD 把段映射到各自的 vaddr（页对齐，重叠页只映射一次）。

        这一步是本题材的核心：**vaddr 不等于文件偏移**是常态（.text 常在高位、
        .rodata 可能在低位），把整个文件往某个基址一放必然读错表。
        """
        mapped: list[tuple[int, int]] = []
        for p_offset, p_vaddr, p_filesz in self.segments:
            start = p_vaddr & ~(_PAGE - 1)
            size = _align(p_vaddr + p_filesz) - start
            if not any(s <= start and start + size <= s + n for s, n in mapped):
                mu.mem_map(start, size)
                mapped.append((start, size))
            mu.mem_write(p_vaddr, self.raw[p_offset:p_offset + p_filesz])


def _parse_args_spec(spec: str) -> list[tuple[str, object]]:
    """解析 `str:` / `hex:` / `int:` / `len` 参数序列（裸整数按 int 收）。

    `len` 取**上一个缓冲区参数**的长度（C checker 常见签名：
    `check(const char* input, int len, const uint8_t* key, int keylen)`）。

    裸整数（如 `str:flag{...},42,hex:...,16`）是 2026-09-27 实测里模型的第一
    反应写法——按 int 收下，省掉一次"参数无法解析"的往返。
    """
    parsed: list[tuple[str, object]] = []
    if not (spec or "").strip():
        return parsed
    for token in str(spec).split(","):
        item = token.strip()
        if not item:
            continue
        if item == "len":
            if not parsed or parsed[-1][0] not in ("str", "hex"):
                raise ValueError("`len` 必须跟在 str:/hex: 缓冲区参数之后")
            parsed.append(("int", len(parsed[-1][1])))       # type: ignore[arg-type]
            continue
        if ":" not in item:
            try:
                parsed.append(("int", int(item, 0)))
                continue
            except ValueError:
                raise ValueError(
                    f"参数 {item!r} 无法解析；"
                    f"可用：int:N / str:TEXT / hex:AABB / len（裸整数按 int 收）"
                ) from None
        kind, _, value = item.partition(":")
        if kind == "int":
            parsed.append(("int", int(value, 0)))
        elif kind == "str":
            data = value.encode("utf-8")
            if len(data) > _MAX_ARG_BYTES:
                raise ValueError("str 参数过长")
            parsed.append(("str", data))
        elif kind == "hex":
            try:
                data = bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(f"hex 参数不是合法十六进制: {exc}") from exc
            parsed.append(("hex", data))
        else:
            raise ValueError(f"未知参数类型 {kind!r}；"
                             f"可用：int:N / str:TEXT / hex:AABB / len")
    return parsed


def _parse_dumps(spec: str) -> list[tuple[str, int]]:
    """`0x207f90:16,sp-0x70:16` → [(地址表达式, 长度)]"""
    out: list[tuple[str, int]] = []
    for token in str(spec or "").split(","):
        item = token.strip()
        if not item:
            continue
        addr_expr, _, size_text = item.partition(":")
        if not size_text:
            raise ValueError(f"dump 项 {item!r} 缺少长度（形如 addr:len）")
        out.append((addr_expr.strip().lower(), int(size_text, 0)))
    return out


def _resolve_dump_addr(expr: str, sp: int) -> int:
    """`0x207f90` / `sp` / `sp-0x70` / `sp+0x10` → 绝对地址。"""
    if expr == "sp":
        return sp
    if expr.startswith("sp"):
        rest = expr[2:]
        if not rest:
            return sp
        sign = -1 if rest.startswith("-") else 1
        return sp + sign * int(rest.lstrip("+-"), 0)
    return int(expr, 0)


def native_emu(elf: str = "", func: str = "", args: str = "", expect: str = "1",
               dump: str = "", max_insns: str = "") -> dict:
    """真机执行 ELF 里的判定器函数，返回 `verdict`（accept/reject）。

    参数：
    - `elf`：ELF 路径（容器视角 `/samples/...` 与宿主路径都支持）；
    - `func`：导出符号名，或直接给函数地址（如 `0x1067c`）；留空则列出全部符号；
    - `args`：参数序列，逗号分隔：`int:N` / `str:TEXT` / `hex:AABB` /
      `len`（上一个缓冲区的长度）；
    - `expect`：视为"接受"的返回值（默认 1；想只看原始返回值可传空串）；
    - `dump`：返回后要读的内存，`地址:长度`（地址可用 `sp`、`sp-0x70` 相对栈顶）；
    - `max_insns`：指令数上界（默认 500 万，跑飞即停并报"未返回"）。
    """
    from penagent.ctf_tools import _resolve_path

    if not (elf or "").strip():
        return {"error": "缺少 elf 参数（ELF 路径）",
                "hint": "先 file_type 确认是 ELF，再 native_emu(elf=...) 调用它"}
    path, tried = _resolve_path(elf)
    if not path.is_file():
        return {"error": f"文件不存在: {path}", "tried": tried}
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return {"error": f"读取失败: {exc}"}
    try:
        image = _Elf(raw, str(path))
    except ValueError as exc:
        return {"error": str(exc)}

    if not (func or "").strip():
        return {"ok": True, "elf": str(path), "arch": image.arch,
                "symbols": {k: hex(v) for k, v in sorted(image.symbols.items())},
                "note": "未指定 func：上面是该 ELF 的符号表（挑判定器函数再调）"}

    name = str(func).strip()
    if name.lower().startswith("0x"):
        entry = int(name, 16)
    elif name in image.symbols:
        entry = image.symbols[name]
    else:
        return {"error": f"符号 {name!r} 不在 {path.name} 的符号表里",
                "symbols": {k: hex(v) for k, v in sorted(image.symbols.items())},
                "hint": "导出符号名区分大小写；也可以直接给地址（func=0x1067c）"}

    try:
        parsed_args = _parse_args_spec(args)
        parsed_dumps = _parse_dumps(dump)
    except ValueError as exc:
        return {"error": str(exc)}
    try:
        insn_cap = int(str(max_insns), 0) if str(max_insns or "").strip() \
            else _DEFAULT_MAX_INSNS
    except ValueError:
        return {"error": f"max_insns 不是整数: {max_insns!r}"}

    try:
        import unicorn
        from unicorn import UC_HOOK_CODE, Uc
    except ImportError:
        return {"error": "运行环境缺少 unicorn（pip install unicorn）",
                "hint": "native_emu 需要 Unicorn 才能真机执行 ELF 代码"
                        "（pip install unicorn；Docker 镜像 proteus-sandbox 已内置）"}

    arch, arg_regs, ret_reg = image.arch, image.arg_regs, image.ret_reg
    if arch == "aarch64":
        mu = Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    else:
        mu = Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    image.map_into(mu)
    mu.mem_map(_STACK_BASE, _STACK_SIZE)
    mu.mem_map(_SENTINEL, _PAGE)
    sp = _STACK_BASE + _STACK_SIZE - 0x10

    # 参数缓冲区依次落在 _ARG_BASE 之后（每块页对齐），寄存器传指针/立即数
    arg_blobs: list[tuple[int, bytes]] = []
    cursor = _ARG_BASE
    for kind, value in parsed_args:
        if kind in ("str", "hex"):
            blob = value if kind == "hex" else bytes(value) + b"\0"
            arg_blobs.append((cursor, blob))
            cursor = _align(cursor + max(len(blob), 1))
    for addr, blob in arg_blobs:
        mu.mem_map(addr & ~(_PAGE - 1), _align(max(len(blob), 1)))
        mu.mem_write(addr, blob)

    if arch == "aarch64":
        reg_map = {name_: getattr(unicorn.arm64_const, f"UC_ARM64_REG_{name_.upper()}")
                   for name_ in arg_regs}
        ret_id = unicorn.arm64_const.UC_ARM64_REG_X0
        pc_id = unicorn.arm64_const.UC_ARM64_REG_PC
        sp_id = unicorn.arm64_const.UC_ARM64_REG_SP
        lr_id = unicorn.arm64_const.UC_ARM64_REG_LR
    else:
        reg_map = {name_: getattr(unicorn.x86_const, f"UC_X86_REG_{name_.upper()}")
                   for name_ in arg_regs}
        ret_id = unicorn.x86_const.UC_X86_REG_RAX
        pc_id = unicorn.x86_const.UC_X86_REG_RIP
        sp_id = unicorn.x86_const.UC_X86_REG_RSP
        lr_id = None

    # 按 C ABI 传参：缓冲区参数传指针，int 传立即数
    blob_iter = iter(arg_blobs)
    ptr_by_index: dict[int, int] = {}
    for idx, (kind, _value) in enumerate(parsed_args):
        if kind in ("str", "hex"):
            ptr_by_index[idx] = next(blob_iter)[0]
    if len(parsed_args) > len(arg_regs):
        return {"error": f"参数超过 {len(arg_regs)} 个（寄存器传参上限）"}

    values: list[int] = []
    for idx, (kind, value) in enumerate(parsed_args):
        values.append(ptr_by_index[idx] if kind in ("str", "hex") else int(value))
    for name_, value in zip(arg_regs, values):
        mu.reg_write(reg_map[name_], value)

    mu.reg_write(sp_id, sp)
    if lr_id is not None:
        mu.reg_write(lr_id, _SENTINEL)          # aarch64：ret 落到哨兵
        mu.reg_write(pc_id, entry)
    else:
        mu.mem_write(sp - 8, struct.pack("<Q", _SENTINEL))   # x86-64：压返回地址
        mu.reg_write(sp_id, sp - 8)
        mu.reg_write(pc_id, entry)

    state = {"n": 0, "deadline": time.monotonic() + _WALL_LIMIT_SECONDS,
             "timeout": False}

    def _tick(_mu, _addr, _size, _ud):
        state["n"] += 1
        if state["n"] % 8192 == 0 and time.monotonic() > state["deadline"]:
            state["timeout"] = True
            _mu.emu_stop()

    mu.hook_add(UC_HOOK_CODE, _tick)
    fault = ""
    try:
        mu.emu_start(entry, _SENTINEL, count=insn_cap)
    except Exception as exc:                       # UcError：缺页/非法指令等
        fault = f"{type(exc).__name__}: {exc}"
    pc = mu.reg_read(pc_id)

    ret_value = mu.reg_read(ret_id)
    dumps: dict[str, str] = {}
    for expr, size in parsed_dumps:
        try:
            addr = _resolve_dump_addr(expr, sp)
            dumps[f"{expr}:{size}"] = bytes(mu.mem_read(addr, size)).hex()
        except Exception as exc:
            dumps[f"{expr}:{size}"] = f"ERR {exc}"

    out: dict = {
        "ok": True, "elf": str(path), "arch": arch, "func": name,
        "entry": hex(entry), "stack_top": hex(sp), "insns": state["n"],
        "args": [f"{k}:{v if k == 'int' else v.hex()}" for k, v in parsed_args],
        "ret": ret_value, "ret_hex": hex(ret_value & ((1 << 64) - 1)),
    }
    if dumps:
        out["dumps"] = dumps
    if fault:
        out.update(ok=False, error=f"执行中断：{fault}",
                   note="多半是输入/内存布局问题：确认 func 地址、参数形态与"
                        "（若是 .so）是否需要按 PT_LOAD 装载——本工具已按段映射，"
                        "报缺页地址可用 dump 查该处是否真的在段内")
        return out
    if state["timeout"] or pc != _SENTINEL:
        out.update(ok=False, error="函数未在指令/时间上界内返回（疑似死循环）",
                   pc=hex(pc), note=f"指令数上界 {insn_cap}，"
                                    f"墙钟上界 {_WALL_LIMIT_SECONDS:.0f}s")
        return out

    expect_text = str(expect or "").strip()
    if expect_text:
        try:
            want = int(expect_text, 0)
        except ValueError:
            return {"error": f"expect 不是整数: {expect_text!r}"}
        out["expect"] = want
        out["verdict"] = "accept" if ret_value == want else "reject"
        out["note"] = (
            f"ret == expect（{want}）：判定器**接受**这个输入——这就是可引用的"
            f"接受性证据" if ret_value == want else
            f"ret != expect（{want}）：判定器**拒绝**这个输入。拒绝只说明这次"
            f"输入没被接受，**不代表门不可满足**——换输入或回头检查推导"
            f"（中间量如 key/seed 不是 flag），不要断言\"作者埋了死路\"")
    else:
        out["note"] = "未给 expect：只回原始返回值，请自行判读"
    return out
