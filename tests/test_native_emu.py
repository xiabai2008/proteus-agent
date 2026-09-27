"""native_emu 工具测试：装载语义（vaddr ≠ 文件偏移）+ 真机调用 + accept/reject。

为什么判据要落在"装载语义"上（2026-09-27 实测，R-45）：一次 CTF 会话里模型
手搓 Unicorn 把整个 .so 放到 0x10000，而代码用 adrp/adr 指到 .rodata 的绝对
地址（该题 .rodata 在 0x2c0、.text 在 0x1067c），于是每次都在
`UC_ERR_READ_UNMAPPED` 上失败，最后把"模拟不出来"写成"作者埋了死路"。
本文件的 ELF 故意把段放在 vaddr 0x20000 / 0x1000 而文件偏移是 0x200 / 0x300
——**按文件偏移装载的实现必然读错表**，于是这些用例同时是回归判据。

ELF 由测试就地构造（不依赖本机编译器）：手写 aarch64 机器码，
`Check(s, n)` 比较 s[0] 与 .rodata 首字节（adrp 取址，专门压段映射），
`CheckLen(s, n)` 只判 n == 4（压 `len` 参数渲染）。
"""
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.native_emu import (_Elf, _parse_args_spec, _parse_dumps,
                                 native_emu)
from penagent.modes import load_mode
from penagent.registry import build_center

# ----------------------------------------------------------------------
# 最小 aarch64 ELF 构造（段 vaddr 与文件偏移刻意不一致）
# ----------------------------------------------------------------------
TEXT_VADDR, TEXT_OFF = 0x20000, 0x200
RO_VADDR, RO_OFF = 0x1000, 0x300
DYNSTR_OFF, DYNSYM_OFF, SHSTR_OFF = 0x100, 0x140, 0x190
SHOFF, SHENTSIZE = 0x400, 64
RODATA = b"f" + bytes(15)
CHECK_OFF, CHECKLEN_OFF = 0, 24          # 两个函数在 .text 内的偏移


def _check_code() -> bytes:
    """Check(const char* s, int n) → s[0] == .rodata[0] ? 1 : 0"""
    words = (
        0x39400002,      # ldrb w2, [x0]
        0xB0FFFF03,      # adrp x3, #-0x1f000   → 页 0x1000（.rodata 所在页）
        0x39400063,      # ldrb w3, [x3]
        0x6B03005F,      # cmp  w2, w3
        0x1A9F17E0,      # cset w0, eq
        0xD65F03C0,      # ret
    )
    return b"".join(struct.pack("<I", w) for w in words)


def _checklen_code() -> bytes:
    """CheckLen(const char* s, int n) → n == 4 ? 1 : 0"""
    words = (
        0x7100103F,      # cmp w1, #4
        0x1A9F17E0,      # cset w0, eq
        0xD65F03C0,      # ret
    )
    return b"".join(struct.pack("<I", w) for w in words)


def _strtab(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob, offs = b"\x00", {}
    for name in names:
        offs[name] = len(blob)
        blob += name.encode() + b"\x00"
    return blob, offs


def build_elf(*, machine: int = 0xB7, elf_class: int = 2) -> bytes:
    text = _check_code().ljust(CHECKLEN_OFF, b"\x00") + _checklen_code()
    dynstr, offs = _strtab(["Check", "CheckLen"])
    shstr, sh_offs = _strtab([".dynsym", ".dynstr", ".shstrtab"])

    syms = [
        (0, 0, 0, 0, 0, 0),                                     # 空符号
        (offs["Check"], 0x12, 0, 1, TEXT_VADDR + CHECK_OFF, 24),
        (offs["CheckLen"], 0x12, 0, 1, TEXT_VADDR + CHECKLEN_OFF, 12),
    ]
    dynsym = b"".join(struct.pack("<IBBHQQ", *s) for s in syms)

    buf = bytearray(SHOFF + 4 * SHENTSIZE)
    ident = b"\x7fELF" + bytes([elf_class, 1, 1, 0]) + bytes(8)
    struct.pack_into("<16sHHIQQQIHHHHHH", buf, 0, ident, 3, machine, 1,
                     TEXT_VADDR, 0x40, SHOFF, 0, 64, 56, 2, SHENTSIZE, 4, 3)
    # PT_LOAD[0] = .text（vaddr 0x20000 / 文件 0x200）
    struct.pack_into("<IIQQQQQQ", buf, 0x40, 1, 5, TEXT_OFF, TEXT_VADDR,
                     TEXT_VADDR, len(text), len(text), 0x1000)
    # PT_LOAD[1] = .rodata（vaddr 0x1000 / 文件 0x300）
    struct.pack_into("<IIQQQQQQ", buf, 0x78, 1, 4, RO_OFF, RO_VADDR,
                     RO_VADDR, len(RODATA), len(RODATA), 0x1000)
    buf[DYNSTR_OFF:DYNSTR_OFF + len(dynstr)] = dynstr
    buf[DYNSYM_OFF:DYNSYM_OFF + len(dynsym)] = dynsym
    buf[SHSTR_OFF:SHSTR_OFF + len(shstr)] = shstr
    buf[TEXT_OFF:TEXT_OFF + len(text)] = text
    buf[RO_OFF:RO_OFF + len(RODATA)] = RODATA

    def sh(idx, name, typ, off, size, link=0, entsize=0):
        name_off = sh_offs[name] if name else 0
        struct.pack_into("<IIQQQQIIQQ", buf, SHOFF + idx * SHENTSIZE,
                         name_off, typ, 0, 0, off, size, link, 0, 8,
                         entsize)

    sh(0, "", 0, 0, 0)
    sh(1, ".dynsym", 11, DYNSYM_OFF, len(dynsym), link=2, entsize=24)
    sh(2, ".dynstr", 3, DYNSTR_OFF, len(dynstr))
    sh(3, ".shstrtab", 3, SHSTR_OFF, len(shstr))
    return bytes(buf)


@pytest.fixture(autouse=True)
def _quiet_unicorn_seh():
    """临时关掉 faulthandler：unicorn 2.1.2 在 Windows 上**每次 mem_map**
    都会触发一次 first-chance access violation（其内部地址探测行为，映射
    本身成功——实测 0x0 / 0x1000 / 0x11000 三个地址均如此）。pytest 默认
    启用 faulthandler，会把这类非致命异常打成转储刷屏；关掉只是不再打印
    转储，真正的崩溃仍会让进程退出。仅 Windows 上生效。
    """
    if sys.platform != "win32":
        yield
        return
    import faulthandler

    faulthandler.disable()
    try:
        yield
    finally:
        faulthandler.enable()


@pytest.fixture()
def elf_file(tmp_path):
    path = tmp_path / "checker.so"
    path.write_bytes(build_elf())
    return str(path)


# ----------------------------------------------------------------------
# 1. 装载语义：按 PT_LOAD 的 vaddr 映射，不是文件偏移
# ----------------------------------------------------------------------
def test_loader_maps_by_vaddr_not_file_offset():
    """vaddr ≠ 文件偏移时也能读对表——这条用例是本工具存在的理由。"""
    pytest.importorskip("unicorn", reason="native_emu 需要 unicorn（可选依赖）")
    from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc

    image = _Elf(build_elf(), "checker.so")
    assert image.vaddr_to_offset(TEXT_VADDR) == TEXT_OFF
    assert image.vaddr_to_offset(RO_VADDR) == RO_OFF
    assert image.arch == "aarch64"

    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    image.map_into(mu)
    assert bytes(mu.mem_read(RO_VADDR, 2)) == RODATA[:2]
    assert bytes(mu.mem_read(TEXT_VADDR, 4)) == _check_code()[:4]
    # 文件偏移那套口径在这里必须读不到（否则就是"整文件放到某基址"的老毛病）
    with pytest.raises(Exception):
        mu.mem_read(RO_OFF, 2)


def test_symbol_table_parsed_from_dynsym(elf_file):
    out = native_emu(elf=elf_file)
    assert out["ok"] is True
    assert out["symbols"]["Check"] == hex(TEXT_VADDR + CHECK_OFF)
    assert out["symbols"]["CheckLen"] == hex(TEXT_VADDR + CHECKLEN_OFF)


# ----------------------------------------------------------------------
# 2. 真机调用与 verdict
# ----------------------------------------------------------------------
def test_check_reads_rodata_via_adrp(elf_file):
    """Check 走 adrp 取 .rodata——装载错就必然失败，装载对则 accept/reject 正确。"""
    pytest.importorskip("unicorn", reason="native_emu 需要 unicorn（可选依赖）")

    hit = native_emu(elf=elf_file, func="Check", args="str:flag{abc},len",
                     expect="1")
    assert hit["ok"] is True and hit["ret"] == 1
    assert hit["verdict"] == "accept"
    assert "接受" in hit["note"]

    miss = native_emu(elf=elf_file, func="Check", args="str:xyz,len",
                      expect="1")
    assert miss["ret"] == 0 and miss["verdict"] == "reject"
    # 拒绝必须带上"这不是死路"的提示——防的正是 2026-09-27 那次自圆其说
    assert "不代表门不可满足" in miss["note"]


def test_len_token_and_int_arg_land_in_same_register(elf_file):
    pytest.importorskip("unicorn", reason="native_emu 需要 unicorn（可选依赖）")

    assert native_emu(elf=elf_file, func="CheckLen", args="str:abcd,len",
                      expect="1")["ret"] == 1
    assert native_emu(elf=elf_file, func="CheckLen", args="str:abcde,len",
                      expect="1")["ret"] == 0
    # int: 立即数与 len 渲染等价（同一寄存器通道）
    assert native_emu(elf=elf_file, func="CheckLen", args="str:abcd,int:4",
                      expect="1")["ret"] == 1
    # 裸整数也按 int 收（2026-09-27 实测：模型第一反应就是写 42 而不是 int:42）
    assert native_emu(elf=elf_file, func="CheckLen", args="str:abcd,4",
                      expect="1")["ret"] == 1
    # expect 留空 → 只回原始返回值，不判 accept/reject
    out = native_emu(elf=elf_file, func="CheckLen", args="str:abcd,len",
                     expect="")
    assert "verdict" not in out and out["ret"] == 1


def test_hex_arg_is_raw_bytes(elf_file):
    pytest.importorskip("unicorn", reason="native_emu 需要 unicorn（可选依赖）")

    # 'f' = 0x66：hex 缓冲区首字节与 .rodata 首字节相同 → accept
    out = native_emu(elf=elf_file, func="Check", args="hex:66aa,len",
                     expect="1")
    assert out["ret"] == 1 and out["verdict"] == "accept"
    assert out["args"][0] == "hex:66aa"


def test_dump_reads_stack_frame(elf_file):
    pytest.importorskip("unicorn", reason="native_emu 需要 unicorn（可选依赖）")

    out = native_emu(elf=elf_file, func="Check", args="str:f,len",
                     dump="sp-0x10:4")
    assert out["dumps"]["sp-0x10:4"] == "0" * 8      # 未写入的栈 = 0
    assert out["stack_top"].startswith("0x")


def test_func_can_be_an_address(elf_file):
    pytest.importorskip("unicorn", reason="native_emu 需要 unicorn（可选依赖）")

    out = native_emu(elf=elf_file, func=hex(TEXT_VADDR + CHECKLEN_OFF),
                     args="str:abcd,len", expect="1")
    assert out["ret"] == 1 and out["verdict"] == "accept"


# ----------------------------------------------------------------------
# 3. 错误路径可操作（不静默、不误导）
# ----------------------------------------------------------------------
def test_unknown_symbol_lists_candidates(elf_file):
    out = native_emu(elf=elf_file, func="NoSuchFn")
    assert "error" in out
    assert "Check" in out["symbols"]                 # 给出候选，帮模型自我纠正


def test_unsupported_machine_and_class_are_reported(tmp_path):
    bad_arch = tmp_path / "i386.so"
    bad_arch.write_bytes(build_elf(machine=0x03))
    assert "e_machine" in native_emu(elf=str(bad_arch))["error"]

    bad_class = tmp_path / "elf32.so"
    bad_class.write_bytes(build_elf(elf_class=1))
    assert "64 位" in native_emu(elf=str(bad_class))["error"]


def test_missing_file_and_bad_args(elf_file):
    assert "不存在" in native_emu(elf=str(Path(elf_file).parent / "nope.so"))["error"]
    assert "缺少 elf" in native_emu(elf="")["error"]
    with pytest.raises(ValueError):
        _parse_args_spec("len")                      # len 必须跟在缓冲区之后
    with pytest.raises(ValueError):
        _parse_args_spec("bogus:1")
    with pytest.raises(ValueError):
        _parse_dumps("0x1000")                       # 缺长度


def test_missing_unicorn_message_is_actionable(elf_file, monkeypatch):
    monkeypatch.setitem(sys.modules, "unicorn", None)   # 模拟未安装
    out = native_emu(elf=elf_file, func="Check", args="str:f,len")
    assert "unicorn" in out["error"]
    assert "pip install unicorn" in out["hint"]


# ----------------------------------------------------------------------
# 4. 工具面：只在 ctf-* 可见，且模式名单可解析
# ----------------------------------------------------------------------
def test_native_emu_visible_in_ctf_modes_only():
    center = build_center()
    entries = {e.name: e for e in center.discover(mode_id="ctf-crypto")}
    assert "native_emu" in entries
    assert entries["native_emu"].origin == "ctf_tools"
    assert set(entries["native_emu"].modes) == {"ctf-web", "ctf-crypto",
                                                "ctf-reverse"}
    assert entries["native_emu"].spec.dangerous is False   # 纯模拟器，无宿主副作用

    pentest = center.build_registry(load_mode("pentest-standard"))
    assert "native_emu" not in pentest.names()

    for mode_id in ("ctf-web", "ctf-crypto"):
        mode = load_mode(mode_id)
        assert "native_emu" in mode.capability.allow
        assert "native_emu" in mode.permission.auto_approve


def test_ctf_budget_allows_long_reverse_engineering():
    """60 步装不下真机反解（实测 83 步未收敛），预算上调不得回退。"""
    for mode_id in ("ctf-web", "ctf-crypto"):
        mode = load_mode(mode_id)
        assert mode.budget.max_steps >= 120
        assert mode.budget.max_minutes >= 60


def test_ctf_seed_skill_targets_native_checker_workflow():
    """种子技能必须落在 ctf-* 的技能包里，否则会被机制性过滤掉。"""
    from penagent.skill_seeds import SEED_SKILLS

    seed = next(s for s in SEED_SKILLS if s.id == "ctf-native-checker-oracle")
    assert seed.category in load_mode("ctf-crypto").skills
    assert "native_emu" in seed.tools
    joined = "\n".join(seed.steps)
    assert "不代表门不可满足" in joined      # 拒绝≠死路
    assert "中间量不是 flag" in joined       # 推导值不是答案
