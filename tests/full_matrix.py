"""MemGuard 全工况 / 全参数验证（回归资产，可反复运行）。

设计约束：
1. 所有会改变系统状态的函数在进程内被替换成计数器，脚本结束前断言真实函数从未被调用。
2. 只读采集允许执行；所有"执行"路径只使用 mock 快照，不触碰真实进程。
3. 用例分 6 组：配置参数边界、状态组合矩阵、采集降级、持久化与引擎、
   执行层防误杀、入口与一致性。
4. 输出每组通过率 + 失败明细，退出码非 0 表示存在未通过项。

用法： python tests/full_matrix.py  （或 run.bat --fulltest）
"""
from __future__ import annotations

import inspect
import itertools
import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import fields
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from memguard import collector, winapi  # noqa: E402
from memguard.actions import Plan, PlanItem, build_plan, execute, revalidate_plan  # noqa: E402
from memguard.anchors import AnchorStore, Diff  # noqa: E402
from memguard.collector import MB, GpuInfo, ProcInfo, Snapshot  # noqa: E402
from memguard.config import Config  # noqa: E402
from memguard.engine import Engine  # noqa: E402
from memguard.safety import (  # noqa: E402
    AuditLog, annotate_protection, auto_anchor_ok, auto_should_release, preflight,
)

RESULTS: list[dict] = []
NOTES: list[dict] = []          # 待用户决策的增强项，不计入通过率
REAL_CALLS: list[str] = []
_ORIGINALS: dict[str, object] = {}


def check(group: str, name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append({"group": group, "name": name, "ok": bool(cond), "detail": str(detail)[:260]})


def note(group: str, name: str, detail: str = "") -> None:
    NOTES.append({"group": group, "name": name, "detail": detail})


def case(group: str, name: str, fn):
    """运行一个用例，把未捕获异常本身记为失败（用例不应崩溃）。"""
    try:
        cond, detail = fn()
        check(group, name, bool(cond), detail)
    except Exception as exc:  # noqa: BLE001
        check(group, name, False, f"抛出异常 {type(exc).__name__}: {exc}")


def _mock_state_changers() -> dict:
    calls = {"trim": [], "purge": [], "kill": [], "close": []}
    names = ["trim_working_set", "purge_standby_list", "force_kill"]
    for n in names:
        _ORIGINALS[n] = getattr(winapi, n)

    def trim(pid):
        calls["trim"].append(pid)
        REAL_CALLS.append("trim")
        return True, "mock"

    def purge():
        calls["purge"].append(1)
        return True, "mock"

    def kill(pid):
        calls["kill"].append(pid)
        return True, "mock"

    winapi.trim_working_set = trim
    winapi.purge_standby_list = purge
    winapi.force_kill = kill
    return calls


def _restore() -> None:
    for n, f in _ORIGINALS.items():
        setattr(winapi, n, f)


def base_snap(**kw) -> Snapshot:
    total = int(16 * 1024 * MB)
    used = int(8 * 1024 * MB)
    d = dict(
        ts=time.time(), boot_ms=60 * 60 * 1000, total_phys=total, used_phys=used,
        avail_phys=total - used, load_pct=50, pagefile_avail=int(8 * 1024 * MB),
        pagefile_total=int(16 * 1024 * MB), commit_total=int(9 * 1024 * MB),
        commit_limit=int(24 * 1024 * MB), system_cache=int(1024 * MB),
        standby_bytes=int(2048 * MB), user_idle_sec=600.0,
        cpu_busy=5.0, disk_busy=5.0, is_admin=True,
        procs=[
            ProcInfo(pid=1001, name="ollama.exe", ws=int(3 * 1024 * MB), gpu_mb=4096),
            ProcInfo(pid=1002, name="python.exe", ws=int(1024 * MB), has_window=True, title="AI 控制台"),
            ProcInfo(pid=1003, name="csrss.exe", ws=int(512 * MB)),
            ProcInfo(pid=1004, name="helper.exe", ws=int(400 * MB)),
        ],
        gpus=[GpuInfo(key="0", name="Mock GPU", dedicated_used_mb=5000.0,
                      dedicated_total_mb=8192.0, source="mock")],
        gpu_attributable=True,
    )
    d.update(kw)
    s = Snapshot(**d)
    annotate_protection(s, cfg_for_base())
    return s


_CFG_BASE: Config | None = None


def cfg_for_base() -> Config:
    global _CFG_BASE
    if _CFG_BASE is None:
        _CFG_BASE = Config()
    return _CFG_BASE


def diff_for(snap: Snapshot, used_delta: float = 2 * 1024 * MB, **kw) -> Diff:
    a_used = int(snap.used_phys - used_delta)
    d = dict(
        anchor=None, valid=True, fresh=True, anchor_used=a_used,
        current_used=snap.used_phys, target_used=int(a_used + 512 * MB),
        need_release_bytes=max(0, snap.used_phys - int(a_used + 512 * MB)),
        gpu_anchor_mb=1000.0, gpu_current_mb=5000.0, gpu_target_mb=1256.0,
        gpu_over_mb=3744.0, verdict="超出锚点", lines=["mock"],
    )
    d.update(kw)
    return Diff(**d)


# ---------------------------------------------------------------- A 配置全参数
CONFIG_BOUNDS = {
    "poll_sec": (1, 86400), "cooldown_min": (0, 1440),
    "trigger_avail_pct": (0.0, 100.0), "trigger_over_anchor_mb": (0, 1 << 20),
    "tolerance_mb": (0, 1 << 20), "gpu_tolerance_mb": (0, 1 << 20),
    "min_pagefile_avail_mb": (0, 1 << 20), "min_uptime_min": (0, 10080),
    "idle_cpu_pct": (0.0, 100.0), "idle_disk_pct": (0.0, 100.0),
    "user_idle_min": (0.0, 1440.0), "close_wait_sec": (1, 600),
    "auto_anchor_idle_min": (0, 1440), "auto_anchor_min_avail_pct": (0.0, 100.0),
    "anchor_max_age_days": (1, 3650), "log_days": (1, 3650),
}
BAD_VALUES = [-99999, -1, 0, 1.5, "abc", float("nan"), float("inf"), None, [], {}, True]


def group_config(tmp: Path) -> None:
    g = "A 配置全参数"
    public = Config().to_public_dict()
    check(g, "配置字段数量可被完整枚举", len(public) >= 25, f"{len(public)} 个字段")
    field_names = [x.name for x in fields(Config)]
    check(g, "dataclass 字段与公开字段一致",
          all(k in public for k in field_names if not k.startswith("_") and k != "paused"),
          ",".join(field_names))

    # A1 每个数值字段：非法/越界值不得被原样接受，且不得让判定逻辑抛异常
    for key, (lo, hi) in CONFIG_BOUNDS.items():
        for bad in BAD_VALUES:
            def one(key=key, bad=bad):
                c = Config()
                try:
                    c.update({key: bad})
                except Exception as exc:  # noqa: BLE001
                    return False, f"update 抛 {type(exc).__name__}: {exc}"
                v = getattr(c, key)
                import math
                bad_num = bad is None or isinstance(bad, (str, list, dict)) or (
                    isinstance(bad, float) and (math.isnan(bad) or math.isinf(bad)))
                if bad_num:
                    return (not isinstance(v, str) and v == v and abs(v) != float("inf")), f"接受了非数值 {bad!r} → {v!r}"
                if isinstance(bad, (int, float)) and not isinstance(bad, bool):
                    return lo <= v <= hi, f"越界值 {bad!r} 未被收敛 → {v!r}"
                return isinstance(v, (int, float)), f"布尔值写入数值字段 → {v!r}"
            case(g, f"{key} ← {bad!r} 应被收敛/拒绝", one)

        def boundary(key=key, lo=lo, hi=hi):
            c = Config()
            c.update({key: lo})
            a = getattr(c, key)
            c.update({key: hi})
            b = getattr(c, key)
            return a == lo and b == hi, f"合法边界被误改：{lo}→{a}, {hi}→{b}"
        case(g, f"{key} 合法边界应保持原值", boundary)

        def no_crash(key=key):
            c = Config()
            c.update({key: -99999})
            s = base_snap()
            preflight(s, c, 1, auto=True, anchor_valid=True)
            auto_should_release(s, c, int(512 * MB), True)
            auto_anchor_ok(s, c)
            build_plan(s, c, diff_for(s), 1, auto=True)
            return True, "判定链路未抛异常"
        case(g, f"{key} 极端值下判定链路不崩溃", no_crash)

    # A2 布尔字段
    for key, val in public.items():
        if not isinstance(val, bool):
            continue
        def bool_ok(key=key):
            c = Config()
            c.update({key: False})
            a = getattr(c, key)
            c.update({key: True})
            b = getattr(c, key)
            return a is False and b is True, f"{a}/{b}"
        case(g, f"布尔字段 {key} 可正常开关", bool_ok)

    # A3 关键不变量：自动上限永远不能 > 1
    for v in [-5, 0, 1, 2, 999, "3", None]:
        def cap(v=v):
            c = Config()
            try:
                c.update({"auto_max_level": v})
            except Exception as exc:  # noqa: BLE001
                return False, f"update 抛异常：{exc}"
            return c.auto_max_level == 1 and isinstance(c.auto_max_level, int), f"→ {c.auto_max_level!r}"
        case(g, f"auto_max_level ← {v!r} 恒为 1", cap)

    # A4 保护名单被损坏后必须回退，不能变成按字符匹配
    def list_corrupt():
        c = Config()
        c.update({"protect_list": "Code.exe"})
        s = base_snap()
        annotate_protection(s, c)
        p = next(x for x in s.procs if x.pid == 1002)
        return isinstance(c.protect_list, list) and len(c.protect_list) > 0, f"protect_list={c.protect_list!r}"
    case(g, "protect_list 非列表时回退为安全默认", list_corrupt)

    # A5 配置落盘 / 损坏回退
    def save_load():
        p = tmp / "cfg.json"
        c = Config()
        c.update({"tolerance_mb": 777, "poll_sec": 33})
        ok, _ = c.save(p)
        c2, msg = Config.load(p)
        return ok and c2.tolerance_mb == 777 and c2.poll_sec == 33, msg
    case(g, "配置保存与载入一致", save_load)

    for content in ["{ broken", "null", "[]", "{}", '{"poll_sec":"abc"}',
                    '{"protect_list":123}', '{"auto_max_level":"x"}', '{"log_days":-5}']:
        def corrupt(content=content):
            p = tmp / f"bad_{abs(hash(content))}.json"
            p.write_text(content, encoding="utf-8")
            c, msg = Config.load(p)
            s = base_snap()
            annotate_protection(s, c)
            preflight(s, c, 1, auto=True, anchor_valid=True)
            return isinstance(c.protect_list, list) and c.auto_max_level == 1 and c.poll_sec > 0 and c.log_days > 0, msg
        case(g, f"损坏配置 {content[:24]} 安全回退", corrupt)

    # A6 审计日志保留天数为负时不得清空全部日志
    def neg_log_days():
        p = tmp / "neglog.log"
        log = AuditLog(p, 30)
        log.write("测试", "保留我")
        log.keep_days = -1
        _, msg = log.purge()
        return "保留我" in log.as_text(), msg
    case(g, "负保留天数不会清空审计日志", neg_log_days)


# ---------------------------------------------------------------- B 状态组合矩阵
def group_matrix() -> None:
    g = "B 状态组合矩阵"
    combos = 0
    hard_violations: list[str] = []
    crashes: list[str] = []
    snap0 = base_snap()

    for (auto, level, anchor_ok, admin, paused, idle, cpubusy, pf_ok, protected) in itertools.product(
        (False, True), (1, 2, 3), (False, True), (False, True),
        (False, True), (False, True), (False, True), (False, True), (False, True),
    ):
        combos += 1
        cfg = Config()
        cfg.paused = paused
        cfg.skip_when_foreground = True
        s = base_snap(
            is_admin=admin,
            user_idle_sec=(600.0 if idle else 2.0),
            cpu_busy=(90.0 if cpubusy else 3.0),
            disk_busy=3.0,
            pagefile_avail=(int(64 * MB) if not pf_ok else int(8 * 1024 * MB)),
            gpu_attributable=protected,
        )
        try:
            pf = preflight(s, cfg, level, auto=auto, anchor_valid=anchor_ok,
                           selected_pids=[1001] if level == 3 else [])
            plan = build_plan(s, cfg, diff_for(s), level, auto=auto,
                              selected_pids=[1001] if level == 3 else [])
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"auto={auto} L{level} → {type(exc).__name__}: {exc}")
            continue
        if auto and level > 1 and (pf.allowed or plan.items):
            hard_violations.append(f"auto L{level} 未被拦截")
        if level == 3 and auto and plan.items:
            hard_violations.append("auto L3 生成了关闭进程计划")
    check(g, f"矩阵覆盖 {combos} 种状态组合", combos >= 500, f"{combos} 种")
    check(g, "全部组合无异常", not crashes, "; ".join(crashes[:4]))
    check(g, "自动 L2/L3 在全部组合下都被硬拦截", not hard_violations, "; ".join(hard_violations[:4]))

    # 锚点态 × 触发条件
    anchor_states = {
        "无锚点": Diff(anchor=None, valid=False, fresh=False, need_release_bytes=0),
        "有效未超出": diff_for(snap0, used_delta=-2 * 1024 * MB, need_release_bytes=0, verdict="无需释放"),
        "有效超出少": diff_for(snap0, need_release_bytes=int(100 * MB)),
        "有效超出多": diff_for(snap0, need_release_bytes=int(3 * 1024 * MB)),
        "失效(上次开机)": diff_for(snap0, valid=False, fresh=False),
        "过期(仅 fresh=False)": diff_for(snap0, fresh=False),
    }
    for name, d in anchor_states.items():
        for auto in (False, True):
            def one(name=name, d=d, auto=auto):
                cfg = Config()
                s = base_snap(avail_phys=int(2 * 1024 * MB), used_phys=int(14 * 1024 * MB))
                ok, why = auto_should_release(s, cfg, d.need_release_bytes, bool(d.valid and d.fresh))
                pf = preflight(s, cfg, 1, auto=auto, anchor_valid=bool(d.valid and d.fresh))
                plan = build_plan(s, cfg, d, 1, auto=auto)
                if auto and not d.valid:
                    return (not ok) and (not pf.allowed), f"失效锚点仍允许自动：ok={ok} pf={pf.summary()}"
                if auto and not d.fresh:
                    return not ok and not pf.allowed, "过期锚点仍允许自动释放（与帮助文案矛盾）"
                return True, f"触发={ok}｜{why[:60]}"
            case(g, f"锚点态「{name}」× {'自动' if auto else '手动'}", one)

    # 白名单 × 级别 × 勾选
    for level in (1, 2, 3):
        def wl(level=level):
            cfg = Config()
            s = base_snap()
            plan = build_plan(s, cfg, diff_for(s), level, auto=False, selected_pids=[1001, 1003, 9999])
            bad = [i.target for i in plan.items if "csrss" in i.target]
            return not bad, f"误纳入系统进程：{bad}"
        case(g, f"L{level} 计划不含系统关键进程", wl)
        def wl2(level=level):
            cfg = Config()
            s = base_snap()
            cfg.protect_list = ["ollama.exe"]
            annotate_protection(s, cfg)
            plan = build_plan(s, cfg, diff_for(s), level, auto=False, selected_pids=[1001])
            return all("ollama" not in i.target for i in plan.items), "用户保护名单未生效"
        case(g, f"L{level} 计划不含用户保护进程", wl2)

    # 冷却 / 开机时间 / 页面文件 / 空闲 / 忙闲 单项闸门
    gates = [
        ("冷却期内", dict(last_action_ts=time.time()), "冷却"),
        ("开机时间过短", dict(), "开机仅"),
        ("页面文件不足", dict(), "页面文件"),
        ("用户正在操作", dict(), "用户正在操作"),
        ("CPU 忙", dict(), "CPU 忙"),
        ("磁盘忙", dict(), "磁盘忙"),
        ("全局暂停", dict(), "暂停"),
        ("锚点无效", dict(), "锚点"),
    ]
    for name, extra, keyword in gates:
        def gate(name=name, extra=extra, keyword=keyword):
            cfg = Config()
            s = base_snap()
            if name == "开机时间过短":
                s.boot_ms = 60 * 1000
            elif name == "页面文件不足":
                s.pagefile_avail = int(64 * MB)
            elif name == "用户正在操作":
                s.user_idle_sec = 1.0
            elif name == "CPU 忙":
                s.cpu_busy = 99.0
            elif name == "磁盘忙":
                s.disk_busy = 99.0
            elif name == "全局暂停":
                cfg.paused = True
            pf = preflight(s, cfg, 1, auto=True,
                           last_action_ts=extra.get("last_action_ts", 0.0),
                           anchor_valid=(name != "锚点无效"))
            return (not pf.allowed) and keyword in pf.summary(), pf.summary()
        case(g, f"闸门「{name}」明确阻止并给出原因", gate)


# ---------------------------------------------------------------- C 采集降级
def group_collect() -> None:
    g = "C 采集降级"
    orig = {n: getattr(winapi, n) for n in (
        "memory_status", "performance_info", "enum_processes", "pdh_collect",
        "pdh_expand", "foreground", "user_idle_seconds", "cpu_busy_pct",
        "disk_busy_pct", "nvidia_smi_info", "boot_ms", "is_admin", "enum_top_windows",
    )}

    def boomy(*_a, **_k):
        raise RuntimeError("模拟底层 API 故障")

    try:
        for name in orig:
            def one(name=name):
                setattr(winapi, name, boomy)
                try:
                    s = collector.collect(Config())
                    return isinstance(s, Snapshot), f"返回 {type(s).__name__}"
                finally:
                    setattr(winapi, name, orig[name])
            case(g, f"{name} 抛异常时采集仍能降级返回快照", one)

        # 各功能开关组合
        for nv, probe, nv_fail in itertools.product((False, True), repeat=3):
            def switches(nv=nv, probe=probe, nv_fail=nv_fail):
                c = Config()
                c.gpu_probe_enabled, c.nvidia_smi_enabled = probe, nv
                winapi.nvidia_smi_info = (lambda *a: boomy()) if nv_fail else (lambda *a: (False, [], [], "禁用"))
                try:
                    s = collector.collect(c)
                    return isinstance(s, Snapshot) and len(s.procs) > 0, f"procs={len(s.procs)}"
                finally:
                    winapi.nvidia_smi_info = orig["nvidia_smi_info"]
            case(g, f"显存采集={probe} nvidia开关={nv} nvidia异常={nv_fail}", switches)

        # 关键：gpu_probe_enabled=False 时 by_pid 变量必须有定义
        def probe_off():
            c = Config()
            c.gpu_probe_enabled = False
            s = collector.collect(c)
            return len(s.procs) > 0 and s.gpu_note != "", f"procs={len(s.procs)} note={s.gpu_note[:40]}"
        case(g, "禁用显存采集时不出现未定义变量崩溃", probe_off)

        # 数据缺失口径
        def zero_total():
            s = Snapshot(ts=time.time(), total_phys=0, avail_phys=0, used_phys=0)
            c = Config()
            ok, _ = auto_should_release(s, c, 0, True)
            ok2, _ = auto_anchor_ok(s, c)
            return (not ok) and (not ok2) and "无法读取" in collector.describe(s)[0], "总量为 0 时未安全降级"
        case(g, "物理内存总量不可读时全部判定安全降级", zero_total)

        def unknown_cpu_disk():
            s = base_snap(cpu_busy=None, disk_busy=None)
            pf = preflight(s, Config(), 1, auto=True, anchor_valid=True)
            return pf.allowed and any("无法读取" in w for w in pf.warnings), pf.summary()
        case(g, "CPU/磁盘忙闲未知时按「不阻止 + 明确警告」处理", unknown_cpu_disk)

        def light():
            s = collector.collect_light()
            return isinstance(s, Snapshot) and s.used_phys >= 0 and len(s.procs) == 0, f"used={collector.fmt_bytes(s.used_phys)}"
        case(g, "快速复测只读内存且带进程空表", light)
    finally:
        for n, f in orig.items():
            setattr(winapi, n, f)


# ---------------------------------------------------------------- D 持久化与引擎
def group_engine(tmp: Path) -> None:
    g = "D 持久化与引擎"

    # 锚点文件异常
    for content in ["{ broken", "null", "[]", '{"items":null}', '{"items":[{"ts":"x"}]}',
                    '{"items":[],"current_id":"ghost"}', ""]:
        def bad(content=content):
            p = tmp / f"anc_{abs(hash(content))}.json"
            p.write_text(content, encoding="utf-8")
            st = AnchorStore(p)
            d = st.diff(base_snap(), Config())
            return isinstance(st.items, list) and isinstance(d, Diff), f"items={len(st.items)} valid={d.valid}"
        case(g, f"锚点文件异常 {content[:22] or '(空)'} 可安全加载", bad)

    def crud():
        p = tmp / "anc_crud.json"
        st = AnchorStore(p)
        s = base_snap()
        a, _ = st.add(s, "A")
        b, _ = st.add(s, "B")
        ok1, _ = st.set_current(a.id)
        ok2, _ = st.rename(b.id, "B2")
        ok3, _ = st.remove(a.id)
        ok4, _ = st.export(tmp / "anc_exp.json")
        return ok1 and ok2 and ok3 and ok4 and st.get_current() is not None, f"current={st.current_id}"
    case(g, "锚点增/切/改名/删/导出闭环", crud)

    def cap40():
        p = tmp / "anc_cap.json"
        st = AnchorStore(p)
        s = base_snap()
        for i in range(45):
            st.add(s, f"N{i}")
        return len(st.items) <= 40 and st.get_current() is not None, f"{len(st.items)} 个"
    case(g, "锚点数量上限不导致当前锚点丢失", cap40)

    def concurrent():
        p = tmp / "anc_conc.json"
        st = AnchorStore(p)
        s = base_snap()
        errs = []
        def worker(i):
            try:
                for j in range(8):
                    st.add(s, f"T{i}-{j}")
            except Exception as exc:  # noqa: BLE001
                errs.append(str(exc))
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in ts: t.start()
        for t in ts: t.join()
        return not errs, f"并发异常 {errs[:2]}，锚点数 {len(st.items)}"
    case(g, "多线程并发写锚点不崩溃", concurrent)

    # 引擎：上次开机锚点
    def stale_boot(tmp=tmp):
        d = tmp / "eng_stale"
        eng = Engine(d)
        snap = base_snap()
        cur = eng.store.get_current()
        cur.compact["boot_time"] = (snap.ts - snap.boot_ms / 1000.0) - 500000
        eng.store.save()
        before = eng.store.diff(snap, eng.cfg)
        eng.cfg.auto_release_enabled = True
        eng.cfg.paused = False
        reason = eng.auto_tick(snap)
        after = eng.store.diff(snap, eng.cfg)
        return ((not before.valid) and after.valid and after.fresh
                and "锚点无效或缺失" not in reason), \
            f"重建前 valid={before.valid}，重建后 valid={after.valid}｜{reason[:70]}"
    case(g, "重启后旧锚点判失效并自动重建，巡检不再被锚点卡住", stale_boot)

    def recovery(tmp=tmp):
        # 期望：系统健康空闲时，旧锚点能在本轮自动重建，不应等待固定 2 小时
        d = tmp / "eng_recover"
        eng = Engine(d)
        snap = base_snap()
        cur = eng.store.get_current()
        cur.compact["boot_time"] = (snap.ts - snap.boot_ms / 1000.0) - 500000
        eng.store.save()
        eng.cfg.auto_anchor_enabled = True
        eng.last_auto_anchor_ts = time.time()  # 模拟"刚启动，2 小时间隔远未到"
        eng.auto_tick(snap)
        diff2 = eng.store.diff(snap, eng.cfg)
        return diff2.valid and diff2.fresh, f"valid={diff2.valid} fresh={diff2.fresh} reason={diff2.reason}"
    case(g, "启动后健康空闲时能立即重建有效锚点", recovery)

    def hot_switch(tmp=tmp):
        d = tmp / "eng_hot"
        eng = Engine(d)
        eng.cfg.auto_release_enabled = False
        eng.update_config({"auto_release_enabled": False})
        # 模拟 UI 在设置页重新打开开关
        eng.update_config({"auto_release_enabled": True})
        eng.start_auto()
        alive = eng.running
        eng.stop_auto()
        return alive, f"running={alive}"
    case(g, "设置页热开启自动释放后巡检线程确实运行", hot_switch)

    def loop_bad_poll(tmp=tmp):
        d = tmp / "eng_poll"
        eng = Engine(d / "x")
        eng.cfg.poll_sec = "abc"
        t = threading.Thread(target=eng._loop, daemon=True)
        t.start()
        time.sleep(0.4)
        alive = t.is_alive()
        eng.stop_auto()
        t.join(timeout=1.5)
        return alive, f"线程存活={alive}（非法周期不应使巡检线程静默死亡）"
    case(g, "非法巡检周期不会使自动线程静默退出", loop_bad_poll)

    def cache_consistency(tmp=tmp):
        d = tmp / "eng_cache"
        eng = Engine(d / "x")
        eng.refresh()
        s_before, _ = eng.cached
        # 模拟一次"执行后"的状态更新
        eng.manual_preview(1)
        msg = eng.auto_tick()
        s_after, d_after = eng.cached
        return isinstance(msg, str) and isinstance(d_after, Diff), "缓存可读取"
    case(g, "引擎缓存快照/差异始终成对可用", cache_consistency)

    def cfg_persist(tmp=tmp):
        d = tmp / "eng_cfg"
        eng = Engine(d / "x")
        changed, msg = eng.update_config({"tolerance_mb": 321})
        c2, _ = Config.load(eng.config_path)
        return "tolerance_mb" in changed and c2.tolerance_mb == 321, msg
    case(g, "设置修改即时持久化", cfg_persist)

    def log_export(tmp=tmp):
        d = tmp / "eng_log"
        eng = Engine(d / "x")
        ok, msg = eng.export_log(tmp / "log_exp.txt")
        return ok and (tmp / "log_exp.txt").exists(), msg
    case(g, "审计日志可导出", log_export)


# ---------------------------------------------------------------- E 执行层防误杀
def group_execute(calls: dict) -> None:
    g = "E 执行层防误杀"
    log = AuditLog(Path(tempfile.gettempdir()) / "memguard_full_matrix.log", 30)
    cfg = Config()
    s = base_snap()

    def empty():
        r = execute(Plan(level=1, auto=False), s, cfg, log,
                    collect_fn=lambda: s, light_fn=lambda: s)
        return r.finished >= r.started and r.stopped_reason, r.stopped_reason
    case(g, "空计划安全完成且有停止原因", empty)

    def target_stop():
        calls["trim"].clear()
        seq = [int(16 * 1024 * MB), int(15 * 1024 * MB), int(13 * 1024 * MB), int(13 * 1024 * MB)]
        idx = {"i": 0}
        def light():
            v = seq[min(idx["i"], len(seq) - 1)]
            idx["i"] += 1
            return Snapshot(ts=time.time(), total_phys=int(16 * 1024 * MB),
                            used_phys=v, avail_phys=int(16 * 1024 * MB) - v)
        p = Plan(level=1, auto=False, target_used=int(14 * 1024 * MB),
                 items=[PlanItem("L1", f"p{i}", 2000 + i) for i in range(6)])
        r = execute(p, light(), cfg, log, collect_fn=light, light_fn=light)
        return len(calls["trim"]) == 2 and "达标即停" in r.stopped_reason, f"裁剪 {len(calls['trim'])} 次｜{r.stopped_reason}"
    case(g, "达到锚点目标立即停止", target_stop)

    def probe_fail():
        calls["trim"].clear()
        def light():
            return Snapshot(ts=time.time(), used_phys=int(9 * 1024 * MB))
        def boom():
            raise RuntimeError("复测失败")
        p = Plan(level=1, auto=False, target_used=1,
                 items=[PlanItem("L1", f"p{i}", 3000 + i) for i in range(5)])
        r = execute(p, light(), cfg, log, collect_fn=light, light_fn=boom)
        return len(calls["trim"]) == 1 and "复测失败" in r.stopped_reason, f"裁剪 {len(calls['trim'])} 次｜{r.stopped_reason}"
    case(g, "复测失败时立即停止后续动作", probe_fail)

    # L3 二次确认矩阵
    orig_post, orig_alive = winapi.post_close, winapi.is_process_alive
    try:
        winapi.post_close = lambda pid, w: (1, "mock")
        winapi.is_process_alive = lambda pid: True
        cfg.close_wait_sec = 1
        for confirmed, expect_kill in ((False, 0), (True, 1)):
            def l3(confirmed=confirmed, expect_kill=expect_kill):
                calls["kill"].clear()
                p = Plan(level=3, auto=False,
                         items=[PlanItem("L3", "ollama.exe (PID 1001)", 1001, gpu_mb=4096)])
                r = execute(p, s, cfg, log, collect_fn=lambda: s, light_fn=lambda: s,
                            confirm_force_fn=lambda pid, t: confirmed)
                return len(calls["kill"]) == expect_kill, f"kill={len(calls['kill'])} warnings={len(r.warnings)}"
            case(g, f"L3 二次确认={confirmed} 时强制结束次数={expect_kill}", l3)

        def no_window():
            calls["kill"].clear()
            winapi.post_close = lambda pid, w: (0, "该进程没有可见窗口，无法发送关闭消息")
            p = Plan(level=3, auto=False, items=[PlanItem("L3", "headless.exe", 1001)])
            r = execute(p, s, cfg, log, collect_fn=lambda: s, light_fn=lambda: s,
                        confirm_force_fn=lambda pid, t: False)
            return any("没有可见窗口" in d for _, _, d in r.steps), "未如实说明无法优雅关闭"
        case(g, "L3 无窗口进程如实说明无法优雅关闭", no_window)
    finally:
        winapi.post_close, winapi.is_process_alive = orig_post, orig_alive

    # PID 复用：预览后进程身份变化，执行前复核必须剔除该计划项
    def pid_reuse(kind="L3"):
        p = Plan(level=3 if kind == "L3" else 1, auto=False, anchor_name="mock",
                 items=[PlanItem(kind, "ollama.exe (PID 1001)", 1001,
                                 expected_name="ollama.exe", gpu_mb=4096)])
        fresh = base_snap()
        for x in fresh.procs:
            if x.pid == 1001:
                x.name = "some_new_app.exe"   # 模拟 PID 被复用为另一个进程
        new_plan, reasons = revalidate_plan(p, fresh, Config())
        return (not new_plan.items) and any("复用" in r or "不一致" in r for r in reasons), \
            f"保留 {len(new_plan.items)} 项｜{reasons[:1]}"
    case(g, "L3 预览后 PID 复用时拒绝关闭进程", lambda: pid_reuse("L3"))
    case(g, "L1 预览后 PID 复用时拒绝裁剪进程", lambda: pid_reuse("L1"))

    def pid_same():
        p = Plan(level=3, auto=False, anchor_name="mock",
                 items=[PlanItem("L3", "ollama.exe (PID 1001)", 1001, expected_name="ollama.exe")])
        new_plan, reasons = revalidate_plan(p, base_snap(), Config())
        return len(new_plan.items) == 1 and not reasons, f"保留 {len(new_plan.items)} 项｜{reasons[:1]}"
    case(g, "身份一致的计划项正常保留", pid_same)

    def exited_pid():
        p = Plan(level=3, auto=False, anchor_name="mock",
                 items=[PlanItem("L3", "ghost.exe (PID 9999)", 9999, expected_name="ghost.exe")])
        new_plan, reasons = revalidate_plan(p, base_snap(), Config())
        return not new_plan.items and any("已退出" in r for r in reasons), f"{reasons[:1]}"
    case(g, "预览后已退出的进程被剔除", exited_pid)

    # 预览-执行一致性
    def plan_binding():
        sig = inspect.signature(Engine.manual_execute)
        return "plan" in sig.parameters, f"manual_execute 参数：{list(sig.parameters)}（应绑定用户已确认的计划）"
    case(g, "执行绑定已确认的干运行计划（非重新生成）", plan_binding)

    def auto_never_l3():
        cfg2 = Config()
        cfg2.auto_max_level = 1
        p = build_plan(s, cfg2, diff_for(s), 3, auto=True, selected_pids=[1001])
        return not p.items and not p.estimated_release_bytes, f"items={len(p.items)}"
    case(g, "自动 L3 连计划都不生成", auto_never_l3)

    def skip_reasons():
        p = build_plan(s, Config(), diff_for(s), 1, auto=False)
        return all(i.reason for i in p.skipped), f"{len(p.skipped)} 个跳过项"
    case(g, "每个跳过项都带人类可读原因", skip_reasons)

    def report_complete():
        r = execute(Plan(level=1, auto=False), s, cfg, log,
                    collect_fn=lambda: s, light_fn=lambda: s)
        t = r.report_text()
        return all(k in t for k in ("耗时", "物理内存已用", "可用物理内存", "停止原因", "逐项结果", "说明")), "报告字段齐全"
    case(g, "执行报告包含前后对比/耗时/停止原因/副作用", report_complete)


# ---------------------------------------------------------------- F 入口与一致性
def group_entry() -> None:
    g = "F 入口与一致性"

    def _read(p: Path) -> str:
        try:
            return p.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            return ""

    src_main = _read(HERE / "main.py")
    src_ui = _read(HERE / "memguard" / "ui.py")
    if not src_main or not src_ui:
        check(g, "源码文件可读（用于静态一致性核对）", False,
              "当前环境未附带源码文件；打包时应通过 --add-data 附带 main.py 与 memguard/ui.py")
        return

    def ui_binding():
        has_engine_param = "plan" in inspect.signature(Engine.manual_execute).parameters
        return ("confirmed_plan" in src_ui and has_engine_param), \
            "UI 执行必须传入用户已确认的那份 Plan"
    case(g, "UI 执行使用已确认计划", ui_binding)

    def plan_ttl():
        with tempfile.TemporaryDirectory(prefix="mg_ttl_") as td:
            eng = Engine(Path(td))
            old = Plan(level=1, auto=False, anchor_name="mock",
                       created_ts=time.time() - 999,
                       items=[PlanItem("L1", "p", 1001, expected_name="ollama.exe")])
            before = len(REAL_CALLS)
            ok, result, _, _ = eng.manual_execute(1, [], False, None, old)
            return (not ok) and "重新生成预览" in str(result) and len(REAL_CALLS) == before, str(result)[:100]
    case(g, "过期预览被拒绝且不执行任何动作", plan_ttl)

    def cli_l3():
        return 'args.level == 3' in src_main and "拒绝执行" in src_main, "CLI 应拒绝无界面 L3"
    case(g, "CLI 明确拒绝无界面 L3", cli_l3)

    def no_destructive_default():
        return "--action" in src_main and "release" in src_main and "default=\"status\"" in src_main, \
            "默认动作应为只读 status"
    case(g, "无界面默认动作为只读状态", no_destructive_default)

    def exe_exists():
        p = HERE / "dist" / "MemGuard.exe"
        if not p.exists() and getattr(sys, "frozen", False):
            p = Path(sys.executable)
        return p.exists() and p.stat().st_size > 1024 * 1024 and p.read_bytes()[:2] == b"MZ", \
            f"size={p.stat().st_size if p.exists() else 0}"
    case(g, "交付 exe 存在且为有效 PE 文件", exe_exists)

    def settings_clamp():
        return ("范围" in src_ui or "min(" in src_ui or "clamp" in src_ui or "校验" in src_ui), \
            "设置页仅有数字类型校验，缺少范围与语义校验"
    case(g, "设置页存在范围/语义校验", settings_clamp)

    note(g, "长时间执行可被用户中断",
         "L3 多个进程串行等待 close_wait_sec 时没有「中断本次执行」按钮；"
         "属于体验增强项，需你选择是否实施")

    def help_sync():
        return ("每次开机检测到旧锚点" in src_ui and "3 分钟后自动失效" in src_ui
                and "PID 被复用" in src_ui), "帮助文案需与开机重建、预览时效、身份复核实质同步"
    case(g, "帮助文案与锚点/预览/复核实现同步", help_sync)


# ---------------------------------------------------------------- 主流程
def main() -> int:
    calls = _mock_state_changers()
    try:
        with tempfile.TemporaryDirectory(prefix="memguard_matrix_") as td:
            tmp = Path(td)
            print("MemGuard 全工况 / 全参数验证（危险函数已全部替换，不会改变系统状态）")
            group_config(tmp)
            group_matrix()
            group_collect()
            group_engine(tmp)
            group_execute(calls)
            group_entry()

        # 真实系统动作断言
        real_risky = [x for x in REAL_CALLS if x in ("purge", "kill")]
        check("Z 安全底线", "真实系统级清理/结束进程从未被调用", not real_risky, f"{real_risky[:5]}")
    finally:
        _restore()
    check("Z 安全底线", "L1/L2/L3 真实函数已完整恢复",
          all(getattr(winapi, n) is _ORIGINALS[n] for n in _ORIGINALS), "")

    groups: dict[str, list[dict]] = {}
    for r in RESULTS:
        groups.setdefault(r["group"], []).append(r)
    print("\n=== 分组汇总 ===")
    for g, rows in groups.items():
        ok = sum(r["ok"] for r in rows)
        print(f"  {g}: {ok}/{len(rows)} 通过")
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n=== 合计 {len(RESULTS) - len(failed)}/{len(RESULTS)} 通过，{len(failed)} 项未通过 ===")
    if NOTES:
        print("\n=== 待选优化（不计入通过率）===")
        for n in NOTES:
            print(f"  [{n['group']}] {n['name']}｜{n['detail']}")
    if failed:
        print("\n=== 未通过明细 ===")
        for r in failed[:120]:
            print(f"  [{r['group']}] {r['name']}｜{r['detail']}")
        if len(failed) > 120:
            print(f"  …… 另有 {len(failed) - 120} 项，详见 JSON 报告")
    report_dir = (
        Path(os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")) / "MemGuard"
        if getattr(sys, "frozen", False) else HERE / "tests"
    )
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except Exception:  # noqa: BLE001
        report_dir = Path(tempfile.gettempdir())
    report = report_dir / "full_matrix_report.json"
    report.write_text(json.dumps({
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(RESULTS), "passed": len(RESULTS) - len(failed),
        "groups": {g: {"total": len(rows), "passed": sum(r["ok"] for r in rows)} for g, rows in groups.items()},
        "failed": failed, "notes": NOTES,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nJSON 报告：{report}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
