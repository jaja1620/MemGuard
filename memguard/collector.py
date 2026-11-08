"""统一采集：内存、显存、进程、系统空闲状态 —— 生成一份 Snapshot。

采集遵守「不伪造数据」原则：任何取不到的指标都记为 None 并附带说明，
由 UI 显示「无法读取」而不是显示 0。
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from . import winapi
from .config import Config

MB = 1024.0 * 1024.0
GB = 1024.0 * MB


def fmt_bytes(n: float | None, unit: str = "auto") -> str:
    if n is None:
        return "无法读取"
    if n < 0:
        return "-"
    if unit == "MB" or (unit == "auto" and n < GB):
        return f"{n / MB:,.0f} MB"
    return f"{n / GB:,.2f} GB"


def fmt_mb(n: float | None) -> str:
    return "无法读取" if n is None else f"{n:,.0f} MB"


@dataclass
class ProcInfo:
    pid: int
    name: str
    ws: int = 0
    private: int = 0
    has_window: bool = False
    title: str = ""
    accessible: bool = True
    gpu_mb: float = 0.0
    gpu_source: str = ""
    protected: bool = False
    protect_reason: str = ""

    def label(self) -> str:
        return f"{self.name or '<权限不足>'} (PID {self.pid})"


@dataclass
class GpuInfo:
    key: str
    name: str
    dedicated_used_mb: float = 0.0
    dedicated_total_mb: float | None = None
    shared_used_mb: float = 0.0
    shared_total_mb: float | None = None
    source: str = ""

    def usage_text(self) -> str:
        if self.dedicated_total_mb:
            pct = self.dedicated_used_mb / self.dedicated_total_mb * 100.0
            return f"{self.dedicated_used_mb:,.0f} / {self.dedicated_total_mb:,.0f} MB（{pct:.0f}%）"
        return f"{self.dedicated_used_mb:,.0f} MB（总量未知）"


@dataclass
class Snapshot:
    ts: float = 0.0
    boot_ms: int = 0
    total_phys: int = 0
    avail_phys: int = 0
    used_phys: int = 0
    load_pct: int = 0
    commit_total: int = 0
    commit_limit: int = 0
    pagefile_total: int = 0
    pagefile_avail: int = 0
    system_cache: int = 0
    standby_bytes: int | None = None
    standby_note: str = ""
    procs: list[ProcInfo] = field(default_factory=list)
    gpus: list[GpuInfo] = field(default_factory=list)
    gpu_note: str = ""
    gpu_attributable: bool = False
    foreground_pid: int = 0
    foreground_title: str = ""
    user_idle_sec: float = -1.0
    cpu_busy: float | None = None
    disk_busy: float | None = None
    is_admin: bool = False
    notes: list[str] = field(default_factory=list)

    def gpu_used_total(self) -> float:
        return sum(g.dedicated_used_mb for g in self.gpus)

    def top_procs(self, n: int = 15) -> list[ProcInfo]:
        return sorted(self.procs, key=lambda p: p.ws, reverse=True)[:n]

    def to_dict(self) -> dict:
        return asdict(self)

    def compact(self) -> dict:
        """锚点保存用的精简快照：数值齐全，进程只留前 15 名，避免文件膨胀。"""
        return {
            "ts": self.ts, "boot_ms": self.boot_ms,
            "boot_time": self.ts - self.boot_ms / 1000.0,
            "total_phys": self.total_phys, "avail_phys": self.avail_phys,
            "used_phys": self.used_phys, "load_pct": self.load_pct,
            "commit_total": self.commit_total, "commit_limit": self.commit_limit,
            "pagefile_total": self.pagefile_total, "pagefile_avail": self.pagefile_avail,
            "system_cache": self.system_cache, "standby_bytes": self.standby_bytes,
            "gpu": [asdict(g) for g in self.gpus],
            "gpu_used_total_mb": self.gpu_used_total(),
            "gpu_attributable": self.gpu_attributable,
            "top_procs": [
                {"pid": p.pid, "name": p.name, "ws": p.ws, "private": p.private, "gpu_mb": p.gpu_mb}
                for p in self.top_procs(15)
            ],
            "is_admin": self.is_admin,
        }


# ---------------------------------------------------------------- 显存

def _gpu_from_pdh(notes: list[str]) -> tuple[list[GpuInfo], dict[int, float], str]:
    gpus: list[GpuInfo] = []
    by_pid: dict[int, float] = {}
    ded_paths, note1 = winapi.pdh_expand(r"\GPU Adapter Memory(*)\Dedicated Usage")
    shared_paths, note2 = winapi.pdh_expand(r"\GPU Adapter Memory(*)\Shared Usage")
    if not ded_paths and not shared_paths:
        notes.append(f"PDH 无 GPU Adapter Memory 计数器（{note1}；{note2}）")
        return [], by_pid, "PDH 无显存计数器"

    vals, _ = winapi.pdh_collect(ded_paths + shared_paths, settle=0.25)
    instances: dict[str, GpuInfo] = {}

    def inst_of(path: str) -> str:
        m = re.search(r"\((.*?)\)", path)
        return m.group(1) if m else path

    for path in ded_paths:
        v = vals.get(path)
        inst = inst_of(path)
        g = instances.setdefault(inst, GpuInfo(key=inst, name=inst, source="PDH"))
        if v is not None:
            g.dedicated_used_mb += v / MB
    for path in shared_paths:
        v = vals.get(path)
        inst = inst_of(path)
        g = instances.setdefault(inst, GpuInfo(key=inst, name=inst, source="PDH"))
        if v is not None:
            g.shared_used_mb += v / MB

    proc_paths, note3 = winapi.pdh_expand(r"\GPU Process Memory(*)\Local Usage")
    if proc_paths:
        pvals, _ = winapi.pdh_collect(proc_paths, settle=0.20)
        for path, v in pvals.items():
            m = re.search(r"pid_(\d+)", path, re.I)
            if m and v is not None:
                by_pid[int(m.group(1))] = by_pid.get(int(m.group(1)), 0.0) + v / MB
    else:
        notes.append(f"PDH 无 GPU Process Memory 计数器，显存无法按进程归因（{note3}）")

    gpus = [g for g in instances.values() if g.dedicated_used_mb > 0 or g.shared_used_mb > 0]
    return gpus, by_pid, "PDH 计数器（可读取已用显存，总量可能未知）"


def _gpu_collect(cfg: Config, notes: list[str]) -> tuple[list[GpuInfo], dict[int, float], bool, str]:
    nv_ok, nv_gpus, nv_apps, nv_note = winapi.nvidia_smi_info() if cfg.nvidia_smi_enabled else (False, [], [], "已在设置中禁用 nvidia-smi")
    pdh_gpus, pdh_by_pid, pdh_note = _gpu_from_pdh(notes)

    if nv_ok and nv_gpus:
        gpus = [
            GpuInfo(
                key=f"nv{i}", name=g["name"],
                dedicated_used_mb=g["used_mb"], dedicated_total_mb=g["total_mb"],
                shared_used_mb=(pdh_gpus[i].shared_used_mb if i < len(pdh_gpus) else 0.0),
                source="nvidia-smi",
            )
            for i, g in enumerate(nv_gpus)
        ]
        by_pid = {a["pid"]: a["gpu_mb"] for a in nv_apps}
        note = f"显存数据来自 {nv_note}；共享显存由 PDH 补充。"
        if not nv_apps:
            note += " 当前没有 CUDA/计算进程占用显存；图形进程的显存占用不在此列表中。"
        return gpus, by_pid, True, note

    if pdh_gpus:
        # 用 EnumDisplayDevices 的友好名称替换 PDH 的 LUID 实例名（顺序仅供参考）。
        names = winapi.display_adapters()
        for i, g in enumerate(pdh_gpus):
            if i < len(names):
                g.name = names[i]
        # 部分系统「GPU Adapter Memory\Dedicated Usage」恒为 0，但按进程计数器有值：
        # 此时把按进程求和的结果作为专用显存已用，并如实标注来源，绝不显示伪造的 0。
        agg = sum(pdh_by_pid.values())
        dedicated = sum(g.dedicated_used_mb for g in pdh_gpus)
        if dedicated < 1 and agg > 0:
            pdh_gpus[0].dedicated_used_mb = agg
            pdh_gpus[0].source = "PDH 按进程聚合"
            extra = f"；适配器专用计数器读数为 0，已改用「GPU Process Memory 按进程求和」= {agg:,.0f} MB"
        else:
            extra = ""
        note = (
            f"{nv_note}；改用 {pdh_note}{extra}。"
            "专用显存总量无法读取，显卡名称按系统枚举顺序匹配，仅供参考。"
        )
        return pdh_gpus, pdh_by_pid, bool(pdh_by_pid), note

    note = f"{nv_note}；{pdh_note}。当前环境无法读取显存占用，程序不会臆造数值。"
    return [], {}, False, note


# ---------------------------------------------------------------- 主采集

def collect(cfg: Config) -> Snapshot:
    """采集全量快照。

    每个底层调用都独立兜底：某个计数器/驱动异常只让该项显示「无法读取」并写入
    采集说明，绝不让整个界面或自动巡检线程崩掉。
    """
    notes: list[str] = []
    ts = time.time()

    def guard(label: str, fn, default, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{label} 调用异常，按「无法读取」处理：{type(exc).__name__}: {exc}")
            return default

    boot = guard("开机时间", winapi.boot_ms, 0)
    admin = guard("权限检测", winapi.is_admin, False)
    snap = Snapshot(ts=ts, boot_ms=int(boot), is_admin=bool(admin))

    ok, ms = guard("物理内存状态", winapi.memory_status, (False, {"error": "调用异常"}))
    if ok and isinstance(ms, dict) and "total_phys" in ms:
        snap.total_phys = ms["total_phys"]
        snap.avail_phys = ms["avail_phys"]
        snap.used_phys = ms["used_phys"]
        snap.load_pct = ms["load_pct"]
        snap.pagefile_total = ms["total_pagefile"]
        snap.pagefile_avail = ms["avail_pagefile"]
    else:
        notes.append(f"物理内存状态读取失败：{str(ms)[:160]}")

    ok, pi = guard("提交内存/缓存", winapi.performance_info, (False, {"error": "调用异常"}))
    if ok and isinstance(pi, dict) and "commit_total" in pi:
        snap.commit_total = pi["commit_total"]
        snap.commit_limit = pi["commit_limit"]
        snap.system_cache = pi["system_cache"]
    else:
        notes.append(f"提交内存/缓存读取失败：{str(pi)[:160]}")

    standby_paths = [
        r"\Memory\Standby Cache Core Bytes",
        r"\Memory\Standby Cache Normal Priority Bytes",
        r"\Memory\Standby Cache Reserve Bytes",
    ]
    svals, snote = guard("备用列表计数器", winapi.pdh_collect,
                         ({p: None for p in standby_paths}, "调用异常"), standby_paths, settle=0.10)
    got = [v for v in (svals or {}).values() if v is not None]
    snap.standby_bytes = int(sum(got)) if got else None
    snap.standby_note = "PDH 三类备用缓存之和" if got else f"备用列表大小无法读取（{snote}）"
    if not got:
        notes.append(snap.standby_note)

    fg = guard("前台窗口", winapi.foreground, (0, ""))
    snap.foreground_pid, snap.foreground_title = (fg if isinstance(fg, tuple) else (0, ""))
    snap.user_idle_sec = float(guard("用户空闲时间", winapi.user_idle_seconds, -1.0))
    snap.cpu_busy = guard("CPU 忙闲", winapi.cpu_busy_pct, None)
    snap.disk_busy = guard("磁盘忙闲", winapi.disk_busy_pct, None)
    if snap.cpu_busy is None:
        notes.append("CPU 忙闲无法读取，此项前置检查将按「未知、不阻止」处理")
    if snap.disk_busy is None:
        notes.append("磁盘忙闲无法读取，此项前置检查将按「未知、不阻止」处理")

    # by_pid 必须先定义：显存采集被禁用时也应有空字典，否则进程归因会崩。
    by_pid: dict[int, float] = {}
    if cfg.gpu_probe_enabled:
        try:
            gpus, by_pid, attributable, gpu_note = _gpu_collect(cfg, notes)
        except Exception as exc:  # noqa: BLE001
            gpus, by_pid, attributable, gpu_note = [], {}, False, f"显存采集异常：{exc}"
            notes.append(gpu_note)
        snap.gpus = gpus
        snap.gpu_note = gpu_note
        snap.gpu_attributable = bool(attributable)
    else:
        snap.gpu_note = "已在设置中禁用显存采集"

    windows = guard("顶层窗口枚举", winapi.enum_top_windows, {})
    raw_procs = guard("进程枚举", winapi.enum_processes, [], windows or {})
    for raw in raw_procs or []:
        try:
            p = ProcInfo(
                pid=raw["pid"], name=raw["name"], ws=raw["ws"], private=raw["private"],
                has_window=raw["has_window"], title=raw["title"], accessible=raw["accessible"],
            )
        except (KeyError, TypeError):
            continue
        if p.pid in by_pid:
            p.gpu_mb = by_pid[p.pid]
            p.gpu_source = "nvidia-smi" if any(g.source == "nvidia-smi" for g in snap.gpus) else "PDH"
        snap.procs.append(p)

    snap.notes = notes
    return snap


def collect_light() -> Snapshot:
    """执行过程中的快速复测：只读内存与页面文件，约毫秒级，不触碰 PDH/GPU。

    用于「每步复测、达标即停」的判定；最终报告仍用完整 collect() 生成。
    """
    notes: list[str] = []

    def guard(label: str, fn, default):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{label} 调用异常：{type(exc).__name__}: {exc}")
            return default

    snap = Snapshot(ts=time.time(), boot_ms=int(guard("开机时间", winapi.boot_ms, 0)),
                    is_admin=bool(guard("权限检测", winapi.is_admin, False)))
    ok, ms = guard("物理内存状态", winapi.memory_status, (False, {}))
    if ok and isinstance(ms, dict) and "total_phys" in ms:
        snap.total_phys = ms["total_phys"]
        snap.avail_phys = ms["avail_phys"]
        snap.used_phys = ms["used_phys"]
        snap.load_pct = ms["load_pct"]
        snap.pagefile_total = ms["total_pagefile"]
        snap.pagefile_avail = ms["avail_pagefile"]
    ok, pi = guard("提交内存/缓存", winapi.performance_info, (False, {}))
    if ok and isinstance(pi, dict) and "commit_total" in pi:
        snap.commit_total = pi["commit_total"]
        snap.commit_limit = pi["commit_limit"]
        snap.system_cache = pi["system_cache"]
    snap.notes = notes
    return snap


def describe(snap: Snapshot) -> list[str]:
    """给 UI 用的简明指标清单（每项都有可读解释，见 ui.py 的帮助页）。"""
    # 总量为 0 代表「没读到」，不能显示 0 MB 让用户误以为内存真是 0。
    if snap.total_phys > 0:
        mem_line = (f"物理内存 {fmt_bytes(snap.used_phys)} / {fmt_bytes(snap.total_phys)}"
                    f"（可用 {fmt_bytes(snap.avail_phys)}，占用 {snap.load_pct}%）")
    else:
        mem_line = "物理内存：无法读取（采集失败或总量为 0；所有释放判定已自动暂停）"
    return [
        mem_line,
        f"提交内存 {fmt_bytes(snap.commit_total)} / {fmt_bytes(snap.commit_limit)}",
        f"页面文件可用 {fmt_bytes(snap.pagefile_avail)}",
        f"系统缓存 {fmt_bytes(snap.system_cache)}；备用列表 {fmt_bytes(snap.standby_bytes)}",
        f"专用显存合计 {fmt_mb(snap.gpu_used_total())}（{len(snap.gpus)} 块适配器）",
        f"进程 {len(snap.procs)} 个；用户空闲 {snap.user_idle_sec / 60:.1f} 分钟" if snap.user_idle_sec >= 0 else "用户空闲时间无法读取",
        f"CPU 忙 {snap.cpu_busy:.0f}%" if snap.cpu_busy is not None else "CPU 忙闲无法读取",
        f"磁盘忙 {snap.disk_busy:.0f}%" if snap.disk_busy is not None else "磁盘忙闲无法读取",
        f"权限：{'管理员' if snap.is_admin else '标准用户（L2 不可用）'}",
    ]
