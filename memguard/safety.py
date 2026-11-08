"""安全闸门：白名单标注、前置检查、动作边界、冷却时间与审计日志。

原则：宁可「跳过并说明原因」，也不「勉强执行」。
任何被跳过的项目都必须带一条人类可读的原因，写进日志并展示在界面上。
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .collector import Snapshot, fmt_bytes
from .config import CRITICAL_PROCESSES, Config

SELF_PID = os.getpid()


def annotate_protection(snap: Snapshot, cfg: Config) -> None:
    """在快照上标注每个进程是否可被动作触及。原地修改。"""
    custom = {n.lower() for n in cfg.protect_list}
    for p in snap.procs:
        lname = (p.name or "").lower()
        if not lname:
            p.protected, p.protect_reason = True, "无法读取进程名（权限不足或系统保护进程）"
        elif p.pid == SELF_PID:
            p.protected, p.protect_reason = True, "程序自身（硬保护）"
        elif lname in CRITICAL_PROCESSES:
            p.protected, p.protect_reason = True, "系统关键进程（硬保护，不可解除）"
        elif lname in custom:
            p.protected, p.protect_reason = True, "在用户保护名单中"
        elif not p.accessible:
            p.protected, p.protect_reason = True, "进程无法读取/打开（受保护或权限不足）"
        else:
            p.protected, p.protect_reason = False, ""


@dataclass
class Preflight:
    allowed: bool
    level: int
    auto: bool
    blocks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.allowed:
            return "前置检查通过" + (f"；注意：{'；'.join(self.warnings)}" if self.warnings else "")
        return "已阻止执行：" + "；".join(self.blocks)


def preflight(
    snap: Snapshot, cfg: Config, level: int, auto: bool,
    last_action_ts: float = 0.0, anchor_valid: bool = True,
    selected_pids: list[int] | None = None,
) -> Preflight:
    pf = Preflight(allowed=False, level=level, auto=auto)
    b, w = pf.blocks, pf.warnings

    # 边界：自动流程硬上限 L1，任何配置都不能突破
    if auto and level > 1:
        b.append(f"自动释放的硬上限是 L1，拒绝 L{level}（防止自动结束/影响进程）")
    if auto and level > cfg.auto_max_level:
        b.append(f"当前设置允许自动上限 L{cfg.auto_max_level}")
    if auto and not cfg.auto_release_enabled:
        b.append("自动释放总开关已关闭")
    if cfg.paused:
        b.append("全局暂停开关已打开")

    if level == 2:
        if auto:
            b.append("L2 清理备用列表不允许自动执行")
        if not cfg.allow_l2_manual:
            b.append("设置中未启用 L2")
        if not snap.is_admin:
            b.append("L2 需要管理员权限，请以管理员身份重启程序")

    if level == 3:
        if auto:
            b.append("L3 关闭进程永远不允许自动执行")
        if not cfg.allow_l3_manual:
            b.append("设置中未启用 L3")
        if not selected_pids:
            b.append("没有勾选任何进程（L3 必须逐项勾选）")
        if snap.gpu_attributable is False:
            w.append("当前无法把显存占用归因到进程，请自行核对勾选对象")

    # 系统环境
    uptime_min = snap.boot_ms / 60000.0
    if uptime_min < cfg.min_uptime_min:
        b.append(f"开机仅 {uptime_min:.1f} 分钟（要求 ≥ {cfg.min_uptime_min} 分钟，避开启动阶段）")

    pf_avail_mb = snap.pagefile_avail / (1024 * 1024)
    if snap.pagefile_avail > 0 and pf_avail_mb < cfg.min_pagefile_avail_mb:
        b.append(f"页面文件可用仅 {pf_avail_mb:,.0f} MB（要求 ≥ {cfg.min_pagefile_avail_mb} MB）：换出物理页需要页面文件空间，贸然裁剪可能引发更严重的内存压力")

    if auto:
        if last_action_ts > 0:
            rest = cfg.cooldown_min * 60 - (time.time() - last_action_ts)
            if rest > 0:
                b.append(f"处于冷却期，还需 {rest / 60:.1f} 分钟")
        if not anchor_valid:
            b.append("当前锚点无效或缺失（自动释放必须参照有效锚点）")
        if snap.cpu_busy is not None and snap.cpu_busy > cfg.idle_cpu_pct:
            b.append(f"CPU 忙 {snap.cpu_busy:.0f}%（要求 ≤ {cfg.idle_cpu_pct:.0f}%，避免干扰正在运行的任务）")
        if snap.disk_busy is not None and snap.disk_busy > cfg.idle_disk_pct:
            b.append(f"磁盘忙 {snap.disk_busy:.0f}%（要求 ≤ {cfg.idle_disk_pct:.0f}%）")
        else:
            if snap.disk_busy is None:
                w.append("磁盘忙闲无法读取，此项按「未知、不阻止」处理")
        if cfg.skip_when_foreground and snap.user_idle_sec >= 0:
            if snap.user_idle_sec < cfg.user_idle_min * 60:
                b.append(f"用户正在操作电脑（空闲 {snap.user_idle_sec:.0f} 秒，要求 ≥ {cfg.user_idle_min * 60:.0f} 秒）")
        elif snap.user_idle_sec < 0:
            w.append("用户空闲时间无法读取，此项按「未知、不阻止」处理")

    if level == 1:
        w.append("L1 只把物理页换出到页面文件，不释放提交内存；切回被裁剪的应用时可能短暂卡顿")

    pf.allowed = not b
    return pf


def auto_should_release(snap: Snapshot, cfg: Config, need_release_bytes: int, anchor_valid: bool) -> tuple[bool, str]:
    """自动触发条件：内存吃紧 + 确实超出锚点。两个条件必须同时满足。"""
    if not anchor_valid:
        return False, "锚点无效，不触发"
    if snap.total_phys <= 0:
        return False, "无法读取物理内存总量"
    avail_pct = snap.avail_phys / snap.total_phys * 100.0
    if avail_pct >= cfg.trigger_avail_pct:
        return False, f"可用内存 {avail_pct:.1f}%（阈值 < {cfg.trigger_avail_pct:.1f}%），暂不需要释放"
    over_mb = need_release_bytes / (1024 * 1024)
    if over_mb < cfg.trigger_over_anchor_mb:
        return False, f"超出锚点仅 {over_mb:,.0f} MB（阈值 ≥ {cfg.trigger_over_anchor_mb} MB）"
    return True, f"可用内存 {avail_pct:.1f}% 且超出锚点 {over_mb:,.0f} MB，满足自动释放条件"


def auto_anchor_ok(snap: Snapshot, cfg: Config) -> tuple[bool, str]:
    """自动锚点只在系统空闲且状态健康时记录，避免把内存紧张状态记成基线。"""
    if not cfg.auto_anchor_enabled:
        return False, "自动锚点已关闭"
    if snap.total_phys <= 0:
        return False, "内存数据不可读"
    avail_pct = snap.avail_phys / snap.total_phys * 100.0
    if avail_pct < cfg.auto_anchor_min_avail_pct:
        return False, f"可用内存 {avail_pct:.1f}% 低于健康线 {cfg.auto_anchor_min_avail_pct:.0f}%"
    if snap.user_idle_sec >= 0 and snap.user_idle_sec < cfg.auto_anchor_idle_min * 60:
        return False, f"用户空闲不足 {cfg.auto_anchor_idle_min} 分钟"
    if snap.cpu_busy is not None and snap.cpu_busy > cfg.idle_cpu_pct:
        return False, f"CPU 忙 {snap.cpu_busy:.0f}%，系统不空闲"
    return True, f"系统空闲（用户空闲 {snap.user_idle_sec / 60:.1f} 分钟，可用内存 {avail_pct:.1f}%）"


# ---------------------------------------------------------------- 审计日志

def _safe_keep_days(v: int) -> int:
    """保留天数必须为正；负数/非法值会把 cutoff 推到未来，导致日志被整份清空。"""
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        return 30
    return max(1, min(3650, n))


class AuditLog:
    def __init__(self, path: Path, keep_days: int = 30):
        self.path = path
        self.keep_days = _safe_keep_days(keep_days)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, action: str, detail: str, level: str = "info", **extra: Any) -> None:
        ev = {
            "ts": time.time(),
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "action": action,
            "detail": detail,
        }
        ev.update(extra)
        with self._lock:
            try:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            except Exception:  # noqa: BLE001
                pass

    def read(self, limit: int = 300) -> list[dict]:
        if not self.path.exists():
            return []
        out: list[dict] = []
        with self._lock:
            try:
                lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines[-limit:]:
                    try:
                        out.append(json.loads(line))
                    except Exception:  # noqa: BLE001
                        continue
            except Exception:  # noqa: BLE001
                return []
        return list(reversed(out))

    def as_text(self, limit: int = 300) -> str:
        rows = self.read(limit)
        if not rows:
            return "暂无日志记录。"
        marks = {"info": "信息", "warn": "警告", "error": "错误", "ok": "成功", "block": "阻止"}
        lines = []
        for r in rows:
            extra = {k: v for k, v in r.items() if k not in ("ts", "time", "level", "action", "detail")}
            tail = ("  " + json.dumps(extra, ensure_ascii=False)) if extra else ""
            lines.append(f"[{r.get('time','')}] [{marks.get(r.get('level',''), '信息')}] {r.get('action','')} - {r.get('detail','')}{tail}")
        return "\n".join(lines)

    def purge(self) -> tuple[int, str]:
        """删除过期日志（只重写本程序自己的日志文件，不触碰其它文件）。"""
        if not self.path.exists():
            return 0, "无日志可清理"
        self.keep_days = _safe_keep_days(self.keep_days)
        cutoff = time.time() - self.keep_days * 86400
        with self._lock:
            try:
                lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
                kept = []
                removed = 0
                for line in lines:
                    try:
                        if float(json.loads(line).get("ts", 0)) < cutoff:
                            removed += 1
                            continue
                    except Exception:  # noqa: BLE001
                        pass
                    kept.append(line)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
                tmp.replace(self.path)
                return removed, f"已清理 {removed} 条超过 {self.keep_days} 天的日志"
            except Exception as exc:  # noqa: BLE001
                return 0, f"日志清理失败：{exc}"
