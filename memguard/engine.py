"""编排层：自动巡检、手动释放、锚点生命周期、通知与日志。

自动流程是单线程后台任务，硬编码只走 L1；
任何 L2 / L3 都必须来自 UI 的显式手动调用。

手动执行遵循「已确认计划」原则：UI 展示并让用户确认的那份 Plan 才是执行对象，
执行前再用新快照复核进程身份（防 PID 复用误杀），绝不悄悄重新生成一份新计划。
"""
from __future__ import annotations

import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import collector, winapi
from .actions import PLAN_TTL_SEC, Plan, build_plan, execute, revalidate_plan
from .anchors import AnchorStore, Diff
from .collector import Snapshot, fmt_bytes
from .config import Config, default_data_dir
from .safety import (
    AuditLog, annotate_protection, auto_anchor_ok, auto_should_release, preflight,
)

AUTO_ANCHOR_MIN_INTERVAL = 7200.0
DEFAULT_POLL_SEC = 60

ProgressFn = Callable[[str], None] | None
ConfirmFn = Callable[[int, str], bool] | None


class Engine:
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = Path(data_dir) if data_dir else default_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.data_dir / "config.json"
        self.cfg, cfg_msg = Config.load(self.config_path)
        self.log = AuditLog(self.data_dir / "audit.log", self.cfg.log_days)
        self.store = AnchorStore(self.data_dir / "anchors.json")

        self.last_action_ts = 0.0
        self.last_auto_anchor_ts = 0.0
        self._last_skip_reason = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self.messages: queue.Queue = queue.Queue()
        self._snap: Snapshot | None = None
        self._diff: Diff | None = None

        self.log.write("启动", cfg_msg, level="info")
        self.log.write(
            "启动",
            f"权限={'管理员' if winapi.is_admin() else '标准用户'}；自动硬上限 L1；数据目录 {self.data_dir}",
            level="info",
        )
        self.log.purge()
        self.ensure_startup_anchor()

    # ---------------------------------------------------------------- 基础

    def _full_collect(self) -> Snapshot:
        s = collector.collect(self.cfg)
        annotate_protection(s, self.cfg)
        return s

    def refresh(self) -> tuple[Snapshot, Diff]:
        snap = self._full_collect()
        diff = self.store.diff(snap, self.cfg)
        self._snap, self._diff = snap, diff
        return snap, diff

    @property
    def cached(self) -> tuple[Snapshot | None, Diff | None]:
        return self._snap, self._diff

    def notify(self, title: str, text: str, level: str = "info") -> None:
        self.messages.put({"title": title, "text": text, "level": level, "ts": time.time()})
        self.log.write("通知", f"{title}：{text[:300]}", level=level)

    def drain_messages(self) -> list[dict]:
        out = []
        while True:
            try:
                out.append(self.messages.get_nowait())
            except queue.Empty:
                break
        return out

    def _progress(self, msg: str) -> None:
        self.messages.put({"title": "执行进度", "text": msg, "level": "info", "ts": time.time()})

    # ---------------------------------------------------------------- 锚点

    @staticmethod
    def _anchor_is_stale_boot(anchor, snap: Snapshot | None = None) -> bool:
        """锚点是否来自上一次开机。用轻量方式判断，避免启动时多一次全量采集。"""
        boot_a = float((anchor.compact or {}).get("boot_time") or 0)
        if not boot_a:
            return False
        if snap is not None:
            boot_now = snap.ts - snap.boot_ms / 1000.0
        else:
            boot_now = time.time() - winapi.boot_ms() / 1000.0
        return abs(boot_a - boot_now) > 180

    def ensure_startup_anchor(self) -> None:
        """首次运行 / 重启后自动建立本次开机的基线，让自动释放立刻有有效参照。"""
        cur = self.store.get_current()
        if cur is not None and not self._anchor_is_stale_boot(cur):
            return
        snap = self._full_collect()
        why = "首次运行" if cur is None else "检测到锚点来自上一次开机，已保留历史并重建本次开机基线"
        anchor, msg = self.store.add(snap, "启动基线（本次开机）", "startup")
        self.last_auto_anchor_ts = time.time()
        self.log.write("锚点", f"{why}：{msg}", level="ok")
        self._snap, self._diff = snap, self.store.diff(snap, self.cfg)

    def set_anchor(self, name: str = "", source: str = "manual") -> tuple[bool, str]:
        snap = self._full_collect()
        anchor, msg = self.store.add(snap, name, source)
        self._snap, self._diff = snap, self.store.diff(snap, self.cfg)
        self.log.write("锚点", msg, level="ok")
        self.notify("锚点已设置", msg, level="ok")
        return True, msg

    # ---------------------------------------------------------------- 手动释放

    def manual_preview(
        self, level: int, selected_pids: list[int] | None = None,
        ignore_anchor: bool = False,
    ) -> tuple[Snapshot, Diff, Any, Plan]:
        snap, diff = self.refresh()
        pf = preflight(
            snap, self.cfg, level, auto=False,
            anchor_valid=diff.valid, selected_pids=selected_pids or [],
        )
        plan = build_plan(
            snap, self.cfg, diff, level, auto=False,
            selected_pids=selected_pids or [], ignore_anchor=ignore_anchor,
        )
        return snap, diff, pf, plan

    def manual_execute(
        self, level: int, selected_pids: list[int] | None = None,
        ignore_anchor: bool = False, confirm_force_fn: ConfirmFn = None,
        plan: Plan | None = None,
    ) -> tuple[bool, Any, Plan, Diff]:
        """执行释放。plan 为用户已预览并确认的计划；None 仅供无界面 CLI 使用。"""
        tag = {1: "L1 工作集裁剪", 2: "L2 清理备用列表", 3: "L3 关闭占用进程"}.get(level, f"L{level}")

        # 1) 拿到用户确认的那份计划（CLI 才允许现场生成）
        if plan is None:
            _, diff, pf, plan = self.manual_preview(level, selected_pids, ignore_anchor)
            self.log.write("干运行预览", f"[无界面 CLI] [{tag}] {plan.preview_text()[:2500]}",
                           level="info", level_no=level)
        else:
            if plan.level != level or plan.auto:
                return False, "计划与当前执行级别不一致，请重新生成预览", plan, Diff(anchor=None, valid=False)
            if plan.age_sec() > PLAN_TTL_SEC:
                return False, (f"预览已超过 {PLAN_TTL_SEC / 60:.0f} 分钟，系统状态可能已变化；"
                               "请重新生成预览后再执行（程序不会沿用旧确认）"), plan, self.store.diff(self._full_collect(), self.cfg)
            self.log.write("执行确认", f"[{tag}] 使用已确认计划，指纹 {plan.signature()[:400]}", level="info")

        # 2) 用执行时刻的新快照重新做前置检查 + 进程身份复核
        fresh = self._full_collect()
        diff = self.store.diff(fresh, self.cfg)
        pf = preflight(fresh, self.cfg, level, auto=False,
                       anchor_valid=diff.valid, selected_pids=selected_pids or [])
        if not pf.allowed:
            self.log.write("阻止", f"[{tag}] 执行前复核未通过：{pf.summary()}", level="block")
            return False, pf.summary(), plan, diff

        plan, reasons = revalidate_plan(plan, fresh, self.cfg)
        for r in reasons:
            self.log.write("执行前复核", r, level="warn")
        if not plan.items:
            text = ("执行前复核后没有可执行的动作：预览时的进程已退出、身份变化或已受保护。"
                    "系统状态未发生任何改变。")
            self.log.write("阻止", f"[{tag}] {text}", level="block")
            return False, text, plan, diff

        result = execute(
            plan, fresh, self.cfg, self.log,
            collect_fn=self._full_collect,
            confirm_force_fn=confirm_force_fn,
            progress_fn=self._progress,
            light_fn=collector.collect_light,
        )
        self.last_action_ts = time.time()
        self.refresh()  # 成对更新缓存快照与差异，避免界面显示旧数据配新判定
        self.notify(
            f"{tag} 完成",
            f"物理内存已用 {fmt_bytes(result.before_used)} → {fmt_bytes(result.after_used)}；{result.stopped_reason}",
            level="ok",
        )
        return True, result, plan, diff

    # ---------------------------------------------------------------- 自动巡检

    def auto_tick(self, snap: Snapshot | None = None) -> str:
        """执行一轮自动巡检。snap 可注入以便测试；生产路径使用真实采集。"""
        snap = snap if snap is not None else self._full_collect()
        diff = self.store.diff(snap, self.cfg)

        if self.cfg.auto_anchor_enabled:
            ok, why = auto_anchor_ok(snap, self.cfg)
            # 上次开机的锚点必须立刻重建，不能让用户等「空闲 10 分钟 + 2 小时间隔」。
            urgent = (not diff.valid) and self._anchor_is_stale_boot(diff.anchor, snap) if diff.anchor else False
            need_new = (
                ok and (
                    urgent
                    or (time.time() - self.last_auto_anchor_ts >= AUTO_ANCHOR_MIN_INTERVAL
                        and (diff.anchor is None or (not diff.valid) or (not diff.fresh)))
                )
            )
            if need_new:
                _, msg = self.store.add(snap, "", "auto")
                self.last_auto_anchor_ts = time.time()
                diff = self.store.diff(snap, self.cfg)
                self.log.write("锚点", f"自动锚点：{why}；{msg}", level="ok")
                self.notify("已自动设置锚点", f"{why}；{msg}", level="ok")

        pf = preflight(
            snap, self.cfg, 1, auto=True,
            last_action_ts=self.last_action_ts,
            anchor_valid=bool(diff.valid and diff.fresh),
        )
        if not pf.allowed:
            reason = pf.summary()
            if reason != self._last_skip_reason:
                self.log.write("自动巡检跳过", reason, level="info")
                self._last_skip_reason = reason
            return reason

        triggered, why = auto_should_release(snap, self.cfg, diff.need_release_bytes, bool(diff.valid and diff.fresh))
        if not triggered:
            if why != self._last_skip_reason:
                self.log.write("自动巡检跳过", why, level="info")
                self._last_skip_reason = why
            return why

        plan = build_plan(snap, self.cfg, diff, 1, auto=True)
        self.log.write("自动干运行", plan.preview_text()[:2500], level="info")
        if not plan.items:
            self.log.write("自动巡检跳过", "没有符合条件的进程，未改变系统状态", level="info")
            return "无可执行进程"

        # 自动流程同样做身份复核：后台巡检与手动操作可能相隔数十秒。
        plan, reasons = revalidate_plan(plan, snap, self.cfg)
        for r in reasons:
            self.log.write("自动巡检复核", r, level="warn")
        if not plan.items:
            return "复核后无可执行进程"

        result = execute(
            plan, snap, self.cfg, self.log,
            collect_fn=self._full_collect,
            progress_fn=self._progress,
            light_fn=collector.collect_light,
        )
        self.last_action_ts = time.time()
        self._last_skip_reason = ""
        self.log.write("自动释放", result.report_text()[:2500], level="ok")
        self.notify("自动释放完成（仅 L1）", f"{why}；{result.stopped_reason}", level="ok")
        return result.stopped_reason

    def _loop(self) -> None:
        while not self._stop.is_set():
            # 每轮重新读取周期：设置页改动即时生效；非法值回退而不让线程静默死亡。
            try:
                wait = max(5, int(self.cfg.poll_sec))
            except (TypeError, ValueError, OverflowError):
                self.cfg.poll_sec = DEFAULT_POLL_SEC
                self.log.write("自动", "巡检周期非法，已回退 60 秒", level="warn")
                wait = DEFAULT_POLL_SEC
            if self._stop.wait(wait):
                break
            try:
                self.auto_tick()
            except Exception as exc:  # noqa: BLE001
                self.log.write("自动巡检异常", f"{type(exc).__name__}: {exc}", level="error")
                self.notify("自动巡检异常", f"{type(exc).__name__}: {exc}", level="error")

    def start_auto(self) -> str:
        if self._thread and self._thread.is_alive():
            return "自动巡检已在运行"
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="MemGuard-Auto")
        self._thread.start()
        self._running = True
        msg = f"自动巡检已启动：每 {self.cfg.poll_sec} 秒检查一次，硬上限 L1，绝不结束进程"
        self.log.write("自动", msg, level="ok")
        return msg

    def stop_auto(self) -> str:
        self._stop.set()
        self._running = False
        self.log.write("自动", "自动巡检已停止", level="warn")
        return "自动巡检已停止"

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def set_paused(self, paused: bool) -> str:
        self.cfg.paused = bool(paused)
        msg = "已暂停全部自动动作" if paused else "已恢复自动动作"
        self.log.write("暂停开关", msg, level="warn" if paused else "info")
        self.notify("暂停开关", msg, level="warn" if paused else "info")
        return msg

    # ---------------------------------------------------------------- 配置与导出

    def update_config(self, patch: dict) -> tuple[list[str], str]:
        was_on = self.cfg.auto_release_enabled
        changed = self.cfg.update(patch)
        ok, msg = self.cfg.save(self.config_path)
        self.log = AuditLog(self.data_dir / "audit.log", self.cfg.log_days)
        self.log.write("设置", f"已修改 {', '.join(changed) or '（无变更）'}；{msg}", level="info")
        # 总开关改了就立刻生效，不需要重启程序。
        if self.cfg.auto_release_enabled and not was_on and not self.running:
            self.start_auto()
        elif was_on and not self.cfg.auto_release_enabled and self.running:
            self.stop_auto()
        return changed, msg

    def export_anchors(self, path: Path) -> tuple[bool, str]:
        return self.store.export(Path(path))

    def export_log(self, path: Path) -> tuple[bool, str]:
        try:
            Path(path).write_text(self.log.as_text(10000), encoding="utf-8")
            return True, f"日志已导出到 {path}"
        except Exception as exc:  # noqa: BLE001
            return False, f"日志导出失败：{exc}"

    def purge_log(self) -> str:
        n, msg = self.log.purge()
        return msg
