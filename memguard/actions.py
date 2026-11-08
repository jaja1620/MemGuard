"""分级执行：先生成干运行计划（只描述不动作），确认后才真正执行。

L1 裁剪工作集 / L2 清备用列表 / L3 优雅关闭用户勾选的进程。
L1、L2 每执行一步都会复测内存，达到锚点目标立即停止，避免过度释放。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Callable

from . import winapi
from .anchors import Diff
from .collector import MB, Snapshot, fmt_bytes, fmt_mb
from .config import Config
from .safety import AuditLog, annotate_protection

CollectFn = Callable[[], Snapshot]
ConfirmFn = Callable[[int, str], bool] | None

# 干运行计划的有效期：超时后必须重新预览，避免用户确认的是几分钟前的系统状态。
PLAN_TTL_SEC = 180.0


@dataclass
class PlanItem:
    kind: str
    target: str
    pid: int | None = None
    reason: str = ""
    estimated_bytes: int = 0
    side_effect: str = ""
    gpu_mb: float = 0.0
    expected_name: str = ""        # 预览时的进程名，执行前用于防 PID 复用误杀

    def line(self) -> str:
        est = f"，预计可换出 {fmt_bytes(self.estimated_bytes)}" if self.estimated_bytes else ""
        return f"[{self.kind}] {self.target}{est}｜{self.reason}"


@dataclass
class Plan:
    level: int
    auto: bool
    anchor_name: str = ""
    target_used: int = 0
    items: list[PlanItem] = field(default_factory=list)
    skipped: list[PlanItem] = field(default_factory=list)
    estimated_release_bytes: int = 0
    notes: list[str] = field(default_factory=list)
    created_ts: float = field(default_factory=time.time)

    def signature(self) -> str:
        """用户确认的对象指纹。执行前会用它核对「确认的计划 == 执行的计划」。"""
        items = "|".join(f"{i.kind}:{i.pid}:{i.expected_name}" for i in sorted(
            self.items, key=lambda x: (x.kind, int(x.pid or 0))))
        return f"L{self.level}/{'auto' if self.auto else 'manual'}/{self.anchor_name}/{self.target_used}/{items}"

    def age_sec(self) -> float:
        return max(0.0, time.time() - self.created_ts)

    def preview_text(self) -> str:
        head = [
            f"执行级别：L{self.level}（{'自动' if self.auto else '手动'}）",
            f"参照锚点：{self.anchor_name or '无'}",
            f"停止条件：物理内存已用降至 {fmt_bytes(self.target_used)} 以下即停" if self.target_used else "停止条件：完成计划项即停",
            f"预计可释放：约 {fmt_bytes(self.estimated_release_bytes)}（估算值，实际以执行后复测为准）",
            f"将执行 {len(self.items)} 项，跳过 {len(self.skipped)} 项。",
            "",
            "—— 将执行的动作 ——",
        ]
        items = [f"  {i + 1}. {it.line()}" for i, it in enumerate(self.items)] or ["  （无）"]
        skips = ["  " + f"跳过 {it.target}：{it.reason}" for it in self.skipped[:20]]
        if len(self.skipped) > 20:
            skips.append(f"  …… 另有 {len(self.skipped) - 20} 项跳过，详见日志")
        tail = ["", "—— 跳过项及原因 ——"] + (skips or ["  （无）"])
        notes = ["", "—— 说明与副作用 ——"] + [f"  · {n}" for n in self.notes]
        return "\n".join(head + items + tail + notes)


@dataclass
class ExecResult:
    level: int
    auto: bool
    started: float
    finished: float = 0.0
    before_used: int = 0
    after_used: int = 0
    before_avail: int = 0
    after_avail: int = 0
    gpu_before_mb: float = 0.0
    gpu_after_mb: float = 0.0
    steps: list[tuple[bool, str, str]] = field(default_factory=list)
    stopped_reason: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def released_bytes(self) -> int:
        return self.before_used - self.after_used

    def report_text(self) -> str:
        secs = self.finished - self.started
        lines = [
            f"执行完成：L{self.level}（{'自动' if self.auto else '手动'}），耗时 {secs:.1f} 秒",
            f"物理内存已用：{fmt_bytes(self.before_used)} → {fmt_bytes(self.after_used)}（净变化 {fmt_bytes(-self.released_bytes)}）",
            f"可用物理内存：{fmt_bytes(self.before_avail)} → {fmt_bytes(self.after_avail)}",
            f"专用显存合计：{fmt_mb(self.gpu_before_mb)} → {fmt_mb(self.gpu_after_mb)}",
            f"停止原因：{self.stopped_reason or '计划项全部执行完毕'}",
            "",
            "—— 逐项结果 ——",
        ]
        for ok, target, detail in self.steps:
            lines.append(f"  [{'成功' if ok else '跳过/失败'}] {target}：{detail}")
        if not self.steps:
            lines.append("  （没有执行任何动作）")
        if self.warnings:
            lines += ["", "—— 提示 ——"] + [f"  · {w}" for w in self.warnings]
        lines += [
            "",
            "说明：物理内存「下降」主要是把页面换出到页面文件，不等于释放了提交内存；"
            "被裁剪的应用切回前台时可能发生短暂卡顿，属正常现象。",
        ]
        return "\n".join(lines)


LEVEL_NAME = {1: "L1 工作集裁剪", 2: "L2 清理备用列表", 3: "L3 关闭占用显存的进程"}


def build_plan(
    snap: Snapshot, cfg: Config, diff: Diff, level: int, *,
    auto: bool = False, selected_pids: list[int] | None = None,
    ignore_anchor: bool = False,
) -> Plan:
    """只生成计划，不调用任何会改变系统状态的函数。"""
    p = Plan(level=level, auto=auto, anchor_name=diff.anchor.name if diff.anchor else "")

    # 纵深防御：即便上层漏了前置检查，自动流程也绝不生成 L2/L3 计划。
    if auto and level > 1:
        p.notes.append("自动流程硬上限 L1：已拒绝生成 L2/L3 计划，不会改变系统状态。")
        return p

    constrained = bool(diff.valid and not ignore_anchor)
    need = diff.need_release_bytes if constrained else 0
    p.target_used = diff.target_used if (constrained and diff.target_used > 0) else 0

    # 默认严格参照锚点：没超出目标就不生成任何动作，从源头杜绝「为好看的数字乱清」。
    if constrained and need == 0 and level == 1:
        p.notes += [
            "按锚点规则：当前物理内存已用未超过「锚点 + 容差」，本次不生成任何动作，系统状态不会改变。",
            "这是有意设计：无目标地反复清空缓存会带来额外磁盘 IO 与应用卡顿。",
            "如确需主动清理，请在「释放」页勾选「不受锚点限制」后重新生成预览。",
        ]
        return p

    if level == 1:
        candidates = sorted(
            [x for x in snap.procs if x.ws > 16 * MB],
            key=lambda x: x.ws, reverse=True,
        )
        budget = int(need * 1.25) if need > 0 else (1 << 62)
        acc = 0
        for proc in candidates:
            if proc.protected:
                p.skipped.append(PlanItem("skip", proc.label(), proc.pid, proc.protect_reason))
                continue
            if auto and cfg.skip_windowed_for_auto and proc.has_window:
                p.skipped.append(PlanItem("skip", proc.label(), proc.pid, "自动模式跳过有可见窗口的进程，避免干扰正在进行的工作"))
                continue
            if acc >= budget:
                p.skipped.append(PlanItem("skip", proc.label(), proc.pid, "按锚点已凑够目标释放量，不再扩大影响范围"))
                continue
            est = int(proc.ws * 0.35)
            p.items.append(PlanItem(
                "L1", proc.label(), proc.pid,
                f"工作集 {fmt_bytes(proc.ws)}，不在保护名单中",
                est, "物理页换出到页面文件，进程继续运行，切回时可能短暂卡顿",
                expected_name=proc.name,
            ))
            acc += est
        p.estimated_release_bytes = sum(i.estimated_bytes for i in p.items)
        p.notes += [
            "L1 不会结束任何进程，也不会释放提交内存；它只把暂时不用的物理页换出到页面文件。",
            "预计释放量按工作集 35% 经验估算，不是承诺值；实际以执行后复测为准。",
            "每执行一项都会复测，达到锚点目标即停止，不会继续清空所有进程的工作集。",
        ]
        if need > 0:
            p.notes.append(f"本次只针对超出锚点的 {fmt_bytes(need)} 组织动作，已限制影响范围。")
        else:
            p.notes.append("已勾选「不受锚点限制」：按全部可触及进程组织动作，属于主动清理，请确认确实需要。")
        if not p.items:
            p.notes.append("没有符合条件的进程（都受保护、太小或已凑够目标），本次不会改变任何系统状态。")

    elif level == 2:
        p.items.append(PlanItem(
            "L2", "系统备用列表（Standby List）", None,
            "清理文件缓存/备用页，需管理员与 SeProfileSingleProcessPrivilege",
            int(snap.standby_bytes or 0),
            "系统缓存被清后，短时间内重新打开大文件会有更多磁盘读取",
        ))
        p.estimated_release_bytes = int(snap.standby_bytes or 0)
        p.notes += [
            "L2 与 RAMMap 的「Empty Standby List」同原理，清理的是可丢弃的文件缓存页，不会结束进程。",
            "这是系统级操作，必须管理员权限；非管理员运行时会被前置检查直接阻止。",
            "L2 永远不会被自动流程调用，只能由你手动点击执行。",
        ]

    elif level == 3:
        selected = set(selected_pids or [])
        by_pid = {x.pid: x for x in snap.procs}
        for pid in sorted(selected):
            proc = by_pid.get(pid)
            if proc is None:
                p.skipped.append(PlanItem("skip", f"PID {pid}", pid, "该进程已退出或不在本次快照中"))
                continue
            if proc.protected:
                p.skipped.append(PlanItem("skip", proc.label(), pid, proc.protect_reason))
                continue
            p.items.append(PlanItem(
                "L3", proc.label(), pid,
                f"你已勾选；{'显存占用 ' + fmt_mb(proc.gpu_mb) if proc.gpu_mb else '显存占用无法归因，按你的勾选处理'}",
                0,
                "会先发送 WM_CLOSE 让应用保存；超时后需要你再次确认才会强制结束，未保存的改动可能丢失",
                proc.gpu_mb,
                expected_name=proc.name,
            ))
        p.notes += [
            "Windows 没有显存回收 API，显存只能由持有它的进程释放；关闭进程是唯一有效路径。",
            "程序无法检测应用里是否有未保存内容：请自行确认勾选对象，勾选框默认全部不选中。",
            "执行顺序：先投递 WM_CLOSE → 等待应用自行退出 → 仍未退出时才弹出第二次确认，得到确认才强制结束。",
            "L3 永远不会被自动流程调用，也不会动系统关键进程、程序自身或保护名单中的程序。",
        ]
        if not p.items:
            p.notes.append("没有可执行的勾选对象，本次不会关闭任何进程。")
    else:
        p.notes.append("未知执行级别，已拒绝生成计划。")

    return p


def revalidate_plan(plan: Plan, fresh: Snapshot, cfg: Config) -> tuple[Plan, list[str]]:
    """执行前的最后一道闸门：用新快照核对「预览时勾选的进程现在还是不是它」。

    这是防止 PID 复用误杀的关键：Windows 会回收退出进程的 PID，
    仅凭 PID 关闭进程可能在几分钟后杀掉一个完全无关的新进程。
    返回的 reasons 会写进日志和界面，绝不含糊带过。
    """
    annotate_protection(fresh, cfg)
    by_pid = {p.pid: p for p in fresh.procs}
    kept: list[PlanItem] = []
    reasons: list[str] = []

    for it in plan.items:
        if it.kind == "L2":
            kept.append(it)  # 系统级动作不针对具体 PID
            continue
        pid = int(it.pid or 0)
        proc = by_pid.get(pid)
        if proc is None:
            reasons.append(f"跳过 {it.target}：预览后进程已退出（或不在新快照中）")
            continue
        expected = it.expected_name or it.target.rsplit(" (PID", 1)[0]
        if expected and proc.name and proc.name.lower() != expected.lower():
            reasons.append(
                f"跳过 {it.target}：PID {pid} 现在是 {proc.name}，与预览时不一致"
                "（PID 可能被复用），为防误杀拒绝动作"
            )
            continue
        if proc.protected:
            reasons.append(f"跳过 {it.target}：新快照中已受保护（{proc.protect_reason}）")
            continue
        kept.append(it)

    new_plan = replace(
        plan,
        items=kept,
        estimated_release_bytes=sum(i.estimated_bytes for i in kept),
        notes=list(plan.notes) + ([f"执行前复核：{len(reasons)} 项被剔除"] if reasons else ["执行前复核：全部计划项身份一致"]),
    )
    return new_plan, reasons


def execute(
    plan: Plan, snap_before: Snapshot, cfg: Config, log: AuditLog,
    collect_fn: CollectFn, confirm_force_fn: ConfirmFn = None,
    progress_fn: Callable[[str], None] | None = None,
    light_fn: CollectFn | None = None,
) -> ExecResult:
    """执行已确认的计划。所有危险分支都要求显式确认。

    light_fn 用于逐步复测（毫秒级），collect_fn 用于生成最终完整报告。
    """
    probe = light_fn or collect_fn

    def emit(msg: str) -> None:
        if progress_fn:
            try:
                progress_fn(msg)
            except Exception:  # noqa: BLE001
                pass
        log.write("执行", msg, level="info")

    r = ExecResult(
        level=plan.level, auto=plan.auto, started=time.time(),
        before_used=snap_before.used_phys, before_avail=snap_before.avail_phys,
        gpu_before_mb=snap_before.gpu_used_total(),
    )
    current = snap_before
    windows = winapi.enum_top_windows()

    for idx, item in enumerate(plan.items):
        if item.kind == "L1":
            ok, detail = winapi.trim_working_set(int(item.pid or 0))
            r.steps.append((ok, item.target, detail))
            emit(f"{idx + 1}/{len(plan.items)} {item.target}：{detail}")
            # 每项后复测，达标即停
            try:
                current = probe()
            except Exception as exc:  # noqa: BLE001
                r.warnings.append(f"复测失败：{exc}，已停止后续动作以避免盲目释放")
                r.stopped_reason = "复测失败，安全起见提前停止"
                break
            if plan.target_used and current.used_phys <= plan.target_used:
                r.stopped_reason = f"已回到锚点目标 {fmt_bytes(plan.target_used)}（当前 {fmt_bytes(current.used_phys)}），达标即停"
                emit(r.stopped_reason)
                break
        elif item.kind == "L2":
            ok, detail = winapi.purge_standby_list()
            r.steps.append((ok, item.target, detail))
            emit(f"{item.target}：{detail}")
            try:
                current = probe()
            except Exception as exc:  # noqa: BLE001
                r.warnings.append(f"复测失败：{exc}")
        elif item.kind == "L3":
            pid = int(item.pid or 0)
            sent, detail = winapi.post_close(pid, windows)
            r.steps.append((sent > 0, item.target, detail))
            emit(f"{item.target}：{detail}")
            if sent <= 0:
                # 没有可见窗口就没有「等应用保存」的意义，不再空等 close_wait_sec。
                r.warnings.append(
                    f"{item.target} 没有可见窗口，无法发送关闭消息；程序不会假装已优雅关闭，"
                    "直接进入是否强制结束的单独确认"
                )
            deadline = time.time() + (max(2, cfg.close_wait_sec) if sent > 0 else 0.5)
            while time.time() < deadline and winapi.is_process_alive(pid):
                time.sleep(0.4)
            if not winapi.is_process_alive(pid):
                r.steps.append((True, item.target, "应用已自行退出，无需强制结束"))
                emit(f"{item.target}：应用已自行退出（显存与内存由系统回收）")
            else:
                allowed = bool(confirm_force_fn and confirm_force_fn(pid, item.target))
                if allowed:
                    ok, detail2 = winapi.force_kill(pid)
                    r.steps.append((ok, item.target, f"二次确认后：{detail2}"))
                    emit(f"{item.target}：二次确认后 {detail2}")
                else:
                    r.steps.append((False, item.target, "优雅关闭后进程仍在运行；未获得强制结束的二次确认，已保留该进程"))
                    r.warnings.append(f"{item.target} 未退出，且未获二次确认，程序没有强制结束它（这是有意的安全行为）")
                    emit(f"{item.target}：已保留，未强制结束")
            try:
                current = probe()
            except Exception as exc:  # noqa: BLE001
                r.warnings.append(f"复测失败：{exc}")

    try:
        final = collect_fn()
    except Exception:  # noqa: BLE001
        final = current
    r.after_used = final.used_phys
    r.after_avail = final.avail_phys
    r.gpu_after_mb = final.gpu_used_total()
    r.finished = time.time()
    if not r.stopped_reason:
        r.stopped_reason = "计划项全部执行完毕"
    if r.released_bytes < 0:
        r.warnings.append("复测显示物理内存占用反而上升（可能有新进程分配内存），这不代表操作失败，请以逐项结果为准")
    for it in plan.skipped[:30]:
        log.write("跳过", f"{it.target}：{it.reason}", level="info")
    log.write(
        "释放结果",
        f"L{plan.level} 完成，已用 {fmt_bytes(r.before_used)} → {fmt_bytes(r.after_used)}，{r.stopped_reason}",
        level="ok", level_no=plan.level, auto=plan.auto,
        steps=len(r.steps), released_bytes=r.released_bytes,
    )
    return r
