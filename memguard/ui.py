"""中文桌面界面：概览 / 锚点 / 释放 / 保护与设置 / 日志与说明。

所有会改变系统状态的操作都必须经过「干运行预览 → 显式确认 → 执行」三步；
L3 在关闭进程前还有第二次全局确认，强制结束前再有一次逐进程确认。
"""
from __future__ import annotations

import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from . import winapi
from .collector import MB, fmt_bytes, fmt_mb
from .config import CRITICAL_PROCESSES
from .engine import Engine
from .tray import Tray

FONT = ("Microsoft YaHei", 10)
FONT_B = ("Microsoft YaHei", 11, "bold")
MONO = ("Consolas", 10)

HELP_TEXT = """【这个程序解决什么问题】
AI 软件退出后显存/内存没及时归还、打开大量文件后可用内存长期偏低。Windows 把文件缓存放在「备用列表」里，
并把进程暂时不用的物理页留在工作集中，这些都不会自动立刻归还；另外有些 AI 进程（Python / ollama / ComfyUI 等）
主窗口关了但进程还在，显存就一直被占着。

【重要事实：不要被「一键释放几个 GB」骗了】
· Windows 没有通用的「清空显存」接口。显存由持有它的进程经 GPU 驱动分配，只能由该进程释放。
  本程序的 L3 是「列出占用进程 → 你逐项勾选 → 先发 WM_CLOSE 让应用保存 → 超时后再确认才强制结束」。
· L1 裁剪工作集只是把物理页换出到页面文件，可用物理内存会上升，但提交内存不变、进程也没结束。
  切回被裁剪的应用时可能出现短暂卡顿，属于正常现象。
· 进程私有内存（提交内存）只能靠结束进程释放，自动流程永远不会这么做。

【指标含义】
· 物理内存已用 / 可用：GlobalMemoryStatusEx 的实时值，是本程序释放效果的主要观测口径。
· 提交内存 / 提交上限：所有进程申请的地址空间总量与其上限；L1/L2 不会改变它。
· 页面文件可用：换出物理页需要的空间。低于设置下限时程序会拒绝执行，避免制造更严重的内存压力。
· 系统缓存 / 备用列表：可丢弃的文件缓存页，L2 清理的就是这部分。
· 专用显存 / 共享显存：专用是显卡板载显存；共享显存本质是系统内存，会随内存释放间接改善。
· 工作集：进程当前占用的物理内存；提交量（PrivateUsage）：进程申请且不与其他进程共享的内存。
· 无法读取：某些计数器在部分系统/驱动上不存在，程序显示「无法读取」而不是伪造 0。

【四个执行级别】
· L0 只读观测：只显示指标与建议，不改变系统。
· L1 工作集裁剪：对不在保护名单的进程调用 EmptyWorkingSet；自动流程的默认上限，绝不结束进程。
· L2 清理备用列表：与 RAMMap「Empty Standby List」同原理，需管理员 + SeProfileSingleProcessPrivilege；只允许手动。
· L3 关闭占用进程：显存释放的唯一有效路径；只允许手动、必须逐项勾选、默认全不选中、先优雅关闭、超时后二次确认才强制结束。

【锚点规则】
锚点 = 某一时刻的完整快照（内存全量指标 + Top 进程 + 每块显卡显存 + 开机时间 + 采集说明）。
自动锚点只在「系统空闲且可用内存健康」时记录；首次运行、以及每次开机检测到旧锚点时，
都会自动建立「本次开机基线」（旧锚点保留在历史里，不删除）；也可随时手动设置。
释放目标 = 锚点时已用物理内存 + 容差；超出量 = 当前已用 − 目标。
程序只为超出量组织动作，每执行一项立即复测，回到目标即停，不会无目标地反复清空缓存。
锚点超过保留天数会提示并暂停自动释放，系统空闲健康时可自动续期，也可手动重设；
物理内存总量变化时对比仅供参考。

【自动释放的触发与闸门】
必须同时满足：可用内存低于阈值 + 超出锚点达到阈值 + 锚点有效且新鲜。
前置检查包括：全局暂停开关、冷却期、开机时间、页面文件余量、CPU/磁盘忙闲、用户是否正在操作、
单实例、执行级别硬上限。任一项不通过就跳过，并把原因写进日志与界面，不会「勉强执行」。

【为什么有时执行后数字没降】
· 有新进程正在分配内存；
· 备用列表/缓存已被系统自行回收，本来就没有多少可清；
· 受保护进程太多，计划里没有可执行的项；
· 你看到的「已用」是物理内存，而被清的是缓存页或已换出的页。
每次执行都给出前后对比、逐项结果与停止原因，请以这些为准，不要只看一个数字。

【安全声明】
· 不修改页面文件大小、不重启系统、不写注册表关键项、不联网、不上传任何数据。
· 系统关键进程、程序自身、杀软与用户保护名单一律跳过；硬保护名单不允许从界面移除。
· 自动流程硬编码止于 L1，任何配置都无法让它自动结束进程。
· 干运行预览 3 分钟后自动失效；执行前会用新快照重新核对每个目标进程的身份与保护状态，
  PID 被复用、进程已退出或新变为受保护时，该项会被跳过并写明原因，绝不沿用旧确认盲目动作。
· 配置文件里的非法/越界参数会自动收敛到合法区间，界面会回显真正生效的值。
· 所有动作、跳过项、失败原因、权限状态都写入审计日志，可导出、可清理。
· 数据只放在 %LOCALAPPDATA%\\MemGuard 下（config.json / anchors.json / audit.log）。

【常见问题】
Q：L2 提示需要管理员？ A：右键程序或快捷方式「以管理员身份运行」，清理备用列表属于系统级操作。
Q：显存显示「无法读取」？ A：可能没有 NVIDIA 驱动或系统未提供 GPU 计数器；程序改用 PDH 计数器，仍读不到会如实说明，此时 L3 需要你自行核对进程。
Q：托盘图标没出现？ A：缺少可选的 pystray/Pillow，程序仍在任务栏正常运行，功能不受影响。
Q：想彻底释放某个 AI 进程？ A：到「释放」页选 L3，勾选该进程，执行并确认；注意未保存的模型输出/任务会丢失。
"""

SETTING_FIELDS = [
    ("auto_release_enabled", "自动释放总开关", "bool"),
    ("auto_anchor_enabled", "空闲时自动设置锚点", "bool"),
    ("tray_enabled", "启用托盘（重启后生效）", "bool"),
    ("show_toast", "显示气泡提示", "bool"),
    ("allow_l2_manual", "允许手动 L2 清备用列表", "bool"),
    ("allow_l3_manual", "允许手动 L3 关闭进程", "bool"),
    ("skip_windowed_for_auto", "自动 L1 跳过有窗口进程", "bool"),
    ("skip_when_foreground", "用户正在操作时跳过自动", "bool"),
    ("poll_sec", "自动巡检周期（秒）", "int"),
    ("cooldown_min", "自动释放冷却（分钟）", "int"),
    ("trigger_avail_pct", "触发：可用内存低于（%）", "float"),
    ("trigger_over_anchor_mb", "触发：超出锚点至少（MB）", "int"),
    ("tolerance_mb", "内存锚点容差（MB）", "int"),
    ("gpu_tolerance_mb", "显存锚点容差（MB）", "int"),
    ("user_idle_min", "用户空闲判定（分钟）", "float"),
    ("auto_anchor_idle_min", "自动锚点空闲（分钟）", "int"),
    ("min_pagefile_avail_mb", "页面文件可用下限（MB）", "int"),
    ("close_wait_sec", "L3 优雅关闭等待（秒）", "int"),
    ("log_days", "日志保留（天）", "int"),
    ("gpu_probe_enabled", "启用显存采集", "bool"),
    ("nvidia_smi_enabled", "尝试用 nvidia-smi 读显存", "bool"),
]


class App:
    def __init__(self, engine: Engine, enable_tray: bool = True):
        self.engine = engine
        self.root = tk.Tk()
        self.root.title("MemGuard 内存锚点管家 v1.0")
        self.root.geometry("1120x760")
        self.root.minsize(980, 640)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.snap = None
        self.diff = None
        self.plan = None
        self.pf = None
        self.sel_pids: set[int] = set()
        self._toast_win: tk.Toplevel | None = None
        self._busy = False

        self._build()
        self.tray = Tray(self) if (enable_tray and self.engine.cfg.tray_enabled) else None
        if self.tray is None:
            self._tray_reason = "本次启动未启用托盘（程序仍在任务栏正常运行）"
        else:
            self._tray_reason = self.tray.reason
        self.engine.log.write("界面", f"主界面已启动；{self._tray_reason}", level="info")

        self.refresh(silent=True)
        self.root.after(600, self._poll_messages)
        if self.engine.cfg.auto_release_enabled:
            self.engine.start_auto()

    # ---------------------------------------------------------------- 构建

    def _build(self) -> None:
        hdr = ttk.Frame(self.root)
        hdr.pack(fill="x", padx=10, pady=8)
        ttk.Label(hdr, text="MemGuard 内存锚点管家", font=("Microsoft YaHei", 14, "bold")).pack(side="left")
        self.lbl_perm = ttk.Label(hdr, text="权限：检测中", font=FONT)
        self.lbl_perm.pack(side="left", padx=14)
        self.lbl_auto = ttk.Label(hdr, text="自动：检测中", font=FONT)
        self.lbl_auto.pack(side="left", padx=6)
        for text, cmd in (
            ("退出", self.quit_app),
            ("刷新", lambda: self.refresh()),
            ("设为锚点", lambda: self.on_set_anchor()),
            ("暂停 / 恢复自动", self.toggle_pause),
        ):
            ttk.Button(hdr, text=text, command=cmd).pack(side="right", padx=3)

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=4)
        self._tab_overview()
        self._tab_anchors()
        self._tab_release()
        self._tab_settings()
        self._tab_log()

        self.status = ttk.Label(self.root, text="就绪", relief="sunken", anchor="w", font=FONT, padding=(6, 3))
        self.status.pack(fill="x", side="bottom")

    def _text(self, parent, height: int = 10) -> tk.Text:
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True)
        t = tk.Text(box, height=height, wrap="word", font=FONT, background="#ffffff",
                    foreground="#1f2937", relief="flat", padx=8, pady=6)
        sb = ttk.Scrollbar(box, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        return t

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _append_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.insert("end", "\n\n" + text)
        widget.see("end")
        widget.configure(state="disabled")

    def _tab_overview(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  概览  ")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ringbox = ttk.LabelFrame(top, text="占用概览")
        ringbox.pack(side="left", fill="y", padx=(4, 6), pady=4)
        self.cv = tk.Canvas(ringbox, width=340, height=176, bg="#ffffff", highlightthickness=0)
        self.cv.pack(padx=6, pady=6)
        infobox = ttk.LabelFrame(top, text="实时指标与采集说明（悬停说明见「日志与说明」页）")
        infobox.pack(side="left", fill="both", expand=True, padx=6, pady=4)
        self.txt_info = self._text(infobox, height=10)

        mid = ttk.LabelFrame(f, text="锚点对比与释放判定")
        mid.pack(fill="both", padx=6, pady=4)
        self.txt_diff = self._text(mid, height=9)

        bottom = ttk.LabelFrame(f, text="进程（按工作集排序，受保护项不会被动到）")
        bottom.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("name", "pid", "ws", "private", "gpu", "window", "protect")
        self.tree_procs = ttk.Treeview(bottom, columns=cols, show="headings", height=10)
        for c, label, w in (
            ("name", "进程", 190), ("pid", "PID", 70), ("ws", "工作集", 100),
            ("private", "提交量", 100), ("gpu", "显存", 90), ("window", "窗口标题", 260),
            ("protect", "保护状态", 190),
        ):
            self.tree_procs.heading(c, text=label)
            self.tree_procs.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(bottom, command=self.tree_procs.yview)
        self.tree_procs.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree_procs.pack(side="left", fill="both", expand=True)

    def _tab_anchors(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  锚点  ")
        bar = ttk.Frame(f)
        bar.pack(fill="x", padx=6, pady=6)
        for text, cmd in (
            ("手动设为锚点", lambda: self.on_set_anchor()),
            ("设为当前", self.on_set_current),
            ("重命名", self.on_rename),
            ("删除", self.on_remove),
            ("导出锚点", self.on_export_anchors),
        ):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)
        ttk.Label(bar, text="锚点只是参照快照，不修改系统状态", foreground="#475569", font=FONT).pack(side="right")

        cols = ("cur", "name", "time", "source", "used", "gpu")
        self.tree_anchors = ttk.Treeview(f, columns=cols, show="headings", height=9)
        for c, label, w in (
            ("cur", "当前", 50), ("name", "名称", 230), ("time", "创建时间", 160),
            ("source", "来源", 150), ("used", "锚点时物理内存已用", 170), ("gpu", "锚点专用显存", 150),
        ):
            self.tree_anchors.heading(c, text=label)
            self.tree_anchors.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(f, command=self.tree_anchors.yview)
        self.tree_anchors.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree_anchors.pack(fill="x", padx=6, pady=4)

        box = ttk.LabelFrame(f, text="当前锚点详情与完整对比说明")
        box.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_anchor_detail = self._text(box, height=14)

    def _tab_release(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  释放  ")
        ctrl = ttk.LabelFrame(f, text="第一步：选择级别并生成干运行预览（此步绝不改变系统状态）")
        ctrl.pack(fill="x", padx=6, pady=6)
        self.var_level = tk.IntVar(value=1)
        for v, label in (
            (1, "L1 工作集裁剪（温和，自动流程的上限）"),
            (2, "L2 清理备用列表 / 文件缓存（需管理员，仅手动）"),
            (3, "L3 关闭占用显存的进程（仅手动，需逐项勾选 + 多次确认）"),
        ):
            ttk.Radiobutton(ctrl, text=label, value=v, variable=self.var_level,
                            command=self._on_level_change).pack(anchor="w", padx=8, pady=1)
        row = ttk.Frame(ctrl)
        row.pack(fill="x", padx=8, pady=4)
        self.var_ignore = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="不受锚点限制（完全清理；默认关闭，建议保持锚点约束）",
                        variable=self.var_ignore).pack(side="left")
        ttk.Button(row, text="生成干运行预览", command=self.on_preview).pack(side="right", padx=4)
        self.btn_exec = ttk.Button(row, text="执行释放（需先预览）", command=self.on_execute, state="disabled")
        self.btn_exec.pack(side="right", padx=4)

        self.lbl_level_hint = ttk.Label(ctrl, text="", foreground="#854F0B", font=FONT, wraplength=1000)
        self.lbl_level_hint.pack(fill="x", padx=8, pady=(0, 4))
        self._on_level_change()

        mid = ttk.LabelFrame(f, text="第二步：预览 / 前置检查 / 执行结果")
        mid.pack(fill="both", expand=True, padx=6, pady=4)
        self.txt_preview = self._text(mid, height=12)

        selbox = ttk.LabelFrame(f, text="L3 进程勾选区（默认全部不选中；点击第一列切换；受保护项不可选）")
        selbox.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("sel", "name", "pid", "gpu", "ws", "title", "protect")
        self.tree_sel = ttk.Treeview(selbox, columns=cols, show="headings", height=9, selectmode="none")
        for c, label, w in (
            ("sel", "勾选", 56), ("name", "进程", 190), ("pid", "PID", 70),
            ("gpu", "显存占用", 100), ("ws", "工作集", 100), ("title", "窗口标题", 280),
            ("protect", "保护状态", 190),
        ):
            self.tree_sel.heading(c, text=label)
            self.tree_sel.column(c, width=w, anchor="w")
        self.tree_sel.bind("<Button-1>", self._on_sel_click)
        sb = ttk.Scrollbar(selbox, command=self.tree_sel.yview)
        self.tree_sel.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree_sel.pack(side="left", fill="both", expand=True)

    def _tab_settings(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  保护与设置  ")
        left = ttk.LabelFrame(f, text="保护名单（这些进程任何级别都不会被动到）")
        left.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        self.lst_protect = tk.Listbox(left, height=12, font=FONT)
        self.lst_protect.pack(fill="both", expand=True, padx=6, pady=4)
        row = ttk.Frame(left)
        row.pack(fill="x", padx=6, pady=3)
        self.var_new_protect = tk.StringVar()
        ttk.Entry(row, textvariable=self.var_new_protect, width=24).pack(side="left")
        ttk.Button(row, text="添加", command=self.on_add_protect).pack(side="left", padx=3)
        ttk.Button(row, text="移除选中", command=self.on_del_protect).pack(side="left", padx=3)
        hard = ttk.LabelFrame(left, text="硬保护名单（系统关键进程，不可移除）")
        hard.pack(fill="both", expand=True, padx=6, pady=6)
        t = tk.Text(hard, height=7, wrap="word", font=FONT, background="#f8fafc")
        t.insert("1.0", "、".join(sorted(CRITICAL_PROCESSES)))
        t.configure(state="disabled")
        sb = ttk.Scrollbar(hard, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)

        right = ttk.LabelFrame(f, text="设置（修改后点击保存；自动上限恒为 L1，不可调高）")
        right.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        grid = ttk.Frame(right)
        grid.pack(fill="both", expand=True, padx=6, pady=4)
        self.setting_vars: dict[str, Any] = {}
        for i, (key, label, kind) in enumerate(SETTING_FIELDS):
            c, r = divmod(i, 11)
            ttk.Label(grid, text=label, font=FONT).grid(row=r, column=c * 2, sticky="w", padx=4, pady=2)
            if kind == "bool":
                var: Any = tk.BooleanVar(value=bool(getattr(self.engine.cfg, key)))
                ttk.Checkbutton(grid, variable=var).grid(row=r, column=c * 2 + 1, sticky="w")
            else:
                var = tk.StringVar(value=str(getattr(self.engine.cfg, key)))
                ttk.Entry(grid, textvariable=var, width=9).grid(row=r, column=c * 2 + 1, sticky="w", pady=2)
            self.setting_vars[key] = (var, kind)
        bar = ttk.Frame(right)
        bar.pack(fill="x", padx=6, pady=6)
        ttk.Button(bar, text="保存设置", command=self.on_save_settings).pack(side="left", padx=3)
        ttk.Button(bar, text="恢复默认值", command=self.on_reset_settings).pack(side="left", padx=3)
        self.lbl_env = ttk.Label(right, text="", font=FONT, foreground="#475569", wraplength=480, justify="left")
        self.lbl_env.pack(fill="x", padx=6, pady=4)

    def _tab_log(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  日志与说明  ")
        bar = ttk.Frame(f)
        bar.pack(fill="x", padx=6, pady=6)
        ttk.Button(bar, text="刷新日志", command=self.on_refresh_log).pack(side="left", padx=3)
        ttk.Button(bar, text="导出日志", command=self.on_export_log).pack(side="left", padx=3)
        ttk.Button(bar, text="清理过期日志", command=self.on_purge_log).pack(side="left", padx=3)
        ttk.Label(bar, text="所有动作、跳过原因、错误与权限状态都记录在这里", font=FONT,
                  foreground="#475569").pack(side="right")
        logbox = ttk.LabelFrame(f, text="审计日志（最新在上）")
        logbox.pack(fill="both", expand=True, padx=6, pady=4)
        self.txt_log = self._text(logbox, height=12)
        helpbox = ttk.LabelFrame(f, text="使用说明 / 指标解释 / 安全声明")
        helpbox.pack(fill="both", expand=True, padx=6, pady=4)
        self.txt_help = self._text(helpbox, height=12)
        self._set_text(self.txt_help, HELP_TEXT)

    # ---------------------------------------------------------------- 绘制

    def _ring(self, cx: int, cy: int, r: int, pct: float | None, color: str, title: str, sub: str) -> None:
        self.cv.create_oval(cx - r, cy - r, cx + r, cy + r, outline="#e5e7eb", width=12)
        if pct is not None:
            pct = max(0.0, min(100.0, pct))
            if pct > 0.2:
                self.cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=90,
                                   extent=-3.6 * pct, style="arc", outline=color, width=12)
        self.cv.create_text(cx, cy - 24, text=title, font=("Microsoft YaHei", 10), fill="#475569")
        self.cv.create_text(cx, cy + 2, text=("无法读取" if pct is None else f"{pct:.0f}%"),
                            font=("Microsoft YaHei", 17, "bold"), fill=color)
        self.cv.create_text(cx, cy + 28, text=sub, font=("Microsoft YaHei", 9), fill="#64748b")

    def _draw_rings(self, snap) -> None:
        self.cv.delete("all")
        mem_pct = snap.used_phys / snap.total_phys * 100.0 if snap.total_phys else None
        total_gpu = sum(g.dedicated_total_mb or 0 for g in snap.gpus)
        used_gpu = snap.gpu_used_total()
        gpu_pct = (used_gpu / total_gpu * 100.0) if total_gpu > 0 else None
        self._ring(88, 88, 62, mem_pct, "#185FA5", "物理内存",
                   f"{fmt_bytes(snap.used_phys)} / {fmt_bytes(snap.total_phys)}")
        self._ring(252, 88, 62, gpu_pct, "#0F6E56", "专用显存",
                   (f"{used_gpu:,.0f} / {total_gpu:,.0f} MB" if total_gpu > 0 else
                    (f"已用 {used_gpu:,.0f} MB" if snap.gpus else "无法读取")))

    def _paint(self, snap, diff) -> None:
        from .collector import describe
        self.snap, self.diff = snap, diff
        self.lbl_perm.configure(text=f"权限：{'管理员（L2 可用）' if snap.is_admin else '标准用户（L2 不可用）'}")
        auto_txt = "自动：运行中" if self.engine.running else "自动：已停止"
        if self.engine.cfg.paused:
            auto_txt += "｜已暂停"
        if self.engine.last_action_ts:
            rest = self.engine.cfg.cooldown_min * 60 - (time.time() - self.engine.last_action_ts)
            if rest > 0:
                auto_txt += f"｜冷却 {rest / 60:.1f} 分"
        self.lbl_auto.configure(text=auto_txt)
        self._draw_rings(snap)

        lines = describe(snap)
        if snap.gpus:
            for g in snap.gpus:
                lines.append(f"  · {g.name}：专用 {g.usage_text()}，共享 {fmt_mb(g.shared_used_mb)}（来源 {g.source}）")
        lines.append(f"显存采集说明：{snap.gpu_note}")
        lines.append(f"备用列表：{snap.standby_note}")
        lines.append(f"前台窗口：{snap.foreground_title or '无'}（PID {snap.foreground_pid}）")
        if snap.notes:
            lines.append("采集降级/提示：")
            lines += [f"  ! {n}" for n in snap.notes]
        self._set_text(self.txt_info, "\n".join(lines))

        self._set_text(self.txt_diff, diff.as_text())
        self._paint_anchor_detail(diff)
        self._paint_procs(snap)
        self._paint_sel(snap)
        self._paint_anchors()
        self.lbl_env.configure(
            text=f"数据目录：{self.engine.data_dir}\n权限：{'管理员' if snap.is_admin else '标准用户'}\n"
                 f"托盘：{getattr(self, '_tray_reason', '未初始化')}\n"
                 f"自动上限：L1（硬编码，配置无法突破）｜L2/L3 永远只能手动",
        )
        self._set_status(f"状态已更新于 {datetime.now().strftime('%H:%M:%S')}｜{diff.verdict}")

    def _paint_procs(self, snap) -> None:
        self.tree_procs.delete(*self.tree_procs.get_children())
        for p in sorted(snap.procs, key=lambda x: x.ws, reverse=True)[:80]:
            self.tree_procs.insert("", "end", values=(
                p.name or "<无法读取>", p.pid, fmt_bytes(p.ws), fmt_bytes(p.private),
                fmt_mb(p.gpu_mb) if p.gpu_mb else "-",
                (p.title[:38] if p.title else "-"),
                p.protect_reason or "可触及",
            ))

    def _paint_sel(self, snap) -> None:
        alive = {p.pid for p in snap.procs}
        self.sel_pids = {p for p in self.sel_pids if p in alive}
        self.tree_sel.delete(*self.tree_sel.get_children())
        procs = sorted(snap.procs, key=lambda x: (-x.gpu_mb, -x.ws))
        for p in procs[:120]:
            self.tree_sel.insert("", "end", iid=str(p.pid), values=(
                "☑" if p.pid in self.sel_pids else "☐",
                p.name or "<无法读取>", p.pid,
                fmt_mb(p.gpu_mb) if p.gpu_mb else "-",
                fmt_bytes(p.ws), (p.title[:38] if p.title else "-"),
                ("受保护：" + p.protect_reason) if p.protected else "可勾选",
            ))

    def _paint_anchors(self) -> None:
        self.tree_anchors.delete(*self.tree_anchors.get_children())
        cur = self.engine.store.current_id
        for a in reversed(self.engine.store.items):
            self.tree_anchors.insert("", "end", iid=a.id, values=(
                "★" if a.id == cur else "", a.name, a.time_text(), a.source_text(),
                a.used_text(), a.gpu_text(),
            ))
        if cur:
            try:
                self.tree_anchors.selection_set(cur)
            except Exception:  # noqa: BLE001
                pass

    def _paint_anchor_detail(self, diff) -> None:
        if not diff.anchor:
            self._set_text(self.txt_anchor_detail, "当前没有锚点。点击「手动设为锚点」建立基线。\n\n" + diff.as_text())
            return
        c = diff.anchor.compact
        lines = [
            f"当前锚点：{diff.anchor.name}（{diff.anchor.source_text()}，{diff.anchor.time_text()}）",
            f"有效性：{'有效' if diff.valid else '失效'}｜新鲜度：{'新鲜' if diff.fresh else '过期/需重设'}｜{diff.reason or '无异常'}",
            "",
            f"锚点时物理内存：已用 {fmt_bytes(c.get('used_phys', 0))} / 总量 {fmt_bytes(c.get('total_phys', 0))}，可用 {fmt_bytes(c.get('avail_phys', 0))}",
            f"锚点时提交内存：{fmt_bytes(c.get('commit_total', 0))} / 上限 {fmt_bytes(c.get('commit_limit', 0))}",
            f"锚点时系统缓存：{fmt_bytes(c.get('system_cache', 0))}；备用列表：{fmt_bytes(c.get('standby_bytes'))}",
            f"锚点时专用显存合计：{fmt_mb(c.get('gpu_used_total_mb', 0.0))}",
            "",
            "锚点时占用最高的进程：",
        ]
        for p in c.get("top_procs", [])[:10]:
            lines.append(f"  · {p.get('name', '?')} (PID {p.get('pid')})：工作集 {fmt_bytes(p.get('ws', 0))}，显存 {fmt_mb(p.get('gpu_mb'))}")
        lines += ["", "—— 完整对比 ——", diff.as_text()]
        self._set_text(self.txt_anchor_detail, "\n".join(lines))

    # ---------------------------------------------------------------- 交互

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text[:300])

    def _run_async(self, work, done, quiet: bool = False) -> None:
        if self._busy:
            if not quiet:
                messagebox.showinfo("请稍候", "上一个操作还在进行中。")
            return
        self._busy = True
        self._set_status("正在处理，请稍候…")

        def runner():
            try:
                res = work()
            except Exception as exc:  # noqa: BLE001
                res = exc
            self.root.after(0, lambda: self._finish(done, res))

        threading.Thread(target=runner, daemon=True, name="MemGuard-Work").start()

    def _finish(self, done, res) -> None:
        self._busy = False
        try:
            done(res)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("界面错误", f"{type(exc).__name__}: {exc}")

    def refresh(self, silent: bool = False) -> None:
        if not silent:
            self._set_status("正在采集系统状态（含显存计数器）…")
        self._run_async(
            lambda: self.engine.refresh(),
            lambda res: messagebox.showerror("采集失败", str(res)) if isinstance(res, Exception)
            else self._paint(*res),
            quiet=True,
        )

    def on_set_anchor(self, name: str = "", source: str = "manual") -> None:
        ok, msg = self.engine.set_anchor(name, source)
        self._set_status(msg)
        self.refresh(silent=True)
        if source == "manual":
            messagebox.showinfo("锚点已设置", msg)

    def _selected_anchor_id(self) -> str | None:
        sel = self.tree_anchors.selection()
        return sel[0] if sel else None

    def on_set_current(self) -> None:
        aid = self._selected_anchor_id()
        if not aid:
            messagebox.showwarning("提示", "请先在列表中选择一个锚点。")
            return
        ok, msg = self.engine.store.set_current(aid)
        self._set_status(msg)
        self.refresh(silent=True)

    def on_rename(self) -> None:
        aid = self._selected_anchor_id()
        if not aid:
            messagebox.showwarning("提示", "请先选择锚点。")
            return
        name = simpledialog.askstring("重命名锚点", "输入新名称：")
        if name:
            _, msg = self.engine.store.rename(aid, name)
            self._set_status(msg)
            self.refresh(silent=True)

    def on_remove(self) -> None:
        aid = self._selected_anchor_id()
        if not aid:
            messagebox.showwarning("提示", "请先选择锚点。")
            return
        if not messagebox.askyesno("确认删除", "确定删除这个锚点吗？此操作只删除参照快照，不影响系统内存状态。"):
            return
        _, msg = self.engine.store.remove(aid)
        self._set_status(msg)
        self.refresh(silent=True)

    def on_export_anchors(self) -> None:
        path = filedialog.asksaveasfilename(title="导出锚点", defaultextension=".json",
                                            filetypes=[("JSON 文件", "*.json")],
                                            initialfile="memguard_anchors.json")
        if not path:
            return
        ok, msg = self.engine.export_anchors(Path(path))
        messagebox.showinfo("导出锚点", msg)
        self._set_status(msg)

    def _on_level_change(self) -> None:
        hints = {
            1: "L1：只把物理页换出到页面文件，进程继续运行；自动流程默认上限，绝不结束进程。",
            2: "L2：清理备用列表/文件缓存，需要管理员权限；只可手动执行，清缓存后短时磁盘读取会增多。",
            3: "L3：显存的唯一释放路径。默认不勾选任何进程；执行前需两次全局确认，强制结束前还有逐进程确认。未保存内容可能丢失。",
        }
        self.lbl_level_hint.configure(text=hints.get(self.var_level.get(), ""))

    def _on_sel_click(self, event) -> None:
        if self.tree_sel.identify_column(event.x) != "#1":
            return
        item = self.tree_sel.identify_row(event.y)
        if not item or not self.snap:
            return
        pid = int(item)
        proc = next((p for p in self.snap.procs if p.pid == pid), None)
        if proc is None:
            return
        if proc.protected:
            messagebox.showwarning("不可勾选", f"{proc.label()} 不能勾选：{proc.protect_reason}")
            return
        if pid in self.sel_pids:
            self.sel_pids.discard(pid)
        else:
            self.sel_pids.add(pid)
        self._paint_sel(self.snap)
        self._set_status(f"已勾选 {len(self.sel_pids)} 个进程；只有这些进程才可能被关闭")

    def on_preview(self) -> None:
        level = self.var_level.get()
        pids = sorted(self.sel_pids) if level == 3 else []
        ignore = bool(self.var_ignore.get())
        self._set_status("正在生成干运行预览（不会改变系统状态）…")
        self._run_async(
            lambda: self.engine.manual_preview(level, pids, ignore),
            lambda res: self._done_preview(res),
        )

    def _done_preview(self, res) -> None:
        if isinstance(res, Exception):
            messagebox.showerror("预览失败", str(res))
            return
        snap, diff, pf, plan = res
        self.snap, self.diff, self.pf, self.plan = snap, diff, pf, plan
        text = (
            "【前置检查】\n" + pf.summary() +
            "\n\n【锚点对比】\n" + diff.as_text() +
            "\n\n【干运行预览 · 尚未执行任何动作】\n" + plan.preview_text()
        )
        self._set_text(self.txt_preview, text)
        self.btn_exec.configure(state="normal" if (pf.allowed and plan.items) else "disabled")
        stamp = datetime.fromtimestamp(plan.created_ts).strftime("%H:%M:%S")
        self._set_status(
            ("预览通过，确认无误后点击「执行释放」" if pf.allowed else "前置检查未通过，执行按钮已禁用：") +
            ("；" + pf.summary() if not pf.allowed else "") +
            f"｜预览生成于 {stamp}，超过 3 分钟需重新预览；执行前会再核对进程身份"
        )
        self.engine.log.write("干运行预览", f"界面生成 L{self.var_level.get()} 预览：{len(plan.items)} 项动作，{len(plan.skipped)} 项跳过", level="info")

    def _confirm_force(self, pid: int, target: str) -> bool:
        box: dict[str, bool] = {}
        ev = threading.Event()

        def ask():
            box["ok"] = messagebox.askyesno(
                "强制结束的二次确认",
                f"{target} 收到关闭消息后仍未退出。\n\n是否强制结束该进程？\n\n"
                "警告：应用里未保存的内容会丢失。选择「否」则完整保留该进程，程序不会做任何强制操作。",
            )
            ev.set()

        self.root.after(0, ask)
        ev.wait(timeout=90)
        return bool(box.get("ok"))

    def on_execute(self) -> None:
        if self.plan is None or self.pf is None:
            messagebox.showwarning("提示", "请先生成干运行预览。")
            return
        level = self.var_level.get()
        pids = sorted(self.sel_pids) if level == 3 else []
        ignore = bool(self.var_ignore.get())
        n = len(self.plan.items)
        if level == 3:
            if not pids:
                messagebox.showwarning("未勾选进程", "L3 必须先在下方勾选要关闭的进程，默认全部不选中。")
                return
            names = "\n".join(f"  · {it.target}" for it in self.plan.items[:15])
            if not messagebox.askyesno(
                "第一次确认 · 关闭进程",
                f"即将处理 {n} 个进程：\n{names}\n\n这些进程可能被关闭，未保存的内容可能丢失。\n"
                "程序会先发送关闭消息让应用保存。确定继续吗？",
            ):
                return
            if not messagebox.askyesno(
                "第二次确认 · 再次核对",
                "请再次核对上面的进程列表。\n\n确认后程序才会开始发送关闭消息；"
                "对超时未退出的进程，还会再单独询问一次是否强制结束。",
            ):
                return
        elif level == 2:
            if not messagebox.askyesno(
                "确认执行 L2",
                f"将清理系统备用列表（当前约 {fmt_bytes(self.plan.estimated_release_bytes)} 可清缓存）。\n\n"
                "需要管理员权限；清理后短时间重新打开大文件会有更多磁盘读取。确定继续吗？",
            ):
                return
        else:
            if not messagebox.askyesno(
                "确认执行 L1",
                f"将按预览裁剪 {n} 个进程的工作集。\n\n进程不会被结束，但切回这些应用时可能短暂卡顿。确定继续吗？",
            ):
                return

        self._set_status(f"正在执行 L{level}（沿用已确认的预览计划，并复核进程身份）…")
        confirmed_plan = self.plan
        self._run_async(
            lambda: self.engine.manual_execute(level, pids, ignore, self._confirm_force, confirmed_plan),
            self._done_execute,
        )

    def _done_execute(self, res) -> None:
        if isinstance(res, Exception):
            messagebox.showerror("执行异常", str(res))
            return
        ok, result, plan, diff = res
        if ok:
            text = "【执行结果】\n" + result.report_text()
            self._append_text(self.txt_preview, text)
            messagebox.showinfo("执行完成", f"{result.stopped_reason}\n\n完整结果见「释放」页。")
        else:
            self._append_text(self.txt_preview, "【未执行】\n" + str(result))
            messagebox.showwarning("未执行", str(result))
        self.btn_exec.configure(state="disabled")
        self.plan = None
        self._set_status("执行结束，正在刷新状态…")
        self.refresh(silent=True)

    # ---------------------------------------------------------------- 设置 / 日志

    def on_add_protect(self) -> None:
        name = self.var_new_protect.get().strip()
        if not name:
            return
        lst = list(self.engine.cfg.protect_list)
        if name.lower() not in {x.lower() for x in lst}:
            lst.append(name)
            self.engine.update_config({"protect_list": lst})
        self.var_new_protect.set("")
        self._paint_protect_list()
        self._set_status(f"已加入保护名单：{name}（下次采集生效）")

    def on_del_protect(self) -> None:
        sel = self.lst_protect.curselection()
        if not sel:
            return
        name = self.lst_protect.get(sel[0])
        lst = [x for x in self.engine.cfg.protect_list if x.lower() != name.lower()]
        self.engine.update_config({"protect_list": lst})
        self._paint_protect_list()
        self._set_status(f"已从保护名单移除：{name}（请确认该进程没有未保存工作）")

    def _paint_protect_list(self) -> None:
        self.lst_protect.delete(0, "end")
        for n in self.engine.cfg.protect_list:
            self.lst_protect.insert("end", n)

    def on_save_settings(self) -> None:
        patch: dict[str, Any] = {}
        for key, (var, kind) in self.setting_vars.items():
            try:
                patch[key] = (bool(var.get()) if kind == "bool" else
                              (float(var.get()) if kind == "float" else int(var.get())))
            except ValueError:
                messagebox.showerror("设置无效", f"{key} 需要填写数字")
                return
        changed, msg = self.engine.update_config(patch)
        # 配置层会把非法/越界值收敛；界面必须回显真正生效的值，不能让输入框撒谎。
        corrected = []
        for key, (var, kind) in self.setting_vars.items():
            real = getattr(self.engine.cfg, key)
            shown = bool(var.get()) if kind == "bool" else (
                float(var.get()) if kind == "float" else int(var.get()))
            if shown != real:
                var.set(real if kind == "bool" else str(real))
                corrected.append(f"{key}: {shown} → {real}")
        tail = ("\n\n以下值超出合法范围，已自动收敛为：" + "；".join(corrected)) if corrected else ""
        self._set_status(f"设置已保存：{', '.join(changed) or '无变更'}｜{msg}")
        messagebox.showinfo(
            "设置已保存",
            f"已修改：{', '.join(changed) or '无变更'}\n{msg}\n\n"
            "巡检周期与总开关即时生效；托盘需重启程序。" + tail,
        )

    def on_reset_settings(self) -> None:
        if not messagebox.askyesno("恢复默认", "确定把所有设置恢复为默认值吗？"):
            return
        from .config import Config
        d = Config().to_public_dict()
        self.engine.update_config(d)
        for key, (var, kind) in self.setting_vars.items():
            var.set(bool(d[key]) if kind == "bool" else str(d[key]))
        self._paint_protect_list()
        self._set_status("设置已恢复为默认值")

    def on_refresh_log(self) -> None:
        self._set_text(self.txt_log, self.engine.log.as_text(500))

    def on_export_log(self) -> None:
        path = filedialog.asksaveasfilename(title="导出日志", defaultextension=".txt",
                                            filetypes=[("文本文件", "*.txt")],
                                            initialfile="memguard_audit.txt")
        if not path:
            return
        ok, msg = self.engine.export_log(Path(path))
        messagebox.showinfo("导出日志", msg)

    def on_purge_log(self) -> None:
        msg = self.engine.purge_log()
        self.on_refresh_log()
        self._set_status(msg)
        messagebox.showinfo("日志清理", msg)

    # ---------------------------------------------------------------- 生命周期

    def _toast(self, title: str, text: str, level: str) -> None:
        if not self.engine.cfg.show_toast:
            return
        try:
            if self._toast_win is not None and self._toast_win.winfo_exists():
                self._toast_win.destroy()
        except Exception:  # noqa: BLE001
            pass
        color = {"ok": "#0F6E56", "warn": "#854F0B", "error": "#A32D2D"}.get(level, "#185FA5")
        w = tk.Toplevel(self.root)
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.configure(background="#ffffff")
        frame = tk.Frame(w, background="#ffffff", highlightbackground=color, highlightthickness=2)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text=title, font=FONT_B, fg=color, bg="#ffffff", anchor="w").pack(fill="x", padx=12, pady=(10, 2))
        tk.Label(frame, text=text[:150], font=FONT, fg="#334155", bg="#ffffff",
                 wraplength=320, justify="left", anchor="w").pack(fill="x", padx=12, pady=(0, 10))
        w.update_idletasks()
        sw, sh = w.winfo_screenwidth(), w.winfo_screenheight()
        w.geometry(f"+{sw - w.winfo_width() - 24}+{sh - w.winfo_height() - 80}")
        self._toast_win = w
        w.after(4000, lambda: w.destroy() if w.winfo_exists() else None)

    def _poll_messages(self) -> None:
        for m in self.engine.drain_messages():
            self._set_status(f"[{m['level']}] {m['title']}：{m['text'][:180]}")
            if m["level"] in ("ok", "warn", "error"):
                self._toast(m["title"], m["text"], m["level"])
            if m["title"] in ("自动释放完成（仅 L1）", "已自动设置锚点", "锚点已设置", "设置"):
                self.refresh(silent=True)
            if "日志" in m["title"]:
                self.on_refresh_log()
        self.root.after(600, self._poll_messages)

    def toggle_pause(self) -> None:
        msg = self.engine.set_paused(not self.engine.cfg.paused)
        self._set_status(msg)
        self.lbl_auto.configure(text=("自动：已暂停" if self.engine.cfg.paused else "自动：运行中"))

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def on_close(self) -> None:
        if getattr(self, "tray", None) and self.tray.available:
            self.root.withdraw()
            self._toast("已最小化到托盘", "程序仍在后台巡检；右键托盘图标可退出。", "info")
        else:
            self.quit_app()

    def quit_app(self) -> None:
        if not messagebox.askyesno("退出", "退出后自动巡检将停止。确定退出 MemGuard 吗？"):
            return
        try:
            self.engine.stop_auto()
        except Exception:  # noqa: BLE001
            pass
        if getattr(self, "tray", None):
            self.tray.stop()
        self.root.destroy()

    def run(self) -> None:
        self._paint_protect_list()
        self.on_refresh_log()
        self.root.mainloop()
