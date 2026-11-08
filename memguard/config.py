"""配置与默认保护名单。

所有会被写盘的内容都放在 %LOCALAPPDATA%\\MemGuard 下，
不写注册表、不改页面文件、不动系统目录。

外部输入（配置文件 / 设置页 / 命令行补丁）一律经 _coerce 收敛：
非法类型回退默认值，越界数值夹到合法区间，自动上限恒为 L1。
这样即使配置被手工改坏，程序也不会出现「负容差导致全量清理」
「非法巡检周期让自动线程静默死亡」这类问题。
"""
from __future__ import annotations

import json
import math
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP_DIR_NAME = "MemGuard"


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / APP_DIR_NAME


# ---------------------------------------------------------------- 保护名单

# 系统关键进程：硬编码，UI 不允许移除，任何级别都跳过。
CRITICAL_PROCESSES = frozenset(
    x.lower()
    for x in (
        "System", "System Idle Process", "Registry", "Memory Compression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
        "dwm.exe", "audiodg.exe", "sihost.exe", "ctfmon.exe",
        "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe",
        "SecurityHealthSystray.exe", "spoolsv.exe", "explorer.exe",
        "conhost.exe", "WUDFHost.exe", "unsecapp.exe",
        # Windows 外壳与系统服务：裁剪它们会让开始菜单/搜索/通知出现可感知卡顿
        "StartMenuExperienceHost.exe", "SearchHost.exe", "ShellExperienceHost.exe",
        "ApplicationFrameHost.exe", "RuntimeBroker.exe", "LockApp.exe",
        "TextInputHost.exe", "SystemSettings.exe", "taskhostw.exe",
        "SearchIndexer.exe", "wmiprvse.exe", "dllhost.exe",
        "backgroundTaskHost.exe", "WpnUserService.exe", "PhoneExperienceHost.exe",
        "CrossDeviceService.exe", "SurfaceApp.Desktop.exe",
    )
)

# 用户可编辑的默认保护名单：多为可能有未保存工作的应用。
DEFAULT_PROTECT_LIST = [
    "MemGuard.exe",
    "Code.exe", "devenv.exe", "idea64.exe", "pycharm64.exe", "WorkBuddy.exe",
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "wps.exe", "et.exe", "wpp.exe",
    "WeChat.exe", "WXWork.exe", "QQ.exe", "DingTalk.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
    "OBS64.exe", "JianyingPro.exe", "Photoshop.exe",
]

# 数值字段的 (下限, 上限, 目标类型)。这是「全参数」的唯一真源。
NUMERIC_RANGES: dict[str, tuple[float, float, type]] = {
    "poll_sec": (1, 86400, int),
    "cooldown_min": (0, 1440, int),
    "trigger_avail_pct": (0.0, 100.0, float),
    "trigger_over_anchor_mb": (0, 1 << 20, int),
    "tolerance_mb": (0, 1 << 20, int),
    "gpu_tolerance_mb": (0, 1 << 20, int),
    "min_pagefile_avail_mb": (0, 1 << 20, int),
    "min_uptime_min": (0, 10080, int),
    "idle_cpu_pct": (0.0, 100.0, float),
    "idle_disk_pct": (0.0, 100.0, float),
    "user_idle_min": (0.0, 1440.0, float),
    "close_wait_sec": (1, 600, int),
    "auto_anchor_idle_min": (0, 1440, int),
    "auto_anchor_min_avail_pct": (0.0, 100.0, float),
    "anchor_max_age_days": (1, 3650, int),
    "log_days": (1, 3650, int),
}

BOOL_FIELDS = frozenset({
    "auto_release_enabled", "skip_when_foreground", "skip_windowed_for_auto",
    "allow_l2_manual", "allow_l3_manual", "auto_anchor_enabled",
    "gpu_probe_enabled", "nvidia_smi_enabled", "tray_enabled", "show_toast",
    "paused",
})


def _coerce(key: str, value: Any, default: Any) -> Any:
    """把一个外部输入收敛成该字段的合法值。永不抛异常。"""
    # 安全上限：任何来源都不可把自动释放抬到 L2/L3。
    if key == "auto_max_level":
        return 1

    if key == "protect_list":
        if not isinstance(value, (list, tuple)):
            return list(DEFAULT_PROTECT_LIST)
        out: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                continue
            name = item.strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            out.append(name)
            if len(out) >= 200:
                break
        return out or list(DEFAULT_PROTECT_LIST)

    if key in BOOL_FIELDS:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() not in ("", "0", "false", "no", "off", "否", "关")
        return bool(value)

    spec = NUMERIC_RANGES.get(key)
    if spec is None:
        return value
    lo, hi, kind = spec
    try:
        num = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if math.isnan(num) or math.isinf(num):
        return default
    num = max(lo, min(hi, num))
    return int(round(num)) if kind is int else float(num)


@dataclass
class Config:
    # 自动释放
    auto_release_enabled: bool = True
    auto_max_level: int = 1                 # 硬上限，永远不允许超过 1
    poll_sec: int = 60                     # 自动巡检周期
    cooldown_min: int = 15                 # 两次自动释放之间的冷却
    trigger_avail_pct: float = 20.0        # 可用物理内存低于该百分比才考虑触发
    trigger_over_anchor_mb: int = 256      # 且超出锚点至少该值
    tolerance_mb: int = 512                # 内存锚点容差
    gpu_tolerance_mb: int = 256            # 显存锚点容差
    min_pagefile_avail_mb: int = 1024      # 页面文件可用量下限，低于则跳过
    min_uptime_min: int = 5                # 开机多久后才允许动作
    idle_cpu_pct: float = 35.0
    idle_disk_pct: float = 60.0
    user_idle_min: float = 3.0             # 用户无键鼠输入多久才算空闲
    skip_when_foreground: bool = True      # 有前台交互时跳过自动动作
    skip_windowed_for_auto: bool = True    # 自动 L1 跳过有可见窗口的进程

    # 手动释放
    allow_l2_manual: bool = True           # 清理备用列表（需管理员）
    allow_l3_manual: bool = True           # 关闭占用显存的进程（需逐项勾选 + 二次确认）
    close_wait_sec: int = 8                # 优雅关闭等待秒数

    # 锚点
    auto_anchor_enabled: bool = True
    auto_anchor_idle_min: int = 10         # 连续空闲多少分钟后自动记录
    auto_anchor_min_avail_pct: float = 30.0
    anchor_max_age_days: int = 7

    # 采集与呈现
    gpu_probe_enabled: bool = True
    nvidia_smi_enabled: bool = True
    tray_enabled: bool = True
    show_toast: bool = True
    log_days: int = 30
    protect_list: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECT_LIST))

    # 运行时状态（不持久化）
    paused: bool = field(default=False, repr=False)

    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def to_public_dict(self) -> dict:
        # 不用 dataclasses.asdict：_lock 是同步原语，无法被 deepcopy。
        return {
            k: getattr(self, k)
            for k in self.__dataclass_fields__
            if k not in ("_lock", "paused")
        }

    def normalize(self) -> list[str]:
        """把当前所有字段重新收敛一次；返回被修正的字段名（用于如实提示）。"""
        defaults = type(self)()
        fixed: list[str] = []
        for k in self.to_public_dict():
            old = getattr(self, k)
            new = _coerce(k, old, getattr(defaults, k))
            if old != new:
                setattr(self, k, new)
                fixed.append(k)
        self.paused = bool(self.paused)
        return fixed

    def update(self, patch: dict) -> list[str]:
        """应用配置补丁，返回被真正修改的字段名。非法值一律收敛，不抛异常。"""
        allowed = set(self.to_public_dict().keys()) | {"paused"}
        defaults = type(self)()
        changed = []
        for k, v in patch.items():
            if k not in allowed:
                continue
            old = getattr(self, k, None)
            new = _coerce(k, v, getattr(defaults, k))
            if old != new:
                setattr(self, k, new)
                changed.append(k)
        return changed

    def save(self, path: Path) -> tuple[bool, str]:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(self.to_public_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            tmp.replace(path)
            return True, str(path)
        except Exception as exc:  # noqa: BLE001
            return False, f"配置保存失败：{exc}"

    @classmethod
    def load(cls, path: Path) -> tuple["Config", str]:
        if not path.exists():
            return cls(), "使用默认配置（首次运行）"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return cls(), "配置根节点不是对象，已回退默认值"
            cfg = cls()
            cfg.update({k: v for k, v in raw.items() if isinstance(k, str)})
            fixed = cfg.normalize()
            tail = f"；已自动修正 {', '.join(fixed)}" if fixed else ""
            return cfg, f"已加载配置：{path}{tail}"
        except Exception as exc:  # noqa: BLE001
            return cls(), f"配置读取失败，已回退默认值：{exc}"
