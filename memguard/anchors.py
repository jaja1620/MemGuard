"""锚点：记录某一时刻的内存 / 显存基线，并计算「超出锚点多少」。

释放目标 = 锚点已用 + 容差；只释放超出部分，执行时逐步复测、达标即停。
锚点不参与写系统状态，只是参照物，因此天然安全。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .collector import MB, Snapshot, fmt_bytes, fmt_mb
from .config import Config

MAX_ANCHORS = 40

SOURCE_LABEL = {
    "manual": "手动设置",
    "auto": "空闲时自动设置",
    "startup": "启动时自动设置",
    "post_release": "释放完成后自动设置",
    "import": "导入",
}


@dataclass
class Anchor:
    id: str
    name: str
    ts: float
    source: str
    compact: dict = field(default_factory=dict)

    def time_text(self) -> str:
        return datetime.fromtimestamp(self.ts).strftime("%Y-%m-%d %H:%M:%S")

    def source_text(self) -> str:
        return SOURCE_LABEL.get(self.source, self.source)

    def used_text(self) -> str:
        return fmt_bytes(self.compact.get("used_phys", 0))

    def gpu_text(self) -> str:
        return fmt_mb(self.compact.get("gpu_used_total_mb", 0.0))

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "ts": self.ts, "source": self.source, "compact": self.compact}

    @classmethod
    def from_dict(cls, d: dict) -> "Anchor":
        return cls(id=str(d.get("id") or uuid.uuid4().hex[:8]),
                   name=str(d.get("name") or "未命名锚点"),
                   ts=float(d.get("ts") or time.time()),
                   source=str(d.get("source") or "import"),
                   compact=dict(d.get("compact") or {}))


@dataclass
class Diff:
    anchor: Anchor | None
    valid: bool = True
    fresh: bool = True
    reason: str = ""
    anchor_used: int = 0
    current_used: int = 0
    target_used: int = 0
    need_release_bytes: int = 0
    gpu_anchor_mb: float = 0.0
    gpu_current_mb: float = 0.0
    gpu_target_mb: float = 0.0
    gpu_over_mb: float = 0.0
    verdict: str = ""
    lines: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_text(self) -> str:
        return "\n".join(self.lines + ([f"注意：{'；'.join(self.warnings)}"] if self.warnings else []))


class AnchorStore:
    def __init__(self, path: Path):
        self.path = path
        self.items: list[Anchor] = []
        self.current_id: str | None = None
        self._lock = threading.RLock()
        self.load()

    def load(self) -> str:
        if not self.path.exists():
            return "尚无锚点文件，等待首次设置锚点"
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            self.items = [Anchor.from_dict(x) for x in d.get("items", [])]
            self.current_id = d.get("current_id")
            if self.current_id not in {a.id for a in self.items}:
                self.current_id = self.items[-1].id if self.items else None
            return f"已加载 {len(self.items)} 个锚点"
        except Exception as exc:  # noqa: BLE001
            self.items, self.current_id = [], None
            return f"锚点文件损坏，已忽略：{exc}"

    def save(self) -> tuple[bool, str]:
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                data = {"current_id": self.current_id, "items": [a.to_dict() for a in self.items]}
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(self.path)
                return True, f"锚点已保存到 {self.path}"
            except Exception as exc:  # noqa: BLE001
                return False, f"锚点保存失败：{exc}"

    def add(self, snap: Snapshot, name: str = "", source: str = "manual") -> tuple[Anchor, str]:
        with self._lock:
            ts = time.time()
            label = name.strip() or f"{'手动' if source == 'manual' else '自动'}锚点 {datetime.fromtimestamp(ts).strftime('%m-%d %H:%M')}"
            a = Anchor(id=uuid.uuid4().hex[:10], name=label, ts=ts, source=source, compact=snap.compact())
            self.items.append(a)
            if len(self.items) > MAX_ANCHORS:
                self.items = self.items[-MAX_ANCHORS:]
            self.current_id = a.id
            ok, msg = self.save()
            return a, (f"已设为当前锚点：{label}｜{a.used_text()}，专用显存 {a.gpu_text()}｜{msg}")

    def get_current(self) -> Anchor | None:
        with self._lock:
            for a in self.items:
                if a.id == self.current_id:
                    return a
            return None

    def set_current(self, aid: str) -> tuple[bool, str]:
        with self._lock:
            if aid not in {a.id for a in self.items}:
                return False, "锚点不存在"
            self.current_id = aid
            a = self.get_current()
            ok, msg = self.save()
            return True, f"当前锚点已切换为：{a.name if a else aid}｜{msg}"

    def remove(self, aid: str) -> tuple[bool, str]:
        with self._lock:
            before = len(self.items)
            self.items = [a for a in self.items if a.id != aid]
            if len(self.items) == before:
                return False, "锚点不存在"
            if self.current_id == aid:
                self.current_id = self.items[-1].id if self.items else None
            ok, msg = self.save()
            return True, f"已删除锚点｜{msg}"

    def rename(self, aid: str, name: str) -> tuple[bool, str]:
        with self._lock:
            for a in self.items:
                if a.id == aid:
                    a.name = name.strip() or a.name
                    self.save()
                    return True, f"已重命名为 {a.name}"
            return False, "锚点不存在"

    def export(self, path: Path) -> tuple[bool, str]:
        try:
            path.write_text(
                json.dumps({"current_id": self.current_id, "items": [a.to_dict() for a in self.items]},
                           ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return True, f"已导出 {len(self.items)} 个锚点到 {path}"
        except Exception as exc:  # noqa: BLE001
            return False, f"导出失败：{exc}"

    def diff(self, snap: Snapshot, cfg: Config) -> Diff:
        a = self.get_current()
        if a is None:
            return Diff(
                anchor=None, valid=False, fresh=False, reason="尚未设置锚点",
                verdict="没有参照基线，自动释放不会执行；请先点击「设为锚点」",
                lines=["当前没有锚点。", "自动释放必须参照锚点，这是为了防止无目标地反复裁剪内存。"],
            )

        c = a.compact
        d = Diff(anchor=a)
        d.anchor_used = int(c.get("used_phys", 0))
        d.current_used = int(snap.used_phys)
        tolerance = int(cfg.tolerance_mb) * MB
        d.target_used = int(d.anchor_used + tolerance)
        d.need_release_bytes = max(0, d.current_used - d.target_used)

        d.gpu_anchor_mb = float(c.get("gpu_used_total_mb") or 0.0)
        d.gpu_current_mb = snap.gpu_used_total()
        d.gpu_target_mb = d.gpu_anchor_mb + int(cfg.gpu_tolerance_mb)
        d.gpu_over_mb = max(0.0, d.gpu_current_mb - d.gpu_target_mb)

        age_days = (time.time() - a.ts) / 86400.0
        boot_a = float(c.get("boot_time") or 0)
        boot_now = snap.ts - snap.boot_ms / 1000.0
        total_a = int(c.get("total_phys") or 0)

        if boot_a and abs(boot_a - boot_now) > 180:
            d.valid, d.fresh = False, False
            d.reason = "锚点来自上一次开机"
            d.warnings.append("锚点创建于上次开机，进程与缓存状态已完全不同，请重新设置锚点后再释放")
        elif age_days > cfg.anchor_max_age_days:
            d.fresh = False
            d.warnings.append(f"锚点已创建 {age_days:.1f} 天（上限 {cfg.anchor_max_age_days} 天）；手动仍可参照，但自动释放已暂停，建议重设")
        if total_a and snap.total_phys and abs(total_a - snap.total_phys) > total_a * 0.05:
            d.warnings.append("物理内存总量与锚点时不同（硬件/虚拟内存设置变化），对比仅供参考")
        if not snap.gpus:
            d.warnings.append("当前无法读取显存，显存对比不参与本次判定")

        delta_mb = (d.current_used - d.anchor_used) / MB
        d.lines = [
            f"锚点：{a.name}｜{a.time_text()}｜{a.source_text()}",
            f"锚点时物理内存已用 {fmt_bytes(d.anchor_used)}；当前已用 {fmt_bytes(d.current_used)}（变化 {delta_mb:+,.0f} MB）",
            f"释放目标 = 锚点已用 + 容差 {cfg.tolerance_mb} MB = {fmt_bytes(d.target_used)}",
            (
                f"超出目标 {fmt_bytes(d.need_release_bytes)}，需要释放这部分；达标即停，不会继续往下清"
                if d.need_release_bytes > 0
                else "当前已用未超过目标，无需释放（不会为了「好看的数字」多做动作）"
            ),
            f"专用显存：锚点 {fmt_mb(d.gpu_anchor_mb)} → 当前 {fmt_mb(d.gpu_current_mb)}，超出容差后 {fmt_mb(d.gpu_over_mb)}",
            "显存没有系统级回收接口，超出部分只列出占用进程供你手动确认，程序不会自动结束进程。",
        ]
        if d.need_release_bytes > 0:
            d.verdict = f"需要释放约 {fmt_bytes(d.need_release_bytes)}（回到锚点目标）"
        else:
            d.verdict = "无需释放：当前状态在锚点容差范围内"
        return d
