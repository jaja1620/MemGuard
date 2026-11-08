"""MemGuard 安全自测。

只读采集 + 纯内存模拟；会把所有可能改变系统状态的函数替换成计数器，
断言调用次数为 0。不会裁剪工作集、不会清备用列表、不会结束任何进程。
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from memguard import collector, winapi  # noqa: E402
from memguard.actions import Plan, PlanItem, build_plan, execute  # noqa: E402
from memguard.anchors import AnchorStore, Diff  # noqa: E402
from memguard.collector import MB, ProcInfo, Snapshot  # noqa: E402
from memguard.config import Config  # noqa: E402
from memguard.engine import Engine  # noqa: E402
from memguard.safety import AuditLog, annotate_protection, preflight  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))


def main() -> int:
    calls: dict[str, list] = {"trim": [], "purge": [], "kill": []}
    orig_trim, orig_purge, orig_kill = (
        winapi.trim_working_set, winapi.purge_standby_list, winapi.force_kill
    )
    winapi.trim_working_set = lambda pid: (calls["trim"].append(pid), (True, "mock"))[1]
    winapi.purge_standby_list = lambda: (calls["purge"].append(1), (True, "mock"))[1]
    winapi.force_kill = lambda pid: (calls["kill"].append(pid), (True, "mock"))[1]

    try:
        with tempfile.TemporaryDirectory(prefix="memguard_test_") as td:
            tmp = Path(td)
            cfg = Config()

            # --- 1. 底层采集 ---
            ok, ms = winapi.memory_status()
            check("GlobalMemoryStatusEx 可读", ok and ms.get("total_phys", 0) > 0, str(ms)[:120])
            ok, pi = winapi.performance_info()
            check("GetPerformanceInfo 可读", ok and pi.get("page_size", 0) > 0, str(pi)[:120])
            pids = winapi.enum_pids()
            check("进程枚举可用", len(pids) > 10, f"{len(pids)} 个进程")
            check("顶层窗口枚举可用", isinstance(winapi.enum_top_windows(), dict))
            check("用户空闲时间可读", winapi.user_idle_seconds() >= -1)
            check("前台窗口查询可用", isinstance(winapi.foreground(), tuple))
            cpu = winapi.cpu_busy_pct()
            check("CPU 忙闲可读", cpu is None or 0 <= cpu <= 100, f"{cpu}")
            check("nvidia-smi 查询不抛异常", isinstance(winapi.nvidia_smi_info(), tuple))
            check("PDH 通配符展开不抛异常", isinstance(winapi.pdh_expand(r"\GPU Adapter Memory(*)\Dedicated Usage"), tuple))

            # --- 2. 完整快照 ---
            snap = collector.collect(cfg)
            annotate_protection(snap, cfg)
            check("完整快照含进程", len(snap.procs) > 10, f"{len(snap.procs)} 个")
            if snap.total_phys:
                err = abs((snap.used_phys + snap.avail_phys) - snap.total_phys) / snap.total_phys
                check("内存口径自洽（已用+可用≈总量）", err < 0.05, f"误差 {err * 100:.2f}%")
            check("快照可序列化", isinstance(snap.compact(), dict) and "boot_time" in snap.compact())
            check("显存说明不为空", bool(snap.gpu_note), snap.gpu_note[:100])

            # --- 3. 白名单：绝不动系统关键进程与自身 ---
            mock = Snapshot(
                ts=time.time(), boot_ms=winapi.boot_ms(), total_phys=16 * 1024 * MB,
                avail_phys=8 * 1024 * MB, used_phys=8 * 1024 * MB,
                pagefile_avail=8 * 1024 * MB, is_admin=False,
                procs=[
                    ProcInfo(pid=111, name="csrss.exe", ws=100 * MB),
                    ProcInfo(pid=222, name="svchost.exe", ws=100 * MB),
                    ProcInfo(pid=333, name="Code.exe", ws=100 * MB),
                    ProcInfo(pid=os.getpid(), name="python.exe", ws=100 * MB),
                    ProcInfo(pid=444, name="ollama.exe", ws=2 * 1024 * MB, gpu_mb=4096),
                ],
            )
            annotate_protection(mock, cfg)
            check("csrss.exe 受硬保护", mock.procs[0].protected, mock.procs[0].protect_reason)
            check("svchost.exe 受硬保护", mock.procs[1].protected)
            check("保护名单 Code.exe 受保护", mock.procs[2].protected)
            check("程序自身受保护", mock.procs[3].protected, mock.procs[3].protect_reason)
            check("普通 AI 进程不被误保护", not mock.procs[4].protected)

            # 把关键进程加入用户保护名单也不能被解除
            cfg.protect_list.append("csrss.exe")
            annotate_protection(mock, cfg)
            check("硬保护不可被用户名单覆盖", mock.procs[0].protected)
            cfg.protect_list.remove("csrss.exe")

            # --- 4. 自动边界与配置硬上限 ---
            check("自动 L2 被前置检查阻止", not preflight(snap, cfg, 2, auto=True).allowed)
            check("自动 L3 被前置检查阻止", not preflight(snap, cfg, 3, auto=True, selected_pids=[444]).allowed)
            p2 = build_plan(snap, cfg, Diff(anchor=None, valid=False), 3, auto=True, selected_pids=[444])
            check("自动 L3 连计划都不生成", len(p2.items) == 0, p2.notes[0] if p2.notes else "")
            cfg.update({"auto_max_level": 3})
            check("自动上限无法通过配置突破", cfg.auto_max_level == 1, f"实际 {cfg.auto_max_level}")
            cfg.paused = True
            check("全局暂停阻止自动动作", not preflight(snap, cfg, 1, auto=True).allowed)
            cfg.paused = False

            # --- 5. 锚点参照规则 ---
            store = AnchorStore(tmp / "anchors.json")
            anchor, msg = store.add(snap, "自测锚点", "manual")
            check("锚点可创建并持久化", (tmp / "anchors.json").exists(), msg[:80])
            store2 = AnchorStore(tmp / "anchors.json")
            check("锚点可重新载入", len(store2.items) == 1 and store2.items[0].id == anchor.id)

            anchor.compact["used_phys"] = max(0, snap.used_phys - 2 * 1024 * MB)
            d_big = store.diff(snap, cfg)
            check("超出锚点时需要释放", d_big.need_release_bytes > 0, collector.fmt_bytes(d_big.need_release_bytes))
            plan_big = build_plan(snap, cfg, d_big, 1, auto=False)
            check("按锚点生成 L1 计划", len(plan_big.items) > 0, f"{len(plan_big.items)} 项")

            anchor.compact["used_phys"] = snap.total_phys
            d_small = store.diff(snap, cfg)
            check("未超出锚点时无需释放", d_small.need_release_bytes == 0)
            plan_small = build_plan(snap, cfg, d_small, 1, auto=False)
            check("未超出锚点时不生成任何动作", len(plan_small.items) == 0)
            plan_ignore = build_plan(snap, cfg, d_small, 1, auto=False, ignore_anchor=True)
            check("显式忽略锚点才生成完全清理计划", len(plan_ignore.items) > 0)

            anchor.compact["boot_time"] = (snap.ts - snap.boot_ms / 1000.0) - 100000
            d_stale = store.diff(snap, cfg)
            check("上次开机的锚点被判失效", not d_stale.valid, d_stale.warnings[0] if d_stale.warnings else "")
            ok, msg = store.export(tmp / "anchors_export.json")
            check("锚点可导出", ok and (tmp / "anchors_export.json").exists())

            # --- 6. 干运行与执行层绝不误触 ---
            log = AuditLog(tmp / "audit.log", 30)
            empty = Plan(level=1, auto=False, anchor_name="自测", items=[])
            res = execute(empty, snap, cfg, log,
                          collect_fn=collector.collect_light,
                          light_fn=collector.collect_light)
            check("空计划执行后无异常", res.finished >= res.started)
            check("干运行/空计划未调用任何危险函数",
                  not calls["trim"] and not calls["purge"] and not calls["kill"],
                  f"trim={len(calls['trim'])} purge={len(calls['purge'])} kill={len(calls['kill'])}")
            check("执行报告含前后对比", "物理内存已用" in res.report_text())

            log.write("自测", "一条测试日志", level="info")
            check("审计日志可读", len(log.read()) >= 1)
            removed, msg = log.purge()
            check("审计日志可清理", "已清理" in msg, msg)

            # --- 7. 配置与引擎 ---
            cfg.save(tmp / "config.json")
            cfg2, msg = Config.load(tmp / "config.json")
            check("配置可保存并载入", cfg2.tolerance_mb == cfg.tolerance_mb, msg)
            eng = Engine(tmp / "engine_data")
            check("引擎启动自动建立基线锚点", eng.store.get_current() is not None)
            check("引擎自动流程硬上限为 L1", eng.cfg.auto_max_level == 1)
            check("引擎快照与差异可用", isinstance(eng.refresh(), tuple))
            eng.stop_auto()
            check("日志文本可导出", isinstance(eng.log.as_text(), str) and len(eng.log.as_text()) > 0)

            # --- 8. 核心算法：达标即停 / L3 二次确认（全部 mock，绝不触碰系统）---
            orig_post, orig_alive = winapi.post_close, winapi.is_process_alive
            old_wait = cfg.close_wait_sec
            try:
                winapi.post_close = lambda pid, windows: (1, "mock WM_CLOSE")
                winapi.is_process_alive = lambda pid: True
                cfg.close_wait_sec = 1
                total = 32 * 1024 * MB
                seq = [16 * 1024 * MB, 15 * 1024 * MB, 14 * 1024 * MB, 13 * 1024 * MB]
                idx = {"i": 0}

                def light():
                    v = seq[min(idx["i"], len(seq) - 1)]
                    idx["i"] += 1
                    return Snapshot(ts=time.time(), total_phys=int(total), used_phys=int(v),
                                    avail_phys=int(total - v), pagefile_avail=8 * 1024 * MB)

                fake = light()
                plan = Plan(level=1, auto=False, anchor_name="mock", target_used=int(14.5 * 1024 * MB),
                            items=[PlanItem("L1", f"mock-{i}", 1000 + i, "", 100 * MB) for i in range(5)])
                calls["trim"].clear()
                execute(plan, fake, cfg, log, collect_fn=light, light_fn=light)
                check("达到锚点目标立即停止", len(calls["trim"]) == 2, f"实际裁剪 {len(calls['trim'])} 次后停止")

                plan3 = Plan(level=3, auto=False, anchor_name="mock",
                             items=[PlanItem("L3", "mock-ai-process", 9999, "", 0, "", 4096)])
                calls["kill"].clear()
                r_deny = execute(plan3, fake, cfg, log, collect_fn=light, light_fn=light,
                                 confirm_force_fn=lambda pid, target: False)
                check("未获二次确认绝不强制结束", len(calls["kill"]) == 0 and
                      any("二次确认" in w for w in r_deny.warnings),
                      f"kill={len(calls['kill'])}")
                calls["kill"].clear()
                execute(plan3, fake, cfg, log, collect_fn=light, light_fn=light,
                        confirm_force_fn=lambda pid, target: True)
                check("获得二次确认后才强制结束", len(calls["kill"]) == 1,
                      f"kill={len(calls['kill'])}")
            finally:
                winapi.post_close = orig_post
                winapi.is_process_alive = orig_alive
                cfg.close_wait_sec = old_wait

            check("系统级备用列表清理从未被触发", not calls["purge"],
                  f"purge={len(calls['purge'])}；trim/kill 均为已替换的 mock 计数，未触碰系统")
    finally:
        winapi.trim_working_set = orig_trim
        winapi.purge_standby_list = orig_purge
        winapi.force_kill = orig_kill

    print("=== MemGuard 安全自测报告 ===")
    passed = 0
    for name, ok, detail in RESULTS:
        mark = "通过" if ok else "失败"
        print(f"  [{mark}] {name}" + (f"｜{detail}" if detail else ""))
        passed += int(ok)
    print(f"\n合计 {passed}/{len(RESULTS)} 项通过。")
    print("说明：本自测全程只读，未裁剪工作集、未清备用列表、未结束任何进程。")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
