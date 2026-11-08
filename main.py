"""MemGuard 入口。

常用命令：
  python main.py                        启动图形界面（含自动巡检）
  python main.py --collect              只采集一次并以中文/JSON 打印快照
  python main.py --selftest             运行只读安全自测
  python main.py --fulltest             运行全工况 / 全参数验证（329 项矩阵）
  python main.py --cli                  无界面模式：打印状态与锚点对比
  python main.py --cli --action preview --level 1   生成干运行预览
  python main.py --cli --action release --level 1   执行 L1（L3 需图形界面确认）
  python main.py --cli --action auto    无界面自动巡检（仅 L1，Ctrl+C 停止）
  python main.py --no-auto --no-tray    禁用自动巡检与托盘
  python main.py --data-dir DIR         自定义数据目录

图形界面需要 tkinter。若当前解释器缺少 tkinter，入口会自动寻找系统里
带 tkinter 的 Python 并重启自身；一个都找不到时自动降级为无界面模式。
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _dpi_aware() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass


def _find_tkinter_python() -> str | None:
    """寻找一个带 tkinter 的解释器，用于图形界面自举。"""
    candidates: list[str] = []
    for launcher in ("py -3", "py -3.14", "py -3.13", "py -3.12"):
        parts = launcher.split()
        try:
            r = subprocess.run(parts + ["-c", "import sys;print(sys.executable)"],
                               capture_output=True, text=True, timeout=6)
            if r.returncode == 0 and r.stdout.strip():
                candidates.append(r.stdout.strip().splitlines()[-1])
        except Exception:  # noqa: BLE001
            pass
    try:
        r = subprocess.run(["where", "python"], capture_output=True, text=True, timeout=6)
        if r.returncode == 0:
            candidates += [x.strip() for x in r.stdout.splitlines() if x.strip()]
    except Exception:  # noqa: BLE001
        pass
    from glob import glob
    patterns = [
        "C:/Python3*/python.exe",
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python",
                     "Python3*", "python.exe").replace("\\", "/"),
    ]
    for pat in patterns:
        try:
            candidates += glob(pat)
        except Exception:  # noqa: BLE001
            pass

    seen = set()
    for exe in candidates:
        try:
            key = str(Path(exe).resolve()).lower()
        except Exception:  # noqa: BLE001
            continue
        if key in seen or key == str(Path(sys.executable).resolve()).lower():
            continue
        seen.add(key)
        try:
            r = subprocess.run([exe, "-c", "import tkinter"], capture_output=True, timeout=8)
            if r.returncode == 0:
                return exe
        except Exception:  # noqa: BLE001
            continue
    return None


def _run_bundled_test(script_name: str) -> int:
    """运行内置测试。打包成单文件 exe 后 sys.executable 是 exe 自身，
    不能再用它去解释 .py 文件，因此优先在当前进程内加载模块执行。"""
    import importlib.util

    script = HERE / "tests" / script_name
    if not script.exists():
        print(f"未找到测试脚本：{script}")
        print("源码运行请用 run.bat --selftest / run.bat --fulltest。")
        return 2
    try:
        spec = importlib.util.spec_from_file_location(f"_memguard_{script.stem}", script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return int(mod.main())
    except Exception as exc:  # noqa: BLE001
        print(f"内置加载失败（{exc}），尝试外部解释器…")
        return subprocess.run([sys.executable, str(script)], cwd=str(HERE)).returncode


def _cli_mode(engine, args) -> int:
    from memguard import collector

    action = args.action
    if action == "status":
        snap, diff = engine.refresh()
        print("=== MemGuard 无界面状态 ===")
        for line in collector.describe(snap):
            print("  " + line)
        for g in snap.gpus:
            print(f"  · {g.name}：专用 {g.usage_text()}，共享 {collector.fmt_mb(g.shared_used_mb)}（{g.source}）")
        print(f"  显存说明：{snap.gpu_note}")
        print("\n=== 锚点对比 ===\n" + diff.as_text())
    elif action == "preview":
        snap, diff, pf, plan = engine.manual_preview(args.level, [], args.ignore_anchor)
        print("=== 前置检查 ===\n" + pf.summary())
        print("\n=== 锚点对比 ===\n" + diff.as_text())
        print("\n=== 干运行预览（未执行任何动作）===\n" + plan.preview_text())
    elif action == "release":
        if args.level == 3:
            print("L3 关闭进程必须在图形界面里逐项勾选并经过多次确认，无界面模式拒绝执行。")
            return 3
        ok, result, plan, diff = engine.manual_execute(args.level, [], args.ignore_anchor, None)
        print(result.report_text() if ok else "未执行：" + str(result))
        return 0 if ok else 1
    elif action == "auto":
        print(engine.start_auto())
        print("无界面自动巡检中（硬上限 L1，绝不结束进程）。按 Ctrl+C 停止。")
        try:
            while True:
                time.sleep(1)
                for m in engine.drain_messages():
                    print(f"  [{m['level']}] {m['title']}：{m['text'][:200]}")
        except KeyboardInterrupt:
            print("\n" + engine.stop_auto())
    else:
        print(f"未知 --action：{action}")
        return 2
    return 0


def _setup_output() -> tuple[object | None, str]:
    """--noconsole 打包后 sys.stdout 为 None：GUI 指向空设备；
    文本模式（自测 / CLI / 采集）把输出写到数据目录的文件，避免结果凭空消失。"""
    if sys.stdout is not None:
        return None, ""
    text_mode = any(a in sys.argv for a in ("--selftest", "--fulltest", "--cli", "--collect"))
    if text_mode:
        try:
            base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            d = Path(base) / "MemGuard"
            d.mkdir(parents=True, exist_ok=True)
            f = open(d / "console.txt", "w", encoding="utf-8")
            sys.stdout = f
            return f, str(d / "console.txt")
        except Exception:  # noqa: BLE001
            pass
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
    return None, ""


def main(argv: list[str] | None = None) -> int:
    out_file, out_path = _setup_output()
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    if out_path:
        print(f"本次为无控制台运行，完整输出同时写入：{out_path}")

    ap = argparse.ArgumentParser(description="MemGuard 内存 / 显存锚点管家")
    ap.add_argument("--collect", action="store_true", help="只采集一次快照并打印，不启动界面")
    ap.add_argument("--selftest", action="store_true", help="运行安全自测")
    ap.add_argument("--fulltest", action="store_true", help="运行全工况 / 全参数验证")
    ap.add_argument("--cli", action="store_true", help="无界面模式")
    ap.add_argument("--action", default="status", choices=["status", "preview", "release", "auto"])
    ap.add_argument("--level", type=int, default=1, choices=[1, 2, 3])
    ap.add_argument("--ignore-anchor", action="store_true", help="不受锚点限制（完全清理）")
    ap.add_argument("--no-auto", action="store_true", help="本次启动不开启自动巡检")
    ap.add_argument("--no-tray", action="store_true", help="本次启动不加载托盘")
    ap.add_argument("--data-dir", default="", help="自定义数据目录")
    args = ap.parse_args(argv)
    raw_argv = list(argv) if argv is not None else sys.argv[1:]

    if platform.system() != "Windows":
        print("MemGuard 只支持 Windows（依赖 Win32 / PDH 相关接口）。")
        return 2

    if args.selftest or args.fulltest:
        return _run_bundled_test("full_matrix.py" if args.fulltest else "selftest.py")

    from memguard import collector, winapi
    from memguard.config import Config

    cfg = Config()
    if args.collect:
        snap = collector.collect(cfg)
        print("=== MemGuard 只读快照（本次没有执行任何释放动作）===")
        for line in collector.describe(snap):
            print("  " + line)
        for g in snap.gpus:
            print(f"  · 显卡 {g.name}：专用 {g.usage_text()}，共享 {collector.fmt_mb(g.shared_used_mb)}（来源 {g.source}）")
        print(f"  显存采集说明：{snap.gpu_note}")
        for n in snap.notes:
            print(f"  ! {n}")
        print("\n=== JSON ===")
        print(json.dumps(snap.compact(), ensure_ascii=False, indent=2))
        return 0

    # 图形界面需要 tkinter；缺则先自举到带 tkinter 的解释器，再降级 CLI。
    if not args.cli:
        try:
            import tkinter  # noqa: F401
        except ImportError:
            alt = _find_tkinter_python()
            if alt:
                print(f"当前 Python 缺少 tkinter，改用 {alt} 启动图形界面…")
                return subprocess.run([alt, str(Path(__file__).resolve())] + raw_argv,
                                      cwd=str(HERE)).returncode
            print("未找到带 tkinter 的 Python，已自动降级为无界面模式。")
            args.cli = True

    ok, msg = winapi.single_instance()
    if not ok:
        print(msg)
        return 1
    _dpi_aware()

    from memguard.engine import Engine

    engine = Engine(Path(args.data_dir) if args.data_dir else None)
    if args.no_auto:
        engine.cfg.auto_release_enabled = False
        engine.log.write("启动", "本次启动按命令行参数禁用自动巡检", level="warn")

    if args.cli:
        try:
            return _cli_mode(engine, args)
        finally:
            engine.stop_auto()

    from memguard.ui import App

    app = App(engine, enable_tray=not args.no_tray)
    app.run()
    return 0


if __name__ == "__main__":
    rc = main()
    try:
        if getattr(sys.stdout, "flush", None):
            sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(rc)
