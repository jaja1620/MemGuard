"""可选系统托盘。缺少 pystray / Pillow 时自动降级，不影响主程序运行。"""
from __future__ import annotations

import threading
from typing import Any


class Tray:
    def __init__(self, app: Any):
        self.app = app
        self.icon = None
        self.thread: threading.Thread | None = None
        self.available = False
        self.reason = "未启用"
        try:
            import pystray  # type: ignore
            from PIL import Image, ImageDraw  # type: ignore
        except Exception as exc:  # noqa: BLE001
            self.reason = f"托盘组件未安装（{exc}）；程序仍在任务栏正常运行"
            return
        try:
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.ellipse((4, 4, 60, 60), outline=(24, 95, 165, 255), width=8)
            d.ellipse((16, 16, 48, 48), fill=(24, 95, 165, 255))
            d.rectangle((28, 8, 36, 30), fill=(255, 255, 255, 255))

            menu = pystray.Menu(
                pystray.MenuItem("显示主界面", self._show),
                pystray.MenuItem("设为锚点", self._anchor),
                pystray.MenuItem("暂停 / 恢复自动", self._pause),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("退出", self._quit),
            )
            self.icon = pystray.Icon("MemGuard", img, "MemGuard 内存锚点管家", menu)
            self.thread = threading.Thread(target=self.icon.run, daemon=True, name="MemGuard-Tray")
            self.thread.start()
            self.available = True
            self.reason = "托盘已启用"
        except Exception as exc:  # noqa: BLE001
            self.reason = f"托盘启动失败（{exc}）；程序仍在任务栏正常运行"
            self.icon = None

    def _run(self, fn) -> None:
        try:
            self.app.root.after(0, fn)
        except Exception:  # noqa: BLE001
            pass

    def _show(self, *_a) -> None:
        self._run(self.app.show_window)

    def _anchor(self, *_a) -> None:
        self._run(lambda: self.app.on_set_anchor("", "manual"))

    def _pause(self, *_a) -> None:
        self._run(self.app.toggle_pause)

    def _quit(self, *_a) -> None:
        self._run(self.app.quit_app)

    def stop(self) -> None:
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:  # noqa: BLE001
                pass
