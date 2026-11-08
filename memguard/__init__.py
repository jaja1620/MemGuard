"""MemGuard - Windows 内存 / 显存锚点式安全管理工具。

设计原则：
1. 只读优先、分级执行、自动流程绝不结束进程；
2. 任何动作前先看锚点差异，只释放超出部分，边执行边复测，达标即停；
3. 所有跳过、失败、副作用都写进审计日志并如实呈现给用户。
"""
from __future__ import annotations

__version__ = "1.0.0"
__appname__ = "MemGuard 内存锚点管家"
