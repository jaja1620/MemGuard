"""Win32 / PDH / ntdll 的纯 ctypes 封装（零第三方依赖）。

这一层只做「取数」和「执行单个系统动作」，不做策略判断。
所有可能失败的函数都返回 (ok, detail)，绝不把异常抛到 UI 层：
上层必须把 detail 原样写进审计日志并展示给用户。
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import time
from ctypes import wintypes
from typing import Any

SIZE_T = ctypes.c_size_t
HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD

# ---------------------------------------------------------------- 动态库

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
try:
    pdh = ctypes.WinDLL("pdh", use_last_error=True)
    PDH_OK = True
except OSError:  # pragma: no cover - 极旧系统
    pdh = None
    PDH_OK = False

# ---------------------------------------------------------------- 常量

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_QUOTA = 0x0100
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_ALREADY_EXISTS = 183
WM_CLOSE = 0x0010
WM_NULL = 0x0000
QUOTA_LIMITS_HARDWS_DISABLE = 0x00000003

SystemMemoryListInformation = 80
MemoryPurgeStandbyList = 4

PDH_FMT_DOUBLE = 0x00000200
PDH_FMT_LARGE = 0x00000400
PDH_CSTATUS_VALID_DATA = 0
CREATE_NO_WINDOW = 0x08000000


# ---------------------------------------------------------------- 结构体

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", DWORD), ("dwMemoryLoad", DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("CommitTotal", SIZE_T), ("CommitLimit", SIZE_T), ("CommitPeak", SIZE_T),
        ("PhysicalTotal", SIZE_T), ("PhysicalAvailable", SIZE_T),
        ("SystemCache", SIZE_T), ("KernelTotal", SIZE_T),
        ("KernelPaged", SIZE_T), ("KernelNonpaged", SIZE_T), ("PageSize", SIZE_T),
        ("HandleCount", DWORD), ("ProcessCount", DWORD), ("ThreadCount", DWORD),
    ]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD), ("PageFaultCount", DWORD),
        ("PeakWorkingSetSize", SIZE_T), ("WorkingSetSize", SIZE_T),
        ("QuotaPeakPagedPoolUsage", SIZE_T), ("QuotaPagedPoolUsage", SIZE_T),
        ("QuotaPeakNonPagedPoolUsage", SIZE_T), ("QuotaNonPagedPoolUsage", SIZE_T),
        ("PagefileUsage", SIZE_T), ("PeakPagefileUsage", SIZE_T),
        ("PrivateUsage", SIZE_T),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", DWORD), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", DWORD)]


class _PDH_VALUE(ctypes.Union):
    _fields_ = [
        ("longValue", ctypes.c_long),
        ("doubleValue", ctypes.c_double),
        ("largeValue", ctypes.c_longlong),
        ("AnsiStringValue", ctypes.c_char_p),
        ("WideStringValue", ctypes.c_wchar_p),
    ]


class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    _fields_ = [("CStatus", DWORD), ("value", _PDH_VALUE)]


class DISPLAY_DEVICEW(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("DeviceName", ctypes.c_wchar * 32),
        ("DeviceString", ctypes.c_wchar * 128),
        ("StateFlags", DWORD),
        ("DeviceID", ctypes.c_wchar * 128),
        ("DeviceKey", ctypes.c_wchar * 128),
    ]


WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, ctypes.c_ssize_t)


# ---------------------------------------------------------------- 函数原型

kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
psapi.GetPerformanceInfo.argtypes = [ctypes.POINTER(PERFORMANCE_INFORMATION), DWORD]
psapi.GetPerformanceInfo.restype = wintypes.BOOL
psapi.EnumProcesses.argtypes = [ctypes.POINTER(DWORD), DWORD, ctypes.POINTER(DWORD)]
psapi.EnumProcesses.restype = wintypes.BOOL
psapi.GetProcessMemoryInfo.argtypes = [HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), DWORD]
psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
psapi.EmptyWorkingSet.argtypes = [HANDLE]
psapi.EmptyWorkingSet.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [DWORD, wintypes.BOOL, DWORD]
kernel32.OpenProcess.restype = HANDLE
kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, wintypes.LPWSTR, ctypes.POINTER(DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.SetProcessWorkingSetSizeEx.argtypes = [HANDLE, SIZE_T, SIZE_T, DWORD]
kernel32.SetProcessWorkingSetSizeEx.restype = wintypes.BOOL
kernel32.GetExitCodeProcess.argtypes = [HANDLE, ctypes.POINTER(DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetTickCount64.restype = ctypes.c_ulonglong
kernel32.GetTickCount.restype = DWORD
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = HANDLE
kernel32.GetSystemTimes.argtypes = [ctypes.POINTER(wintypes.FILETIME)] * 3
kernel32.GetSystemTimes.restype = wintypes.BOOL
user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(DWORD)]
user32.GetWindowThreadProcessId.restype = DWORD
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.EnumWindows.argtypes = [WNDENUMPROC, ctypes.c_ssize_t]
user32.EnumWindows.restype = wintypes.BOOL
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t]
user32.PostMessageW.restype = wintypes.BOOL
user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
user32.GetLastInputInfo.restype = wintypes.BOOL
user32.EnumDisplayDevicesW.argtypes = [wintypes.LPCWSTR, DWORD, ctypes.POINTER(DISPLAY_DEVICEW), DWORD]
user32.EnumDisplayDevicesW.restype = wintypes.BOOL
ntdll.NtSetSystemInformation.argtypes = [ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong]
ntdll.NtSetSystemInformation.restype = ctypes.c_long
advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), DWORD, ctypes.c_void_p, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
shell32.IsUserAnAdmin.restype = wintypes.BOOL

if PDH_OK:
    pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(HANDLE)]
    pdh.PdhOpenQueryW.restype = ctypes.c_long
    pdh.PdhAddEnglishCounterW.argtypes = [HANDLE, wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(HANDLE)]
    pdh.PdhAddEnglishCounterW.restype = ctypes.c_long
    pdh.PdhCollectQueryData.argtypes = [HANDLE]
    pdh.PdhCollectQueryData.restype = ctypes.c_long
    pdh.PdhGetFormattedCounterValue.argtypes = [HANDLE, DWORD, ctypes.POINTER(DWORD), ctypes.POINTER(PDH_FMT_COUNTERVALUE)]
    pdh.PdhGetFormattedCounterValue.restype = ctypes.c_long
    pdh.PdhExpandWildCardPathW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(DWORD), DWORD]
    pdh.PdhExpandWildCardPathW.restype = ctypes.c_long
    pdh.PdhCloseQuery.argtypes = [HANDLE]
    pdh.PdhCloseQuery.restype = ctypes.c_long


def _ft(v: wintypes.FILETIME) -> int:
    return (int(v.dwHighDateTime) << 32) | int(v.dwLowDateTime)


def win_error() -> int:
    return ctypes.get_last_error()


# ---------------------------------------------------------------- 系统状态

def boot_ms() -> int:
    return int(kernel32.GetTickCount64())


def memory_status() -> tuple[bool, dict]:
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(st)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        return False, {"error": f"GlobalMemoryStatusEx 失败 ({win_error()})"}
    return True, {
        "total_phys": int(st.ullTotalPhys),
        "avail_phys": int(st.ullAvailPhys),
        "used_phys": int(st.ullTotalPhys - st.ullAvailPhys),
        "load_pct": int(st.dwMemoryLoad),
        "total_pagefile": int(st.ullTotalPageFile),
        "avail_pagefile": int(st.ullAvailPageFile),
        "total_virtual": int(st.ullTotalVirtual),
        "avail_virtual": int(st.ullAvailVirtual),
    }


def performance_info() -> tuple[bool, dict]:
    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(pi)
    if not psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        return False, {"error": f"GetPerformanceInfo 失败 ({win_error()})"}
    page = int(pi.PageSize) or 4096
    return True, {
        "commit_total": int(pi.CommitTotal) * page,
        "commit_limit": int(pi.CommitLimit) * page,
        "commit_peak": int(pi.CommitPeak) * page,
        "system_cache": int(pi.SystemCache) * page,
        "kernel_total": int(pi.KernelTotal) * page,
        "physical_total": int(pi.PhysicalTotal) * page,
        "physical_available": int(pi.PhysicalAvailable) * page,
        "page_size": page,
        "process_count": int(pi.ProcessCount),
        "handle_count": int(pi.HandleCount),
    }


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def enable_privilege(name: str) -> tuple[bool, str]:
    """启用当前进程特权。仅用于备用列表清理，不申请 SeDebugPrivilege。"""
    tok = HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(tok)):
        return False, f"无法打开进程令牌 ({win_error()})"
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False, f"系统不支持特权 {name} ({win_error()})"
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        if not advapi32.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None):
            return False, f"AdjustTokenPrivileges 失败 ({win_error()})"
        if win_error() == 1300:  # ERROR_NOT_ALL_ASSIGNED
            return False, f"当前账户未持有 {name}，通常需要以管理员身份运行"
        return True, f"已启用 {name}"
    finally:
        kernel32.CloseHandle(tok)


def user_idle_seconds() -> float:
    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(lii)
    if not user32.GetLastInputInfo(ctypes.byref(lii)):
        return -1.0
    delta = (int(kernel32.GetTickCount()) - int(lii.dwTime)) & 0xFFFFFFFF
    return delta / 1000.0


def cpu_busy_pct(interval: float = 0.20) -> float | None:
    def sample():
        i, k, u = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
        if not kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u)):
            return None
        return _ft(i), _ft(k), _ft(u)
    a, b = sample(), None
    time.sleep(interval)
    b = sample()
    if a is None or b is None:
        return None
    di, dk, du = b[0] - a[0], b[1] - a[1], b[2] - a[2]
    total = dk + du
    if total <= 0:
        return None
    return max(0.0, min(100.0, (1.0 - di / total) * 100.0))


def foreground() -> tuple[int, str]:
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return 0, ""
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    pid = DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value), buf.value.strip()


def single_instance(name: str = "MemGuard_SingleInstance_Mutex") -> tuple[bool, str]:
    h = kernel32.CreateMutexW(None, False, name)
    if not h:
        return False, f"CreateMutexW 失败 ({win_error()})"
    if win_error() == ERROR_ALREADY_EXISTS:
        return False, "已有 MemGuard 实例在运行，本次启动取消"
    return True, "单实例检查通过"


# ---------------------------------------------------------------- 窗口与进程

def display_adapters() -> list[str]:
    """用 EnumDisplayDevicesW 取显卡友好名称（比 PDH 的 LUID 实例名可读）。"""
    out: list[str] = []
    for i in range(16):
        dd = DISPLAY_DEVICEW()
        dd.cb = ctypes.sizeof(dd)
        if not user32.EnumDisplayDevicesW(None, i, ctypes.byref(dd), 0):
            break
        name = (dd.DeviceString or "").strip()
        if name and name not in out:
            out.append(name)
    return out


def enum_top_windows() -> dict[int, list[tuple[int, str]]]:
    """返回 pid -> [(hwnd, 标题)]，只包含有标题的可见顶层窗口。"""
    out: dict[int, list[tuple[int, str]]] = {}

    def cb(hwnd, _lparam):
        if not hwnd or not user32.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buf, 512)
        title = (buf.value or "").strip()
        if not title:
            return True
        pid = DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        out.setdefault(int(pid.value), []).append((int(hwnd), title))
        return True

    fn = WNDENUMPROC(cb)
    try:
        user32.EnumWindows(fn, 0)
    except Exception:  # noqa: BLE001
        pass
    return out


def enum_pids() -> list[int]:
    count = 1024
    while True:
        arr = (DWORD * count)()
        needed = DWORD(0)
        if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return []
        got = int(needed.value) // ctypes.sizeof(DWORD)
        if got < count:
            return [int(arr[i]) for i in range(got) if int(arr[i]) > 0]
        count *= 2
        if count > 65536:
            return [int(arr[i]) for i in range(min(got, count // 2)) if int(arr[i]) > 0]


def _image_name(h: HANDLE) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    size = DWORD(1024)
    if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
        return os.path.basename(buf.value or "") or f"pid?"
    return ""


def enum_processes(windows: dict[int, list[tuple[int, str]]] | None = None) -> list[dict]:
    """只读枚举进程；打不开的进程也会被列出并标记，便于如实提示。"""
    if windows is None:
        windows = enum_top_windows()
    out = []
    for pid in enum_pids():
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            out.append({
                "pid": pid, "name": "", "ws": 0, "private": 0,
                "has_window": pid in windows, "title": (windows.get(pid) or [("", "")])[0][1],
                "accessible": False,
            })
            continue
        try:
            pmc = PROCESS_MEMORY_COUNTERS_EX()
            pmc.cb = ctypes.sizeof(pmc)
            ok = psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), ctypes.sizeof(pmc))
            wins = windows.get(pid) or []
            out.append({
                "pid": pid,
                "name": _image_name(h),
                "ws": int(pmc.WorkingSetSize) if ok else 0,
                "private": int(pmc.PrivateUsage) if ok else 0,
                "has_window": bool(wins),
                "title": wins[0][1] if wins else "",
                "accessible": bool(ok),
            })
        finally:
            kernel32.CloseHandle(h)
    return out


def is_process_alive(pid: int) -> bool:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = DWORD(0)
        if not kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return int(code.value) == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(h)


# ---------------------------------------------------------------- PDH

def pdh_expand(wildcard_path: str) -> tuple[list[str], str]:
    if not PDH_OK:
        return [], "PDH 库不可用"
    size = DWORD(0)
    pdh.PdhExpandWildCardPathW(None, wildcard_path, None, ctypes.byref(size), 0)
    if size.value <= 0:
        return [], f"计数器不存在：{wildcard_path}"
    buf = ctypes.create_unicode_buffer(int(size.value) + 2)
    size2 = DWORD(len(buf))
    rc = pdh.PdhExpandWildCardPathW(None, wildcard_path, buf, ctypes.byref(size2), 0)
    if rc != 0:
        return [], f"展开计数器失败 {wildcard_path} (PDH 0x{rc & 0xFFFFFFFF:08X})"
    # create_unicode_buffer 返回 c_wchar_Array，没有 .raw 属性，需按地址读回原始字节。
    raw = ctypes.string_at(ctypes.addressof(buf), len(buf) * ctypes.sizeof(ctypes.c_wchar))
    text = raw.decode("utf-16-le", errors="ignore")
    return [s for s in text.split("\x00") if s.strip()], "OK"


def pdh_collect(paths: list[str], settle: float = 0.30) -> tuple[dict[str, float | None], str]:
    """采集一组 PDH 计数器。速率型计数器需要两次采样，内部自动完成。"""
    if not PDH_OK or not paths:
        return {p: None for p in paths}, "PDH 不可用或无计数器"
    hq = HANDLE()
    if pdh.PdhOpenQueryW(None, 0, ctypes.byref(hq)) != 0:
        return {p: None for p in paths}, f"PdhOpenQueryW 失败 ({win_error()})"
    handles: dict[str, HANDLE | None] = {}
    failed: list[str] = []
    try:
        for path in paths:
            h = HANDLE()
            rc = pdh.PdhAddEnglishCounterW(hq, path, 0, ctypes.byref(h))
            if rc == 0:
                handles[path] = h
            else:
                handles[path] = None
                failed.append(path)
        pdh.PdhCollectQueryData(hq)
        time.sleep(settle)
        pdh.PdhCollectQueryData(hq)
        result: dict[str, float | None] = {}
        for path, h in handles.items():
            if h is None:
                result[path] = None
                continue
            val = PDH_FMT_COUNTERVALUE()
            ctype = DWORD(0)
            rc = pdh.PdhGetFormattedCounterValue(h, PDH_FMT_DOUBLE, ctypes.byref(ctype), ctypes.byref(val))
            if rc == 0 and int(val.CStatus) == PDH_CSTATUS_VALID_DATA:
                result[path] = float(val.value.doubleValue)
            else:
                result[path] = None
        note = "OK" if not failed else f"有 {len(failed)} 个计数器不可用（已跳过，不影响其它指标）"
        return result, note
    finally:
        pdh.PdhCloseQuery(hq)


def disk_busy_pct() -> float | None:
    vals, _ = pdh_collect([r"\PhysicalDisk(_Total)\% Disk Time"], settle=0.30)
    v = next(iter(vals.values()), None)
    if v is None:
        return None
    return max(0.0, min(100.0, v))


# ---------------------------------------------------------------- nvidia-smi（只读）

def _run_hidden(args: list[str], timeout: float = 3.0) -> tuple[bool, str]:
    try:
        cp = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, creationflags=CREATE_NO_WINDOW,
        )
        if cp.returncode != 0:
            return False, (cp.stderr or "").strip()[:300] or f"退出码 {cp.returncode}"
        return True, cp.stdout.strip()
    except FileNotFoundError:
        return False, "未找到该命令行工具"
    except subprocess.TimeoutExpired:
        return False, "查询超时"
    except Exception as exc:  # noqa: BLE001
        return False, f"查询异常：{exc}"


def nvidia_smi_info() -> tuple[bool, list[dict], list[dict], str]:
    """只读查询 NVIDIA 显卡总量/用量与显存占用进程；非 N 卡环境会明确失败。"""
    ok, out = _run_hidden([
        "nvidia-smi",
        "--query-gpu=index,name,memory.total,memory.used",
        "--format=csv,noheader,nounits",
    ])
    gpus: list[dict] = []
    if ok:
        for line in out.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            try:
                gpus.append({
                    "index": int(parts[0]), "name": parts[1],
                    "total_mb": float(parts[2]), "used_mb": float(parts[3]),
                })
            except ValueError:
                continue
    ok2, out2 = _run_hidden([
        "nvidia-smi",
        "--query-compute-apps=pid,process_name,used_gpu_memory",
        "--format=csv,noheader,nounits",
    ])
    apps: list[dict] = []
    if ok2 and out2:
        for line in out2.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                continue
            try:
                apps.append({"pid": int(parts[0]), "name": parts[1], "gpu_mb": float(parts[2])})
            except ValueError:
                continue
    note = "nvidia-smi 可用" if ok else f"nvidia-smi 不可用：{out[:160]}"
    return ok, gpus, apps, note


# ---------------------------------------------------------------- 执行动作

def trim_working_set(pid: int) -> tuple[bool, str]:
    """L1：把该进程的物理工作集换出到页面文件，不结束进程、不释放提交内存。"""
    h = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        h = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return False, f"无法以 PROCESS_SET_QUOTA 打开进程 ({win_error()})：受保护进程或权限不足"
    try:
        if psapi.EmptyWorkingSet(h):
            return True, "EmptyWorkingSet 成功（物理页已换出）"
        err = win_error()
        minus = SIZE_T(-1)
        if kernel32.SetProcessWorkingSetSizeEx(h, minus, minus, QUOTA_LIMITS_HARDWS_DISABLE):
            return True, "SetProcessWorkingSetSizeEx 成功（备用裁剪方式）"
        return False, f"两种裁剪方式均失败（Win32 {err} / {win_error()}）"
    finally:
        kernel32.CloseHandle(h)


def purge_standby_list() -> tuple[bool, str]:
    """L2：清理备用列表（RAMMap「Empty Standby List」同款），需管理员。"""
    if not is_admin():
        return False, "需要管理员权限；请以管理员身份重启程序后再试"
    okp, msg = enable_privilege("SeProfileSingleProcessPrivilege")
    if not okp:
        return False, f"特权未就绪：{msg}"
    cmd = ctypes.c_int(MemoryPurgeStandbyList)
    status = int(ntdll.NtSetSystemInformation(
        SystemMemoryListInformation, ctypes.byref(cmd), ctypes.sizeof(cmd)
    ))
    if status == 0:
        return True, f"备用列表清理命令已执行（{msg}）"
    return False, f"NtSetSystemInformation 返回 NTSTATUS 0x{status & 0xFFFFFFFF:08X}（{msg}）"


def post_close(pid: int, windows: dict[int, list[tuple[int, str]]]) -> tuple[int, str]:
    """L3 第一步：向进程所有可见顶层窗口投递 WM_CLOSE，让应用有机会保存。"""
    wins = windows.get(pid) or []
    if not wins:
        return 0, "该进程没有可见窗口，无法发送关闭消息"
    sent = 0
    for hwnd, _title in wins:
        if user32.PostMessageW(ctypes.c_void_p(hwnd), WM_CLOSE, 0, 0):
            sent += 1
    return sent, f"已向 {sent}/{len(wins)} 个窗口发送 WM_CLOSE（等待应用自行保存并退出）"


def force_kill(pid: int) -> tuple[bool, str]:
    """L3 最后一步：仅在用户逐项勾选 + 二次确认 + 优雅关闭超时后调用。"""
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False, f"无法以 PROCESS_TERMINATE 打开进程 ({win_error()})"
    try:
        if kernel32.TerminateProcess(h, 1):
            return True, "进程已强制结束（其显存与内存由系统回收）"
        return False, f"TerminateProcess 失败 ({win_error()})"
    finally:
        kernel32.CloseHandle(h)
