"""Independent native permission inspection for inert report fixtures."""

import ctypes
import os
import re
from ctypes import wintypes
from pathlib import Path


def windows_sddl(path: Path) -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    security = wintypes.LPVOID()
    text = wintypes.LPWSTR()
    result = advapi.GetNamedSecurityInfoW(
        str(path), 1, 5, None, None, None, None, ctypes.byref(security)
    )
    if result:
        raise ctypes.WinError(result)
    try:
        if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security, 1, 5, ctypes.byref(text), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        assert text.value is not None
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
        kernel.LocalFree(security)


def set_windows_dacl(path: Path, sddl: str) -> None:
    """Set only a disposable fixture's DACL; never invoke a shell or elevate."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    security, dacl = wintypes.LPVOID(), wintypes.LPVOID()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(security), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        assert advapi.GetSecurityDescriptorDacl(
            security, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        )
        result = advapi.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None)
        if result:
            raise ctypes.WinError(result)
    finally:
        kernel.LocalFree(security)


def windows_process_sid() -> str:
    """Independently resolve the current process TokenUser, not a username guess."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    token, text = wintypes.HANDLE(), wintypes.LPWSTR()
    assert advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token))
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        assert size.value
        info = ctypes.create_string_buffer(size.value)
        assert advapi.GetTokenInformation(token, 1, info, size, ctypes.byref(size))
        sid = ctypes.cast(info, ctypes.POINTER(wintypes.LPVOID))[0]
        assert advapi.ConvertSidToStringSidW(sid, ctypes.byref(text))
        assert text.value
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
        kernel.CloseHandle(token)


def assert_private(path: Path) -> None:
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        return
    sddl = windows_sddl(path)
    owner, dacl = sddl.removeprefix("O:").split("D:")
    assert owner == windows_process_sid(), sddl
    assert dacl.startswith("P("), sddl  # protected, no inherited permissions
    aces = re.findall(r"\(([^)]+)\)", dacl)
    assert len(aces) == 3, sddl
    assert {tuple(ace.split(";")) for ace in aces} == {
        ("A", "", "FA", "", "", owner),
        ("A", "", "FA", "", "", "SY"),
        ("A", "", "FA", "", "", "BA"),
    }, sddl
