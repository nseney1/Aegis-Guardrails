"""Create an owned Windows directory junction without a shell or privilege changes.

Win32 contracts: DeviceIoControl/FSCTL_SET_REPARSE_POINT, REPARSE_DATA_BUFFER's
MountPointReparseBuffer, and CreateFileW with OPEN_REPARSE_POINT/BACKUP_SEMANTICS.
https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_reparse_point
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
"""
from __future__ import annotations

from pathlib import Path
import os
import struct
import sys

__all__ = ["create_directory_junction"]

_MOUNT_POINT = 0xA0000003


def _kernel32():
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    word, handle, pointer = ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p
    declarations = {
        "CreateFileW": (handle, [ctypes.c_wchar_p, word, word, pointer, word, word, handle]),
        "DeviceIoControl": (ctypes.c_int32, [handle, word, pointer, word, pointer, word,
                                            ctypes.POINTER(word), pointer]),
        "CloseHandle": (ctypes.c_int32, [handle]),
        "GetLastError": (word, []),
        "GetFileInformationByHandleEx": (ctypes.c_int32, [handle, ctypes.c_int32, pointer, word]),
        "GetFileInformationByHandle": (ctypes.c_int32, [handle, pointer]),
        "GetVolumeInformationByHandleW": (ctypes.c_int32, [handle, ctypes.c_wchar_p, word,
            pointer, pointer, pointer, ctypes.c_wchar_p, word]),
    }
    for name, (result, arguments) in declarations.items():
        function = getattr(kernel, name)
        function.restype, function.argtypes = result, arguments
    return kernel


def _opened_identity(kernel, handle) -> tuple[int, int]:
    """Match CPython's stat identity without truncating a modern file identifier.

    FILE_ID_INFO supplies the full 128-bit ID. Older Python stat uses the legacy
    file index, which Microsoft does not guarantee unique on ReFS; require NTFS.
    https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
    https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information
    """
    import ctypes

    if sys.version_info >= (3, 12):
        info = ctypes.create_string_buffer(24)  # FILE_ID_INFO: ULONGLONG + FILE_ID_128.
        if not kernel.GetFileInformationByHandleEx(handle, 18, info, len(info)):
            raise OSError(f"GetFileInformationByHandleEx failed: Windows error {kernel.GetLastError()}")
        identity = (struct.unpack_from("<Q", info.raw)[0], int.from_bytes(info.raw[8:], "little"))
    else:
        filesystem = ctypes.create_unicode_buffer(261)
        if not kernel.GetVolumeInformationByHandleW(handle, None, 0, None, None, None,
                                                    filesystem, len(filesystem)):
            raise OSError(f"GetVolumeInformationByHandleW failed: Windows error {kernel.GetLastError()}")
        if filesystem.value.upper() != "NTFS":
            raise OSError("directory junction identity requires NTFS on Python before 3.12")
        info = (ctypes.c_uint32 * 13)()  # BY_HANDLE_FILE_INFORMATION's DWORD fields.
        if not kernel.GetFileInformationByHandle(handle, info):
            raise OSError(f"GetFileInformationByHandle failed: Windows error {kernel.GetLastError()}")
        identity = (info[7], (info[11] << 32) | info[12])
    if not identity[1]:
        raise OSError("opened directory identity unavailable")
    return identity


def _mount_point_data(target: str) -> bytes:
    target = target.replace("/", "\\")
    if target.startswith("\\\\?\\"):
        target = target[4:]
    if target.startswith("\\\\") or target.upper().startswith("UNC\\"):
        raise OSError("directory junctions require a local target")
    substitute, display = ("\\??\\" + target).encode("utf-16-le"), target.encode("utf-16-le")
    names = substitute + b"\0\0" + display + b"\0\0"
    if len(names) + 16 > 16384:
        raise OSError("directory junction target exceeds the reparse buffer limit")
    return struct.pack("<LHHHHHH", _MOUNT_POINT, len(names) + 8, 0, 0, len(substitute),
                       len(substitute) + 2, len(display)) + names


def create_directory_junction(target: Path, link: Path) -> None:
    """Create a new junction; refuse existing entries and preserve replacements on failure.

    The caller owns successful cleanup with rmdir (which removes the junction,
    never its target), after checking identity, reparse tag and substitution target.
    Windows API errors propagate without attempts to enable token privileges.
    Failed identity verification preserves the entry instead of guessing ownership.
    """
    import ctypes

    if not target.is_dir():
        raise NotADirectoryError(str(target))
    data = _mount_point_data(str(target.resolve()))
    kernel = _kernel32()
    link.mkdir()
    owned = link.lstat()
    safe_cleanup = False
    try:
        # GENERIC_WRITE does not include FILE_READ_ATTRIBUTES for identity queries.
        handle = kernel.CreateFileW(str(link), 0x40000080, 3, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError(f"CreateFileW failed: Windows error {kernel.GetLastError()}")
        try:
            if _opened_identity(kernel, handle) != (owned.st_dev, owned.st_ino):
                raise OSError("directory junction changed during creation")
            safe_cleanup = True
            returned = ctypes.c_uint32()
            buffer = ctypes.create_string_buffer(data)
            if not kernel.DeviceIoControl(handle, 0x000900A4, buffer, len(data), None, 0,
                                          ctypes.byref(returned), None):
                raise OSError(f"DeviceIoControl failed: Windows error {kernel.GetLastError()}")
        finally:
            if not kernel.CloseHandle(handle):
                raise OSError(f"CloseHandle failed: Windows error {kernel.GetLastError()}")
        current = link.lstat()
        if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
            raise OSError("directory junction changed during creation")
        if getattr(current, "st_reparse_tag", 0) != _MOUNT_POINT:
            raise OSError("created directory junction has the wrong reparse tag")
    except BaseException:
        if safe_cleanup and os.path.lexists(link):
            current = link.lstat()
            if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                link.rmdir()
        raise
