"""Read a bounded stable regular file through held, no-follow directories."""

import os
import stat

from .model import DEFAULT_LIMITS, ParseIssue


def read_local(path):
    if type(path) is not str or "\0" in path:
        raise ParseIssue("file_path_input")
    try:
        if len(path.encode("utf-8", "strict")) > 8192:
            raise ParseIssue("file_path_input")
    except UnicodeError:
        raise ParseIssue("file_path_input") from None
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise ParseIssue("safe_file_platform_not_supported")
    absolute = path.startswith("/")
    parts = path.split("/")[1:] if absolute else path.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ParseIssue("file_path_components")
    descriptor = None
    directories = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directories.append(os.open("/" if absolute else ".", flags))
        for name in parts[:-1]:
            directories.append(os.open(name, flags, dir_fd=directories[-1]))
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directories[-1]
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > DEFAULT_LIMITS.file_bytes:
            raise ParseIssue("file_not_regular_or_byte_budget")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, DEFAULT_LIMITS.file_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > DEFAULT_LIMITS.file_bytes:
                raise ParseIssue("file_byte_budget")
        after = os.fstat(descriptor)

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        if (
            not stat.S_ISREG(after.st_mode)
            or identity(before) != identity(after)
            or size != after.st_size
        ):
            raise ParseIssue("file_changed_or_short_read")
        return b"".join(chunks)
    except (OSError, UnicodeError):
        raise ParseIssue("file_input_error") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(directories):
            os.close(directory)
