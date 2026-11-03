
#!/usr/bin/env python3
"""CSCE 5550: file-open permission demonstration."""

import ctypes
import os
import struct
from pathlib import Path

TARGET = Path("/home/osboxes/CSCE5550-Group3/fanotify_test/document.txt")

FAN_CLOEXEC = 0x01
FAN_CLASS_CONTENT = 0x04
FAN_MARK_ADD = 0x01
FAN_OPEN_PERM = 0x00010000
FAN_ALLOW = 0x01
FAN_DENY = 0x02
AT_FDCWD = -100

# Demo policy: allow /usr/bin/cat, deny other processes.
ALLOWED_EXECUTABLES = {"/usr/bin/cat"}

libc = ctypes.CDLL("libc.so.6", use_errno=True)

libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
libc.fanotify_init.restype = ctypes.c_int

libc.fanotify_mark.argtypes = [
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.c_ulonglong,
    ctypes.c_int,
    ctypes.c_char_p,
]
libc.fanotify_mark.restype = ctypes.c_int


def check(result, operation):
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, f"{operation}: {os.strerror(error)}")
    return result


def main():
    if not TARGET.is_file():
        raise FileNotFoundError(TARGET)

    fd = check(
        libc.fanotify_init(
            FAN_CLOEXEC | FAN_CLASS_CONTENT,
            os.O_RDONLY | os.O_CLOEXEC,
        ),
        "fanotify_init",
    )

    try:
        check(
            libc.fanotify_mark(
                fd,
                FAN_MARK_ADD,
                FAN_OPEN_PERM,
                AT_FDCWD,
                os.fsencode(TARGET),
            ),
            "fanotify_mark",
        )

        print(f"Protecting: {TARGET}", flush=True)
        print("Allowed executable: /usr/bin/cat", flush=True)
        print("Press Ctrl+C to stop.", flush=True)

        while True:
            data = os.read(fd, 4096)
            offset = 0

            while offset + 24 <= len(data):
                event_len, version, _, metadata_len, mask, event_fd, pid = (
                    struct.unpack_from("=IBBHQii", data, offset)
                )

                if event_len < 24 or offset + event_len > len(data):
                    raise RuntimeError("Invalid fanotify event")

                offset += event_len

                if event_fd < 0:
                    continue

                try:
                    if not (mask & FAN_OPEN_PERM):
                        continue

                    try:
                        executable = os.readlink(f"/proc/{pid}/exe")
                    except OSError:
                        executable = "UNKNOWN"

                    allowed = executable in ALLOWED_EXECUTABLES
                    decision = FAN_ALLOW if allowed else FAN_DENY

                    os.write(fd, struct.pack("=iI", event_fd, decision))

                    status = "ALLOW" if allowed else "DENY"
                    print(
                        f"{status} | PID={pid} | executable={executable}",
                        flush=True,
                    )
                finally:
                    os.close(event_fd)

    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGuard stopped.")

