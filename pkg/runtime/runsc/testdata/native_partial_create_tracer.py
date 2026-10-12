#!/usr/bin/python3
# Copyright (c) 2026 Ant Group Corporation.
# SPDX-License-Identifier: Apache-2.0
"""Pause an actual managed create after its gofer birth directory fsync.

Explicit BareMetal1 fixture only. Never writes runtime state or sends SIGKILL.
The external host observer audits and terminates the fixed original creator.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


assert os.environ.get("SANDBOXD_RUN_NATIVE_BIRTH_INTEGRATION") == "1"
assert os.uname().machine == "x86_64"
binary = Path(os.environ["NATIVE_BIRTH_RUNSC_BINARY"])
evidence = Path(os.environ["NATIVE_BIRTH_EVIDENCE"])
assert binary.is_absolute() and evidence.is_absolute()
assert hashlib.sha256(binary.read_bytes()).hexdigest() == os.environ["NATIVE_BIRTH_RUNSC_SHA256"]
args = sys.argv[1:]
assert args[-1] == "partial-original" and "create" in args
assert "--scheduler-resource-generation=generation-partial" in args
root = Path(args[args.index("--root") + 1])
state_path = root / "partial-original_sandbox:partial-original.state"
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
PTRACE_TRACEME, PTRACE_SYSCALL, PTRACE_GETREGS = 0, 24, 12
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACECLONE = 1, 8
PTRACE_EVENT_CLONE, WALL, SYS_FSYNC = 3, 0x40000000, 74


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


def ptrace(request, pid, data=None):
    result = libc.ptrace(request, pid, None, data)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def save(name, value):
    with (evidence / name).open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


pid = os.fork()
if pid == 0:
    ptrace(PTRACE_TRACEME, 0)
    os.execv(str(binary), [str(binary), *args])

waited, status = os.waitpid(pid, WALL)
assert waited == pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP
proc = Path("/proc") / str(pid)
tail = (proc / "stat").read_text().rsplit(")", 1)[1].split()
creator = {"pid": pid, "start_ticks": int(tail[19]),
           "executable_sha256": hashlib.sha256((proc / "exe").read_bytes()).hexdigest(),
           "arguments_sha256": hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest(),
           "cgroup_sha256": hashlib.sha256((proc / "cgroup").read_bytes()).hexdigest()}
assert creator["executable_sha256"] == os.environ["NATIVE_BIRTH_RUNSC_SHA256"]
if os.environ.get("NATIVE_LAUNCH_CGROUP_PARENT"):
    # This exec trap precedes the creator's first user instruction and any
    # gofer dispatch. The adapter's durable intent must already exist.
    intent_path = root / ".scheduler-launches/partial-original.json"
    intent = json.loads(intent_path.read_bytes())
    assert intent["sandbox_id"] == "partial-original" and intent["resource_generation"] == "generation-partial"
    assert intent["clone_into_cgroup"] and intent["stage"] == "dispatching"
    creator["launch_intent_present_before_first_instruction"] = True
    creator["original_launch_intent"] = intent
save("partial-creator-ready.json", creator)
deadline = time.monotonic() + 120
while not (evidence / "allow-partial-trace").exists():
    assert time.monotonic() < deadline, "original creator was not externally audited"
    time.sleep(0.01)

ptrace(PTRACE_SETOPTIONS, pid, ctypes.c_void_p(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE))
ptrace(PTRACE_SYSCALL, pid)
paused = False
while not paused:
    tid, status = os.waitpid(-1, WALL)
    assert not os.WIFEXITED(status) and not os.WIFSIGNALED(status), "creator exited before gofer birth publication"
    assert os.WIFSTOPPED(status)
    stop = os.WSTOPSIG(status)
    delivery = 0
    if stop == (signal.SIGTRAP | 0x80):
        registers = Registers()
        ptrace(PTRACE_GETREGS, tid, ctypes.cast(ctypes.byref(registers), ctypes.c_void_p))
        # On x86_64 syscall entry rax is -ENOSYS. A zero fsync return is
        # its actual exit, including threads newly observed after clone.
        if registers.orig_rax == SYS_FSYNC and registers.rax == 0:
            fd = Path("/proc") / str(tid) / "fd" / str(registers.rdi)
            source = fd.stat()
            target = root.stat()
            if stat.S_ISDIR(source.st_mode) and (source.st_dev, source.st_ino) == (target.st_dev, target.st_ino):
                raw = state_path.read_bytes()
                state = json.loads(raw)
                if state.get("goferLaunchState") == "birth_published" and state.get("sentryLaunchState") == "not_dispatched":
                    assert state["id"] == "partial-original" and state["resourceGeneration"] == "generation-partial"
                    assert state["processBirthVersion"] == state["processLaunchVersion"] == 1
                    assert state["runtimeDispatched"] and state["goferRequired"]
                    assert state["goferPid"] == state["goferBirth"]["pid"] and state.get("sandbox") is None
                    # Keep the publishing thread at its real successful fsync
                    # exit. Stop the creator group before any user instruction
                    # can dispatch a Sentry. No process fact is manufactured.
                    os.kill(pid, signal.SIGSTOP)
                    save("partial-create-paused.json", {
                        "creator": creator, "publishing_thread": tid,
                        "syscall": "fsync", "syscall_number": SYS_FSYNC, "actual_return": 0,
                        "synced_directory_device": source.st_dev, "synced_directory_inode": source.st_ino,
                        "state_path": str(state_path), "state_sha256": hashlib.sha256(raw).hexdigest(),
                        "original_producer_state": state, "runtime_state_was_written_by_tracer": False})
                    paused = True
                    break
    elif stop not in (signal.SIGTRAP, signal.SIGSTOP):
        delivery = stop
    ptrace(PTRACE_SYSCALL, tid, ctypes.c_void_p(delivery))

# Only the audited host observer may terminate the creator. Wait for the real
# original creator's exit; do not reinterpret a timeout as completed creation.
while True:
    tid, status = os.waitpid(-1, WALL)
    if tid == pid and os.WIFSIGNALED(status):
        assert os.WTERMSIG(status) == signal.SIGKILL
        save("partial-creator-exited.json", {"creator": creator, "signal": signal.SIGKILL,
                                            "creation_success_reply_received": False})
        raise SystemExit(137)
    if os.WIFSTOPPED(status):
        # SIGSTOP/event stops remain held. SIGKILL is never suppressed by
        # ptrace and will terminate all threads when the host sends it.
        continue
