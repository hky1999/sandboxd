#!/usr/bin/python3
# Copyright (c) 2026 Ant Group Corporation.
# SPDX-License-Identifier: Apache-2.0
"""Hold an owned daemon before its selected cgroup.kill write.

The helper runs outside services, reads original files and never sends SIGKILL.
Only the host observer may terminate the original externally audited daemon.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

assert os.environ.get('SANDBOXD_DAEMON_RETIREMENT_FIXTURE') == '1'
assert os.uname().machine == 'x86_64'
binary = Path('/usr/local/bin/sandboxd')
evidence = Path('/test-state/evidence')
selector = Path('/test-state/close-trace-selector.json')
expected_sha = os.environ['DAEMON_FIXTURE_BINARY_SHA256']
assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected_sha
observers = Path('/sys/fs/cgroup/observers')
observers.mkdir(exist_ok=True)
(observers / 'cgroup.procs').write_text(str(os.getpid()))
assert Path('/proc/self/cgroup').read_text().strip().endswith('/observers')
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
TRACEME, PEEKDATA, SYSCALL, GETREGS = 0, 2, 24, 12
SETOPTIONS, OPTIONS, WALL = 0x4200, 1 | 8, 0x40000000

class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        'r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8',
        'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags',
        'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs')]

def ptrace(request, pid, address=None, data=None):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, address, data)
    if result == -1 and ctypes.get_errno():
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result

def save(name, value):
    with (evidence / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

pid = os.fork()
if pid == 0:
    Path('/sys/fs/cgroup/services/cgroup.procs').write_text(str(os.getpid()))
    ptrace(TRACEME, 0)
    os.execv(str(binary), [str(binary), *sys.argv[1:]])
waited, status = os.waitpid(pid, WALL)
assert waited == pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP
proc = Path('/proc') / str(pid)
tail = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
daemon = {'pid': pid, 'start_ticks': int(tail[19]),
          'executable_sha256': hashlib.sha256((proc / 'exe').read_bytes()).hexdigest(),
          'arguments_sha256': hashlib.sha256((proc / 'cmdline').read_bytes()).hexdigest(),
          'cgroup': (proc / 'cgroup').read_text()}
assert daemon['executable_sha256'] == expected_sha
assert daemon['cgroup'].strip().endswith('/services')
save('traced-daemon-original.json', daemon)
ptrace(SETOPTIONS, pid, data=ctypes.c_void_p(OPTIONS))
ptrace(SYSCALL, pid)
held_tid = None
selection = None
while True:
    tid, status = os.waitpid(-1, WALL)
    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
        if tid == pid:
            killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            save('traced-daemon-exit.json', {'daemon': daemon, 'host_sigkill_observed': killed,
                                           'selected_syscall_held': held_tid is not None})
            raise SystemExit(137 if killed else os.WEXITSTATUS(status))
        continue
    assert os.WIFSTOPPED(status)
    delivery = 0
    stop = os.WSTOPSIG(status)
    if stop == (signal.SIGTRAP | 0x80) and held_tid is None:
        registers = Registers()
        ptrace(GETREGS, tid, data=ctypes.cast(ctypes.byref(registers), ctypes.c_void_p))
        # On x86_64 -ENOSYS identifies entry before the kernel effect.
        if registers.orig_rax == 1 and registers.rax == (2**64 - 38) and registers.rdx == 1:
            if selection is None and selector.exists():
                selection = json.loads(selector.read_text())
            if selection is not None:
                fd = Path('/proc') / str(tid) / 'fd' / str(registers.rdi)
                expected = Path('/sys/fs/cgroup') / selection['cgroup_path'].lstrip('/') / 'cgroup.kill'
                try:
                    selected = os.readlink(fd) == str(expected)
                except FileNotFoundError:
                    selected = False
                if selected:
                    directory = expected.parent.stat()
                    assert (directory.st_dev, directory.st_ino) == (selection['device'], selection['inode'])
                    assert (fd.stat().st_dev, fd.stat().st_ino) == (expected.stat().st_dev, expected.stat().st_ino)
                    assert ptrace(PEEKDATA, tid, ctypes.c_void_p(registers.rsi)) & 0xff == ord('1')
                    key = hashlib.sha256(json.dumps([selection['sandbox_id'], selection['resource_generation']], separators=(',', ':')).encode()).hexdigest()
                    path = Path('/test-state/root/scheduler-retirement-progress') / (key + '.json')
                    raw = path.read_bytes()
                    progress = json.loads(raw)
                    close = progress['cgroup_close']
                    assert progress['sandbox_id'] == selection['sandbox_id']
                    assert progress['generation'] == selection['resource_generation']
                    assert progress['version'] == 2 and progress['completed_steps'] == []
                    assert close['runtime_source_verified']
                    assert close['identity'] == {'Path': selection['cgroup_path'], 'Device': directory.st_dev, 'Inode': directory.st_ino}
                    assert close['request']['generation'] == selection['resource_generation']
                    held_tid = tid
                    save('daemon-cgroup-kill-write-held.json', {'daemon': daemon, 'thread': tid,
                         'syscall_number': 1, 'syscall_not_executed': True, 'write_bytes': '1',
                         'selected_original': selection, 'original_progress': progress,
                         'original_progress_sha256': hashlib.sha256(raw).hexdigest(),
                         'tracer_cgroup': Path('/proc/self/cgroup').read_text(),
                         'runtime_state_modified_by_tracer': False})
                    continue
    elif stop not in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80):
        # Other threads still produce syscall stops while the selected thread
        # is held. 133 is a ptrace stop marker, never a deliverable signal.
        delivery = stop
    if tid != held_tid:
        ptrace(SYSCALL, tid, data=ctypes.c_void_p(delivery))
