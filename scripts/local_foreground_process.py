"""Dependency-free foreground subprocess supervision.

The module owns only native process lifetime, process-tree cleanup, and raw
byte transport.  Provider policy, executable identity, environment policy,
and response parsing belong to callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import hashlib
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Callable, Mapping, Sequence


_STOP_OBSERVATION_SEAL = object()


@dataclass(frozen=True)
class ProcessStopObservation:
    """In-process observation, not a serializable grant or remote-writer proof."""

    request_sha256: str
    observation_id: str
    _seal: object = field(default=None, repr=False, compare=False)


def _request_digest(argv: Sequence[str], cwd: str, input_bytes: bytes) -> str:
    return hashlib.sha256(json.dumps(
        [list(argv), cwd, hashlib.sha256(input_bytes).hexdigest()],
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def verify_process_stop(
    observation: ProcessStopObservation | None, *,
    argv: Sequence[str], cwd: str, input_bytes: bytes,
) -> bool:
    return bool(
        isinstance(observation, ProcessStopObservation)
        and observation._seal is _STOP_OBSERVATION_SEAL
        and observation.request_sha256 == _request_digest(argv, cwd, input_bytes)
    )


@dataclass(frozen=True)
class SupervisedProcessResult:
    returncode: int | None
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    timed_out: bool
    error_code: str | None
    stop_observation: ProcessStopObservation | None = field(default=None, repr=False)


class ProcessSupervisionError(OSError):
    """A fixed, non-sensitive supervision failure category."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class WindowsKillJob:
    """Windows Job Object with kill-on-close, assigned before child release."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = (
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            )

        class IoCounters(ctypes.Structure):
            _fields_ = tuple(
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            )

        class ExtendedLimit(ctypes.Structure):
            _fields_ = (
                ("BasicLimitInformation", BasicLimit),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            )

        self._ctypes = ctypes
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
        )
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
        )
        self._kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise OSError(ctypes.get_last_error(), "CREATE_JOB_OBJECT_FAILED")
        info = ExtendedLimit()
        info.BasicLimitInformation.LimitFlags = 0x00002000
        if not self._kernel32.SetInformationJobObject(
            self._handle, 9, ctypes.byref(info), ctypes.sizeof(info)
        ):
            error = ctypes.get_last_error()
            self.close()
            raise OSError(error, "SET_JOB_LIMIT_FAILED")

    def assign(self, process: subprocess.Popen[bytes]) -> bool:
        return bool(
            self._kernel32.AssignProcessToJobObject(self._handle, process._handle)
        )

    def terminate(self, process: subprocess.Popen[bytes]) -> bool:
        ok = bool(self._kernel32.TerminateJobObject(self._handle, 1))
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            ok = False
        if ok:
            ok = self._wait_empty()
        self.close()
        return ok and process.poll() is not None

    def _wait_empty(self, timeout: float = 10.0) -> bool:
        """Query the still-open Job; parent exit alone is insufficient."""
        ctypes = self._ctypes

        class BasicAccounting(ctypes.Structure):
            _fields_ = (
                ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", ctypes.c_ulong), ("TotalProcesses", ctypes.c_ulong),
                ("ActiveProcesses", ctypes.c_ulong), ("TotalTerminatedProcesses", ctypes.c_ulong),
            )

        deadline = time.monotonic() + timeout
        while True:
            accounting = BasicAccounting()
            if not self._kernel32.QueryInformationJobObject(
                self._handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None,
            ):
                return False
            if accounting.ActiveProcesses == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _windows_wrapper_argv(gate: Path, argv: Sequence[str]) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-S",
        str(Path(__file__).resolve()),
        "_exec-wrapper",
        str(gate),
        json.dumps(list(argv), ensure_ascii=False),
    ]


def _exec_wrapper(gate_text: str, argv_json: str) -> int:
    """Wait until the parent binds this process to a Job, then run the argv."""
    gate = Path(gate_text)
    try:
        argv = json.loads(argv_json)
    except json.JSONDecodeError:
        return 125
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) for item in argv)
    ):
        return 125
    deadline = time.monotonic() + 10
    while gate.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if gate.exists():
        return 124
    try:
        return subprocess.run(argv, check=False).returncode
    except OSError:
        return 126


class SupervisedProcessRunner:
    """Resident owner of one argv and its process tree until completion/cancel.

    Observation intervals never end the task. The caller can keep this run in
    its existing foreground exec session while the host UI yields. No detached
    child, second send or ownership transfer is implied by that UI yield.
    """

    def __init__(
        self,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        self._popen = popen

    @staticmethod
    def _windows_process_tree(root_pid: int) -> list[int]:
        import ctypes
        from ctypes import wintypes

        class ProcessEntry(ctypes.Structure):
            _fields_ = (
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(ProcessEntry),
        )
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(ProcessEntry),
        )
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "PROCESS_SNAPSHOT_FAILED")
        children: dict[int, list[int]] = {}
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        try:
            ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                children.setdefault(int(entry.th32ParentProcessID), []).append(
                    int(entry.th32ProcessID)
                )
                ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)

        postorder: list[int] = []

        def visit(pid: int) -> None:
            for child in children.get(pid, []):
                visit(child)
                postorder.append(child)

        visit(root_pid)
        return postorder

    @staticmethod
    def _windows_pid_exists(pid: int) -> bool:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x00100000, False, pid)
        if not handle:
            return ctypes.get_last_error() != 87
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _windows_terminate_pid(pid: int) -> bool:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x0001 | 0x00100000, False, pid)
        if not handle:
            return (
                ctypes.get_last_error() == 87
                or not SupervisedProcessRunner._windows_pid_exists(pid)
            )
        try:
            if not kernel32.TerminateProcess(handle, 1):
                return kernel32.WaitForSingleObject(handle, 0) == 0
            return kernel32.WaitForSingleObject(handle, 5000) == 0
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _stop_tree(process: subprocess.Popen[bytes]) -> bool:
        if process.poll() is not None:
            return True
        if os.name == "nt":
            try:
                descendants = SupervisedProcessRunner._windows_process_tree(process.pid)
            except OSError:
                descendants = []
                snapshot_ok = False
            else:
                snapshot_ok = True
            SupervisedProcessRunner._windows_terminate_pid(process.pid)
            for pid in descendants:
                SupervisedProcessRunner._windows_terminate_pid(pid)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(
                SupervisedProcessRunner._windows_pid_exists(pid) for pid in descendants
            ):
                time.sleep(0.02)
            remaining = [
                pid
                for pid in descendants
                if SupervisedProcessRunner._windows_pid_exists(pid)
            ]
            tree_command_ok = snapshot_ok and not remaining
        else:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                tree_command_ok = True
            except (OSError, ProcessLookupError):
                tree_command_ok = False
        if not tree_command_ok and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                return False
        return tree_command_ok and process.poll() is not None

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str,
        env: Mapping[str, str] | None,
        input_bytes: bytes,
        timeout_seconds: float | None = None,
        authority_ends_at: float | None = None,
        cancel_event=None,
        observation_interval_seconds: float = 1.0,
    ) -> SupervisedProcessResult:
        if (
            isinstance(argv, (str, bytes))
            or not argv
            or any(not isinstance(item, str) for item in argv)
        ):
            raise ValueError("PROCESS_ARGV_INVALID")
        if not isinstance(cwd, str) or not cwd:
            raise ValueError("PROCESS_CWD_INVALID")
        if not isinstance(input_bytes, bytes):
            raise ValueError("PROCESS_INPUT_INVALID")
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("PROCESS_TIMEOUT_INVALID")
        if authority_ends_at is not None and (
            isinstance(authority_ends_at, bool)
            or not isinstance(authority_ends_at, (int, float))
            or not math.isfinite(authority_ends_at)
        ):
            raise ValueError("PROCESS_AUTHORITY_END_INVALID")
        if (
            isinstance(observation_interval_seconds, bool)
            or not isinstance(observation_interval_seconds, (int, float))
            or not math.isfinite(observation_interval_seconds)
            or observation_interval_seconds <= 0
        ):
            raise ValueError("PROCESS_OBSERVATION_INTERVAL_INVALID")
        if cancel_event is not None and not callable(getattr(cancel_event, "is_set", None)):
            raise ValueError("PROCESS_CANCEL_EVENT_INVALID")
        # A revoked/ended scope must not launch merely to terminate immediately.
        if authority_ends_at is not None and time.time() >= authority_ends_at:
            return SupervisedProcessResult(None, b"", b"", False, "PROCESS_AUTHORITY_EXPIRED")
        if cancel_event is not None and cancel_event.is_set():
            return SupervisedProcessResult(None, b"", b"", False, "PROCESS_CANCELLED")

        flags = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NEW_CONSOLE) if os.name == "nt" else 0
        windows_job: WindowsKillJob | None = None
        launch_temp: tempfile.TemporaryDirectory[str] | None = None
        gate: Path | None = None
        def stopped_observation(confirmed: bool) -> ProcessStopObservation | None:
            if not confirmed or windows_job is None:
                return None
            return ProcessStopObservation(
                _request_digest(argv, cwd, input_bytes), uuid.uuid4().hex, _STOP_OBSERVATION_SEAL,
            )
        launch_argv = list(argv)
        if os.name == "nt" and self._popen is subprocess.Popen:
            try:
                windows_job = WindowsKillJob()
                launch_temp = tempfile.TemporaryDirectory(prefix="local-process-gate-")
                gate = Path(launch_temp.name) / "hold"
                gate.write_text("hold", encoding="ascii")
                launch_argv = _windows_wrapper_argv(gate, argv)
            except OSError:
                if windows_job is not None:
                    windows_job.close()
                if launch_temp is not None:
                    launch_temp.cleanup()
                return SupervisedProcessResult(
                    None, b"", b"", False, "PROCESS_ISOLATION_FAILED"
                )
        # Give this supervised tree its own initially hidden console.  Normal
        # console descendants inherit it rather than create separate windows.
        # Process lifetime remains owned by the existing Windows Job.
        startup_options = {}
        if os.name == "nt":
            startup_info = subprocess.STARTUPINFO()
            startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup_info.wShowWindow = subprocess.SW_HIDE
            startup_options["startupinfo"] = startup_info
        try:
            process = self._popen(
                launch_argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=None if env is None else dict(env),
                cwd=cwd,
                creationflags=flags,
                start_new_session=os.name != "nt",
                **startup_options,
            )
        except (FileNotFoundError, OSError):
            if windows_job is not None:
                windows_job.close()
            if launch_temp is not None:
                launch_temp.cleanup()
            return SupervisedProcessResult(
                None, b"", b"", False, "PROCESS_START_FAILED"
            )

        if windows_job is not None:
            if not windows_job.assign(process):
                cleanup_ok = self._stop_tree(process)
                windows_job.close()
                if launch_temp is not None:
                    launch_temp.cleanup()
                return SupervisedProcessResult(
                    process.returncode,
                    b"",
                    b"",
                    False,
                    "PROCESS_ISOLATION_FAILED" if cleanup_ok else "PROCESS_CLEANUP_FAILED",
                )
            if gate is not None:
                try:
                    gate.unlink()
                except OSError:
                    cleanup_ok = windows_job.terminate(process)
                    if launch_temp is not None:
                        launch_temp.cleanup()
                    return SupervisedProcessResult(
                        process.returncode,
                        b"",
                        b"",
                        False,
                        "PROCESS_ISOLATION_FAILED"
                        if cleanup_ok
                        else "PROCESS_CLEANUP_FAILED",
                    )

        started = time.monotonic()
        stop_reason = None
        latest_stdout = b""
        latest_stderr = b""
        stdin_writer = None
        stdin_errors = []
        try:
            first_communicate = True
            if os.name == "nt" and self._popen is subprocess.Popen:
                # Windows communicate writes stdin synchronously before its
                # timeout loop. Keep backpressure off the resident Job owner.
                import threading
                stdin_pipe = process.stdin
                process.stdin = None
                def send_input_once():
                    try:
                        if input_bytes:
                            stdin_pipe.write(input_bytes)
                        stdin_pipe.close()
                    except BrokenPipeError:
                        pass
                    except (OSError, ValueError) as error:
                        stdin_errors.append(error)
                    finally:
                        try:
                            stdin_pipe.close()
                        except (OSError, ValueError):
                            pass
                stdin_writer = threading.Thread(target=send_input_once, daemon=True)
                stdin_writer.start()
                first_communicate = False
            while True:
                if stdin_errors:
                    raise OSError("PROCESS_STDIN_FAILED")
                if cancel_event is not None and cancel_event.is_set():
                    stop_reason = "PROCESS_CANCELLED"
                elif authority_ends_at is not None and time.time() >= authority_ends_at:
                    stop_reason = "PROCESS_AUTHORITY_EXPIRED"
                elif timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
                    stop_reason = "PROCESS_TIMEOUT"
                if stop_reason:
                    raise subprocess.TimeoutExpired(argv, timeout_seconds, output=latest_stdout, stderr=latest_stderr)
                interval = float(observation_interval_seconds)
                if timeout_seconds is not None:
                    interval = min(interval, max(.001, timeout_seconds - (time.monotonic() - started)))
                if authority_ends_at is not None:
                    interval = min(interval, max(.001, authority_ends_at - time.time()))
                try:
                    # communicate retries drain the SAME process; stdin is sent once.
                    kwargs = {"timeout": interval}
                    if first_communicate:
                        kwargs["input"] = input_bytes
                    first_communicate = False
                    observation_started = time.monotonic()
                    stdout, stderr = process.communicate(**kwargs)
                    if stdin_errors:
                        raise OSError("PROCESS_STDIN_FAILED")
                    break
                except subprocess.TimeoutExpired as exc:
                    if isinstance(exc.output, bytes):
                        latest_stdout = exc.output
                    if isinstance(exc.stderr, bytes):
                        latest_stderr = exc.stderr
                    # On Windows TimeoutExpired may contain no partial bytes.
                    # Parent exit with inherited pipe holders is NOT live work:
                    # reap the owned Job/tree before the bounded final drain.
                    poll = getattr(process, "poll", None)
                    if callable(poll) and poll() is not None:
                        cleanup_ok = windows_job.terminate(process) if windows_job is not None else self._stop_tree(process)
                        try:
                            stdout, stderr = process.communicate(timeout=1)
                        except (OSError, ValueError, subprocess.TimeoutExpired):
                            stdout, stderr = latest_stdout, latest_stderr
                            cleanup_ok = False
                        return SupervisedProcessResult(
                            process.returncode, stdout, stderr, False,
                            None if cleanup_ok else "PROCESS_CLEANUP_FAILED",
                            stopped_observation(cleanup_ok),
                        )
                    # Some transports/mocks report an early observation timeout.
                    # Do not turn that into a busy loop or a productivity cutoff.
                    remaining = interval - (time.monotonic() - observation_started)
                    if remaining > 0:
                        if cancel_event is not None and callable(getattr(cancel_event, "wait", None)):
                            cancel_event.wait(remaining)
                        else:
                            time.sleep(remaining)
                    continue
        except (KeyboardInterrupt, SystemExit):
            cleanup_ok = windows_job.terminate(process) if windows_job is not None else self._stop_tree(process)
            try:
                stdout, stderr = process.communicate(timeout=1)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                stdout, stderr = latest_stdout, latest_stderr
            return SupervisedProcessResult(
                process.returncode, stdout, stderr, False,
                "PROCESS_CANCELLED" if cleanup_ok else "PROCESS_CLEANUP_FAILED",
                stopped_observation(cleanup_ok),
            )
        except subprocess.TimeoutExpired as exc:
            partial_stdout = (
                exc.output if isinstance(exc.output, bytes)
                else exc.output.encode("utf-8", errors="replace")
                if isinstance(exc.output, str) else b""
            )
            partial_stderr = (
                exc.stderr if isinstance(exc.stderr, bytes)
                else exc.stderr.encode("utf-8", errors="replace")
                if isinstance(exc.stderr, str) else b""
            )
            cleanup_ok = (
                windows_job.terminate(process)
                if windows_job is not None
                else self._stop_tree(process)
            )
            # Python guarantees communicate can be retried after TimeoutExpired.
            # Prefer the drained buffers when available because they include all
            # bytes emitted before tree termination; never concatenate them with
            # ``exc.output`` because that can duplicate the same bytes.
            try:
                drained_stdout, drained_stderr = process.communicate(timeout=1)
                if isinstance(drained_stdout, bytes) and drained_stdout:
                    partial_stdout = drained_stdout
                if isinstance(drained_stderr, bytes) and drained_stderr:
                    partial_stderr = drained_stderr
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
            return SupervisedProcessResult(
                process.returncode,
                partial_stdout,
                partial_stderr,
                stop_reason == "PROCESS_TIMEOUT",
                (stop_reason or "PROCESS_TIMEOUT") if cleanup_ok else "PROCESS_CLEANUP_FAILED",
                stopped_observation(cleanup_ok),
            )
        except (OSError, ValueError):
            cleanup_ok = (
                windows_job.terminate(process)
                if windows_job is not None
                else self._stop_tree(process)
            )
            return SupervisedProcessResult(
                process.returncode,
                b"",
                b"",
                False,
                "PROCESS_IO_FAILED" if cleanup_ok else "PROCESS_CLEANUP_FAILED",
                stopped_observation(cleanup_ok),
            )
        finally:
            if stdin_writer is not None:
                stdin_writer.join(timeout=1)
            if launch_temp is not None:
                launch_temp.cleanup()

        cleanup_ok = windows_job.terminate(process) if windows_job is not None else False
        if windows_job is not None and not cleanup_ok:
            return SupervisedProcessResult(
                process.returncode, stdout, stderr, False, "PROCESS_CLEANUP_FAILED",
            )
        return SupervisedProcessResult(
            process.returncode, stdout, stderr, False, None, stopped_observation(cleanup_ok),
        )


def _main(argv: Sequence[str]) -> int:
    if len(argv) == 3 and argv[0] == "_exec-wrapper":
        return _exec_wrapper(argv[1], argv[2])
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
