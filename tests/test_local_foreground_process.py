from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import local_foreground_process as supervised


class _TimeoutProcess:
    pid = 424242
    returncode = None

    def __init__(self):
        self.communicate_calls = 0

    def communicate(self, **kwargs):
        self.communicate_calls += 1
        if self.communicate_calls == 1:
            # Observe elapsed wait: an observation tick is not task expiry.
            time.sleep(kwargs.get("timeout", 1))
            raise subprocess.TimeoutExpired(
                cmd=["synthetic"], timeout=1,
                output=b"partial-out", stderr=b"Bearer partial-secret",
            )
        return b"complete-drain", b"Bearer drained-secret"

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = 1


class LocalForegroundProcessTests(unittest.TestCase):
    def test_null_timeout_does_not_bypass_argv_validation(self):
        with self.assertRaisesRegex(ValueError, "PROCESS_ARGV_INVALID"):
            supervised.SupervisedProcessRunner().run([], cwd=".", env=None, input_bytes=b"", timeout_seconds=None)

    @unittest.skipUnless(os.name == "nt", "Windows host crash closes Job")
    def test_crashed_resident_owner_does_not_leave_a_writer(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);pidfile=root/'writer.pid';marker=root/'late.txt'
            child="import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(20); pathlib.Path(sys.argv[2]).write_text('late')"
            host="import sys; sys.path.insert(0,sys.argv[1]); from local_foreground_process import SupervisedProcessRunner; SupervisedProcessRunner().run([sys.executable,'-c',sys.argv[2],sys.argv[3],sys.argv[4]],cwd=sys.argv[5],env=None,input_bytes=b'',timeout_seconds=None,observation_interval_seconds=.05)"
            process=subprocess.Popen([sys.executable,'-c',host,str(SCRIPTS),child,str(pidfile),str(marker),folder],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+5
                while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.02)
                self.assertTrue(pidfile.exists())
                pid=int(pidfile.read_text())
                process.kill();process.wait(timeout=5)
                deadline=time.monotonic()+3
                while supervised.SupervisedProcessRunner._windows_pid_exists(pid) and time.monotonic()<deadline:time.sleep(.02)
                self.assertFalse(supervised.SupervisedProcessRunner._windows_pid_exists(pid))
                self.assertFalse(marker.exists())
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)

    @unittest.skipUnless(os.name == "nt", "Windows Job ownership")
    def test_long_silent_work_survives_observation_and_receives_stdin_once(self):
        with tempfile.TemporaryDirectory() as folder:
            argv = [sys.executable, "-c", "import sys,time; value=sys.stdin.buffer.read(); time.sleep(.45); sys.stdout.buffer.write(value)"]
            result = supervised.SupervisedProcessRunner().run(
                argv, cwd=folder, env=None, input_bytes=b"once", timeout_seconds=None,
                authority_ends_at=time.time()+10, observation_interval_seconds=.05)
            self.assertEqual(result.stdout, b"once")
            self.assertIsNone(result.error_code)
            self.assertTrue(supervised.verify_process_stop(result.stop_observation, argv=argv, cwd=folder, input_bytes=b"once"))

    @unittest.skipUnless(os.name == "nt", "Windows inherited pipe/Job")
    def test_blocked_stdin_cannot_block_cancel_or_authority_end(self):
        for reason in ["PROCESS_CANCELLED", "PROCESS_AUTHORITY_EXPIRED"]:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as folder:
                event=threading.Event(); timer=threading.Timer(.2,event.set) if reason=="PROCESS_CANCELLED" else None
                argv=[sys.executable,"-c","import time; time.sleep(10)"]
                payload=b"x"*(1024*1024)
                if timer:timer.start()
                start=time.monotonic()
                try:
                    result=supervised.SupervisedProcessRunner().run(argv,cwd=folder,env=None,input_bytes=payload,timeout_seconds=None,cancel_event=event,
                        authority_ends_at=time.time()+(.2 if reason=="PROCESS_AUTHORITY_EXPIRED" else 20),observation_interval_seconds=.03)
                finally:
                    if timer:timer.cancel();timer.join()
                self.assertLess(time.monotonic()-start,2)
                self.assertEqual(result.error_code,reason)
                self.assertTrue(supervised.verify_process_stop(result.stop_observation,argv=argv,cwd=folder,input_bytes=payload))

    @unittest.skipUnless(os.name == "nt", "Windows inherited pipe/Job")
    def test_exited_parent_with_live_pipe_holder_is_reaped_without_task_timeout(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder)/"late.txt"
            child = "import sys,time,pathlib; time.sleep(3); pathlib.Path(sys.argv[1]).write_text('late')"
            parent = "import subprocess,sys; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); print('parent-done',flush=True)"
            argv=[sys.executable,"-c",parent,child,str(marker)]
            start=time.monotonic()
            result=supervised.SupervisedProcessRunner().run(argv,cwd=folder,env=None,input_bytes=b"",timeout_seconds=None,observation_interval_seconds=.05)
            self.assertLess(time.monotonic()-start,2.5)
            self.assertIn(b"parent-done",result.stdout)
            self.assertIsNone(result.error_code)
            self.assertIsNotNone(result.stop_observation)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "Windows cancel/authority proof")
    def test_cancel_and_authority_expiry_are_distinct_and_stop_descendants(self):
        for reason in ["PROCESS_CANCELLED","PROCESS_AUTHORITY_EXPIRED"]:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as folder:
                marker=Path(folder)/"late.txt"
                child="import sys,time,pathlib; time.sleep(2); pathlib.Path(sys.argv[1]).write_text('late')"
                parent="import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); print('started',flush=True); time.sleep(20)"
                argv=[sys.executable,"-c",parent,child,str(marker)]
                event=threading.Event(); timer=threading.Timer(.45,event.set) if reason=="PROCESS_CANCELLED" else None
                if timer:timer.start()
                try:
                    result=supervised.SupervisedProcessRunner().run(argv,cwd=folder,env=None,input_bytes=b"",timeout_seconds=None,cancel_event=event,
                        authority_ends_at=time.time()+(.45 if reason=="PROCESS_AUTHORITY_EXPIRED" else 10),observation_interval_seconds=.05)
                finally:
                    if timer:timer.cancel();timer.join()
                self.assertEqual(result.error_code,reason)
                self.assertFalse(result.timed_out)
                self.assertTrue(supervised.verify_process_stop(result.stop_observation,argv=argv,cwd=folder,input_bytes=b""))
                time.sleep(.1)
                self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "Windows supervised handoff observation")
    def test_native_success_observes_stopped_job_and_binds_exact_request(self):
        with tempfile.TemporaryDirectory() as folder:
            argv = [sys.executable, "-c", "print('done')"]
            result = supervised.SupervisedProcessRunner().run(
                argv, cwd=folder, env=None, input_bytes=b"bound-input", timeout_seconds=5,
            )
            self.assertIsNone(result.error_code)
            self.assertTrue(supervised.verify_process_stop(
                result.stop_observation, argv=argv, cwd=folder, input_bytes=b"bound-input",
            ))
            self.assertFalse(supervised.verify_process_stop(
                result.stop_observation, argv=argv, cwd=folder, input_bytes=b"stale-input",
            ))

    @unittest.skipUnless(os.name == "nt", "Windows supervised process tree")
    def test_normal_parent_exit_cannot_leave_delayed_child_writer(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "late.txt"
            child = "import pathlib,sys,time; time.sleep(0.8); pathlib.Path(sys.argv[1]).write_text('late')"
            parent = (
                "import subprocess,sys; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
            )
            argv = [sys.executable, "-c", parent, child, str(marker)]
            result = supervised.SupervisedProcessRunner().run(
                argv, cwd=folder, env=None, input_bytes=b"", timeout_seconds=5,
            )
            self.assertIsNone(result.error_code)
            self.assertTrue(supervised.verify_process_stop(
                result.stop_observation, argv=argv, cwd=folder, input_bytes=b"",
            ))
            time.sleep(1.0)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "Windows Job accounting")
    def test_unconfirmed_job_empty_does_not_issue_stop_observation(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(supervised.WindowsKillJob, "_wait_empty", return_value=False):
                result = supervised.SupervisedProcessRunner().run(
                    [sys.executable, "-c", "pass"], cwd=folder, env=None,
                    input_bytes=b"", timeout_seconds=5,
                )
            self.assertEqual(result.error_code, "PROCESS_CLEANUP_FAILED")
            self.assertIsNone(result.stop_observation)

    @unittest.skipUnless(os.name == "nt", "Windows Job accounting")
    def test_job_accounting_query_failure_or_active_process_fails_closed(self):
        import ctypes
        for active in (None, 1):
            job = supervised.WindowsKillJob()
            def query(handle, kind, pointer, size, returned):
                if active is None:
                    return False
                pointer._obj.ActiveProcesses = active
                return True
            try:
                with mock.patch.object(job, "_kernel32") as kernel:
                    kernel.QueryInformationJobObject.side_effect = query
                    self.assertFalse(job._wait_empty(timeout=0))
            finally:
                job.close()

    def test_success_preserves_raw_bytes_and_exact_launch_contract(self):
        captured = {}

        class SuccessfulProcess:
            returncode = 7
            pid = 101

            def communicate(self, **kwargs):
                captured["communicate"] = kwargs
                return b"raw-out\xff", b"raw-error\xfe"

        def fake_popen(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return SuccessfulProcess()

        result = supervised.SupervisedProcessRunner(popen=fake_popen).run(
            ["program", "literal argument", ""],
            cwd="C:\\bounded",
            env={"ONLY": "BOUND"},
            input_bytes=b"raw-input\x00",
            timeout_seconds=3.5,
        )

        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"raw-out\xff")
        self.assertEqual(result.stderr, b"raw-error\xfe")
        self.assertIsNone(result.error_code)
        self.assertEqual(captured["argv"], ["program", "literal argument", ""])
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertEqual(captured["kwargs"]["cwd"], "C:\\bounded")
        self.assertEqual(captured["kwargs"]["env"], {"ONLY": "BOUND"})
        self.assertEqual(captured["communicate"]["input"], b"raw-input\x00")
        self.assertGreater(captured["communicate"]["timeout"], 0)
        self.assertLessEqual(captured["communicate"]["timeout"], 3.5)

    def test_timeout_cleanup_failure_is_explicit(self):
        process = _TimeoutProcess()
        runner = supervised.SupervisedProcessRunner(popen=lambda *a, **k: process)
        with mock.patch.object(runner, "_stop_tree", return_value=False):
            result = runner.run(
                ["synthetic"],
                cwd="C:\\bounded",
                env=None,
                input_bytes=b"",
                timeout_seconds=1,
            )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.error_code, "PROCESS_CLEANUP_FAILED")
        self.assertEqual(result.stdout, b"complete-drain")
        self.assertEqual(result.stderr, b"Bearer drained-secret")
        self.assertNotIn("Bearer", repr(result))

    def test_timeout_cleanup_preserves_drained_bytes_without_repr_leak(self):
        process = _TimeoutProcess()
        runner = supervised.SupervisedProcessRunner(popen=lambda *a, **k: process)
        with mock.patch.object(runner, "_stop_tree", return_value=True):
            result = runner.run(
                ["synthetic"], cwd="C:\\bounded", env=None,
                input_bytes=b"", timeout_seconds=1,
            )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.error_code, "PROCESS_TIMEOUT")
        self.assertEqual(result.stdout, b"complete-drain")
        self.assertNotIn("Bearer", repr(result))

    @unittest.skipUnless(os.name == "nt", "Windows Job Object test")
    def test_real_windows_timeout_leaves_no_parent_or_descendant(self):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            child_pid_file = root / "child.pid"
            parent_pid_file = root / "parent.pid"
            program = root / "parent.py"
            program.write_text(
                "import os, pathlib, subprocess, sys, time\n"
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "pathlib.Path(sys.argv[2]).write_text(str(child.pid))\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            result = supervised.SupervisedProcessRunner().run(
                [sys.executable, str(program), str(parent_pid_file), str(child_pid_file)],
                cwd=str(root),
                env=None,
                input_bytes=b"",
                timeout_seconds=1.5,
            )
            self.assertTrue(result.timed_out)
            self.assertEqual(result.error_code, "PROCESS_TIMEOUT")
            self.assertTrue(parent_pid_file.exists())
            self.assertTrue(child_pid_file.exists())
            parent_pid = int(parent_pid_file.read_text(encoding="utf-8"))
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and (
                supervised.SupervisedProcessRunner._windows_pid_exists(parent_pid)
                or supervised.SupervisedProcessRunner._windows_pid_exists(child_pid)
            ):
                time.sleep(0.02)
            self.assertFalse(
                supervised.SupervisedProcessRunner._windows_pid_exists(parent_pid)
            )
            self.assertFalse(
                supervised.SupervisedProcessRunner._windows_pid_exists(child_pid)
            )
            self.assertEqual(
                supervised.SupervisedProcessRunner._windows_process_tree(parent_pid), []
            )


if __name__ == "__main__":
    unittest.main()
