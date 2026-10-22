"""Local-only examples: round trip and bounded timeout; no network access."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from local_foreground_process import SupervisedProcessRunner


def main():
    runner = SupervisedProcessRunner()
    with tempfile.TemporaryDirectory() as folder:
        result = runner.run(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().upper())"],
            cwd=folder, env=None, input_bytes=b"hello\n", timeout_seconds=5,
        )
        if result.error_code or result.returncode != 0 or result.stdout != b"HELLO\n":
            raise RuntimeError("Round-trip example failed")
        print("Round trip: HELLO")
        result = runner.run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=folder, env=None, input_bytes=b"", timeout_seconds=0.5,
        )
        if not result.timed_out or result.error_code != "PROCESS_TIMEOUT":
            raise RuntimeError("Timeout example failed")
        print("Timeout: PROCESS_TIMEOUT")


if __name__ == "__main__":
    main()
