"""A bounded subprocess demonstration, not a security-grade OS sandbox."""

import os
import subprocess
import sys
import tempfile


class VirtualSandbox:
    MAX_MESSAGE_LENGTH = 256
    TIMEOUT_SECONDS = 3

    def run_isolated(self, command):
        """Run only the documented echo form using fixed Python code and argv."""
        if not isinstance(command, (list, tuple)) or len(command) != 2 or command[0] != "echo":
            return "", "Only ['echo', message] is allowed in the demo sandbox."
        message = command[1]
        if not isinstance(message, str) or len(message) > self.MAX_MESSAGE_LENGTH or "\x00" in message:
            return "", "Message must be text of at most 256 characters."

        safe_code = "import sys; print(sys.argv[1])"
        safe_env = {"PYTHONIOENCODING": "utf-8"}
        if os.name == "nt":
            safe_env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        try:
            with tempfile.TemporaryDirectory(prefix="dast-sandbox-") as temp_dir:
                result = subprocess.run(
                    [sys.executable, "-I", "-c", safe_code, message],
                    cwd=temp_dir, env=safe_env, shell=False,
                    capture_output=True, text=True, timeout=self.TIMEOUT_SECONDS, check=False,
                )
            if result.returncode != 0:
                return "", result.stderr[:1000]
            return result.stdout[:1000], result.stderr[:1000]
        except subprocess.TimeoutExpired:
            return "", "Demo process timed out."
        except OSError as exc:
            return "", f"Could not start demo process: {exc}"
