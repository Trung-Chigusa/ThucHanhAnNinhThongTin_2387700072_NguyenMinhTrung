import unittest

from virtual_sandbox import VirtualSandbox


class SandboxTests(unittest.TestCase):
    def test_allows_bounded_echo_through_fixed_subprocess(self):
        stdout, stderr = VirtualSandbox().run_isolated(["echo", "Hello Sandbox"])
        self.assertEqual(stdout.strip(), "Hello Sandbox")
        self.assertEqual(stderr, "")

    def test_rejects_other_commands_without_running_them(self):
        stdout, stderr = VirtualSandbox().run_isolated(["python", "print('bad')"])
        self.assertEqual(stdout, "")
        self.assertIn("Only", stderr)

    def test_limits_message_size(self):
        stdout, stderr = VirtualSandbox().run_isolated(["echo", "x" * 257])
        self.assertEqual(stdout, "")
        self.assertIn("256", stderr)


if __name__ == "__main__":
    unittest.main()
