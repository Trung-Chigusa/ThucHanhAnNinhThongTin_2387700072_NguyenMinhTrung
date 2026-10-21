"""Print a one-shot local runtime snapshot and safe sandbox example."""

import json
import os

from memory_analyzer import MemoryAnalyzer
from network_traffic_analyzer import NetworkTrafficAnalyzer
from runtime_monitor import RuntimeMonitor
from security_behavior_checker import SecurityBehaviorChecker
from virtual_sandbox import VirtualSandbox


def collect_demo():
    monitor = RuntimeMonitor(os.getpid())
    memory = MemoryAnalyzer()
    behavior = SecurityBehaviorChecker()
    stdout, stderr = VirtualSandbox().run_isolated(["echo", "Hello Sandbox"])
    behavior.record_event("sandbox.allowed_text_echo", {"return_code": 0 if stdout else 1})
    return {
        "runtime": monitor.snapshot(),
        "memory": {"trend": memory.check_memory_leaks(), "int64_overflow_demo": memory.check_overflow(2**63)},
        "network_interfaces": NetworkTrafficAnalyzer().get_network_stats(),
        "suspicious_events": behavior.suspicious_calls(),
        "sandbox": {"stdout": stdout.strip(), "stderr": stderr},
    }


if __name__ == "__main__":
    print(json.dumps(collect_demo(), indent=2, ensure_ascii=False))
