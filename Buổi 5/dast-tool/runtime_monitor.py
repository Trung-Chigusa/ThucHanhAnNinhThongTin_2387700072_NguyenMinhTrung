"""Observe resource metadata for the current or explicitly selected PID."""

import os

import psutil


class RuntimeMonitor:
    def __init__(self, pid=None):
        self.pid = os.getpid() if pid is None else int(pid)
        self.process = psutil.Process(self.pid)

    def get_cpu_usage(self):
        return float(self.process.cpu_percent(interval=0.05))

    def get_memory_usage(self):
        return int(self.process.memory_info().rss)

    def get_open_files(self):
        """Return basenames only to avoid disclosing local path details."""
        try:
            return sorted({os.path.basename(item.path) for item in self.process.open_files() if item.path})
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return []

    def snapshot(self):
        open_files = self.get_open_files()
        return {
            "pid": self.pid,
            "cpu_percent": self.get_cpu_usage(),
            "rss_bytes": self.get_memory_usage(),
            "open_file_count": len(open_files),
            "open_files": open_files,
        }
