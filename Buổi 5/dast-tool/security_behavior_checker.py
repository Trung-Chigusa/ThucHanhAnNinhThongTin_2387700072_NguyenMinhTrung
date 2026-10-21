"""Rule-based review of events explicitly recorded by the demo monitor."""


class SecurityBehaviorChecker:
    DEFAULT_RULES = {
        "process.shell", "process.exec", "network.external_connect",
        "file.sensitive_read", "memory.executable_write",
    }

    def __init__(self, suspicious_events=None):
        self.suspicious_events = set(suspicious_events or self.DEFAULT_RULES)
        self.events = []

    def record_event(self, event, details=None):
        self.events.append({"event": str(event), "details": details or {}})

    def suspicious_calls(self):
        return [dict(item) for item in self.events if item["event"] in self.suspicious_events]

    def clear(self):
        self.events.clear()
