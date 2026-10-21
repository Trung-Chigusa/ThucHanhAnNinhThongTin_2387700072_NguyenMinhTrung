"""Loopback-only Flask API for the DAST demonstrations."""

import os

from flask import Flask, jsonify, render_template_string, request
import psutil

from memory_analyzer import MemoryAnalyzer
from network_traffic_analyzer import NetworkTrafficAnalyzer
from runtime_monitor import RuntimeMonitor
from security_behavior_checker import SecurityBehaviorChecker
from virtual_sandbox import VirtualSandbox


def create_app():
    app = Flask(__name__)
    app.config.update(DEBUG=False, TESTING=False, MAX_CONTENT_LENGTH=4096)
    behavior = SecurityBehaviorChecker()

    @app.get("/api/monitor")
    def monitor():
        try:
            return jsonify(RuntimeMonitor(os.getpid()).snapshot())
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            return jsonify({"error": "Process metrics are unavailable."}), 503

    @app.get("/api/memory")
    def memory():
        analyzer = MemoryAnalyzer()
        return jsonify({"sample": analyzer.sample(), "trend": analyzer.check_memory_leaks(samples=3)})

    @app.get("/api/network")
    def network():
        return jsonify({"scope": "aggregate interface counters; no packet payload capture",
                        "interfaces": NetworkTrafficAnalyzer().get_network_stats()})

    @app.get("/api/security")
    def security():
        return jsonify({"suspicious_events": behavior.suspicious_calls()})

    @app.post("/api/sandbox")
    def sandbox():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Send a JSON object with a message field."}), 400
        message = data.get("message")
        stdout, stderr = VirtualSandbox().run_isolated(["echo", message])
        if stderr:
            return jsonify({"error": stderr}), 400
        return jsonify({"stdout": stdout.strip(), "stderr": "", "mode": "bounded echo demo"})

    @app.get("/")
    def index():
        return jsonify({
            "title": "DAST local demo",
            "endpoints": ["/api/monitor", "/api/memory", "/api/network", "/api/security", "POST /api/sandbox", "/demo"],
            "warning": "Loopback demo only; the subprocess sandbox accepts echo text only.",
        })

    @app.get("/demo")
    def demo():
        return render_template_string("""<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DAST — Lab 05</title><style>
:root{color-scheme:dark;font-family:'Segoe UI',sans-serif;background:#101722;color:#e8eef7}body{max-width:900px;margin:42px auto;padding:0 24px}
header,.card{background:#182333;border:1px solid #2a3c54;border-radius:12px;padding:22px 24px;margin-bottom:16px}h1{margin:0 0 8px;font-size:26px}p{color:#aebdd0;line-height:1.5}.label{color:#7fa9d6;font-size:13px;text-transform:uppercase;letter-spacing:.08em}
pre{white-space:pre-wrap;background:#0c121b;border-radius:8px;padding:16px;color:#a9e6bf;min-height:44px}code{color:#9bd4ff}a{color:#86bfff;margin-right:18px}
</style></head><body><header><div class="label">Lab 05 · kiểm thử động cục bộ</div><h1>DAST Sandbox PoC</h1><p>Ứng dụng gửi một chuỗi văn bản đến API sandbox. Tiến trình con chỉ chạy lệnh echo cố định.</p></header>
<section class="card"><div class="label">Yêu cầu JSON</div><pre id="request">{"message":"Hello from Lab 05"}</pre><div class="label">Phản hồi API</div><pre id="result">Đang chạy kiểm chứng…</pre></section>
<section class="card"><div class="label">API trong bài</div><p><a href="/api/monitor">Monitor</a><a href="/api/memory">Memory</a><a href="/api/network">Network counters</a><a href="/api/security">Security events</a></p><p>API bind loopback. Network endpoint chỉ trả bộ đếm tổng hợp, không thu payload.</p></section>
<script>fetch('/api/sandbox',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:'Hello from Lab 05'})}).then(async r=>{const d=await r.json();document.querySelector('#result').textContent=JSON.stringify({status:r.status,...d},null,2)}).catch(e=>document.querySelector('#result').textContent=String(e));</script>
</body></html>""")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
