"""Live dashboard for the AI honeypot (uses only Python's built-in libraries).
Run:  python dashboard.py   then open http://localhost:8502 in a browser."""
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import ai_engine
import db
from analyzer import SEVERITY_LABEL, fmt_time

PORT = 8502

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AI Honeypot Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#111418;--card:#1b2027;--line:#2c333d;--tx:#e6e9ee;--mut:#8b95a3;--acc:#4da3ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;padding:20px}
h1{margin:0 0 4px;font-size:24px}h2{font-size:17px;margin:22px 0 10px}
.mut{color:var(--mut)}.row{display:flex;gap:12px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.metric{flex:1;min-width:150px}.metric b{display:block;font-size:28px}
.cols{display:grid;grid-template-columns:3fr 2fr;gap:16px}@media(max-width:900px){.cols{grid-template-columns:1fr}}
pre{margin:0 0 10px;background:#0b0e12;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;font:13px/1.45 Consolas,monospace}
.tag{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;background:#26303c}
.s3,.s4{background:#5a2323;color:#ffb4b4}.s2{background:#5a4a23;color:#ffe0a0}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.bar{height:10px;background:var(--acc);border-radius:5px}.brow{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:13px}.brow span:first-child{width:150px}
button,select{background:#26303c;color:var(--tx);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font-size:14px;cursor:pointer}
button:hover{background:#2f3b4a}#sum{white-space:pre-wrap;margin-top:12px;background:#12261a;border:1px solid #1f4a30;border-radius:8px;padding:12px;display:none}
</style></head><body>
<h1>AI Honeypot Dashboard</h1>
<div class="mut">Every action of the attacker on the fake SSH server appears here live. AI provider: <b id="prov">-</b></div>
<h2>Overview</h2>
<div class="row">
<div class="card metric"><span class="mut">Sessions</span><b id="m1">0</b></div>
<div class="card metric"><span class="mut">Commands</span><b id="m2">0</b></div>
<div class="card metric"><span class="mut">High / Critical</span><b id="m3">0</b></div>
<div class="card metric"><span class="mut">Attacker IPs</span><b id="m4">0</b></div>
</div>
<div class="cols">
<div><h2>Live terminal (newest first)</h2><div id="live"></div></div>
<div><h2>Attack types</h2><div class="card" id="tags"></div>
<h2>Login attempts</h2><div class="card" id="logins"></div></div>
</div>
<h2>Full command history</h2><div class="card" id="hist"></div>
<h2>AI attack summary</h2>
<div class="row" style="align-items:center">
<button onclick="makeSummary()">Generate summary</button>
<button onclick="clearLogs()" style="margin-left:auto">Clear logs</button></div>
<div id="sum"></div>
<script>
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sevc=n=>n>=3?'s'+n:(n==2?'s2':'');
function render(d){
 prov.textContent=d.provider;m1.textContent=d.sessions;m2.textContent=d.commands;m3.textContent=d.high;m4.textContent=d.ips;
 live.innerHTML=d.cmds.slice(0,6).map(e=>'<pre><span class="mut">['+esc(e.time)+'] '+esc(e.ip)+'</span> <span class="tag '+sevc(e.sev)+'">'+esc(e.tag)+'</span>\n$ '+esc(e.command)+'\n'+esc(e.response)+'</pre>').join('')||'<div class="card mut">No commands yet. Connect from Kali using ssh to try it.</div>';
 const mx=Math.max(1,...Object.values(d.tags));
 tags.innerHTML=Object.entries(d.tags).map(([k,v])=>'<div class="brow"><span>'+esc(k)+'</span><div class="bar" style="width:'+(v/mx*100)+'px"></div><span>'+v+'</span></div>').join('')||'<span class="mut">Nothing yet</span>';
 logins.innerHTML=d.logins.length?'<table><tr><th>Time</th><th>IP</th><th>user:password</th></tr>'+d.logins.map(e=>'<tr><td>'+esc(e.time)+'</td><td>'+esc(e.ip)+'</td><td>'+esc(e.command)+'</td></tr>').join('')+'</table>':'<span class="mut">No login attempts.</span>';
 hist.innerHTML=d.cmds.length?'<table><tr><th>Time</th><th>IP</th><th>Command</th><th>Type</th><th>Danger</th></tr>'+d.cmds.map(e=>'<tr><td>'+esc(e.time)+'</td><td>'+esc(e.ip)+'</td><td>'+esc(e.command)+'</td><td>'+esc(e.tag)+'</td><td><span class="tag '+sevc(e.sev)+'">'+esc(e.sev_label)+'</span></td></tr>').join('')+'</table>':'<span class="mut">Empty for now.</span>';
}
async function refresh(){try{const r=await fetch('/api/data');render(await r.json())}catch(e){}}
async function makeSummary(){sum.style.display='block';sum.textContent='The AI is writing the report...';
 try{const r=await fetch('/api/summary');const d=await r.json();sum.textContent=d.summary}catch(e){sum.textContent='Could not generate the summary.'}}
async function clearLogs(){if(!confirm('Delete all logs?'))return;await fetch('/api/clear',{method:'POST',headers:{'X-Dash':'1'}});sum.style.display='none';refresh()}
refresh();setInterval(refresh,2000);
</script></body></html>"""


def collect():
    events = db.fetch_events(500)
    cmds = [e for e in events if e["event_type"] == "command"]
    logins = [e for e in events if e["event_type"] == "login"]
    tags = {}
    for e in cmds:
        tags[e["tag"]] = tags.get(e["tag"], 0) + 1
    return {
        "provider": ai_engine.provider(),
        "sessions": len({e["session_id"] for e in events}),
        "commands": len(cmds),
        "high": sum(1 for e in cmds if e["severity"] >= 3),
        "ips": len({e["ip"] for e in events}),
        "tags": tags,
        "cmds": [
            {"time": fmt_time(e["ts"]), "ip": e["ip"], "user": e["username"], "command": e["command"],
             "response": e["response"], "tag": e["tag"], "sev": e["severity"],
             "sev_label": SEVERITY_LABEL.get(e["severity"], "")}
            for e in cmds
        ],
        "logins": [{"time": fmt_time(e["ts"]), "ip": e["ip"], "command": e["command"]} for e in logins[:10]],
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif u.path == "/api/data":
            self._send(200, json.dumps(collect()), "application/json")
        elif u.path == "/api/summary":
            text = ai_engine.summarize(db.fetch_events(500, ascending=True))
            self._send(200, json.dumps({"summary": text}), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if urlparse(self.path).path == "/api/clear" and self.headers.get("X-Dash") == "1":
            db.clear_db()
            self._send(200, json.dumps({"ok": True}), "application/json")
        else:
            self._send(403, "forbidden", "text/plain")

    def log_message(self, *args):
        pass


def main():
    db.init_db()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://localhost:{PORT}"
    print(f"Dashboard running at {url}   (press Ctrl+C to stop)")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
