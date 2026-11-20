"""AI brain: fake terminal replies and the attack summary.
Provider: claude (API), ollama (local), or offline (canned replies, no AI)."""
import re
import sys
import time

import requests

import config
from analyzer import fmt_time

_cache = {"t": 0.0, "p": None}
REFUSAL = re.compile(r"^\s*(i can't|i cannot|i'm sorry|sorry,|as an ai|i apologize|i am unable)", re.I)

TERMINAL_SYSTEM = """You are the bash terminal of a Linux server. Hostname: {hostname}. OS: Ubuntu 22.04.3 LTS, kernel 5.15.0-91-generic.
Logged in user: {user}. Current directory: {cwd}.

Fake world (stay consistent with it and with earlier outputs):
- Users: root, admin, deploy, www-data. Services: nginx, mysql, sshd.
- /home/admin has: notes.txt, backup_2024.sql, passwords.txt (a few fake logins), .ssh/, projects/
- /var/www/html has a small PHP website. /var/log has normal logs.

Rules:
- Output ONLY the raw terminal output of the command, exactly as the real program would print it.
- No markdown, no code fences, no explanations, never mention you are an AI or a honeypot.
- Keep output short (max about 25 lines). Invent believable file names, sizes, dates, process lists.
- Any credentials or keys you invent must be fake. Never output real secrets.
- Downloads, reverse shells, or exploit commands must fail realistically (timeout, permission denied, connection refused). Never produce working malicious payloads.
- Unknown commands: print 'bash: <cmd>: command not found'."""

SUMMARY_SYSTEM = """You are a SOC analyst writing a short incident report from honeypot logs.
Write: 1) what the attacker did step by step in order, 2) the attacker's likely skill level and goal, 3) the three most dangerous actions, 4) two defensive recommendations.
Plain text, no markdown tables, max 200 words. Write in plain, simple English."""


# ---------------------------------------------------------------- provider
def provider():
    p = config.AI_PROVIDER.lower()
    if p in ("claude", "ollama", "offline"):
        return p
    now = time.time()
    if _cache["p"] and now - _cache["t"] < 60:
        return _cache["p"]
    if config.ANTHROPIC_API_KEY:
        res = "claude"
    else:
        try:
            requests.get(config.OLLAMA_URL + "/api/tags", timeout=1)
            res = "ollama"
        except Exception:
            res = "offline"
    _cache.update(t=now, p=res)
    return res


def _call_claude(system, user, max_tokens):
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": config.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": config.CLAUDE_MODEL,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
        timeout=config.AI_TIMEOUT,
    )
    r.raise_for_status()
    return "".join(b.get("text", "") for b in r.json().get("content", []))


def _call_ollama(system, user, max_tokens):
    r = requests.post(
        config.OLLAMA_URL + "/api/chat",
        json={
            "model": config.OLLAMA_MODEL,
            "stream": False,
            "keep_alive": "10m",
            "options": {"num_predict": max_tokens, "temperature": 0.4},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        timeout=config.AI_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def call_llm(system, user, max_tokens=500):
    p = provider()
    try:
        if p == "claude":
            return _call_claude(system, user, max_tokens)
        if p == "ollama":
            return _call_ollama(system, user, max_tokens)
    except Exception as e:
        print(f"[ai_engine] {p} error: {e}", file=sys.stderr)
    return None


# ---------------------------------------------------------------- fake terminal
def _clean(text):
    lines = [l for l in text.replace("\r", "").split("\n") if not l.strip().startswith("```")]
    return "\n".join(lines).strip("\n")[:3000]


def fake_response(cmd, cwd, user, history):
    text = None
    if provider() != "offline":
        recent = history[-config.HISTORY_LEN:]
        ctx = "Earlier in this session:\n"
        for h in recent:
            ctx += f"$ {h['cmd']}\n{h['out'][:300]}\n"
        ctx += f"\nNow the user runs (in {cwd}):\n$ {cmd}\nPrint only the output."
        system = TERMINAL_SYSTEM.format(hostname=config.HOSTNAME, user=user, cwd=cwd)
        text = call_llm(system, ctx, 500)
    if not text or REFUSAL.match(text):
        text = offline_response(cmd, cwd, user)
    return _clean(text)


def offline_response(cmd, cwd, user):
    c = cmd.strip()
    parts = c.split()
    base = parts[0] if parts else ""
    fixed = {
        "whoami": user,
        "id": f"uid=1001({user}) gid=1001({user}) groups=1001({user}),27(sudo)",
        "hostname": config.HOSTNAME,
        "uname -a": f"Linux {config.HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "uname": "Linux",
        "uptime": " 10:42:11 up 41 days,  3:17,  2 users,  load average: 0.08, 0.03, 0.01",
        "w": " 10:42:11 up 41 days,  2 users\nUSER     TTY      FROM           LOGIN@   WHAT\nadmin    pts/0    10.0.0.12      09:58    -bash",
        "ls": "Desktop  Documents  backup_2024.sql  notes.txt  passwords.txt  projects",
        "ls -la": "total 44\ndrwxr-xr-x 6 admin admin 4096 Mar  3 10:11 .\ndrwxr-xr-x 4 root  root  4096 Jan 12  2024 ..\n-rw------- 1 admin admin 1021 Mar  3 10:11 .bash_history\ndrwx------ 2 admin admin 4096 Jan 12  2024 .ssh\n-rw-r--r-- 1 admin admin 9120 Feb 20 18:40 backup_2024.sql\n-rw-r--r-- 1 admin admin  214 Feb 28 09:15 notes.txt\n-rw-r--r-- 1 admin admin  167 Feb 28 09:20 passwords.txt\ndrwxr-xr-x 3 admin admin 4096 Jan 30 14:02 projects",
        "cat notes.txt": "TODO: rotate db password\nTODO: update nginx config\nBackup runs every Sunday 02:00",
        "cat passwords.txt": "mysql_root : Winter2024!\nwebpanel   : admin / Adm1n#2024\nbackup_ftp : ftpuser / Backup@123",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1001:1001::/home/admin:/bin/bash\ndeploy:x:1002:1002::/home/deploy:/bin/bash\nmysql:x:114:121:MySQL Server:/nonexistent:/bin/false",
        "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)",
        "ps": "  PID TTY          TIME CMD\n 1042 pts/0    00:00:00 bash\n 1187 pts/0    00:00:00 ps",
        "ps aux": "USER       PID %CPU %MEM COMMAND\nroot         1  0.0  0.1 /sbin/init\nroot       612  0.0  0.2 /usr/sbin/sshd -D\nwww-data   901  0.0  0.3 nginx: worker process\nmysql     1020  0.4  4.1 /usr/sbin/mysqld",
        "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   14G   24G  38% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm",
        "free -m": "               total        used        free\nMem:            3920        1210        1802\nSwap:           2047           0        2047",
    }
    if c in fixed:
        return fixed[c]
    if base == "sudo":
        return f"[sudo] password for {user}: \nSorry, try again."
    if base in ("wget", "curl"):
        return "Connecting... failed: Connection timed out."
    if base in ("cat", "less", "head", "tail") and len(parts) > 1:
        return f"{base}: {parts[-1]}: No such file or directory"
    if base == "ls" and len(parts) > 1:
        return f"ls: cannot access '{parts[-1]}': No such file or directory"
    return f"bash: {base}: command not found"


# ---------------------------------------------------------------- summary
def summarize(events):
    cmds = [e for e in events if e["event_type"] == "command"]
    if not cmds:
        return "No commands recorded yet."
    log = "\n".join(f"{fmt_time(e['ts'])} {e['ip']} [{e['tag']}] $ {e['command']}" for e in cmds)[-6000:]
    if provider() != "offline":
        text = call_llm(SUMMARY_SYSTEM, f"Session log:\n{log}", 700)
        if text:
            return text.strip()
    return rule_summary(cmds)


def rule_summary(cmds):
    """Fallback summary written by simple rules (used when no AI is available)."""
    tags = {}
    for e in cmds:
        tags[e["tag"]] = tags.get(e["tag"], 0) + 1
    order = []
    for e in cmds:
        if e["tag"] not in order and e["tag"] != "Other":
            order.append(e["tag"])
    worst = max(cmds, key=lambda e: e["severity"])
    top = ", ".join(f"{k} ({v})" for k, v in sorted(tags.items(), key=lambda x: -x[1]))
    return (f"The attacker ran {len(cmds)} commands. Stage order: {' -> '.join(order) or 'no clear pattern'}.\n"
            f"Most dangerous command: {worst['command']} ({worst['tag']}).\n"
            f"Command types: {top}.\n"
            "Recommendation: disable password login, use SSH keys, and alert on credential-file access.")
