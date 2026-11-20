import re
import time

# (tag, severity 1-4, regex)
RULES = [
    ("Reconnaissance", 1, r"^(whoami|id|uname|hostname|ifconfig|ip\s|netstat|ss\s|ps|w|who|env|uptime|lscpu|nmap|df|free)\b"),
    ("File discovery", 1, r"^(ls|cat|find|cd|pwd|grep|less|more|head|tail|locate|tree)\b"),
    ("Credential access", 3, r"(/etc/shadow|/etc/passwd|passwords?|\.ssh|id_rsa|bash_history|credentials|\.env\b|aws|secret|\.pem)"),
    ("Privilege escalation", 3, r"(^sudo\b|^su\b|chmod\s+[u+]*s|-perm\s+-?[24]000|/etc/sudoers)"),
    ("Defense evasion", 3, r"(history\s+-c|unset\s+HISTFILE|rm\s+-rf|shred|kill\s+-9|iptables\s+-F)"),
    ("Malware / execution", 4, r"(wget|curl|\bnc\b|netcat|bash\s+-i|/dev/tcp|python\d?\s+-c|chmod\s+\+x|\./\S+|\.sh\b|perl\s+-e)"),
    ("Persistence", 4, r"(crontab|authorized_keys|useradd|adduser|systemctl\s+enable|\.bashrc|rc\.local)"),
    ("Data exfiltration", 4, r"(\bscp\b|rsync|\btar\b|\bzip\b|base64|mysqldump|\.sql\b|sftp)"),
]

SEVERITY_LABEL = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def classify(cmd):
    best_tag, best_sev = "Other", 0
    for tag, sev, pattern in RULES:
        if re.search(pattern, cmd.strip(), re.IGNORECASE) and sev > best_sev:
            best_tag, best_sev = tag, sev
    return best_tag, best_sev


def fmt_time(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))
