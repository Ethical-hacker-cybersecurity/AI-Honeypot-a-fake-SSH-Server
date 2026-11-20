"""AI Honeypot: a fake SSH server that uses an AI to answer every command."""
import os
import posixpath
import socket
import threading
import uuid

import paramiko

import ai_engine
import config
import db
from analyzer import classify


def load_host_key():
    if not os.path.exists(config.HOST_KEY_PATH):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(config.HOST_KEY_PATH)
    return paramiko.RSAKey(filename=config.HOST_KEY_PATH)


HOST_KEY = None


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, ip, session_id):
        self.ip = ip
        self.session_id = session_id
        self.username = "admin"
        self.event = threading.Event()
        self.exec_cmd = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.username = username or "admin"
        db.log_event(self.session_id, self.ip, self.username, "login", f"{username}:{password}", "", "Credential access", 3)
        print(f"[login] {self.ip} {username}:{password}")
        return paramiko.AUTH_SUCCESSFUL  # honeypot: let everyone in

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_cmd = command.decode("utf-8", "ignore")
        self.event.set()
        return True


class Shell:
    def __init__(self, chan, ip, session_id, user):
        self.chan, self.ip, self.sid, self.user = chan, ip, session_id, user
        self.home = "/root" if user == "root" else f"/home/{user}"
        self.cwd = self.home
        self.history = []

    def send(self, text):
        self.chan.send(text.replace("\r\n", "\n").replace("\n", "\r\n"))

    def prompt(self):
        shown = "~" if self.cwd == self.home else self.cwd
        sign = "#" if self.user == "root" else "$"
        return f"{self.user}@{config.HOSTNAME}:{shown}{sign} "

    def read_line(self):
        buf, esc = "", 0
        while True:
            data = self.chan.recv(256)
            if not data:
                return None
            for ch in data.decode("utf-8", "ignore"):
                if esc == 1:
                    esc = 2 if ch in "[O" else 0
                    continue
                if esc == 2:
                    if ch.isalpha() or ch == "~":
                        esc = 0
                    continue
                if ch == "\x1b":
                    esc = 1
                elif ch in "\r\n":
                    self.chan.send("\r\n")
                    return buf
                elif ch in "\x7f\x08":
                    if buf:
                        buf = buf[:-1]
                        self.chan.send("\b \b")
                elif ch == "\x03":
                    self.chan.send("^C\r\n")
                    return ""
                elif ch == "\x04":
                    if not buf:
                        return None
                elif ch.isprintable():
                    buf += ch
                    self.chan.send(ch)

    def run_command(self, cmd):
        """True = keep the shell open, False = close it."""
        cmd = cmd.strip()
        if not cmd:
            return True
        tag, sev = classify(cmd)
        parts = cmd.split()
        out = ""
        keep = True
        if parts[0] in ("exit", "logout"):
            keep = False
        elif parts[0] == "clear":
            self.send("\x1b[H\x1b[2J")
        elif parts[0] == "cd":
            target = parts[1] if len(parts) > 1 else "~"
            if target == "~":
                self.cwd = self.home
            elif target.startswith("~/"):
                self.cwd = posixpath.normpath(posixpath.join(self.home, target[2:]))
            else:
                self.cwd = posixpath.normpath(posixpath.join(self.cwd, target))
        elif cmd == "pwd":
            out = self.cwd
        else:
            out = ai_engine.fake_response(cmd, self.cwd, self.user, self.history)
        if out:
            self.send(out + "\n")
        self.history.append({"cmd": cmd, "out": out})
        db.log_event(self.sid, self.ip, self.user, "command", cmd, out, tag, sev)
        print(f"[cmd] {self.ip} [{tag}] {cmd}")
        return keep

    def loop(self):
        self.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
                  " * Documentation:  https://help.ubuntu.com\n\nLast login: Tue Mar  4 09:58:02 2025 from 10.0.0.12\n")
        while True:
            self.send(self.prompt())
            line = self.read_line()
            if line is None or not self.run_command(line):
                break
        self.send("logout\n")


def handle_client(client, addr):
    ip = addr[0]
    sid = uuid.uuid4().hex[:8]
    transport = None
    try:
        if config.ALLOWED_PREFIX and not (ip.startswith(config.ALLOWED_PREFIX) or ip == "127.0.0.1"):
            print(f"[blocked] {ip} is outside the allowed range")
            client.close()
            return
        db.log_event(sid, ip, "", "connect")
        print(f"[connect] {ip} session={sid}")
        transport = paramiko.Transport(client)
        transport.local_version = config.SSH_BANNER
        transport.add_server_key(HOST_KEY)
        server = HoneypotServer(ip, sid)
        transport.start_server(server=server)
        chan = transport.accept(30)
        if chan is None:
            return
        server.event.wait(10)
        shell = Shell(chan, ip, sid, server.username)
        if server.exec_cmd:
            shell.run_command(server.exec_cmd)
            chan.send_exit_status(0)
        else:
            shell.loop()
        chan.close()
    except Exception as e:
        print(f"[error] {ip}: {e}")
    finally:
        db.log_event(sid, ip, "", "disconnect")
        try:
            if transport:
                transport.close()
        except Exception:
            pass


def main():
    global HOST_KEY
    db.init_db()
    HOST_KEY = load_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((config.HOST, config.PORT))
    sock.listen(20)
    print(f"Honeypot running on {config.HOST}:{config.PORT}  |  AI provider: {ai_engine.provider()}")
    print(f"Allowed range: {config.ALLOWED_PREFIX or 'all'}  (press Ctrl+C to stop)")
    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
