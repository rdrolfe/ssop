#!/usr/bin/env python3
"""Install Mattermost + PostgreSQL on the Matrix-Chat host (VM 801 / 192.168.1.82).

Runs ON the target over SSH. Every stage VERIFIES before continuing and the
script aborts on the first failure — an installer that "passes" silently is
worse than one that stops.

Design notes:
  * Local mode is enabled (ServiceSettings.EnableLocalMode) so admin tasks use
    mmctl over a unix socket instead of needing TLS on loopback.
  * The server binds 0.0.0.0 so the .29 agent host can reach it; SiteURL is set
    to the LAN address because that is how clients will address it.
  * The DB password is GENERATED and recorded outside the repo at
    ~/.ssop/mattermost-db-password.txt (0600) on the TARGET — never in config
    files that end up in git, never in logs.
  * The whole thing runs as a dedicated `mattermost` system user. This host is
    the ops-room, not the SSOP agent plane, so it gets its own identity.

Usage: provision_mattermost.py --host rdrolfe@192.168.1.82
"""
import argparse
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path

SSH_KEY = str(Path.home() / ".ssh/agent-ssh")
# agent-ssh only exists on the .29 agent host, and .29 is the one that can
# reach 192.168.1.82 with it. When run from elsewhere, route through .29.
JUMP_HOST = os.environ.get("SSOP_JUMP_HOST", "rdrolfe@192.168.1.29")
JUMP_KEY = os.environ.get("SSOP_JUMP_KEY", str(Path.home() / ".ssh/hermes_ssop"))
MM_HOME = "/opt/mattermost"
MM_USER = "mattermost"
DB_NAME = "mattermost"
DB_USER = "mattermost"
SITE_URL = "http://192.168.1.82:8065"
ADMIN_USER = "ssopadmin"
ADMIN_EMAIL = "ssopadmin@ssop.local"
# Pinned deliberately. The "latest" alias under mattermost.com/download/ 404s;
# real releases are versioned paths under releases.mattermost.com and the
# tarball unpacks as a bare `mattermost/` directory (NOT mattermost-team-*).
MM_VERSION = "11.11.1"
MM_URL = (f"https://releases.mattermost.com/{MM_VERSION}/"
          f"mattermost-{MM_VERSION}-linux-amd64.tar.gz")


def sh(cmd: str, check: bool = True, timeout: int = 900) -> str:
    """Run a shell snippet on the target. Prints a compact stage banner.

    Uses ProxyJump through the .29 agent host when the local host has no
    agent-ssh key of its own — which is the normal case.
    """
    if not Path(SSH_KEY).exists():
        full = ["ssh", "-i", JUMP_KEY, "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-J", JUMP_HOST,
                TARGET, f"bash -lc {shell_quote(cmd)}"]
    else:
        full = ["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                TARGET, f"bash -lc {shell_quote(cmd)}"]
    r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if check and r.returncode != 0:
        print(f"    !! FAILED rc={r.returncode}")
        if out:
            print("    stdout:", out[-1500:])
        if err:
            print("    stderr:", err[-1500:])
        sys.exit(1)
    return out


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def stage(msg: str) -> None:
    print(f"  -> {msg}")


def gen_password() -> str:
    return subprocess.check_output(
        ["openssl", "rand", "-base64", "24"], text=True).strip().replace("/", "_").replace("+", "-")


def write_secret(path: str, value: str) -> None:
    """Write a secret to a 0600 file owned by rdrolfe.

    Never `openssl rand | sudo tee`: under `bash -lc` with no TTY that pipeline
    writes nothing and fails silently, which then surfaces much later as a
    missing-file error far from its cause. Assert the value reads back.
    """
    sh("sudo install -d -m 0700 -o rdrolfe -g rdrolfe /home/rdrolfe/.ssop")
    sh(f"sudo touch {path}")
    sh(f"printf '%s' '{value}' | sudo tee {path} >/dev/null")
    sh(f"sudo chown rdrolfe:rdrolfe {path} && sudo chmod 600 {path}")
    back = sh(f"sudo cat {path}", check=False)
    assert back.strip() == value.strip(), f"secret write to {path} did not read back"


def main() -> int:
    global TARGET
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="rdrolfe@192.168.1.82")
    ap.add_argument("--skip-download", action="store_true")
    a = ap.parse_args()
    TARGET = a.host

    print(f"=== Mattermost provisioning -> {TARGET} ===")

    # ---------- 1. prerequisites ----------
    stage("base packages")
    sh("sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq")
    sh("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
       "curl ca-certificates postgresql postgresql-contrib tar python3 >/dev/null 2>&1")
    stage("base packages installed")

    # ---------- 2. database ----------
    stage("postgresql")
    sh("sudo systemctl enable --now postgresql >/dev/null 2>&1")
    db_pw: str | None = None
    if not a.skip_download:
        stage("database + role")
        # Reuse an existing password if we provisioned before; else generate+record.
        pw = sh(f"""sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='{DB_USER}'" """)
        if pw.strip() == "1":
            print("    role already exists, reusing recorded password")
            db_pw = sh(f"sudo cat /home/rdrolfe/.ssop/mattermost-db-password.txt").strip()
        else:
            db_pw = gen_password()
            sh(f"sudo -u postgres psql -q -c \"CREATE ROLE {DB_USER} LOGIN PASSWORD '{db_pw}'\"")
            sh("sudo install -d -m 0700 -o rdrolfe -g rdrolfe /home/rdrolfe/.ssop")
            write_secret("/home/rdrolfe/.ssop/mattermost-db-password.txt", db_pw)
            print("    db password recorded on target: ~/.ssop/mattermost-db-password.txt (0600)")

        exists = sh(f"""sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='{DB_NAME}'" """).strip()
        if exists != "1":
            sh(f"sudo -u postgres createdb -O {DB_USER} {DB_NAME}")
        # allow md5 auth from localhost explicitly
        sh("sudo -u postgres psql -q -c \"ALTER SYSTEM SET password_encryption='scram-sha-256'\"")
        sh("sudo systemctl restart postgresql")
        chk = sh(f"""sudo -u postgres psql -tAc "SELECT count(*) FROM pg_database WHERE datname='{DB_NAME}'" """).strip()
        assert chk == "1", f"database {DB_NAME} not present (got {chk!r})"
        print(f"    database {DB_NAME} ready")

    # ---------- 3. mattermost binaries ----------
    stage("mattermost server")
    sh(f"sudo mkdir -p {MM_HOME}")
    # NOTE: every "test ..." probe below MUST pass check=False. `test -x X &&
    # echo yes` exits 1 when the test is false, which is the normal "not yet
    # installed" case — treating that as an error aborts the run on a clean host.
    already = sh("test -x /opt/mattermost/bin/mattermost && echo yes", check=False).strip()
    if already != "yes":
        if sh("test -s /tmp/mm.tar.gz && echo yes", check=False).strip() != "yes":
            sh(f"cd /tmp && curl -fsSL -o mm.tar.gz {MM_URL}", timeout=1800)
        sz = sh("stat -c %s /tmp/mm.tar.gz").strip()
        print(f"    downloaded {MM_VERSION} ({int(sz)//1048576} MB)")
        sh("rm -rf /tmp/mattermost")
        sh("cd /tmp && tar -xzf mm.tar.gz", timeout=1800)
        inner = sh("test -d /tmp/mattermost && echo /tmp/mattermost", check=False).strip()
        assert inner, "tarball did not unpack as mattermost/"
        sh(f"sudo cp -a {inner}/. {MM_HOME}/")
        sh(f"rm -rf /tmp/mm.tar.gz {inner}")
    assert sh(f"test -x {MM_HOME}/bin/mattermost && echo yes", check=False).strip() == "yes"
    print("    binaries in place")

    stage("service user + ownership")
    if sh(f"id -u {MM_USER} >/dev/null 2>&1 && echo yes", check=False).strip() != "yes":
        sh(f"sudo useradd --system --home-dir {MM_HOME} --shell /usr/sbin/nologin {MM_USER}")
    sh(f"sudo chown -R {MM_USER}:{MM_USER} {MM_HOME}")
    sh(f"sudo mkdir -p /var/log/mattermost && sudo chown -R {MM_USER}:{MM_USER} /var/log/mattermost")
    sh(f"sudo mkdir -p /var/lib/mattermost && sudo chown -R {MM_USER}:{MM_USER} /var/lib/mattermost")

    # ---------- 4. config ----------
    stage("config.json")
    if sh(f"test -f {MM_HOME}/config/config.json && echo yes", check=False).strip() != "yes":
        sh(f"sudo cp {MM_HOME}/config/config.json /opt/mattermost-config-default.json")
    # Drive the settings we care about with json so the rest of the file is untouched.
    jq = r"""
import json,sys
p="/opt/mattermost/config/config.json"
c=json.load(open(p))
c["ServiceSettings"]["SiteURL"]=SITE
c["ServiceSettings"]["ListenAddress"]=":8065"
c["ServiceSettings"]["EnableLocalMode"]=True
c["ServiceSettings"]["EnableDeveloper"]=False
c["ServiceSettings"]["RequirePassword"]=True
c["SqlSettings"]["DriverName"]="postgres"
c["SqlSettings"]["DataSource"]=DSN
c["SqlSettings"]["AtRestEncryptKey"]=ARKEY
c["LogSettings"]["FileLocation"]="/var/log/mattermost/mattermost.log"
c["PluginSettings"]["Enable"]=True
c["FileSettings"]["Directory"]="/var/lib/mattermost/"
json.dump(c,open(p,"w"),indent=2)
print("config written")
"""
    # generate at-rest key.
    # NOTE: `openssl rand | sudo tee` fails under `bash -lc` with no TTY — the
    # tee in a pipeline loses its stdin privileges handling and silently writes
    # nothing. Generate locally and WRITE the value instead of piping it.
    if sh("sudo test -f /home/rdrolfe/.ssop/mattermost-atrest.key && echo yes",
          check=False).strip() != "yes":
        arkey_new = subprocess.check_output(
            ["openssl", "rand", "-base64", "32"], text=True).strip()
        sh("sudo install -d -m 0700 -o rdrolfe -g rdrolfe /home/rdrolfe/.ssop")
        write_secret("/home/rdrolfe/.ssop/mattermost-atrest.key", arkey_new)
    arkey = sh("sudo cat /home/rdrolfe/.ssop/mattermost-atrest.key", check=False).strip()
    if not arkey or "No such file" in arkey:
        print("    !! at-rest key could not be read back — aborting")
        return 1
    if db_pw is None:
        raise SystemExit("internal: db_pw unresolved (run without --skip-download)")
    dsn = (f"postgres://{DB_USER}:{db_pw}@localhost:5432/{DB_NAME}?sslmode=disable&connect_timeout=10"
           f"&binary_parameters=yes")
    script = (jq.replace("SITE", repr(SITE_URL)).replace("DSN", repr(dsn)).replace("ARKEY", repr(arkey)))
    sh("cat > /tmp/mkcfg.py <<'PYEOF'\n" + script + "\nPYEOF")
    sh(f"sudo python3 /tmp/mkcfg.py")
    sh(f"sudo chown {MM_USER}:{MM_USER} {MM_HOME}/config/config.json")
    sh("rm -f /tmp/mkcfg.py")
    print("    config written (SiteURL, ListenAddress, DSN, local mode)")

    # ---------- 5. systemd ----------
    stage("systemd unit")
    unit = f"""[Unit]
Description=Mattermost
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=notify
User={MM_USER}
Group={MM_USER}
WorkingDirectory={MM_HOME}/bin
ExecStart={MM_HOME}/bin/mattermost
ExecStartPre=/bin/mkdir -p /var/log/mattermost /var/lib/mattermost
Restart=always
RestartSec=10
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    sh("cat > /tmp/mm.service <<'ULEOF'\n" + unit + "ULEOF")
    sh("sudo cp /tmp/mm.service /etc/systemd/system/mattermost.service && rm -f /tmp/mm.service")
    sh("sudo systemctl daemon-reload && sudo systemctl enable mattermost")

    # ---------- 6. start ----------
    stage("start mattermost")
    sh("sudo systemctl restart mattermost")
    for i in range(30):
        time.sleep(10)
        st = sh("sudo systemctl is-active mattermost").strip()
        if st == "active":
            break
        if st == "failed":
            print("    !! service failed to start — last log lines:")
            print(sh("sudo journalctl -u mattermost -n 25 --no-pager"))
            return 1
    else:
        print("    !! did not become active in time")
        print(sh("sudo journalctl -u mattermost -n 25 --no-pager"))
        return 1
    print("    service active")

    # ---------- 7. verify HTTP ----------
    stage("verify HTTP")
    code = sh("""curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8065/api/v4/system/ping""").strip()
    print(f"    /api/v4/system/ping -> HTTP {code}")
    if code != "200":
        print(sh("sudo journalctl -u mattermost -n 25 --no-pager"))
        return 1

    # ---------- 8. admin user ----------
    stage("admin user")
    have = sh(f"""sudo -u {MM_USER} {MM_HOME}/bin/mmctl user list 2>/dev/null | grep -c '^{ADMIN_USER} ' || true""").strip()
    if have == "0":
        admin_pw = gen_password()
        sh("sudo install -d -m 0700 -o rdrolfe -g rdrolfe /home/rdrolfe/.ssop")
        write_secret("/home/rdrolfe/.ssop/mattermost-admin-password.txt", admin_pw)
        sh(f"""sudo -u {MM_USER} MM_SQLSETTINGS_DATASOURCE='{dsn}' {MM_HOME}/bin/mmctl user create """
           f"""--email '{ADMIN_EMAIL}' --username '{ADMIN_USER}' --password '{admin_pw}' --system-admin 2>&1""")
        print(f"    admin {ADMIN_USER} created, password recorded on target (0600)")
    else:
        print("    admin already exists")

    print("\n=== DONE ===")
    print(f"  URL      : {SITE_URL}")
    print(f"  admin    : {ADMIN_USER}")
    print("  creds    : ~/.ssop/mattermost-*-password.txt on the target (0600)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
