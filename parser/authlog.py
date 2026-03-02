"""
authlog.py - /var/log/auth.log 파서

로그 형식:
  Mon DD HH:MM:SS hostname service[pid]: message

주요 서비스: sshd, sudo, CRON, pam_unix, su 등
"""

import re
import sqlite3
from pathlib import Path
from datetime import datetime

AUTH_LOG_GLOB: str = "auth.log*"
TABLE = "authlog"

# ── 날짜 파싱 ──────────────────────────────────────────
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

def _parse_datetime(month: str, day: str, time: str, year: int = None) -> str:
    """'Mar  1 00:07:35' → 'YYYY-MM-DD HH:MM:SS'"""
    if year is None:
        year = datetime.now().year
    m = _MONTHS.get(month, 1)
    d = int(day.strip())
    return f"{year}-{m:02d}-{d:02d} {time}"


# ── 헤더 파싱 ─────────────────────────────────────────
# Mar  1 00:07:35 ip-172-31-47-239 sshd[1664994]: ...
_HEADER_RE = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL
)

# ── 메시지 패턴 ───────────────────────────────────────
_PATTERNS = {
    # sshd - 인증 실패/성공
    "sshd_invalid_user":        re.compile(r'^Invalid user (\S+) from ([\d.:a-fA-F]+) port (\d+)'),
    "sshd_accepted_password":   re.compile(r'^Accepted password for (\S+) from ([\d.:a-fA-F]+) port (\d+)'),
    "sshd_accepted_publickey":  re.compile(r'^Accepted publickey for (\S+) from ([\d.:a-fA-F]+) port (\d+)'),
    "sshd_failed_password":     re.compile(r'^Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port (\d+)'),
    "sshd_conn_closed":         re.compile(r'^Connection closed by (?:(?:authenticating|invalid) user (\S+) )?([\d.:a-fA-F]+) port (\d+)'),
    "sshd_conn_reset":          re.compile(r'^Connection reset by (?:(?:authenticating|invalid) user (\S+) )?([\d.:a-fA-F]+) port (\d+)'),
    "sshd_disconnected":        re.compile(r'^Disconnected from (?:(?:authenticating|invalid) user (\S+) )?([\d.:a-fA-F]+) port (\d+)'),
    "sshd_no_id_string":        re.compile(r'^Did not receive identification string from ([\d.:a-fA-F]+) port (\d+)'),
    "sshd_kex_error":           re.compile(r'^error: kex_exchange_identification: (.+)'),
    "sshd_banner_exchange":     re.compile(r'^banner exchange: Connection from ([\d.:a-fA-F]+) port (\d+): (.+)'),
    "sshd_unable_negotiate":    re.compile(r'^Unable to negotiate with ([\d.:a-fA-F]+) port (\d+): (.+)'),
    "sshd_max_auth":            re.compile(r'^error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port (\d+)'),
    "sshd_session_opened":      re.compile(r'^pam_unix\(sshd:session\): session opened for user (\S+)'),
    "sshd_session_closed":      re.compile(r'^pam_unix\(sshd:session\): session closed for user (\S+)'),
    # sudo
    "sudo_command":             re.compile(r'^(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=([^;]+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)'),
    "sudo_auth_failure":        re.compile(r'^pam_unix\(sudo:auth\): authentication failure.*user=(\S+)'),
    # CRON
    "cron_session_opened":      re.compile(r'^pam_unix\(cron:session\): session opened for user (\S+)'),
    "cron_session_closed":      re.compile(r'^pam_unix\(cron:session\): session closed for user (\S+)'),
    # su
    "su_session_opened":        re.compile(r'^pam_unix\(su(?:-l)?:session\): session opened for user (\S+)'),
    "su_session_closed":        re.compile(r'^pam_unix\(su(?:-l)?:session\): session closed for user (\S+)'),
    "su_to":                    re.compile(r'^\(to (\S+)\) (\S+) on (\S+)'),
    # ssh key fingerprint
    "sshd_publickey_detail":    re.compile(r'^Accepted publickey for (\S+) from ([\d.:a-fA-F]+) port (\d+) \S+: (\S+) (\S+)'),
    # 일반 pam auth failure
    "pam_auth_failure":         re.compile(r'^pam_unix\(\S+:auth\): authentication failure.*ruser=(\S*)\s+rhost=([\d.:a-fA-F]+)'),
}


def _classify(service: str, message: str) -> tuple[str, str, str, str, str]:
    """(event_type, user, src_ip, port, detail) 반환"""
    event_type = "unknown"
    user = ""
    src_ip = ""
    port = ""
    detail = message

    # sshd
    if "sshd" in service or service == "sshd":
        for name, rx in _PATTERNS.items():
            if not name.startswith("sshd"):
                continue
            m = rx.search(message)
            if not m:
                continue
            event_type = name
            g = m.groups()
            if name in ("sshd_invalid_user", "sshd_accepted_password",
                        "sshd_accepted_publickey", "sshd_failed_password",
                        "sshd_max_auth"):
                user, src_ip, port = g[0], g[1], g[2]
            elif name in ("sshd_conn_closed", "sshd_conn_reset", "sshd_disconnected"):
                user = g[0] or ""
                src_ip, port = g[1], g[2]
            elif name == "sshd_no_id_string":
                src_ip, port = g[0], g[1]
            elif name == "sshd_kex_error":
                detail = g[0]
            elif name == "sshd_banner_exchange":
                src_ip, port, detail = g[0], g[1], g[2]
            elif name == "sshd_unable_negotiate":
                src_ip, port, detail = g[0], g[1], g[2]
            elif name in ("sshd_session_opened", "sshd_session_closed"):
                user = g[0]
            elif name == "sshd_publickey_detail":
                user, src_ip, port = g[0], g[1], g[2]
                detail = f"{g[3]} {g[4]}"  # key_type fingerprint
                event_type = "sshd_accepted_publickey"
            break

    # sudo
    elif "sudo" in service:
        m = _PATTERNS["sudo_command"].search(message)
        if m:
            event_type = "sudo_command"
            user, _, _, _, detail = m.groups()
        else:
            m2 = _PATTERNS["sudo_auth_failure"].search(message)
            if m2:
                event_type = "sudo_auth_failure"
                user = m2.group(1)

    # CRON
    elif "CRON" in service or "cron" in service:
        m = _PATTERNS["cron_session_opened"].search(message)
        if m:
            event_type = "cron_session_opened"
            user = m.group(1)
        else:
            m = _PATTERNS["cron_session_closed"].search(message)
            if m:
                event_type = "cron_session_closed"
                user = m.group(1)

    # su
    elif service in ("su", "su-l"):
        m = _PATTERNS["su_to"].search(message)
        if m:
            event_type = "su_to"
            detail = m.group(1)   # target_user
            user   = m.group(2)   # from_user
        else:
            m = _PATTERNS["su_session_opened"].search(message)
            if m:
                event_type = "su_session_opened"
                user = m.group(1)
            else:
                m = _PATTERNS["su_session_closed"].search(message)
                if m:
                    event_type = "su_session_closed"
                    user = m.group(1)

    return event_type, user, src_ip, port, detail


# ── 데이터 클래스 ─────────────────────────────────────
class AuthLogEntry:
    def __init__(self, line: str, year: int = None):
        self.raw_line = line.rstrip()
        self.date_time = ""
        self.hostname = ""
        self.service = ""
        self.pid = ""
        self.message = ""
        self.event_type = "unknown"
        self.user = ""
        self.src_ip = ""
        self.port = ""
        self.detail = ""

        m = _HEADER_RE.match(line)
        if not m:
            return

        month, day, time, hostname, service, pid, message = m.groups()
        self.date_time = _parse_datetime(month, day, time, year)
        self.hostname   = hostname
        self.service    = service
        self.pid        = pid or ""
        self.message    = message

        self.event_type, self.user, self.src_ip, self.port, self.detail = \
            _classify(service, message)


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        hostname   TEXT,
        service    TEXT,
        pid        TEXT,
        event_type TEXT,
        user       TEXT,
        src_ip     TEXT,
        port       TEXT,
        detail     TEXT,
        raw_line   TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_dt   ON {TABLE}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ev   ON {TABLE}(event_type)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ip   ON {TABLE}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_user ON {TABLE}(user)")
    conn.commit()


def table_has_data(conn: sqlite3.Connection) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    )
    if not cur.fetchone():
        return False
    return conn.execute(f"SELECT 1 FROM {TABLE} LIMIT 1").fetchone() is not None


def to_row(entry: AuthLogEntry) -> tuple:
    return (
        entry.date_time, entry.hostname, entry.service, entry.pid,
        entry.event_type, entry.user, entry.src_ip, entry.port,
        entry.detail, entry.raw_line,
    )


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE}
        (date_time, hostname, service, pid, event_type, user, src_ip, port, detail, raw_line)
    VALUES (?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()


# ── 파싱 ──────────────────────────────────────────────
def parse(file_path: Path, year: int = None) -> list[AuthLogEntry]:
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                result.append(AuthLogEntry(line, year=year))
    return result
