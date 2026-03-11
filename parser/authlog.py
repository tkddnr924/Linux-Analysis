"""
authlog.py - /var/log/auth.log 파서

지원 로그 형식:
  1. Syslog (BSD)  : Mon DD HH:MM:SS hostname service[pid]: message
     - Debian, Ubuntu, Amazon Linux 등 대부분의 배포판 기본 형식
     - 연도가 없으므로 파일 mtime 에서 추론
  2. ISO 8601      : YYYY-MM-DDTHH:MM:SS.ffffff+TZ hostname service[pid]: message
     - rsyslog 고정밀 타임스탬프 설정 시 사용
     - openSUSE, 일부 RHEL/CentOS 커스텀 설정

주요 서비스: sshd, sudo, CRON, pam_unix, su 등
"""

import re
import sqlite3
from pathlib import Path
from datetime import datetime

AUTH_LOG_GLOB: str = "auth.log*"
TABLE = "authlog"

# ── 포맷 상수 ─────────────────────────────────────────
FMT_SYSLOG = "syslog"     # Mon DD HH:MM:SS  (연도 없음)
FMT_ISO    = "iso8601"     # YYYY-MM-DDTHH:MM:SS[.us][+TZ]

# ── 날짜 파싱 ──────────────────────────────────────────
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_datetime(month: str, day: str, time: str, year: int) -> str:
    """'Mar  1 00:07:35' + year → 'YYYY-MM-DD HH:MM:SS.000'
    Syslog (BSD) 형식에는 밀리초가 없으므로 .000 을 붙인다."""
    m = _MONTHS.get(month, 1)
    d = int(day.strip())
    return f"{year}-{m:02d}-{d:02d} {time}.000"


def _parse_iso_datetime(iso_str: str) -> str:
    """'2024-01-15T00:07:35.123456+09:00' → '2024-01-15 00:07:35.123'
    밀리초(3자리)까지 보존한다."""
    if "T" in iso_str:
        date_part, rest = iso_str.split("T", 1)
        time_hms = rest[:8]             # HH:MM:SS
        if len(rest) > 8 and rest[8] == '.':
            # 소수 부분에서 처음 3자리만 취해 ms 로 사용
            ms = (rest[9:12] + '000')[:3]
        else:
            ms = '000'
        return f"{date_part} {time_hms}.{ms}"
    # T 없이 공백으로 구분된 경우 (YYYY-MM-DD HH:MM:SS[.mmm])
    base = iso_str[:19]
    ms   = (iso_str[20:23] + '000')[:3] if len(iso_str) > 19 and iso_str[19] == '.' else '000'
    return f"{base}.{ms}"


def _infer_year(file_mtime: datetime | None, month: int) -> int:
    """
    파일 mtime 에서 연도를 추론.
    연도 경계 처리: 로그가 12월인데 파일 mtime 이 다음 해 1~2월이면
    → 전년도로 판단.
    """
    if file_mtime is None:
        return datetime.now().year
    file_year = file_mtime.year
    file_month = file_mtime.month
    # 로그 월이 11~12월인데 파일 mtime 이 1~2월이면 → 전년도
    if month >= 11 and file_month <= 2:
        return file_year - 1
    return file_year


# ── 헤더 파싱 ─────────────────────────────────────────

# 형식 1: Syslog (BSD)
# Mar  1 00:07:35 ip-172-31-47-239 sshd[1664994]: ...
_RE_SYSLOG = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL
)

# 형식 2: ISO 8601
# 2024-01-15T00:07:35.123456+09:00 hostname sshd[1234]: ...
# 2024-01-15T00:07:35+09:00 hostname sshd[1234]: ...
_RE_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\S+?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL
)

# ── 포맷 자동 감지 ────────────────────────────────────
def _detect_format(file_path: Path) -> str:
    """파일 첫 10줄을 읽어 로그 형식을 감지한다."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                line = line.strip()
                if not line:
                    continue
                # ISO 8601 형식 먼저 체크 (더 구체적)
                if _RE_ISO.match(line):
                    return FMT_ISO
                if _RE_SYSLOG.match(line):
                    return FMT_SYSLOG
    except Exception:
        pass
    return FMT_SYSLOG   # 기본값: syslog


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
    def __init__(self, line: str, fmt: str = FMT_SYSLOG,
                 year: int | None = None, file_mtime: datetime | None = None):
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

        if fmt == FMT_ISO:
            self._parse_iso(line)
        else:
            self._parse_syslog(line, year, file_mtime)

    def _parse_syslog(self, line: str, year: int | None, file_mtime: datetime | None):
        m = _RE_SYSLOG.match(line)
        if not m:
            return
        month_str, day, time, hostname, service, pid, message = m.groups()
        # 연도 추론: 명시적 year → file_mtime 기반 → 현재 연도
        month_num = _MONTHS.get(month_str, 1)
        if year is not None:
            resolved_year = year
        else:
            resolved_year = _infer_year(file_mtime, month_num)
        self.date_time = _parse_syslog_datetime(month_str, day, time, resolved_year)
        self.hostname  = hostname
        self.service   = service
        self.pid       = pid or ""
        self.message   = message
        self.event_type, self.user, self.src_ip, self.port, self.detail = \
            _classify(service, message)

    def _parse_iso(self, line: str):
        m = _RE_ISO.match(line)
        if not m:
            return
        iso_ts, hostname, service, pid, message = m.groups()
        self.date_time = _parse_iso_datetime(iso_ts)
        self.hostname  = hostname
        self.service   = service
        self.pid       = pid or ""
        self.message   = message
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
def parse(file_path: Path, year: int = None,
          file_mtime: datetime | None = None) -> list[AuthLogEntry]:
    """
    auth.log 파일 파싱.

    Args:
        file_path:   파싱할 파일 경로
        year:        명시적 연도 (syslog 형식에서 사용, None 이면 file_mtime 에서 추론)
        file_mtime:  원본 파일의 수정 시간 (압축 해제 전 원본 기준)
                     syslog 형식에서 연도가 없을 때 이 값으로 연도 추론
    """
    fmt = _detect_format(file_path)
    print(f"    [FORMAT] {fmt} 형식 감지됨")

    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                result.append(AuthLogEntry(line, fmt=fmt, year=year,
                                           file_mtime=file_mtime))
    return result
