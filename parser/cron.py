"""
cron.py — cron 로그 파서

파일 감지:
  RHEL/CentOS : cron (정확한 이름), cron-YYYYMMDD
  Debian/Ubuntu: cron.log (정확한 이름), cron.log.[0-9]* (cron.log.1 등)

포맷: syslog (authlog 와 동일 — BSD 전통 포맷 + ISO 8601 모두 지원)

이벤트 분류(event_type):
  CMD           — 크론잡 실행: (user) CMD (command)
  SESSION_OPEN  — PAM 세션 시작
  SESSION_CLOSE — PAM 세션 종료
  ERROR         — 오류: (user) ERROR (...) / (CRON) error (...)
  MAIL          — 출력 메일 처리: (user) MAIL (...)
  INFO          — 정보 메시지: (CRON) INFO (...)
  RELOAD        — 설정 리로드: (CRON) RELOAD (...)
  STARTUP       — 데몬 시작: (CRON) STARTUP (...)
  OTHER         — 위 패턴 미해당 (message + raw_line 보존)
"""

import re
import sqlite3
from datetime import datetime
from pathlib import Path

# ── 파일 감지 ──────────────────────────────────────────────────────────────────

CRON_LOG          = "cron"
CRON_LOG_GLOB     = "cron-*"           # RHEL 로테이션: cron-20240101
CRON_LOG_DEBIAN   = "cron.log"
CRON_LOG_DEB_GLOB = "cron.log.[0-9]*"  # Debian 로테이션: cron.log.1

TABLE = "cron"

# ── 타임스탬프 (authlog 와 동일 로직) ─────────────────────────────────────────

FMT_SYSLOG = "syslog"
FMT_ISO    = "iso8601"

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_dt(month: str, day: str, time: str, year: int) -> str:
    m = _MONTHS.get(month, 1)
    return f"{year}-{m:02d}-{int(day.strip()):02d} {time}.000"


def _parse_iso_dt(iso_str: str) -> str:
    if "T" in iso_str:
        date_part, rest = iso_str.split("T", 1)
        time_hms = rest[:8]
        ms = (rest[9:12] + "000")[:3] if len(rest) > 8 and rest[8] == "." else "000"
        return f"{date_part} {time_hms}.{ms}"
    base = iso_str[:19]
    ms   = (iso_str[20:23] + "000")[:3] if len(iso_str) > 19 and iso_str[19] == "." else "000"
    return f"{base}.{ms}"


def _infer_year(file_mtime: datetime | None, month: int) -> int:
    if file_mtime is None:
        return datetime.now().year
    y, m = file_mtime.year, file_mtime.month
    return y - 1 if month >= 11 and m <= 2 else y


# ── 헤더 파싱 ──────────────────────────────────────────────────────────────────

_RE_SYSLOG = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL,
)
_RE_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\S+?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL,
)


def _detect_format(file_path: Path) -> str:
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                if _RE_ISO.match(line.strip()):
                    return FMT_ISO
                if _RE_SYSLOG.match(line.strip()):
                    return FMT_SYSLOG
    except Exception:
        pass
    return FMT_SYSLOG


# ── 메시지 분류 ────────────────────────────────────────────────────────────────

# (user) CMD (command)
_R_CMD = re.compile(r'^\((\S+)\)\s+CMD\s+\((.+)\)$')

# pam_unix(cron:session): session opened/closed for user X
_R_SESSION_OPEN  = re.compile(r'pam_\w+\(cron:session\):\s+session\s+opened\s+for\s+user\s+(\S+)')
_R_SESSION_CLOSE = re.compile(r'pam_\w+\(cron:session\):\s+session\s+closed\s+for\s+user\s+(\S+)')

# (user|CRON) ERROR/error (detail)
_R_ERROR = re.compile(r'^\((\S+)\)\s+(?:ERROR|error)\s+\((.+)\)$')

# (user|CRON) MAIL (detail)
_R_MAIL = re.compile(r'^\((\S+)\)\s+MAIL\s+\((.+)\)$')

# (CRON) INFO (detail)
_R_INFO = re.compile(r'^\((\S+)\)\s+INFO\s+\((.+)\)$')

# (CRON) RELOAD (tabs/user)
_R_RELOAD = re.compile(r'^\((\S+)\)\s+RELOAD\s+\((.+)\)$')

# (CRON) STARTUP (detail)
_R_STARTUP = re.compile(r'^\((\S+)\)\s+STARTUP\s+\((.+)\)$')


def _classify(msg: str) -> tuple[str, str, str]:
    """(event_type, user, detail) 반환."""

    m = _R_CMD.match(msg)
    if m:
        return "CMD", m.group(1), m.group(2)

    m = _R_SESSION_OPEN.search(msg)
    if m:
        return "SESSION_OPEN", m.group(1), ""

    m = _R_SESSION_CLOSE.search(msg)
    if m:
        return "SESSION_CLOSE", m.group(1), ""

    m = _R_ERROR.match(msg)
    if m:
        return "ERROR", m.group(1), m.group(2)

    m = _R_MAIL.match(msg)
    if m:
        return "MAIL", m.group(1), m.group(2)

    m = _R_INFO.match(msg)
    if m:
        return "INFO", m.group(1), m.group(2)

    m = _R_RELOAD.match(msg)
    if m:
        return "RELOAD", m.group(1), m.group(2)

    m = _R_STARTUP.match(msg)
    if m:
        return "STARTUP", m.group(1), m.group(2)

    return "OTHER", "", ""


# ── 파싱 ───────────────────────────────────────────────────────────────────────

def parse(file_path: Path, file_mtime: datetime | None = None):
    """cron 로그 파일 → dict 제너레이터."""
    fmt = _detect_format(file_path)
    print(f"    [FORMAT] {fmt} 형식 감지됨")

    with open(file_path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip()
            if not line:
                continue

            timestamp = hostname = process = pid = message = ""

            if fmt == FMT_ISO:
                m = _RE_ISO.match(line)
                if not m:
                    continue
                iso_ts, hostname, process, pid, message = m.groups()
                pid       = pid or ""
                timestamp = _parse_iso_dt(iso_ts)

            else:  # FMT_SYSLOG
                m = _RE_SYSLOG.match(line)
                if not m:
                    continue
                mon, day, time, hostname, process, pid, message = m.groups()
                pid       = pid or ""
                month_num = _MONTHS.get(mon, 1)
                year      = _infer_year(file_mtime, month_num)
                timestamp = _parse_syslog_dt(mon, day, time, year)

            event_type, user, detail = _classify(message)

            yield {
                "timestamp":  timestamp,
                "hostname":   hostname,
                "process":    process,
                "pid":        pid,
                "event_type": event_type,
                "user":       user,
                "command":    detail if event_type == "CMD" else "",
                "detail":     detail if event_type != "CMD" else "",
                "message":    message,
                "raw_line":   line,
            }


# ── DB ─────────────────────────────────────────────────────────────────────────

_COLS = [
    "timestamp", "hostname", "process", "pid",
    "event_type", "user", "command", "detail",
    "message", "raw_line",
]

_INSERT_SQL = (
    f"INSERT INTO {TABLE} ({','.join(_COLS)}) "
    f"VALUES ({','.join('?' * len(_COLS))})"
)


def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT    NOT NULL,
        hostname   TEXT,
        process    TEXT,
        pid        TEXT,
        event_type TEXT,   -- CMD/SESSION_OPEN/SESSION_CLOSE/ERROR/MAIL/INFO/RELOAD/STARTUP/OTHER
        user       TEXT,   -- 크론잡 실행 사용자
        command    TEXT,   -- CMD 이벤트의 실행 명령
        detail     TEXT,   -- CMD 외 이벤트의 상세 정보
        message    TEXT,
        raw_line   TEXT    NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ts   ON {TABLE}(timestamp)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ev   ON {TABLE}(event_type)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_user ON {TABLE}(user)")
    conn.commit()


def to_row(record: dict) -> tuple:
    return tuple(record.get(c, "") or "" for c in _COLS)


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(_INSERT_SQL, rows)
    conn.commit()
