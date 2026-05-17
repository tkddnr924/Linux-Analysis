"""
syslog.py — /var/log/syslog 및 /var/log/messages 파서

파일 감지:
  Debian/Ubuntu : syslog (정확한 이름), syslog.[0-9]* (syslog.1 등)
  RHEL/CentOS   : messages (정확한 이름), messages-* (messages-20240101 등)

포맷: syslog (BSD 전통 포맷) 또는 ISO 8601
  [BSD]  Mon DD HH:MM:SS hostname service[pid]: message
  [ISO]  YYYY-MM-DDTHH:MM:SS.ffffff+TZ hostname service[pid]: message

모든 줄을 구조화하여 parser.db :: syslog 테이블에 저장.
"""

import re
import sqlite3
from pathlib import Path
from datetime import datetime

# ── 파일 감지 ──────────────────────────────────────────────────────────────────

SYSLOG_LOG        = "syslog"           # Debian 현재 파일
SYSLOG_LOG_GLOB   = "syslog.[0-9]*"   # Debian 로테이션: syslog.1, syslog.2
MESSAGES_LOG      = "messages"         # RHEL 현재 파일
MESSAGES_LOG_GLOB = "messages-*"       # RHEL 로테이션: messages-20240101

TABLE = "syslog"

# ── 포맷 상수 ──────────────────────────────────────────────────────────────────

FMT_SYSLOG = "syslog"
FMT_ISO    = "iso8601"

# ── 날짜 파싱 ──────────────────────────────────────────────────────────────────

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


# ── 헤더 정규식 ────────────────────────────────────────────────────────────────

# BSD: Mar  1 00:07:35 hostname service[pid]: message
_RE_SYSLOG = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL,
)

# ISO 8601: 2026-03-01T00:00:01.062741+09:00 hostname service[pid]: message
_RE_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\S+?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL,
)


# ── 포맷 자동 감지 ─────────────────────────────────────────────────────────────

def _detect_format(file_path: Path) -> str:
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if _RE_ISO.match(stripped):
                    return FMT_ISO
                if _RE_SYSLOG.match(stripped):
                    return FMT_SYSLOG
    except Exception:
        pass
    return FMT_SYSLOG


# ── 파싱 ───────────────────────────────────────────────────────────────────────

def parse(file_path: Path, file_mtime: datetime | None = None, **_):
    """syslog / messages 파일 → dict 제너레이터."""
    fmt = _detect_format(file_path)
    print(f"    [FORMAT] {fmt} 형식 감지됨")

    with open(file_path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip()
            if not line:
                continue

            timestamp = hostname = service = pid = message = ""

            if fmt == FMT_ISO:
                m = _RE_ISO.match(line)
                if not m:
                    continue
                iso_ts, hostname, service, pid, message = m.groups()
                pid       = pid or ""
                timestamp = _parse_iso_dt(iso_ts)

            else:  # FMT_SYSLOG
                m = _RE_SYSLOG.match(line)
                if not m:
                    continue
                mon, day, time, hostname, service, pid, message = m.groups()
                pid       = pid or ""
                month_num = _MONTHS.get(mon, 1)
                year      = _infer_year(file_mtime, month_num)
                timestamp = _parse_syslog_dt(mon, day, time, year)

            yield {
                "timestamp": timestamp,
                "hostname":  hostname,
                "service":   service,
                "pid":       pid,
                "message":   message,
                "raw_line":  line,
            }


# ── DB ─────────────────────────────────────────────────────────────────────────

_COLS = ["timestamp", "hostname", "service", "pid", "message", "raw_line"]

_INSERT_SQL = (
    f"INSERT INTO {TABLE} ({','.join(_COLS)}) "
    f"VALUES ({','.join('?' * len(_COLS))})"
)


def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        hostname  TEXT,
        service   TEXT,
        pid       TEXT,
        message   TEXT,
        raw_line  TEXT NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ts      ON {TABLE}(timestamp)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_service ON {TABLE}(service)")
    conn.commit()


def to_row(record: dict) -> tuple:
    return tuple(record.get(c, "") or "" for c in _COLS)


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(_INSERT_SQL, rows)
    conn.commit()
