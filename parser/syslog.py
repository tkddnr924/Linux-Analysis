"""
syslog.py - /var/log/syslog 파서

로그 형식:
  1. Syslog (BSD)  : Mon DD HH:MM:SS hostname service[pid]: message
  2. ISO 8601      : YYYY-MM-DDTHH:MM:SS.ffffff+TZ hostname service[pid]: message

모든 줄을 구조화하여 parser.db :: syslog 테이블에 저장.
"""

import re
import sqlite3
from pathlib import Path
from datetime import datetime

SYSLOG_LOG_GLOB: str = "syslog*"
TABLE = "syslog"

# ── 포맷 상수 ─────────────────────────────────────────
FMT_SYSLOG = "syslog"
FMT_ISO    = "iso8601"

# ── 날짜 파싱 ──────────────────────────────────────────
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_datetime(month: str, day: str, time: str, year: int) -> str:
    m = _MONTHS.get(month, 1)
    d = int(day.strip())
    return f"{year}-{m:02d}-{d:02d} {time}"


def _parse_iso_datetime(iso_str: str) -> str:
    if "T" in iso_str:
        date_part, rest = iso_str.split("T", 1)
        time_part = rest[:8]
        return f"{date_part} {time_part}"
    return iso_str[:19]


def _infer_year(file_mtime: datetime | None, month: int) -> int:
    if file_mtime is None:
        return datetime.now().year
    file_year  = file_mtime.year
    file_month = file_mtime.month
    if month >= 11 and file_month <= 2:
        return file_year - 1
    return file_year


# ── 헤더 정규식 ───────────────────────────────────────

# Syslog (BSD): Mar  1 00:07:35 hostname service[pid]: message
_RE_SYSLOG = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL
)

# ISO 8601: 2026-03-01T00:00:01.062741+09:00 hostname service[pid]: message
_RE_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\S+?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL
)


# ── 포맷 자동 감지 ────────────────────────────────────
def _detect_format(file_path: Path) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                line = line.strip()
                if not line:
                    continue
                if _RE_ISO.match(line):
                    return FMT_ISO
                if _RE_SYSLOG.match(line):
                    return FMT_SYSLOG
    except Exception:
        pass
    return FMT_SYSLOG


# ── 데이터 클래스 ─────────────────────────────────────
class SyslogEntry:
    def __init__(self, line: str, fmt: str = FMT_SYSLOG,
                 year: int | None = None, file_mtime: datetime | None = None):
        self.raw_line  = line.rstrip()
        self.date_time = ""
        self.hostname  = ""
        self.service   = ""
        self.pid       = ""
        self.message   = ""

        if fmt == FMT_ISO:
            self._parse_iso(line)
        else:
            self._parse_syslog(line, year, file_mtime)

    def _parse_syslog(self, line: str, year: int | None, file_mtime: datetime | None):
        m = _RE_SYSLOG.match(line)
        if not m:
            return
        month_str, day, time, hostname, service, pid, message = m.groups()
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


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        hostname   TEXT,
        service    TEXT,
        pid        TEXT,
        message    TEXT,
        raw_line   TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_dt      ON {TABLE}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_service ON {TABLE}(service)")
    conn.commit()


def table_has_data(conn: sqlite3.Connection) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    )
    if not cur.fetchone():
        return False
    return conn.execute(f"SELECT 1 FROM {TABLE} LIMIT 1").fetchone() is not None


def to_row(entry: SyslogEntry) -> tuple:
    return (
        entry.date_time, entry.hostname, entry.service, entry.pid,
        entry.message, entry.raw_line,
    )


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE}
        (date_time, hostname, service, pid, message, raw_line)
    VALUES (?,?,?,?,?,?)
    """, rows)
    conn.commit()


# ── 파싱 ──────────────────────────────────────────────
def parse(file_path: Path, year: int = None,
          file_mtime: datetime | None = None) -> list[SyslogEntry]:
    fmt = _detect_format(file_path)
    print(f"    [FORMAT] {fmt} 형식 감지됨")

    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                result.append(SyslogEntry(line, fmt=fmt, year=year,
                                          file_mtime=file_mtime))
    return result
