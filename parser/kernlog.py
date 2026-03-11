"""
kernlog.py - /var/log/kern.log 파서

로그 형식:
  ISO 8601: YYYY-MM-DDTHH:MM:SS.ffffff+TZ hostname kernel[pid]: message
  (kern.log 는 항상 ISO 8601 형식; rsyslog 기본)

UFW BLOCK/ALLOW/AUDIT 메시지는 syslog/ufw.log 에서 이미 파싱되므로 제외.
"""

import re
import sqlite3
from pathlib import Path

KERN_LOG_GLOB: str = "kern.log*"
TABLE = "kernlog"

# ISO 8601 헤더: 타임스탬프 + hostname + "kernel[pid]:" + message
_RE_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\S+?)\s+(\S+)\s+kernel(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL
)


def _parse_iso_datetime(iso_str: str) -> str:
    """ISO 8601 → 'YYYY-MM-DD HH:MM:SS.mmm' (밀리초 3자리 보존)."""
    if "T" in iso_str:
        date_part, rest = iso_str.split("T", 1)
        time_hms = rest[:8]
        if len(rest) > 8 and rest[8] == '.':
            ms = (rest[9:12] + '000')[:3]
        else:
            ms = '000'
        return f"{date_part} {time_hms}.{ms}"
    base = iso_str[:19]
    ms   = (iso_str[20:23] + '000')[:3] if len(iso_str) > 19 and iso_str[19] == '.' else '000'
    return f"{base}.{ms}"


# ── 데이터 클래스 ─────────────────────────────────────
class KernLogEntry:
    def __init__(self, line: str):
        self.raw_line  = line.rstrip()
        self.date_time = ""
        self.hostname  = ""
        self.pid       = ""
        self.message   = ""
        self._parse(line)

    def _parse(self, line: str):
        m = _RE_ISO.match(line)
        if not m:
            return
        iso_ts, hostname, pid, message = m.groups()
        self.date_time = _parse_iso_datetime(iso_ts)
        self.hostname  = hostname
        self.pid       = pid or ""
        self.message   = message.strip()


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        hostname   TEXT,
        pid        TEXT,
        message    TEXT,
        raw_line   TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_dt ON {TABLE}(date_time)")
    conn.commit()


def table_has_data(conn: sqlite3.Connection) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    )
    if not cur.fetchone():
        return False
    return conn.execute(f"SELECT 1 FROM {TABLE} LIMIT 1").fetchone() is not None


def to_row(entry: KernLogEntry) -> tuple:
    return (entry.date_time, entry.hostname, entry.pid, entry.message, entry.raw_line)


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE} (date_time, hostname, pid, message, raw_line)
    VALUES (?,?,?,?,?)
    """, rows)
    conn.commit()


# ── 파싱 ──────────────────────────────────────────────
def parse(file_path: Path, **kwargs) -> list[KernLogEntry]:
    """
    kern.log 파일 파싱.
    - UFW 관련 메시지는 syslog_ufw 에서 이미 처리되므로 건너뜀
    - 파싱 실패(date_time 공백) 항목 제외
    """
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            # UFW 중복 방지 (syslog / ufw.log 에서 이미 파싱됨)
            if "[UFW " in line:
                continue
            entry = KernLogEntry(line)
            if entry.date_time:
                result.append(entry)
    return result
