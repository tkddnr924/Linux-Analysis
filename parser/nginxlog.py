"""
parser/nginxlog.py - nginx access.log 파서

로그 형식 (Combined Log Format):
  IP - user [DD/Mon/YYYY:HH:MM:SS +tz] "METHOD URI PROTO" STATUS BYTES "referer" "UA"

저장 조건:
  - HTTP 상태코드 2xx (200~299) 만 저장
  - 분석 목적: 실제로 성공한 요청 중 공격 패턴 탐지

저장 테이블: parser.db :: nginx
"""

import re
import sqlite3
from pathlib import Path
from datetime import datetime

NGINX_LOG_GLOB: str = "access.log*"
TABLE = "nginx"

# ── 날짜 파싱 ──────────────────────────────────────────
_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

def _parse_datetime(raw: str) -> str:
    """02/Mar/2026:00:01:57 +0000 → 2026-03-02 00:01:57"""
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})', raw)
    if not m:
        return raw
    day, mon, year, time = m.groups()
    return f"{year}-{_MONTHS.get(mon, '00')}-{day} {time}"


# ── 로그 라인 파싱 ─────────────────────────────────────
# 152.42.255.97 - - [02/Mar/2026:00:01:57 +0000] "GET / HTTP/1.1" 404 134 "-" "UA"
_LOG_RE = re.compile(
    r'(?P<src_ip>\S+)'          # IP
    r' \S+ \S+ '                # ident, auth_user (무시)
    r'\[(?P<datetime>[^\]]+)\]' # [timestamp]
    r' "(?P<request>[^"]*)"'    # "METHOD URI PROTO"
    r' (?P<status>\d{3})'       # 상태코드
    r' (?P<bytes>\S+)'          # 바이트 (or '-')
    r'(?: "(?P<referer>[^"]*)")?' # referer (optional)
    r'(?: "(?P<user_agent>[^"]*)")?' # user_agent (optional)
)

_REQUEST_RE = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)$')


class NginxLogEntry:
    __slots__ = (
        "src_ip", "date_time", "method", "uri", "protocol",
        "status", "bytes_sent", "referer", "user_agent", "raw_line",
    )

    def __init__(self, line: str):
        self.raw_line   = line.rstrip()
        self.src_ip     = ""
        self.date_time  = ""
        self.method     = ""
        self.uri        = ""
        self.protocol   = ""
        self.status     = 0
        self.bytes_sent = 0
        self.referer    = ""
        self.user_agent = ""

        m = _LOG_RE.match(line)
        if not m:
            return

        self.src_ip     = m.group("src_ip")
        self.date_time  = _parse_datetime(m.group("datetime"))
        self.status     = int(m.group("status"))
        self.bytes_sent = int(m.group("bytes")) if m.group("bytes") != "-" else 0
        self.referer    = m.group("referer")    or ""
        self.user_agent = m.group("user_agent") or ""

        req = _REQUEST_RE.match(m.group("request") or "")
        if req:
            self.method, self.uri, self.protocol = req.groups()
        else:
            self.uri = m.group("request") or ""


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT,
        src_ip      TEXT,
        method      TEXT,
        uri         TEXT,
        protocol    TEXT,
        status      INTEGER,
        bytes_sent  INTEGER,
        referer     TEXT,
        user_agent  TEXT,
        raw_line    TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_dt     ON {TABLE}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ip     ON {TABLE}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_status ON {TABLE}(status)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_uri    ON {TABLE}(uri)")
    conn.commit()


def to_row(entry: NginxLogEntry) -> tuple:
    return (
        entry.date_time, entry.src_ip, entry.method, entry.uri,
        entry.protocol, entry.status, entry.bytes_sent,
        entry.referer, entry.user_agent, entry.raw_line,
    )


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE}
        (date_time, src_ip, method, uri, protocol, status, bytes_sent,
         referer, user_agent, raw_line)
    VALUES (?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()


# ── 파싱 ──────────────────────────────────────────────
def parse(file_path: Path) -> list[NginxLogEntry]:
    """2xx 상태코드 라인만 파싱하여 반환"""
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            entry = NginxLogEntry(line)
            # 2xx (200~299) 만 저장
            if 200 <= entry.status <= 299:
                result.append(entry)
    return result
