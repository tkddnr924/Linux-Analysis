"""
parser/apache2log.py - Apache2 access log 파서

지원 형식:
  1. Combined Log Format (기본 vhost, product-access.log 등):
       IP - - [DD/Mon/YYYY:HH:MM:SS +TZ] "METHOD URI PROTO" STATUS BYTES "referer" "UA"

  2. Vhost 접두어 형식 (other_vhosts_access.log):
       vhost:port IP - - [DD/Mon/YYYY:HH:MM:SS +TZ] "METHOD URI PROTO" STATUS BYTES "referer" "UA"

vhost 추출 규칙:
  - product-access.log      → vhost = "product"
  - api-http-access.log     → vhost = "api-http"
  - access.log              → vhost = "default"
  - other_vhosts_access.log → 각 라인의 vhost:port 접두어에서 추출

저장 조건:
  - HTTP 상태코드 2xx (200~299) 만 저장
  - nginx와 동일 기준: 실제 성공한 요청에서 공격 패턴 탐지

저장 테이블: parser.db :: apache2
"""

import re
import sqlite3
from pathlib import Path

APACHE2_LOG_GLOB: str = "*access.log*"
TABLE = "apache2"

# ── 날짜 파싱 ──────────────────────────────────────────
_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_datetime(raw: str) -> str:
    """05/Mar/2026:07:38:42 +0900 → 2026-03-05 07:38:42"""
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})', raw)
    if not m:
        return raw
    day, mon, year, time = m.groups()
    return f"{year}-{_MONTHS.get(mon, '00')}-{day} {time}"


# ── vhost 추출 ─────────────────────────────────────────
def _vhost_from_path(file_path: Path) -> tuple[str, bool]:
    """
    파일명에서 vhost 이름과 "라인에 vhost 포함 여부" 반환.

    Returns:
        (default_vhost, vhost_in_line)
        vhost_in_line=True  → other_vhosts_access.log 형식 (라인 파싱으로 추출)
        vhost_in_line=False → 파일명에서 추출한 고정 vhost 사용
    """
    name = file_path.name
    # 압축 확장자 제거
    if name.endswith(".gz"):
        name = name[:-3]
    # 순환 숫자 접미사 제거 (.1, .2 등)
    name = re.sub(r"\.\d+$", "", name)

    if name == "other_vhosts_access.log":
        return ("", True)   # 각 라인에서 vhost 추출

    m = re.match(r"^(.+)-access\.log$", name)
    if m:
        return (m.group(1), False)

    if name == "access.log":
        return ("default", False)

    return ("unknown", False)


# ── 정규식 ─────────────────────────────────────────────
# Combined Log Format: IP - - [timestamp] "request" status bytes "referer" "ua"
_COMBINED_RE = re.compile(
    r"^(?P<src_ip>\S+)"              # IP (IPv4 / IPv6)
    r" \S+ \S+ "                     # ident, authuser (무시)
    r"\[(?P<datetime>[^\]]+)\]"      # [timestamp]
    r' "(?P<request>[^"]*)"'         # "METHOD URI PROTO"
    r" (?P<status>\d{3})"            # 상태코드
    r" (?P<bytes>\S+)"               # 바이트 수 or '-'
    r'(?: "(?P<referer>[^"]*)")?'    # "referer" (optional)
    r'(?: "(?P<ua>[^"]*)")?'         # "ua" (optional)
)

# Vhost-prefixed: vhost:port IP - - [timestamp] "request" status bytes ...
_VHOST_RE = re.compile(
    r"^(?P<vhost_port>\S+?:\d+) "   # vhost:port
    r"(?P<src_ip>\S+)"               # IP
    r" \S+ \S+ "
    r"\[(?P<datetime>[^\]]+)\]"
    r' "(?P<request>[^"]*)"'
    r" (?P<status>\d{3})"
    r" (?P<bytes>\S+)"
    r'(?: "(?P<referer>[^"]*)")?'
    r'(?: "(?P<ua>[^"]*)")?'
)

_REQUEST_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)$")


# ── 로그 엔트리 ────────────────────────────────────────
class Apache2LogEntry:
    __slots__ = (
        "date_time", "vhost", "src_ip", "method", "uri", "protocol",
        "status", "bytes_sent", "referer", "user_agent", "raw_line",
    )

    def __init__(self, line: str, default_vhost: str, vhost_in_line: bool):
        self.raw_line   = line.rstrip()
        self.date_time  = ""
        self.vhost      = default_vhost
        self.src_ip     = ""
        self.method     = ""
        self.uri        = ""
        self.protocol   = ""
        self.status     = 0
        self.bytes_sent = 0
        self.referer    = ""
        self.user_agent = ""

        if vhost_in_line:
            m = _VHOST_RE.match(line)
            if m:
                vhost_port = m.group("vhost_port")
                self.vhost = vhost_port.split(":")[0]   # port 제거
                self._fill(m)
        else:
            m = _COMBINED_RE.match(line)
            if m:
                self._fill(m)

    def _fill(self, m: re.Match):
        self.src_ip     = m.group("src_ip")
        self.date_time  = _parse_datetime(m.group("datetime"))
        self.status     = int(m.group("status"))
        raw_bytes       = m.group("bytes")
        self.bytes_sent = int(raw_bytes) if raw_bytes and raw_bytes != "-" else 0
        self.referer    = m.group("referer") or ""
        self.user_agent = m.group("ua") or ""

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
        vhost       TEXT,
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
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_vhost  ON {TABLE}(vhost)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_uri    ON {TABLE}(uri)")
    conn.commit()


def to_row(entry: Apache2LogEntry) -> tuple:
    return (
        entry.date_time, entry.vhost, entry.src_ip,
        entry.method, entry.uri, entry.protocol,
        entry.status, entry.bytes_sent,
        entry.referer, entry.user_agent, entry.raw_line,
    )


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE}
        (date_time, vhost, src_ip, method, uri, protocol,
         status, bytes_sent, referer, user_agent, raw_line)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()


# ── 파싱 ──────────────────────────────────────────────
def parse(file_path: Path) -> list[Apache2LogEntry]:
    """2xx 상태코드 라인만 파싱하여 반환"""
    default_vhost, vhost_in_line = _vhost_from_path(file_path)
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            entry = Apache2LogEntry(line, default_vhost, vhost_in_line)
            if 200 <= entry.status <= 299:
                result.append(entry)
    return result
