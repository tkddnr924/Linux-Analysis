"""
parser/apache2log.py - Apache2 access / error 로그 파서

──────────────────────────────────────────
접근 로그 (APACHE2_ACCESS_GLOBS)
──────────────────────────────────────────
지원 파일명:
  *access.log*    — Debian/Ubuntu 기본 (access.log, access.log.1, ...)
  *access_log*    — RHEL/CentOS 기본   (access_log, access_log.1, ...)
  other_vhosts_access.log — 멀티 vhost 통합 로그

지원 형식:
  1. Combined Log Format:
       IP - - [DD/Mon/YYYY:HH:MM:SS +TZ] "METHOD URI PROTO" STATUS BYTES "referer" "UA"
  2. Vhost 접두어 형식 (other_vhosts_access.log):
       vhost:port IP - - [timestamp] "request" STATUS BYTES "referer" "UA"

vhost 추출 규칙:
  - product-access.log / product_access_log → vhost = "product"
  - access.log / access_log                 → vhost = "default"
  - other_vhosts_access.log                 → 각 라인 접두어에서 추출

저장 조건:
  - HTTP 2xx (200~299) 만 저장

──────────────────────────────────────────
에러 로그 (APACHE2_ERROR_GLOBS)
──────────────────────────────────────────
지원 파일명:
  *error.log*     — Debian/Ubuntu
  *error_log*     — RHEL/CentOS

지원 형식:
  - Apache 2.4: [Weekday Mon DD HH:MM:SS.usec YYYY] [module:level] [pid N] [client IP:port] msg
  - Apache 2.2: [Weekday Mon DD HH:MM:SS YYYY] [level] [client IP] msg

저장 조건:
  - level: warn / error / crit / alert / emerg (notice·info·debug 제외)

저장 테이블: parser.db :: apache2, apache2_error
"""

import re
import sqlite3
from pathlib import Path

# ── 파일 글로브 ───────────────────────────────────────
APACHE2_ACCESS_GLOBS: list[str] = ["*access.log*", "*access_log*"]
APACHE2_ERROR_GLOBS:  list[str] = ["*error.log*",  "*error_log*"]

TABLE       = "apache2"
TABLE_ERROR = "apache2_error"

# ─────────────────────────────────────────────────────
# 접근 로그 파싱
# ─────────────────────────────────────────────────────

_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_datetime(raw: str) -> str:
    """05/Mar/2026:07:38:42 +0900 → 2026-03-05 07:38:42.000"""
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})', raw)
    if not m:
        return raw
    day, mon, year, time = m.groups()
    return f"{year}-{_MONTHS.get(mon, '00')}-{day} {time}.000"


def _vhost_from_path(file_path: Path) -> tuple[str, bool]:
    """
    파일명에서 (default_vhost, vhost_in_line) 반환.
    vhost_in_line=True → other_vhosts_access.log 형식 (라인 파싱으로 추출)
    """
    name = file_path.name
    if name.endswith(".gz"):
        name = name[:-3]
    name = re.sub(r"\.\d+$", "", name)
    # 언더스코어 변형 정규화: access_log → access.log 형태로 간주
    name_norm = name.replace("_access_log", "-access.log").replace("_access.log", "-access.log")

    if name in ("other_vhosts_access.log",):
        return ("", True)

    m = re.match(r"^(.+)-access\.log$", name_norm)
    if m:
        return (m.group(1), False)

    if name in ("access.log", "access_log"):
        return ("default", False)

    return ("unknown", False)


_COMBINED_RE = re.compile(
    r"^(?P<src_ip>\S+)"
    r" \S+ \S+ "
    r"\[(?P<datetime>[^\]]+)\]"
    r' "(?P<request>[^"]*)"'
    r" (?P<status>\d{3})"
    r" (?P<bytes>\S+)"
    r'(?: "(?P<referer>[^"]*)")?'
    r'(?: "(?P<ua>[^"]*)")?'
)

_VHOST_RE = re.compile(
    r"^(?P<vhost_port>\S+?:\d+) "
    r"(?P<src_ip>\S+)"
    r" \S+ \S+ "
    r"\[(?P<datetime>[^\]]+)\]"
    r' "(?P<request>[^"]*)"'
    r" (?P<status>\d{3})"
    r" (?P<bytes>\S+)"
    r'(?: "(?P<referer>[^"]*)")?'
    r'(?: "(?P<ua>[^"]*)")?'
)

_REQUEST_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)$")


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
                self.vhost = vhost_port.split(":")[0]
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


def parse(file_path: Path) -> list[Apache2LogEntry]:
    """2xx 상태코드 라인만 파싱"""
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


# ─────────────────────────────────────────────────────
# 에러 로그 파싱
# ─────────────────────────────────────────────────────

_ERR_MONTHS = {
    "Jan": 1, "Feb": 2,  "Mar": 3,  "Apr": 4,
    "May": 5, "Jun": 6,  "Jul": 7,  "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Apache 2.4: [Weekday Mon DD HH:MM:SS.usec YYYY] [module:level] [pid N] [client IP:port] msg
_ERROR_24_RE = re.compile(
    r"^\[\w+ (?P<datetime>\w+ \d{1,2} [\d:.]+\s+\d{4})\]"
    r" \[(?P<module>[^:]+):(?P<level>\w+)\]"
    r" \[pid (?P<pid>\d+)\]"
    r"(?: \[client (?P<client>[^\]]+)\])?"
    r" (?P<message>.+)$"
)

# Apache 2.2: [Weekday Mon DD HH:MM:SS YYYY] [level] [client IP] msg
_ERROR_22_RE = re.compile(
    r"^\[\w+ (?P<datetime>\w+ \d{1,2} [\d:]+\s+\d{4})\]"
    r" \[(?P<level>\w+)\]"
    r"(?: \[client (?P<client>[^\]]+)\])?"
    r" (?P<message>.+)$"
)


def _parse_error_datetime(raw: str) -> str:
    """Oct 11 14:32:52.763677 2000  또는  Oct 11 14:32:52 2000 → 2000-10-11 14:32:52.000"""
    m = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+(\d{4})', raw)
    if m:
        mon, day, time, year = m.groups()
        mo = _ERR_MONTHS.get(mon, 0)
        return f"{year}-{mo:02d}-{int(day):02d} {time}.000"
    return raw


class Apache2ErrorEntry:
    __slots__ = ("date_time", "level", "module", "pid", "client_ip", "message", "raw_line")

    def __init__(self, line: str):
        self.raw_line  = line.rstrip()
        self.date_time = ""
        self.level     = ""
        self.module    = ""
        self.pid       = 0
        self.client_ip = ""
        self.message   = ""

        # Apache 2.4 먼저 시도
        m = _ERROR_24_RE.match(line)
        if m:
            self.date_time = _parse_error_datetime(m.group("datetime"))
            self.module    = m.group("module")
            self.level     = m.group("level").lower()
            self.pid       = int(m.group("pid") or 0)
            client         = m.group("client") or ""
            self.client_ip = client.rsplit(":", 1)[0] if ":" in client else client
            self.message   = m.group("message")
            return

        # Apache 2.2 fallback
        m = _ERROR_22_RE.match(line)
        if m:
            self.date_time = _parse_error_datetime(m.group("datetime"))
            self.level     = m.group("level").lower()
            self.module    = "core"
            client         = m.group("client") or ""
            self.client_ip = client.rsplit(":", 1)[0] if ":" in client else client
            self.message   = m.group("message")


# warn 이상 레벨만 저장 (notice·info·debug 제외)
_ERROR_KEEP_LEVELS = {"warn", "error", "crit", "alert", "emerg"}


def ensure_db_error(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_ERROR} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        level      TEXT,
        module     TEXT,
        pid        INTEGER,
        client_ip  TEXT,
        message    TEXT,
        raw_line   TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE_ERROR}_dt     ON {TABLE_ERROR}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE_ERROR}_level  ON {TABLE_ERROR}(level)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE_ERROR}_client ON {TABLE_ERROR}(client_ip)")
    conn.commit()


def to_row_error(entry: Apache2ErrorEntry) -> tuple:
    return (
        entry.date_time, entry.level, entry.module,
        entry.pid, entry.client_ip, entry.message, entry.raw_line,
    )


def insert_rows_error(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE_ERROR}
        (date_time, level, module, pid, client_ip, message, raw_line)
    VALUES (?,?,?,?,?,?,?)
    """, rows)
    conn.commit()


def parse_error(file_path: Path) -> list[Apache2ErrorEntry]:
    """warn 이상 레벨 에러 로그 라인만 파싱하여 반환"""
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            entry = Apache2ErrorEntry(line)
            if entry.level in _ERROR_KEEP_LEVELS:
                result.append(entry)
    return result
