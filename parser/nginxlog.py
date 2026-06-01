"""
parser/nginxlog.py - nginx access / error 로그 파서

──────────────────────────────────────────
접근 로그 (NGINX_ACCESS_GLOBS)
──────────────────────────────────────────
지원 파일명:
  access.log*   — 현재 + 로테이션 (access.log.1, access.log.2.gz ...)
  access_log*   — RHEL 변형

지원 형식 (Combined Log Format):
  IP - user [DD/Mon/YYYY:HH:MM:SS +tz] "METHOD URI PROTO" STATUS BYTES "referer" "UA"

저장 조건:
  - 전체 저장 (상태코드 무관)

──────────────────────────────────────────
에러 로그 (NGINX_ERROR_GLOBS)
──────────────────────────────────────────
지원 파일명:
  error.log*    — 현재 + 로테이션
  error_log*    — RHEL 변형

지원 형식:
  YYYY/MM/DD HH:MM:SS [level] pid#tid: [*cid] message

저장 조건:
  - 전체 저장 (레벨 무관)

저장 테이블: parser.db :: nginx, nginx_error
"""

import re
import sqlite3
from pathlib import Path
from typing import Iterator

# ── 파일 글로브 ────────────────────────────────────────────────────────────────

NGINX_ACCESS_GLOBS: list[str] = ["access.log*", "access_log*"]
NGINX_ERROR_GLOBS:  list[str] = ["error.log*",  "error_log*"]

TABLE       = "nginx"
TABLE_ERROR = "nginx_error"

# ─────────────────────────────────────────────────────────────────────────────
# 접근 로그 파싱
# ─────────────────────────────────────────────────────────────────────────────

_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_access_dt(raw: str) -> str:
    """02/Mar/2026:00:01:57 +0000 → 2026-03-02 00:01:57.000"""
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})', raw)
    if not m:
        return raw
    day, mon, year, time = m.groups()
    return f"{year}-{_MONTHS.get(mon, '00')}-{day} {time}.000"


# nginx 따옴표 필드 안의 " 는 \" 로 이스케이프. 외부 LogFormat 변종에도
# 견디도록 IP 뒤 ident/userid 와 인터필드 공백을 유연하게, bytes 이후는
# 통째로 캡처해 findall 로 따옴표 필드만 추출(위치 기반: 0=referer, 1=ua, 2=xff).
_Q = r'(?:[^"\\]|\\.)*'

_ACCESS_RE = re.compile(
    r'^\s*(?P<src_ip>\S+)'
    r'[^[]*'
    r'\[(?P<datetime>[^\]]+)\]'
    rf'\s+"(?P<request>{_Q})"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<bytes>\S+)'
    r'(?P<rest>.*)$'
)

_REQUEST_RE      = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)$')
_QUOTED_FIELD_RE = re.compile(rf'"({_Q})"')
_UNQUOTED_TOK_RE = re.compile(r'\S+')

# LogFormat 이스케이프 해제: \" → ",  \\ → \
_UNESC_RE = re.compile(r'\\(.)')
def _unesc(s: str) -> str:
    return _UNESC_RE.sub(r'\1', s) if s else s


def _clean_ip(s: str) -> str:
    """ALB/프록시 뒤 환경에서 %h 자리에 'IP, IP, IP' 체인이 들어오는 경우 첫 IP 만."""
    if not s:
        return s
    s = s.strip()
    if "," in s or ";" in s:
        s = re.split(r"[,;]", s, 1)[0].strip()
    return s.rstrip(",;").strip()


def _trailing_fields(rest: str) -> list[str]:
    """bytes 이후 referer / ua / xff 후보 — apache2log._trailing_fields 와 동일 정책.
       따옴표 있으면 그대로, 없으면 unquoted body 전체를 UA 로 보존
       (단, 첫 토큰이 `-` 또는 http(s):// 이면 그것만 referer 로 분리)."""
    quoted = _QUOTED_FIELD_RE.findall(rest)
    if quoted:
        return quoted

    body = rest.strip()
    if not body:
        return []
    parts = body.split(None, 1)
    first = parts[0]
    tail  = parts[1] if len(parts) > 1 else ""
    if first == "-" or first.startswith(("http://", "https://")):
        return [first, tail]
    return ["", body]


class NginxLogEntry:
    __slots__ = (
        "src_ip", "date_time", "method", "uri", "protocol",
        "status", "bytes_sent", "referer", "user_agent", "xff", "raw_line",
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
        self.xff        = ""

        m = _ACCESS_RE.match(line)
        if not m:
            return

        self.src_ip     = _clean_ip(m.group("src_ip"))
        self.date_time  = _parse_access_dt(m.group("datetime"))
        self.status     = int(m.group("status"))
        raw_bytes       = m.group("bytes")
        self.bytes_sent = int(raw_bytes) if raw_bytes and raw_bytes != "-" else 0
        # bytes 이후 referer / ua / xff — 따옴표 우선, 없으면 unquoted fallback
        fields = _trailing_fields(m.group("rest") or "")
        self.referer    = _unesc(fields[0]) if len(fields) >= 1 else ""
        self.user_agent = _unesc(fields[1]) if len(fields) >= 2 else ""
        self.xff        = _unesc(fields[2]) if len(fields) >= 3 else ""

        request_raw = _unesc(m.group("request") or "")
        req = _REQUEST_RE.match(request_raw)
        if req:
            self.method, self.uri, self.protocol = req.groups()
        else:
            self.uri = request_raw


def ensure_db(conn: sqlite3.Connection):
    """테이블만 생성. 인덱스는 대량 삽입 후 ensure_indexes()로 1회 구축."""
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
        xff         TEXT,
        raw_line    TEXT
    )
    """)
    # 기존 DB(컬럼 없던 시절) 마이그레이션: xff 가 없으면 추가
    existing = {r[1] for r in conn.execute(f"PRAGMA table_info({TABLE})").fetchall()}
    if 'xff' not in existing:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN xff TEXT")
    conn.commit()


def ensure_indexes(conn: sqlite3.Connection):
    """대량 삽입 완료 후 1회 호출 — 인덱스를 한 번에 구축."""
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_dt     ON {TABLE}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ip     ON {TABLE}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_status ON {TABLE}(status)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_uri    ON {TABLE}(uri)")
    conn.commit()


def to_row(entry: NginxLogEntry) -> tuple:
    return (
        entry.date_time, entry.src_ip, entry.method, entry.uri,
        entry.protocol, entry.status, entry.bytes_sent,
        entry.referer, entry.user_agent, entry.xff, entry.raw_line,
    )


def insert_rows(conn: sqlite3.Connection, rows: list):
    # commit 없음 — 호출측(main.py)에서 주기적으로/파일 단위로 커밋
    conn.executemany(f"""
    INSERT INTO {TABLE}
        (date_time, src_ip, method, uri, protocol, status, bytes_sent,
         referer, user_agent, xff, raw_line)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, rows)


def parse(file_path: Path) -> Iterator[NginxLogEntry]:
    """접근 로그 스트리밍 파싱 (상태코드 무관). 한 줄씩 yield → 메모리 상수."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            entry = NginxLogEntry(line)
            if entry.status:
                yield entry


# ─────────────────────────────────────────────────────────────────────────────
# 에러 로그 파싱
# ─────────────────────────────────────────────────────────────────────────────

# 2024/01/15 12:34:56 [error] 1234#5678: *90 message ...
# 2024/01/15 12:34:56 [warn]  1234#5678: message without cid
_ERROR_RE = re.compile(
    r'^(?P<datetime>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r' \[(?P<level>\w+)\]'
    r' (?P<pid>\d+)#(?P<tid>\d+):'
    r'(?: \*(?P<cid>\d+))?'
    r' (?P<message>.+)$'
)

# "client: IP" 추출 — message 안에 포함될 수 있음
_CLIENT_RE = re.compile(r'client:\s*([\d.:a-fA-F]+)')


def _parse_error_dt(raw: str) -> str:
    """2024/01/15 12:34:56 → 2024-01-15 12:34:56.000"""
    return raw.replace("/", "-", 2) + ".000"


class NginxErrorEntry:
    __slots__ = ("date_time", "level", "pid", "tid", "cid", "client_ip", "message", "raw_line")

    def __init__(self, line: str):
        self.raw_line  = line.rstrip()
        self.date_time = ""
        self.level     = ""
        self.pid       = 0
        self.tid       = 0
        self.cid       = 0
        self.client_ip = ""
        self.message   = ""

        m = _ERROR_RE.match(line)
        if not m:
            return

        self.date_time = _parse_error_dt(m.group("datetime"))
        self.level     = m.group("level").lower()
        self.pid       = int(m.group("pid"))
        self.tid       = int(m.group("tid"))
        self.cid       = int(m.group("cid")) if m.group("cid") else 0
        self.message   = m.group("message").strip()

        cm = _CLIENT_RE.search(self.message)
        if cm:
            self.client_ip = cm.group(1)


def ensure_db_error(conn: sqlite3.Connection):
    """테이블만 생성. 인덱스는 ensure_indexes_error()로 후행 구축."""
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_ERROR} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        level      TEXT,
        pid        INTEGER,
        tid        INTEGER,
        cid        INTEGER,
        client_ip  TEXT,
        message    TEXT,
        raw_line   TEXT
    )
    """)
    conn.commit()


def ensure_indexes_error(conn: sqlite3.Connection):
    """대량 삽입 완료 후 1회 호출."""
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE_ERROR}_dt     ON {TABLE_ERROR}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE_ERROR}_level  ON {TABLE_ERROR}(level)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE_ERROR}_client ON {TABLE_ERROR}(client_ip)")
    conn.commit()


def to_row_error(entry: NginxErrorEntry) -> tuple:
    return (
        entry.date_time, entry.level, entry.pid, entry.tid,
        entry.cid, entry.client_ip, entry.message, entry.raw_line,
    )


def insert_rows_error(conn: sqlite3.Connection, rows: list):
    # commit 없음 — 호출측에서 커밋
    conn.executemany(f"""
    INSERT INTO {TABLE_ERROR}
        (date_time, level, pid, tid, cid, client_ip, message, raw_line)
    VALUES (?,?,?,?,?,?,?,?)
    """, rows)


def parse_error(file_path: Path) -> Iterator[NginxErrorEntry]:
    """에러 로그 스트리밍 파싱 (레벨 무관). 한 줄씩 yield."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            entry = NginxErrorEntry(line)
            if entry.date_time:
                yield entry
