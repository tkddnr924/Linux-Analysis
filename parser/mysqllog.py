"""
parser/mysqllog.py - MySQL 로그 파서

지원 로그:
  1. General Query Log (query.log*)
       형식: YYYY-MM-DDTHH:MM:SS.ffffffZ TAB <space>thread_id command [TAB argument]
       예)  2026-03-04T15:00:17.158183Z\t 2908 Query\tSELECT ...
            2026-03-04T15:00:02.239449Z\t 2927 Quit
       저장 테이블: parser.db :: mysql_query

  2. Error Log (error.log*)
       형식: YYYY-MM-DDTHH:MM:SS.ffffffZ thread_id [level] [error_code] [subsystem] message
       예)  2026-03-04T17:33:18.013562Z 3047 [Warning] [MY-010057] [Server] ...
       저장 테이블: parser.db :: mysql_error

  3. Slow Query Log (mysql-slow.log*) - 실제 데이터 없음, 파싱 생략

glob:
  MYSQL_QUERY_GLOB = "query.log*"
  MYSQL_ERROR_GLOB = "error.log*"
"""

import re
import sqlite3
from pathlib import Path

MYSQL_QUERY_GLOB: str = "query.log*"
MYSQL_ERROR_GLOB: str = "error.log*"

TABLE_QUERY = "mysql_query"
TABLE_ERROR = "mysql_error"

# ── 날짜 파싱 ──────────────────────────────────────────
_DT_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})')


def _parse_datetime(raw: str) -> str:
    """2026-03-04T15:00:02.239449Z → 2026-03-04 15:00:02"""
    m = _DT_RE.match(raw)
    return f"{m.group(1)} {m.group(2)}" if m else raw


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    """mysql_query, mysql_error 테이블 모두 생성 (멱등)"""
    # ── mysql_query
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_QUERY} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT,
        thread_id   INTEGER,
        command     TEXT,
        argument    TEXT,
        raw_line    TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_q_dt      ON {TABLE_QUERY}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_q_tid     ON {TABLE_QUERY}(thread_id)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_q_cmd     ON {TABLE_QUERY}(command)")

    # ── mysql_error
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_ERROR} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT,
        thread_id   INTEGER,
        level       TEXT,
        error_code  TEXT,
        subsystem   TEXT,
        message     TEXT,
        raw_line    TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_e_dt      ON {TABLE_ERROR}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_e_level   ON {TABLE_ERROR}(level)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_e_code    ON {TABLE_ERROR}(error_code)")

    conn.commit()


# ══════════════════════════════════════════════════════
# 1. General Query Log (query.log*)
# ══════════════════════════════════════════════════════

# 헤더 줄 패턴 (무시)
_QUERY_SKIP_RE = re.compile(r'^(?:/usr/sbin/mysqld|Tcp port|Time\s+Id\s+Command)')

# 타임스탬프 접두사: YYYY-MM-DDTHH:MM:SS...Z
_QUERY_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\t'  # timestamp
    r'\s*(\d+)\s+'                                     # thread_id
    r'(\S+)'                                           # command
    r'(?:\t(.*))?$'                                    # argument (optional)
)


class MySQLQueryEntry:
    __slots__ = ("date_time", "thread_id", "command", "argument", "raw_line")

    def __init__(self, date_time: str, thread_id: int,
                 command: str, argument: str, raw_line: str):
        self.date_time = date_time
        self.thread_id = thread_id
        self.command   = command
        self.argument  = argument
        self.raw_line  = raw_line


def parse_query(file_path: Path) -> list[MySQLQueryEntry]:
    """General Query Log 파싱 — 전체 라인 저장"""
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or _QUERY_SKIP_RE.match(line):
                continue

            m = _QUERY_LINE_RE.match(line)
            if not m:
                continue

            date_time = _parse_datetime(m.group(1))
            thread_id = int(m.group(2))
            command   = m.group(3)
            argument  = (m.group(4) or "").rstrip()

            result.append(MySQLQueryEntry(date_time, thread_id, command, argument, line))
    return result


def to_row_query(entry: MySQLQueryEntry) -> tuple:
    return (
        entry.date_time, entry.thread_id, entry.command,
        entry.argument, entry.raw_line,
    )


def insert_rows_query(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE_QUERY} (date_time, thread_id, command, argument, raw_line)
    VALUES (?,?,?,?,?)
    """, rows)
    conn.commit()


# ══════════════════════════════════════════════════════
# 2. Error Log (error.log*)
# ══════════════════════════════════════════════════════

# 형식: YYYY-MM-DDTHH:MM:SS.ffffffZ thread_id [level] [code] [subsystem] message
_ERROR_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)'   # timestamp
    r'\s+(\d+)'                                       # thread_id
    r'\s+\[(\w+)\]'                                   # [level]
    r'\s+\[([^\]]+)\]'                                # [error_code]
    r'\s+\[([^\]]+)\]'                                # [subsystem]
    r'\s+(.*)'                                        # message
)


class MySQLErrorEntry:
    __slots__ = ("date_time", "thread_id", "level",
                 "error_code", "subsystem", "message", "raw_line")

    def __init__(self, date_time: str, thread_id: int, level: str,
                 error_code: str, subsystem: str, message: str, raw_line: str):
        self.date_time  = date_time
        self.thread_id  = thread_id
        self.level      = level
        self.error_code = error_code
        self.subsystem  = subsystem
        self.message    = message
        self.raw_line   = raw_line


def parse_error(file_path: Path) -> list[MySQLErrorEntry]:
    """MySQL Error Log 파싱"""
    result = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            m = _ERROR_LINE_RE.match(line)
            if not m:
                continue

            result.append(MySQLErrorEntry(
                date_time  = _parse_datetime(m.group(1)),
                thread_id  = int(m.group(2)),
                level      = m.group(3),
                error_code = m.group(4),
                subsystem  = m.group(5),
                message    = m.group(6).strip(),
                raw_line   = line,
            ))
    return result


def to_row_error(entry: MySQLErrorEntry) -> tuple:
    return (
        entry.date_time, entry.thread_id, entry.level,
        entry.error_code, entry.subsystem, entry.message, entry.raw_line,
    )


def insert_rows_error(conn: sqlite3.Connection, rows: list):
    conn.executemany(f"""
    INSERT INTO {TABLE_ERROR} (date_time, thread_id, level,
                               error_code, subsystem, message, raw_line)
    VALUES (?,?,?,?,?,?,?)
    """, rows)
    conn.commit()
