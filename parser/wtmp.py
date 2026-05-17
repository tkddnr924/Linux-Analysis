"""
wtmp.py — /var/log/wtmp 및 /var/log/btmp 파서

wtmp : 로그인/로그아웃/부팅 이력  (last 명령과 동일 데이터)
btmp : 실패한 로그인 시도         (lastb 명령과 동일 데이터)

파일 형식: 바이너리 utmp struct — 384 bytes / record (Linux x86_64, glibc 2.x)

파일 감지:
  wtmp : wtmp (정확한 이름), wtmp.[0-9]* (wtmp.1 등), wtmp-* (wtmp-20240101 등)
  btmp : btmp (정확한 이름), btmp.[0-9]*, btmp-*

utmp struct 레이아웃 (little-endian, standard sizes):
  Offset  Size  Field
       0     2  ut_type         (short)
       2     2  <padding>
       4     4  ut_pid          (int32)
       8    32  ut_line         (char[32])  — tty 장치명
      40     4  ut_id           (char[4])   — 터미널 ID
      44    32  ut_user         (char[32])  — 사용자명
      76   256  ut_host         (char[256]) — 원격 호스트 / 커널 버전
     332     2  ut_exit.e_termination
     334     2  ut_exit.e_exit
     336     4  ut_session      (int32)
     340     4  ut_tv.tv_sec    (int32, Unix epoch)
     344     4  ut_tv.tv_usec   (int32)
     348    16  ut_addr_v6      (int32[4])  — 원격 IP (IPv4/IPv6)
     364    20  __reserved
     Total: 384 bytes
"""

import socket
import struct
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── 파일 감지 ──────────────────────────────────────────────────────────────────

WTMP_LOG       = "wtmp"
WTMP_GLOB_NUM  = "wtmp.[0-9]*"   # Debian 로테이션: wtmp.1, wtmp.2
WTMP_GLOB_DATE = "wtmp-*"        # RHEL 로테이션:   wtmp-20240101

BTMP_LOG       = "btmp"
BTMP_GLOB_NUM  = "btmp.[0-9]*"
BTMP_GLOB_DATE = "btmp-*"

WTMP_TABLE = "wtmp"
BTMP_TABLE = "btmp"

# ── utmp struct ────────────────────────────────────────────────────────────────

_UTMP    = struct.Struct('<hh i 32s 4s 32s 256s hh l ll 4l 20s')
UTMP_SIZE = _UTMP.size   # 384

_KST = timezone(timedelta(hours=9))

_TYPE_NAME = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}


def _clean(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def _decode_addr(a: int, b: int, c: int, d: int) -> str:
    """ut_addr_v6 4개 int32 → 사람이 읽을 수 있는 IP."""
    if b == 0 and c == 0 and d == 0 and a != 0:
        try:
            return socket.inet_ntoa(struct.pack("<I", a))
        except OSError:
            pass
    elif any(x != 0 for x in (a, b, c, d)):
        try:
            return socket.inet_ntop(socket.AF_INET6, struct.pack("<4I", a, b, c, d))
        except OSError:
            pass
    return ""


# ── 파싱 ───────────────────────────────────────────────────────────────────────

def parse(file_path: Path):
    """wtmp/btmp 바이너리 파일 → dict 제너레이터."""
    with open(file_path, "rb") as f:
        while chunk := f.read(UTMP_SIZE):
            if len(chunk) < UTMP_SIZE:
                break  # 불완전한 마지막 레코드 스킵
            try:
                (ut_type, _pad, ut_pid,
                 ut_line, ut_id, ut_user, ut_host,
                 ut_exit_term, ut_exit_code,
                 ut_session, ut_tv_sec, ut_tv_usec,
                 addr0, addr1, addr2, addr3,
                 _reserved) = _UTMP.unpack(chunk)
            except struct.error:
                continue

            if ut_type == 0:  # EMPTY — 사용하지 않는 슬롯
                continue

            ts = datetime.fromtimestamp(ut_tv_sec, tz=timezone.utc).astimezone(_KST)
            timestamp = f"{ts:%Y-%m-%d %H:%M:%S}.{ut_tv_usec // 1000:03d}"

            yield {
                "ut_type":   ut_type,
                "type_name": _TYPE_NAME.get(ut_type, str(ut_type)),
                "timestamp": timestamp,
                "pid":       ut_pid,
                "line":      _clean(ut_line),
                "ut_id":     _clean(ut_id),
                "user":      _clean(ut_user),
                "host":      _clean(ut_host),
                "src_ip":    _decode_addr(addr0, addr1, addr2, addr3),
                "session":   ut_session,
                "exit_term": ut_exit_term,
                "exit_code": ut_exit_code,
            }


# ── DB ─────────────────────────────────────────────────────────────────────────

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS {table} (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ut_type    INTEGER NOT NULL,
    type_name  TEXT,
    timestamp  TEXT    NOT NULL,
    pid        INTEGER,
    line       TEXT,
    ut_id      TEXT,
    user       TEXT,
    host       TEXT,
    src_ip     TEXT,
    session    INTEGER,
    exit_term  INTEGER,
    exit_code  INTEGER
)"""

_COLS = [
    "ut_type", "type_name", "timestamp",
    "pid", "line", "ut_id", "user", "host", "src_ip",
    "session", "exit_term", "exit_code",
]

_INSERT = "INSERT INTO {table} ({cols}) VALUES ({placeholders})"


def _ensure(conn: sqlite3.Connection, table: str):
    conn.execute(_SCHEMA.format(table=table))
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_ts   ON {table}(timestamp)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_user ON {table}(user)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_ip   ON {table}(src_ip)")
    conn.commit()


def ensure_db(conn: sqlite3.Connection):
    _ensure(conn, WTMP_TABLE)


def ensure_db_btmp(conn: sqlite3.Connection):
    _ensure(conn, BTMP_TABLE)


def to_row(record: dict) -> tuple:
    return tuple(record.get(c) for c in _COLS)


to_row_btmp = to_row


def _insert_rows(conn: sqlite3.Connection, rows: list, table: str):
    sql = _INSERT.format(
        table=table,
        cols=",".join(_COLS),
        placeholders=",".join("?" * len(_COLS)),
    )
    conn.executemany(sql, rows)
    conn.commit()


def insert_rows(conn: sqlite3.Connection, rows: list):
    _insert_rows(conn, rows, WTMP_TABLE)


def insert_rows_btmp(conn: sqlite3.Connection, rows: list):
    _insert_rows(conn, rows, BTMP_TABLE)
