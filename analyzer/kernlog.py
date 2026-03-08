"""
analyzer/kernlog.py - kern.log 보안 이벤트 분석

parser.db :: kernlog 테이블을 읽어 아래 항목을 탐지합니다:
  - AppArmor DENIED  → analysis.db :: kernlog_apparmor
  - 시스템 재부팅     → analysis.db :: kernlog_boot
"""

import re
import sqlite3

# AppArmor 이벤트 파싱
# apparmor="DENIED" operation="capable" profile="/usr/sbin/cupsd" comm="cupsd" ...
_RE_AA      = re.compile(r'apparmor="(\w+)".*?operation="([^"]+)".*?profile="([^"]+)".*?comm="([^"]*)"')
_RE_AA_CAP  = re.compile(r'capname="([^"]+)"')
_RE_AA_NAME = re.compile(r'\bname="([^"]+)"')
_RE_PID     = re.compile(r'\bpid=(\d+)\b')
_RE_BOOT    = re.compile(r'Linux version (\S+)')

TABLE_APPARMOR = "kernlog_apparmor"
TABLE_BOOT     = "kernlog_boot"


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_APPARMOR} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        action     TEXT,
        operation  TEXT,
        profile    TEXT,
        comm       TEXT,
        detail     TEXT,
        pid        TEXT,
        raw_line   TEXT
    )
    """)
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_{TABLE_APPARMOR}_dt ON {TABLE_APPARMOR}(date_time)"
    )
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_BOOT} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time  TEXT,
        kernel_ver TEXT,
        raw_line   TEXT
    )
    """)
    conn.commit()


# ── 분석 ──────────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict:
    rows_aa   = []
    rows_boot = []

    for dt, msg, raw in src_conn.execute(
        "SELECT date_time, message, raw_line FROM kernlog ORDER BY date_time"
    ):
        # ── AppArmor 이벤트 ──────────────────────────
        m = _RE_AA.search(msg)
        if m:
            action, op, profile, comm = m.groups()
            # detail: capname(능력 차단) 또는 name(파일/소켓 차단)
            cap_m  = _RE_AA_CAP.search(msg)
            name_m = _RE_AA_NAME.search(msg)
            detail = cap_m.group(1) if cap_m else (name_m.group(1) if name_m else "")
            pid_m  = _RE_PID.search(msg)
            pid    = pid_m.group(1) if pid_m else ""
            rows_aa.append((dt, action, op, profile, comm, detail, pid, raw))
            continue

        # ── 시스템 재부팅 (커널 버전 메시지) ────────────
        m = _RE_BOOT.search(msg)
        if m:
            rows_boot.append((dt, m.group(1), raw))

    return {"apparmor": rows_aa, "boot": rows_boot}


# ── 저장 ──────────────────────────────────────────────
def insert_all(conn: sqlite3.Connection, result: dict):
    if result.get("apparmor"):
        conn.executemany(f"""
        INSERT INTO {TABLE_APPARMOR}
            (date_time, action, operation, profile, comm, detail, pid, raw_line)
        VALUES (?,?,?,?,?,?,?,?)
        """, result["apparmor"])

    if result.get("boot"):
        conn.executemany(f"""
        INSERT INTO {TABLE_BOOT} (date_time, kernel_ver, raw_line)
        VALUES (?,?,?)
        """, result["boot"])

    conn.commit()
