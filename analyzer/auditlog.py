"""
analyzer/auditlog.py - audit.log 분석기

parser.db 의 audit 테이블을 읽어 집계하고
analysis.db 에 아래 테이블로 저장합니다.

  audit_login  : 인증/로그인 이벤트 (USER_LOGIN, USER_AUTH, USER_ACCT 등)
                 IP + 계정 + 결과별 집계
  audit_cmd    : 명령 실행 이력 (EXECVE 타입)
                 uid + cmd + cwd 별 집계
  audit_file   : 파일 접근 이력 (PATH 타입)
                 exe + 파일경로 별 집계
"""

import sqlite3

SRC_TABLE      = "audit"
TABLE_LOGIN    = "audit_login"
TABLE_CMD      = "audit_cmd"
TABLE_FILE     = "audit_file"

TABLES = [TABLE_LOGIN, TABLE_CMD, TABLE_FILE]

# 인증 관련 audit 타입
LOGIN_TYPES = (
    "'USER_LOGIN'", "'USER_AUTH'", "'USER_ACCT'",
    "'USER_START'", "'USER_END'", "'USER_ERR'",
    "'CRED_ACQ'", "'CRED_DISP'",
)


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    # 인증/로그인 이벤트
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_LOGIN} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        type        TEXT NOT NULL,
        acct        TEXT NOT NULL,
        hostname    TEXT NOT NULL,
        addr        TEXT NOT NULL,
        terminal    TEXT NOT NULL,
        res         TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_login_addr ON {TABLE_LOGIN}(addr)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_login_acct ON {TABLE_LOGIN}(acct)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_login_res  ON {TABLE_LOGIN}(res)")

    # 명령 실행 이력
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_CMD} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        uid         TEXT NOT NULL,
        auid        TEXT NOT NULL,
        cmd         TEXT NOT NULL,
        cwd         TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_cmd_uid  ON {TABLE_CMD}(uid)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_cmd_auid ON {TABLE_CMD}(auid)")

    # 파일 접근 이력
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_FILE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        uid         TEXT NOT NULL,
        exe         TEXT NOT NULL,
        cwd         TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_file_uid ON {TABLE_FILE}(uid)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_file_exe ON {TABLE_FILE}(exe)")

    conn.commit()


def table_has_data(conn: sqlite3.Connection) -> bool:
    for table in TABLES:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        if not cur.fetchone():
            continue
        if conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
            return True
    return False


def insert_all(conn: sqlite3.Connection, results: dict):
    if results.get("login"):
        conn.executemany(f"""
        INSERT INTO {TABLE_LOGIN}
            (type, acct, hostname, addr, terminal, res, first_seen, last_seen, count)
        VALUES (?,?,?,?,?,?,?,?,?)
        """, results["login"])

    if results.get("cmd"):
        conn.executemany(f"""
        INSERT INTO {TABLE_CMD}
            (uid, auid, cmd, cwd, first_seen, last_seen, count)
        VALUES (?,?,?,?,?,?,?)
        """, results["cmd"])

    if results.get("file"):
        conn.executemany(f"""
        INSERT INTO {TABLE_FILE}
            (uid, exe, cwd, first_seen, last_seen, count)
        VALUES (?,?,?,?,?,?)
        """, results["file"])

    conn.commit()


# ── 분석 로직 ─────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    return {
        "login": _analyze_login(src_conn),
        "cmd":   _analyze_cmd(src_conn),
        "file":  _analyze_file(src_conn),
    }


def _analyze_login(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    인증/로그인 이벤트를 type + acct + addr + res 조합별 집계
    실패(res != 'success') 도 포함하여 전체 인증 현황 파악
    """
    types = ", ".join(LOGIN_TYPES)
    return src_conn.execute(f"""
        SELECT
            type,
            acct,
            hostname,
            addr,
            terminal,
            msg_res         AS res,
            MIN(date_time)  AS first_seen,
            MAX(date_time)  AS last_seen,
            COUNT(*)        AS count
        FROM {SRC_TABLE}
        WHERE type IN ({types})
          AND acct != ''
        GROUP BY type, acct, hostname, addr, terminal, msg_res
        ORDER BY count DESC, first_seen
    """).fetchall()


def _analyze_cmd(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    EXECVE 타입 - 실제 실행된 명령어 집계
    uid + auid + cmd + cwd 조합별
    """
    return src_conn.execute(f"""
        SELECT
            uid,
            auid,
            cmd,
            cwd,
            MIN(date_time)  AS first_seen,
            MAX(date_time)  AS last_seen,
            COUNT(*)        AS count
        FROM {SRC_TABLE}
        WHERE type = 'EXECVE'
          AND cmd != ''
        GROUP BY uid, auid, cmd, cwd
        ORDER BY count DESC, first_seen
    """).fetchall()


def _analyze_file(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    PATH 타입 - 파일 접근 이력
    uid + exe + cwd 조합별 집계
    (exe: 접근을 일으킨 실행 파일, cwd: 작업 디렉토리)
    """
    return src_conn.execute(f"""
        SELECT
            uid,
            exe,
            cwd,
            MIN(date_time)  AS first_seen,
            MAX(date_time)  AS last_seen,
            COUNT(*)        AS count
        FROM {SRC_TABLE}
        WHERE type = 'PATH'
          AND exe != ''
        GROUP BY uid, exe, cwd
        ORDER BY count DESC, first_seen
    """).fetchall()
