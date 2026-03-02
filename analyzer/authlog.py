"""
analyzer/authlog.py - auth.log 분석기

parser.db 의 authlog 테이블을 읽어 IP/사용자 중심으로 집계하고
analysis.db 에 아래 테이블로 저장합니다.

  authlog_login      : 로그인 성공 IP+사용자+인증방식별 집계
  authlog_sudo       : sudo 명령 실행 사용자+명령별 집계
  authlog_attack_ip  : 접근 시도 IP 전체 집계 (성공/실패 횟수 포함)
  authlog_su         : su 계정 전환 집계
"""

import sqlite3

SRC_TABLE         = "authlog"
TABLE_LOGIN       = "authlog_login"
TABLE_SUDO        = "authlog_sudo"
TABLE_ATTACK_IP   = "authlog_attack_ip"
TABLE_SU          = "authlog_su"

TABLES = [TABLE_LOGIN, TABLE_SUDO, TABLE_ATTACK_IP, TABLE_SU]


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    # 로그인 성공
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_LOGIN} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip      TEXT NOT NULL,
        user        TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_login_ip   ON {TABLE_LOGIN}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_login_user ON {TABLE_LOGIN}(user)")

    # sudo 실행
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_SUDO} (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user       TEXT NOT NULL,
        command    TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen  TEXT NOT NULL,
        count      INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_sudo_user ON {TABLE_SUDO}(user)")

    # 접근 시도 IP 전체 (실패 포함, 성공한 IP만 의미있게 식별하기 위함)
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_ATTACK_IP} (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip        TEXT NOT NULL UNIQUE,
        first_seen    TEXT NOT NULL,
        last_seen     TEXT NOT NULL,
        total_count   INTEGER NOT NULL,
        success_count INTEGER NOT NULL,
        fail_count    INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_attack_ip ON {TABLE_ATTACK_IP}(src_ip)")

    # su 계정 전환
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_SU} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user   TEXT NOT NULL,
        to_user     TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_su_from ON {TABLE_SU}(from_user)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_su_to   ON {TABLE_SU}(to_user)")

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
        INSERT INTO {TABLE_LOGIN} (src_ip, user, auth_method, first_seen, last_seen, count)
        VALUES (?,?,?,?,?,?)
        """, results["login"])

    if results.get("sudo"):
        conn.executemany(f"""
        INSERT INTO {TABLE_SUDO} (user, command, first_seen, last_seen, count)
        VALUES (?,?,?,?,?)
        """, results["sudo"])

    if results.get("attack_ip"):
        conn.executemany(f"""
        INSERT INTO {TABLE_ATTACK_IP} (src_ip, first_seen, last_seen, total_count, success_count, fail_count)
        VALUES (?,?,?,?,?,?)
        """, results["attack_ip"])

    if results.get("su"):
        conn.executemany(f"""
        INSERT INTO {TABLE_SU} (from_user, to_user, first_seen, last_seen, count)
        VALUES (?,?,?,?,?)
        """, results["su"])

    conn.commit()


# ── 분석 로직 ─────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    return {
        "login":     _analyze_login(src_conn),
        "sudo":      _analyze_sudo(src_conn),
        "attack_ip": _analyze_attack_ip(src_conn),
        "su":        _analyze_su(src_conn),
    }


def _analyze_login(src_conn: sqlite3.Connection) -> list[tuple]:
    """로그인 성공 IP+사용자+인증방식 조합별 집계"""
    return src_conn.execute(f"""
        SELECT
            src_ip,
            user,
            CASE WHEN event_type = 'sshd_accepted_publickey' THEN 'publickey' ELSE 'password' END,
            MIN(date_time),
            MAX(date_time),
            COUNT(*) AS count
        FROM {SRC_TABLE}
        WHERE event_type IN ('sshd_accepted_password', 'sshd_accepted_publickey')
          AND src_ip != ''
        GROUP BY src_ip, user, event_type
        ORDER BY count DESC, MIN(date_time)
    """).fetchall()


def _analyze_sudo(src_conn: sqlite3.Connection) -> list[tuple]:
    """sudo 실행 사용자+명령 조합별 집계"""
    return src_conn.execute(f"""
        SELECT
            user,
            detail,
            MIN(date_time),
            MAX(date_time),
            COUNT(*) AS count
        FROM {SRC_TABLE}
        WHERE event_type = 'sudo_command'
          AND user != ''
        GROUP BY user, detail
        ORDER BY user, count DESC
    """).fetchall()


def _analyze_attack_ip(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    접근 시도 IP별 성공/실패 집계
    → 성공 이력이 없는 IP도 포함 (전체 공격 현황 파악용)
    """
    success_events = "('sshd_accepted_password', 'sshd_accepted_publickey')"
    fail_events    = "('sshd_failed_password', 'sshd_invalid_user', 'sshd_conn_closed', 'sshd_conn_reset', 'sshd_max_auth')"

    return src_conn.execute(f"""
        SELECT
            src_ip,
            MIN(date_time)                                          AS first_seen,
            MAX(date_time)                                          AS last_seen,
            COUNT(*)                                                AS total_count,
            SUM(CASE WHEN event_type IN {success_events} THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN event_type IN {fail_events}    THEN 1 ELSE 0 END) AS fail_count
        FROM {SRC_TABLE}
        WHERE src_ip != ''
        GROUP BY src_ip
        ORDER BY total_count DESC
    """).fetchall()


def _analyze_su(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    su 계정 전환 집계
    event_type='su_to': user=from_user, detail=to_user
    """
    return src_conn.execute(f"""
        SELECT
            user        AS from_user,
            detail      AS to_user,
            MIN(date_time),
            MAX(date_time),
            COUNT(*) AS count
        FROM {SRC_TABLE}
        WHERE event_type = 'su_to'
          AND user  != ''
          AND detail != ''
        GROUP BY user, detail
        ORDER BY count DESC
    """).fetchall()
