"""
analyzer/authlog.py - auth.log 분석기

parser.db 의 authlog 테이블을 읽어 IP/사용자 중심으로 집계하고
analysis.db 에 아래 테이블로 저장합니다.

  authlog_login      : 로그인 성공 IP+사용자+인증방식별 집계
  authlog_sudo       : sudo 명령 실행 사용자+명령별 집계
  authlog_attack_ip  : 접근 시도 IP 전체 집계 (성공/실패 횟수 포함)
  authlog_su         : su 계정 전환 집계
  authlog_bruteforce : SSH 무차별 대입 공격 IP별 집계
"""

import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

SRC_TABLE          = "authlog"
TABLE_LOGIN        = "authlog_login"
TABLE_SUDO         = "authlog_sudo"
TABLE_ATTACK_IP    = "authlog_attack_ip"
TABLE_SU           = "authlog_su"
TABLE_BRUTEFORCE   = "authlog_bruteforce"

TABLES = [TABLE_LOGIN, TABLE_SUDO, TABLE_ATTACK_IP, TABLE_SU, TABLE_BRUTEFORCE]


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

    # SSH 무차별 대입 공격 (brute force) — burst(60s/10회) 단위 저장
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_BRUTEFORCE} (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip         TEXT NOT NULL,
        burst_start    TEXT NOT NULL,
        burst_end      TEXT NOT NULL,
        attempt_count  INTEGER NOT NULL,
        success_count  INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_bf_ip ON {TABLE_BRUTEFORCE}(src_ip)")

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

    if results.get("bruteforce"):
        conn.executemany(f"""
        INSERT INTO {TABLE_BRUTEFORCE} (src_ip, burst_start, burst_end, attempt_count, success_count)
        VALUES (?,?,?,?,?)
        """, results["bruteforce"])

    conn.commit()


# ── 분석 로직 ─────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    return {
        "login":      _analyze_login(src_conn),
        "sudo":       _analyze_sudo(src_conn),
        "attack_ip":  _analyze_attack_ip(src_conn),
        "su":         _analyze_su(src_conn),
        "bruteforce": _analyze_bruteforce(src_conn),
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


_BURST_WINDOW        = timedelta(seconds=60)  # 슬라이딩 윈도우 크기
_BURST_THRESHOLD     = 10                      # burst 판단 최소 시도 횟수
_SUSTAINED_FAIL_MIN  = 50                      # sustained 판단 최소 실패 횟수
_SUSTAINED_FAIL_RATIO = 10                     # 실패가 성공의 N배 이상이어야 함


def _analyze_bruteforce(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    SSH 브루트포스 탐지 — 두 가지 기준:
      1) Burst   : 60초 이내 10회 이상 실패 (burst당 1행)
      2) Sustained: 누적 실패 50회 이상 & 실패:성공 비율 10:1 이상 (IP당 1행)
         → burst로 이미 탐지된 IP는 sustained 에서 제외 (중복 방지)
    Returns: [(src_ip, burst_start, burst_end, attempt_count, success_count), ...]
    """
    fmt = "%Y-%m-%d %H:%M:%S"
    fail_events    = "('sshd_failed_password', 'sshd_invalid_user')"
    success_events = "('sshd_accepted_password', 'sshd_accepted_publickey')"

    # IP별 실패 타임스탬프 수집
    ts_by_ip: dict[str, list[datetime]] = defaultdict(list)
    for src_ip, dt_str in src_conn.execute(f"""
        SELECT src_ip, date_time
        FROM {SRC_TABLE}
        WHERE event_type IN {fail_events}
          AND src_ip != ''
        ORDER BY src_ip, date_time
    """).fetchall():
        try:
            ts_by_ip[src_ip].append(datetime.strptime(dt_str, fmt))
        except ValueError:
            pass

    # IP별 로그인 성공 횟수
    success_cnt: dict[str, int] = {
        ip: cnt for ip, cnt in src_conn.execute(f"""
            SELECT src_ip, COUNT(*)
            FROM {SRC_TABLE}
            WHERE event_type IN {success_events} AND src_ip != ''
            GROUP BY src_ip
        """).fetchall()
    }

    # ── 1) Burst 탐지: 슬라이딩 윈도우 ───────────────────
    bursts: list[tuple] = []
    for ip, timestamps in ts_by_ip.items():
        timestamps.sort()
        i = 0
        while i < len(timestamps):
            win_end = timestamps[i] + _BURST_WINDOW
            j = i + 1
            while j < len(timestamps) and timestamps[j] <= win_end:
                j += 1
            count = j - i
            if count >= _BURST_THRESHOLD:
                bursts.append((
                    ip,
                    timestamps[i].strftime(fmt),      # burst_start
                    timestamps[j - 1].strftime(fmt),  # burst_end
                    count,
                    success_cnt.get(ip, 0),
                ))
                i = j
            else:
                i += 1

    burst_ips = {b[0] for b in bursts}   # burst로 이미 탐지된 IP 집합

    # ── 2) Sustained 탐지: 누적 실패 비율 ────────────────
    for ip, timestamps in ts_by_ip.items():
        if ip in burst_ips:
            continue                       # burst 이미 탐지됨 → 건너뜀
        fail_count = len(timestamps)
        if fail_count < _SUSTAINED_FAIL_MIN:
            continue
        succ_count = success_cnt.get(ip, 0)
        if fail_count < _SUSTAINED_FAIL_RATIO * (succ_count + 1):
            continue
        # 누적 범위 전체를 하나의 행으로
        bursts.append((
            ip,
            timestamps[0].strftime(fmt),   # 첫 실패
            timestamps[-1].strftime(fmt),  # 마지막 실패
            fail_count,
            succ_count,
        ))

    bursts.sort(key=lambda r: r[1])   # burst_start 기준 시간순 정렬
    return bursts
