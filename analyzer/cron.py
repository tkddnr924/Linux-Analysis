"""
analyzer/cron.py - cron 이벤트 분석기

parser.db 의 audit 테이블에서 cron 관련 이벤트를 분석하여
analysis.db 에 아래 테이블로 저장합니다.

  cron_info : 프로세스 단위로 집계한 cron 실행 통계

  process          | 실행된 프로세스/커맨드명 (EXECVE cmd 우선, 없으면 comm/exe)
  user             | 실행 사용자 (uid)
  first_seen       | 최초 실행 시각
  last_seen        | 마지막 실행 시각
  exec_count       | 실행 횟수
  avg_duration_sec | 평균 실행 소요시간(초)  - 이상 실행 감지에 활용
  total_duration_sec | 총 실행 소요시간(초) - 리소스 점유 분석에 활용

프로세스명 결정 우선순위:
  1. 동일 ses 의 EXECVE 레코드 cmd 필드
  2. CRON 레코드의 comm 필드 (cron/crond 자체 제외)
  3. CRON 레코드의 exe 필드
  4. 'unknown'
"""

import sqlite3

SRC_TABLE  = "audit"
TABLE_INFO = "cron_info"
TABLES     = [TABLE_INFO]


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_INFO} (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        process            TEXT NOT NULL,
        user               TEXT NOT NULL,
        first_seen         TEXT NOT NULL,
        last_seen          TEXT NOT NULL,
        exec_count         INTEGER NOT NULL,
        avg_duration_sec   REAL,
        total_duration_sec REAL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_cron_info_process ON {TABLE_INFO}(process)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_cron_info_user    ON {TABLE_INFO}(user)")
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
    if results.get("info"):
        conn.executemany(f"""
        INSERT INTO {TABLE_INFO}
            (process, user, first_seen, last_seen, exec_count, avg_duration_sec, total_duration_sec)
        VALUES (?,?,?,?,?,?,?)
        """, results["info"])
    conn.commit()


# ── 분석 로직 ─────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    return {"info": _analyze_cron_info(src_conn)}


def _analyze_cron_info(src_conn: sqlite3.Connection) -> list[tuple]:
    return src_conn.execute(f"""
        WITH cron_ses AS (
            -- cron 관련 세션의 시작/종료 시각 집계
            -- ses='4294967295' 는 미설정 세션으로 제외
            SELECT
                ses,
                uid,
                MIN(date_time) AS start_time,
                MAX(date_time) AS end_time
            FROM {SRC_TABLE}
            WHERE (type = 'CRON'
               OR  lower(comm) LIKE '%cron%'
               OR  lower(unit) LIKE '%cron%')
              AND ses NOT IN ('', '4294967295')
            GROUP BY ses, uid
        ),
        execve_first AS (
            -- 세션별 EXECVE cmd: 첫 번째 값만 사용 (fan-out 방지)
            SELECT ses, MIN(cmd) AS cmd
            FROM {SRC_TABLE}
            WHERE type = 'EXECVE' AND cmd != ''
              AND ses IN (SELECT ses FROM cron_ses)
            GROUP BY ses
        ),
        cron_fallback AS (
            -- EXECVE 없는 세션의 comm/exe 폴백
            SELECT ses,
                   MIN(CASE
                       WHEN comm NOT IN ('', 'cron', 'crond') THEN comm
                       WHEN exe  != ''                        THEN exe
                       ELSE 'unknown'
                   END) AS process
            FROM {SRC_TABLE}
            WHERE (type = 'CRON' OR lower(comm) LIKE '%cron%')
              AND ses IN (SELECT ses FROM cron_ses)
            GROUP BY ses
        ),
        ses_process AS (
            -- 세션별 최종 프로세스명 결정
            SELECT
                cs.ses,
                cs.uid,
                COALESCE(NULLIF(ef.cmd, ''), cf.process, 'unknown') AS process
            FROM cron_ses cs
            LEFT JOIN execve_first  ef ON cs.ses = ef.ses
            LEFT JOIN cron_fallback cf ON cs.ses = cf.ses
        )
        SELECT
            sp.process,
            sp.uid                                                              AS user,
            MIN(cs.start_time)                                                  AS first_seen,
            MAX(cs.start_time)                                                  AS last_seen,
            COUNT(DISTINCT cs.ses)                                              AS exec_count,
            AVG((julianday(cs.end_time) - julianday(cs.start_time)) * 86400)   AS avg_duration_sec,
            SUM((julianday(cs.end_time) - julianday(cs.start_time)) * 86400)   AS total_duration_sec
        FROM cron_ses cs
        JOIN ses_process sp ON cs.ses = sp.ses
        GROUP BY sp.process, sp.uid
        ORDER BY exec_count DESC, first_seen
    """).fetchall()
