"""
analyzer/loginfo.py - 파싱된 로그 요약 정보

parser.db 의 각 로그 테이블과 info 테이블을 읽어
analysis.db :: log 테이블에 아래 컬럼으로 저장합니다.

  log_name       : 로그 종류 (authlog / audit / nginx)
  first_record   : 로그 첫 기록 일자
  last_record    : 마지막 로그 기록 일자
  total_records  : 총 레코드 수
  file_count     : 파싱된 파일 수 (parser.db info 테이블 기준)
  analyzed_at    : 분석 실행 시각
"""

import sqlite3
from datetime import datetime

TABLE = "log"

# parser.db 에서 date_time 컬럼을 가진 로그 테이블 목록
_LOG_TABLES = [
    ("authlog",     "authlog"),
    ("audit",       "audit"),
    ("nginx",       "nginx"),
    ("syslog",      "syslog"),
    ("apache2",     "apache2"),
    ("mysql_query", "mysql_query"),
    ("mysql_error", "mysql_error"),
    ("kernlog",     "kernlog"),
]


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        log_name      TEXT NOT NULL UNIQUE,
        first_record  TEXT,
        last_record   TEXT,
        total_records INTEGER NOT NULL DEFAULT 0,
        file_count    INTEGER NOT NULL DEFAULT 0,
        analyzed_at   TEXT NOT NULL
    )
    """)
    conn.commit()


# ── 분석 + 저장 ───────────────────────────────────────
def run(dest_conn: sqlite3.Connection, src_conn: sqlite3.Connection):
    ensure_db(dest_conn)

    analyzed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []

    for log_name, table_name in _LOG_TABLES:
        # 해당 테이블이 parser.db 에 존재하는지 확인
        cur = src_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        )
        if not cur.fetchone():
            continue

        # 첫/마지막 기록 일자 + 총 레코드 수
        # MIN/MAX 에서 빈 문자열(파싱 실패 행)을 제외하기 위해 CASE WHEN 사용
        # (SQLite 는 '' 이 모든 날짜 문자열보다 앞에 정렬되므로 MIN 이 '' 반환됨)
        row = src_conn.execute(f"""
            SELECT
                MIN(CASE WHEN date_time != '' THEN date_time END),
                MAX(CASE WHEN date_time != '' THEN date_time END),
                COUNT(*)
            FROM {table_name}
        """).fetchone()

        first_record  = row[0] or ""
        last_record   = row[1] or ""
        total_records = row[2] or 0

        # 파싱된 파일 수 (info 테이블)
        info_cur = src_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='info'"
        )
        if info_cur.fetchone():
            fc = src_conn.execute(
                "SELECT COUNT(*) FROM info WHERE log_type = ?", (log_name,)
            ).fetchone()
            file_count = fc[0] if fc else 0
        else:
            file_count = 0

        rows.append((
            log_name, first_record, last_record,
            total_records, file_count, analyzed_at,
        ))

    if rows:
        dest_conn.executemany(f"""
        INSERT INTO {TABLE} (log_name, first_record, last_record,
                             total_records, file_count, analyzed_at)
        VALUES (?,?,?,?,?,?)
        """, rows)
        dest_conn.commit()

    print(f"[LOG] 로그 요약 저장 완료 ({len(rows)}건)")
    for r in rows:
        print(f"  {r[0]:<10}  {r[1] or 'N/A':>19} ~ {r[2] or 'N/A':<19}"
              f"  {r[3]:>8,}건  파일 {r[4]}개")
