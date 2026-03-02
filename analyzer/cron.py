"""
analyzer/cron.py - cron 이벤트 분석기

parser.db 의 audit 테이블에서 cron 관련 이벤트를 필터링하여
analysis.db 에 아래 테이블로 저장합니다.

  cron_sessions : ses 단위로 그루핑한 cron 작업 실행 요약
                  (사용자, 시작/종료 시각, 실행 명령어, 성공 여부)

cron 판별 기준:
  - type = 'CRON'
  - comm / unit / exe 에 'cron' 포함
"""

import json
import sqlite3

from datetime import datetime

SRC_TABLE     = "audit"
TABLE_SESSION = "cron_sessions"
TABLES        = [TABLE_SESSION]


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_SESSION} (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ses          TEXT NOT NULL,
        auid         TEXT NOT NULL,
        uid          TEXT NOT NULL,
        acct         TEXT NOT NULL,
        start_time   TEXT NOT NULL,
        end_time     TEXT NOT NULL,
        duration_sec REAL,
        commands     TEXT NOT NULL,
        result       TEXT NOT NULL,
        event_count  INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_cron_ses   ON {TABLE_SESSION}(ses)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_cron_start ON {TABLE_SESSION}(start_time)")
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
    if results.get("session"):
        conn.executemany(f"""
        INSERT INTO {TABLE_SESSION}
            (ses, auid, uid, acct, start_time, end_time, duration_sec, commands, result, event_count)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """, results["session"])
    conn.commit()


# ── 분석 로직 ─────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    return {"session": _analyze_sessions(src_conn)}


def _analyze_sessions(src_conn: sqlite3.Connection) -> list[tuple]:
    rows = src_conn.execute(f"""
        SELECT ses, auid, uid, acct, date_time, cmd, body_res, msg_res
        FROM   {SRC_TABLE}
        WHERE  type = 'CRON'
           OR  lower(comm) LIKE '%cron%'
           OR  lower(unit) LIKE '%cron%'
           OR  lower(exe)  LIKE '%cron%'
        ORDER  BY ses, date_time
    """).fetchall()

    sessions: dict = {}
    for ses, auid, uid, acct, dt, cmd, body_res, msg_res in rows:
        if not ses:
            continue
        if ses not in sessions:
            sessions[ses] = dict(
                ses=ses, auid=auid or "", uid=uid or "", acct=acct or "",
                start_time=dt, end_time=dt, commands=[], results=[], count=0,
            )
        s = sessions[ses]
        if dt and dt < s["start_time"]:
            s["start_time"] = dt
        if dt and dt > s["end_time"]:
            s["end_time"] = dt
        if cmd:
            s["commands"].append(cmd)
        res = (msg_res or body_res or "").strip("\"'")
        if res:
            s["results"].append(res)
        if acct and not s["acct"]:
            s["acct"] = acct
        s["count"] += 1

    result_rows = []
    for s in sessions.values():
        try:
            fmt = "%Y-%m-%d %H:%M:%S.%f"
            dur = (
                datetime.strptime(s["end_time"], fmt)
                - datetime.strptime(s["start_time"], fmt)
            ).total_seconds()
        except Exception:
            dur = None

        results = s["results"]
        if "success" in results:
            overall = "success"
        elif "failed" in results:
            overall = "failed"
        else:
            overall = ""

        seen: set = set()
        cmds = [c for c in s["commands"] if c and not (c in seen or seen.add(c))]

        result_rows.append((
            s["ses"], s["auid"], s["uid"], s["acct"],
            s["start_time"], s["end_time"], dur,
            json.dumps(cmds, ensure_ascii=False),
            overall, s["count"],
        ))

    return result_rows
