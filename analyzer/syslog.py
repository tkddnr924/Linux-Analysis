"""
analyzer/syslog.py - syslog 분석기

parser.db 의 syslog 테이블을 읽어 아래 테이블로 저장합니다.

  syslog_cron    : CRON 실행 명령어 (시간 | 계정 | 명령어 | 실행 횟수)
  syslog_ufw     : UFW 방화벽 차단 로그 (SRC IP | DST 포트 | 프로토콜 | 횟수 등)
  syslog_service : systemd 서비스 상태 변화 (시작/실패/중지)
"""

import re
import sqlite3

SRC_TABLE        = "syslog"
TABLE_CRON       = "syslog_cron"
TABLE_UFW        = "syslog_ufw"
TABLE_SERVICE    = "syslog_service"

TABLES = [TABLE_CRON, TABLE_UFW, TABLE_SERVICE]


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    # CRON 실행 명령어
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_CRON} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        account     TEXT NOT NULL,
        command     TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_cron_acct ON {TABLE_CRON}(account)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_cron_cmd  ON {TABLE_CRON}(command)")

    # UFW 차단 로그
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_UFW} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip      TEXT NOT NULL,
        dst_port    TEXT NOT NULL,
        proto       TEXT NOT NULL,
        in_iface    TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        count       INTEGER NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_ufw_src  ON {TABLE_UFW}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_ufw_port ON {TABLE_UFW}(dst_port)")

    # systemd 서비스 상태 변화
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_SERVICE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT NOT NULL,
        service     TEXT NOT NULL,
        state       TEXT NOT NULL,
        detail      TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_svc_dt  ON {TABLE_SERVICE}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_svc_svc ON {TABLE_SERVICE}(service)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_svc_st  ON {TABLE_SERVICE}(state)")

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
    if results.get("cron"):
        conn.executemany(f"""
        INSERT INTO {TABLE_CRON} (account, command, first_seen, last_seen, count)
        VALUES (?,?,?,?,?)
        """, results["cron"])

    if results.get("ufw"):
        conn.executemany(f"""
        INSERT INTO {TABLE_UFW} (src_ip, dst_port, proto, in_iface, first_seen, last_seen, count)
        VALUES (?,?,?,?,?,?,?)
        """, results["ufw"])

    if results.get("service"):
        conn.executemany(f"""
        INSERT INTO {TABLE_SERVICE} (date_time, service, state, detail)
        VALUES (?,?,?,?)
        """, results["service"])

    conn.commit()


# ── 분석 로직 ─────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    return {
        "cron":    _analyze_cron(src_conn),
        "ufw":     _analyze_ufw(src_conn),
        "service": _analyze_service(src_conn),
    }


# ── CRON CMD ──────────────────────────────────────────
# "(root) CMD (certbot -q renew)" 형식
_RE_CRON_CMD = re.compile(r'^\((\S+)\)\s+CMD\s+\((.+)\)\s*$')


def _analyze_cron(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    CRON CMD 메시지에서 계정 + 명령어 추출 후 집계.
    계정 + 명령어 조합별로 최초/마지막 실행 시각, 실행 횟수.
    """
    rows = src_conn.execute(f"""
        SELECT date_time, message FROM {SRC_TABLE}
        WHERE service = 'CRON'
          AND message LIKE '%(%)%CMD%'
          AND date_time != ''
        ORDER BY date_time
    """).fetchall()

    # (account, command) → [min_dt, max_dt, count]
    agg: dict[tuple, list] = {}
    for dt, msg in rows:
        m = _RE_CRON_CMD.match(msg.strip())
        if not m:
            continue
        account = m.group(1)
        command = m.group(2).strip()
        key = (account, command)
        if key not in agg:
            agg[key] = [dt, dt, 0]
        else:
            if dt < agg[key][0]:
                agg[key][0] = dt
            if dt > agg[key][1]:
                agg[key][1] = dt
        agg[key][2] += 1

    return [
        (acct, cmd, v[0], v[1], v[2])
        for (acct, cmd), v in sorted(agg.items(), key=lambda x: -x[1][2])
    ]


# ── UFW BLOCK ─────────────────────────────────────────
# [UFW BLOCK] IN=enp3s0 OUT= MAC=... SRC=x.x.x.x DST=y.y.y.y ... DPT=22 PROTO=TCP
_RE_UFW = re.compile(
    r'\[UFW BLOCK\].*?IN=(\S+).*?SRC=([\d.]+).*?DST=([\d.]+).*?PROTO=(\w+)',
    re.DOTALL
)
_RE_DPT = re.compile(r'DPT=(\d+)')
_RE_SPT = re.compile(r'SPT=(\d+)')


def _analyze_ufw(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    UFW BLOCK 이벤트를 SRC IP + DST 포트 + 프로토콜 조합으로 집계.
    포트 정보가 없는 경우(ICMP 등) DST 포트는 빈값으로 처리.
    """
    rows = src_conn.execute(f"""
        SELECT date_time, message FROM {SRC_TABLE}
        WHERE service = 'kernel'
          AND message LIKE '%[UFW BLOCK]%'
          AND date_time != ''
        ORDER BY date_time
    """).fetchall()

    # (src_ip, dst_port, proto, in_iface) → [min_dt, max_dt, count]
    agg: dict[tuple, list] = {}
    for dt, msg in rows:
        m = _RE_UFW.search(msg)
        if not m:
            continue
        in_iface = m.group(1)
        src_ip   = m.group(2)
        proto    = m.group(4).upper()

        dpt_m = _RE_DPT.search(msg)
        dst_port = dpt_m.group(1) if dpt_m else ""

        key = (src_ip, dst_port, proto, in_iface)
        if key not in agg:
            agg[key] = [dt, dt, 0]
        else:
            if dt < agg[key][0]:
                agg[key][0] = dt
            if dt > agg[key][1]:
                agg[key][1] = dt
        agg[key][2] += 1

    return [
        (src, port, proto, iface, v[0], v[1], v[2])
        for (src, port, proto, iface), v in sorted(agg.items(), key=lambda x: -x[1][2])
    ]


# ── systemd 서비스 상태 변화 ───────────────────────────
# "Started foo.service - Description."
# "foo.service: Failed with result 'exit-code'."
# "foo.service: Deactivated successfully."
# "Stopped foo.service - Description."
# "Starting foo.service - Description..."

_SVC_PATTERNS = [
    # (regex, state)
    (re.compile(r'^Started\s+(\S+\.service)'),           "started"),
    (re.compile(r'^Starting\s+(\S+\.service)'),          "starting"),
    (re.compile(r'^Stopped\s+(\S+\.service)'),           "stopped"),
    (re.compile(r'^Stopping\s+(\S+\.service)'),          "stopping"),
    (re.compile(r'^Failed to start\s+(\S+\.service)'),   "failed"),
    (re.compile(r'^(\S+\.service):\s+Failed'),            "failed"),
    (re.compile(r'^(\S+\.service):\s+Deactivated'),      "stopped"),
    (re.compile(r'^(\S+\.service):\s+Scheduled restart'), "restarting"),
]


def _analyze_service(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    systemd 서비스 상태 변화 이벤트 추출.
    Starting/Started/Stopped/Failed/Restarting 상태를 시계열로 저장.
    """
    rows = src_conn.execute(f"""
        SELECT date_time, message FROM {SRC_TABLE}
        WHERE service = 'systemd'
          AND date_time != ''
          AND (
            message LIKE 'Start%' OR
            message LIKE 'Stop%'  OR
            message LIKE 'Failed%' OR
            message LIKE '%.service:%'
          )
        ORDER BY date_time
    """).fetchall()

    result = []
    for dt, msg in rows:
        msg = msg.strip()
        for rx, state in _SVC_PATTERNS:
            m = rx.search(msg)
            if m:
                service = m.group(1)
                # detail: 상태 설명 (실패 원인 등)
                detail = msg[m.end():].strip().lstrip("-: ").strip()
                result.append((dt, service, state, detail[:200]))
                break

    return result
