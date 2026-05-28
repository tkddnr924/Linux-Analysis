"""
analyzer/dashboard.py - 대시보드 페이로드 사전 계산

파싱이 끝난 뒤 호출돼서 각 테이블의 대시보드용 집계를
`dashboard` 테이블에 JSON 으로 저장한다. 뷰어는 SELECT 한 번으로
즉시 표시 → 큰 테이블에서도 클릭 시 렉 없음.

저장 스키마:
    dashboard(table_name PK, payload TEXT, computed_at TEXT)

각 페이로드 JSON 의 형태는 기존 gui/main.js 핸들러
(getAuditDashboard / getAuthlogDashboard / getSyslogDashboard /
 getApache2Dashboard / getGenericDashboard) 의 리턴값과 **완전히 동일**
하도록 맞췄다 — 뷰어 렌더 함수는 그대로 재사용.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime


TABLE = "dashboard"

# 공통(자동) 대시보드 — 전용 핸들러가 없는 테이블용
GENERIC_KEY_COLS: list[str] = [
    "status", "level", "severity", "event_type", "type", "service", "facility", "unit",
    "src_ip", "client_ip", "addr", "ip", "user", "acct", "username", "method", "vhost",
    "exe", "comm", "command", "terminal", "tty", "hostname", "log_type", "pid",
]
GENERIC_SKIP_COLS: set[str] = {
    "id", "raw_line", "message", "msg", "uri", "referer", "user_agent", "cmdline", "args", "line",
}
GENERIC_SCAN_LIMIT = 2_000_000  # 비인덱스 풀스캔 회피용 상한


# ── 헬퍼 ────────────────────────────────────────────────

def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE} (
            table_name  TEXT PRIMARY KEY,
            payload     TEXT NOT NULL,
            computed_at TEXT NOT NULL
        )
    """)
    conn.commit()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return r is not None


def _cols(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]


def _indexed_cols(conn: sqlite3.Connection, table: str) -> set[str]:
    out: set[str] = set()
    try:
        for ix in conn.execute(f'PRAGMA index_list("{table}")').fetchall():
            for ic in conn.execute(f'PRAGMA index_info("{ix[1]}")').fetchall():
                if ic[2]:
                    out.add(ic[2])
    except sqlite3.OperationalError:
        pass
    return out


def _safe_get(conn, sql, params=()):
    try:    return conn.execute(sql, params).fetchone()
    except sqlite3.OperationalError: return None


def _safe_all(conn, sql, params=()):
    try:    return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError: return []


def _to_dicts(rows, keys) -> list[dict]:
    return [dict(zip(keys, r)) for r in rows]


# ── 전용 대시보드 ───────────────────────────────────────

def compute_audit(conn: sqlite3.Connection) -> dict | None:
    """gui/main.js :: getAuditDashboard 와 동일 구조"""
    if not _table_exists(conn, "audit"): return None
    g = lambda sql, *a: _safe_get(conn, sql, a)
    a = lambda sql, *args: _safe_all(conn, sql, args)
    cnt = lambda t: (g("SELECT COUNT(*) FROM audit WHERE type=?", t) or [0])[0]

    ov = g("SELECT COUNT(*), MIN(date_time), MAX(date_time), COUNT(DISTINCT type) FROM audit")
    overview = (
        {"total": ov[0], "first_dt": ov[1], "last_dt": ov[2], "type_count": ov[3]}
        if ov else None
    )

    type_dist = _to_dicts(
        a("SELECT type, COUNT(*) FROM audit WHERE type!='' GROUP BY type ORDER BY COUNT(*) DESC LIMIT 20"),
        ("type", "cnt"),
    )

    login_stats = {
        "auth":  cnt("USER_AUTH"),
        "login": cnt("USER_LOGIN"),
        "err":   cnt("USER_ERR"),
        "start": cnt("USER_START"),
        "end":   cnt("USER_END"),
    }

    top_ips = _to_dicts(a("""
        SELECT addr, COUNT(*) FROM audit
        WHERE addr NOT IN ('','?') AND addr NOT GLOB '*:*' AND addr!='0.0.0.0'
          AND type IN ('USER_AUTH','USER_LOGIN','USER_ERR','USER_START')
        GROUP BY addr ORDER BY COUNT(*) DESC LIMIT 5
    """), ("addr", "cnt"))

    top_accts = _to_dicts(a("""
        SELECT acct, COUNT(*) FROM audit
        WHERE acct != '' AND type IN ('USER_AUTH','USER_LOGIN','USER_ERR')
        GROUP BY acct ORDER BY COUNT(*) DESC LIMIT 5
    """), ("acct", "cnt"))

    execve   = cnt("EXECVE")
    user_cmd = cnt("USER_CMD")

    top_exe = _to_dicts(a("""
        SELECT exe, COUNT(*) FROM audit
        WHERE exe NOT IN ('','?') AND type='SYSCALL'
        GROUP BY exe ORDER BY COUNT(*) DESC LIMIT 5
    """), ("exe", "cnt"))

    avc_count    = cnt("AVC")
    fail_count   = (g("SELECT COUNT(*) FROM audit WHERE body_res='failed'") or [0])[0]
    syscall_fail = (g("SELECT COUNT(*) FROM audit WHERE type='SYSCALL' AND body_res='no'") or [0])[0]
    err_ip_row   = g("""SELECT addr FROM audit
                        WHERE addr NOT IN ('','?') AND type='USER_ERR'
                        GROUP BY addr ORDER BY COUNT(*) DESC LIMIT 1""")
    user_err_ip  = err_ip_row[0] if err_ip_row else ""

    all_types = _to_dicts(
        a("SELECT type, COUNT(*) FROM audit WHERE type!='' GROUP BY type ORDER BY COUNT(*) DESC"),
        ("type", "cnt"),
    )

    return {
        "overview":   overview,
        "typeDist":   type_dist,
        "loginStats": login_stats,
        "topIPs":     top_ips,
        "topAccts":   top_accts,
        "execve":     execve, "userCmd": user_cmd,
        "topExe":     top_exe,
        "avcCount":   avc_count, "failCount": fail_count, "syscallFail": syscall_fail,
        "userErrIP":  user_err_ip,
        "allTypes":   all_types,
    }


def compute_authlog(conn: sqlite3.Connection) -> dict | None:
    """gui/main.js :: getAuthlogDashboard 와 동일 구조"""
    if not _table_exists(conn, "authlog"): return None
    g = lambda sql, *a: _safe_get(conn, sql, a)
    a = lambda sql, *args: _safe_all(conn, sql, args)
    cnt = lambda t: (g("SELECT COUNT(*) FROM authlog WHERE event_type=?", t) or [0])[0]

    ov = g("SELECT COUNT(*), MIN(date_time), MAX(date_time), COUNT(DISTINCT event_type) FROM authlog")
    overview = (
        {"total": ov[0], "first_dt": ov[1], "last_dt": ov[2], "type_count": ov[3]}
        if ov else None
    )

    event_dist = _to_dicts(
        a("SELECT event_type, COUNT(*) FROM authlog WHERE event_type!='' GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 20"),
        ("type", "cnt"),
    )

    ssh_stats = {
        "accepted_password":  cnt("sshd_accepted_password"),
        "accepted_publickey": cnt("sshd_accepted_publickey"),
        "failed_password":    cnt("sshd_failed_password"),
        "invalid_user":       cnt("sshd_invalid_user"),
        "max_auth":           cnt("sshd_max_auth"),
        "session_opened":     cnt("sshd_session_opened"),
    }

    top_attack_ips = _to_dicts(a("""
        SELECT src_ip, COUNT(*) FROM authlog
        WHERE src_ip != '' AND event_type IN ('sshd_failed_password','sshd_invalid_user','sshd_max_auth')
        GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5
    """), ("src_ip", "cnt"))

    top_success_ips = _to_dicts(a("""
        SELECT src_ip, COUNT(*) FROM authlog
        WHERE src_ip != '' AND event_type IN ('sshd_accepted_password','sshd_accepted_publickey')
        GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5
    """), ("src_ip", "cnt"))

    top_users = _to_dicts(a("""
        SELECT user, COUNT(*) FROM authlog
        WHERE user != '' AND event_type IN ('sshd_accepted_password','sshd_accepted_publickey')
        GROUP BY user ORDER BY COUNT(*) DESC LIMIT 5
    """), ("user", "cnt"))

    top_fail_users = _to_dicts(a("""
        SELECT user, COUNT(*) FROM authlog
        WHERE user != '' AND event_type IN ('sshd_failed_password','sshd_invalid_user')
        GROUP BY user ORDER BY COUNT(*) DESC LIMIT 5
    """), ("user", "cnt"))

    sudo_count = cnt("sudo_command")
    top_sudo_users = _to_dicts(a("""
        SELECT user, COUNT(*) FROM authlog
        WHERE user != '' AND event_type='sudo_command'
        GROUP BY user ORDER BY COUNT(*) DESC LIMIT 5
    """), ("user", "cnt"))

    su_count = (g("SELECT COUNT(*) FROM authlog WHERE event_type IN ('su_to','su_session_opened')") or [0])[0]

    all_types = _to_dicts(
        a("SELECT event_type, COUNT(*) FROM authlog WHERE event_type!='' GROUP BY event_type ORDER BY COUNT(*) DESC"),
        ("type", "cnt"),
    )

    return {
        "overview":      overview,
        "eventDist":     event_dist,
        "sshStats":      ssh_stats,
        "topAttackIPs":  top_attack_ips,
        "topSuccessIPs": top_success_ips,
        "topUsers":      top_users,
        "topFailUsers":  top_fail_users,
        "sudoCount":     sudo_count,
        "topSudoUsers":  top_sudo_users,
        "suCount":       su_count,
        "allTypes":      all_types,
    }


def compute_syslog(conn: sqlite3.Connection) -> dict | None:
    """gui/main.js :: getSyslogDashboard 와 동일 구조"""
    if not _table_exists(conn, "syslog"): return None
    g = lambda sql, *a: _safe_get(conn, sql, a)
    a = lambda sql, *args: _safe_all(conn, sql, args)
    one = lambda sql, *args: (g(sql, *args) or [0])[0]

    ov = g("SELECT COUNT(*), MIN(timestamp), MAX(timestamp), COUNT(DISTINCT service) FROM syslog")
    overview = (
        {"total": ov[0], "first_dt": ov[1], "last_dt": ov[2], "svc_count": ov[3]}
        if ov else None
    )

    top_services = _to_dicts(
        a("SELECT service, COUNT(*) FROM syslog WHERE service!='' GROUP BY service ORDER BY COUNT(*) DESC LIMIT 15"),
        ("service", "cnt"),
    )

    err_count    = one("SELECT COUNT(*) FROM syslog WHERE message LIKE '%error%'")
    warn_count   = one("SELECT COUNT(*) FROM syslog WHERE message LIKE '%warn%'")
    fail_count   = one("SELECT COUNT(*) FROM syslog WHERE message LIKE '%fail%'")
    crit_count   = one("SELECT COUNT(*) FROM syslog WHERE message LIKE '%critical%'")
    killed_count = one("SELECT COUNT(*) FROM syslog WHERE message LIKE '%killed%'")
    panic_count  = one("SELECT COUNT(*) FROM syslog WHERE message LIKE '%panic%'")

    top_err_services = _to_dicts(a("""
        SELECT service, COUNT(*) FROM syslog
        WHERE message LIKE '%error%' AND service!=''
        GROUP BY service ORDER BY COUNT(*) DESC LIMIT 6
    """), ("service", "cnt"))

    kernel_count  = one("SELECT COUNT(*) FROM syslog WHERE service='kernel'")
    systemd_count = one("SELECT COUNT(*) FROM syslog WHERE service LIKE 'systemd%'")
    sshd_count    = one("SELECT COUNT(*) FROM syslog WHERE service='sshd'")
    sudo_count    = one("SELECT COUNT(*) FROM syslog WHERE service='sudo'")
    cron_count    = one("SELECT COUNT(*) FROM syslog WHERE service IN ('cron','CRON','crond','anacron')")
    nm_count      = one("SELECT COUNT(*) FROM syslog WHERE service='NetworkManager'")

    all_types = _to_dicts(
        a("SELECT service, COUNT(*) FROM syslog WHERE service!='' GROUP BY service ORDER BY COUNT(*) DESC"),
        ("type", "cnt"),
    )

    return {
        "overview":       overview,
        "topServices":    top_services,
        "errCount":       err_count,    "warnCount":   warn_count,
        "failCount":      fail_count,   "critCount":   crit_count,
        "killedCount":    killed_count, "panicCount":  panic_count,
        "topErrServices": top_err_services,
        "kernelCount":    kernel_count, "systemdCount": systemd_count,
        "sshdCount":      sshd_count,   "sudoCount":    sudo_count,
        "cronCount":      cron_count,   "nmCount":      nm_count,
        "allTypes":       all_types,
    }


def compute_apache2(conn: sqlite3.Connection) -> dict | None:
    """gui/main.js :: getApache2Dashboard 와 동일 구조"""
    if not _table_exists(conn, "apache2"): return None
    g = lambda sql, *a: _safe_get(conn, sql, a)
    a = lambda sql, *args: _safe_all(conn, sql, args)
    one = lambda sql, *args: (g(sql, *args) or [0])[0]

    ov = g("""SELECT COUNT(*), MIN(date_time), MAX(date_time),
                     COUNT(DISTINCT src_ip), COUNT(DISTINCT uri) FROM apache2""")
    overview = (
        {"total": ov[0], "first_dt": ov[1], "last_dt": ov[2],
         "ip_count": ov[3], "uri_count": ov[4]}
        if ov else None
    )

    status_dist = _to_dicts(
        a("SELECT status, COUNT(*) FROM apache2 GROUP BY status ORDER BY COUNT(*) DESC LIMIT 20"),
        ("status", "cnt"),
    )

    s2xx = one("SELECT COUNT(*) FROM apache2 WHERE status>=200 AND status<300")
    s3xx = one("SELECT COUNT(*) FROM apache2 WHERE status>=300 AND status<400")
    s4xx = one("SELECT COUNT(*) FROM apache2 WHERE status>=400 AND status<500")
    s5xx = one("SELECT COUNT(*) FROM apache2 WHERE status>=500 AND status<600")

    method_dist_200 = _to_dicts(
        a("SELECT method, COUNT(*) FROM apache2 WHERE status=200 AND method!='' GROUP BY method ORDER BY COUNT(*) DESC"),
        ("method", "cnt"),
    )

    top_uri_200 = _to_dicts(
        a("SELECT uri, COUNT(*) FROM apache2 WHERE status=200 GROUP BY uri ORDER BY COUNT(*) DESC LIMIT 10"),
        ("uri", "cnt"),
    )

    top_ips = _to_dicts(
        a("SELECT src_ip, COUNT(*) FROM apache2 WHERE src_ip!='' GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5"),
        ("src_ip", "cnt"),
    )

    top_err_ips = _to_dicts(
        a("SELECT src_ip, COUNT(*) FROM apache2 WHERE status>=400 AND src_ip!='' GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5"),
        ("src_ip", "cnt"),
    )

    vhosts = _to_dicts(
        a("SELECT vhost, COUNT(*) FROM apache2 WHERE vhost!='' GROUP BY vhost ORDER BY COUNT(*) DESC LIMIT 10"),
        ("vhost", "cnt"),
    )

    return {
        "overview":      overview,
        "statusDist":    status_dist,
        "s2xx": s2xx, "s3xx": s3xx, "s4xx": s4xx, "s5xx": s5xx,
        "methodDist200": method_dist_200,
        "topUri200":     top_uri_200,
        "topIPs":        top_ips,
        "topErrIPs":     top_err_ips,
        "vhosts":        vhosts,
    }


# ── 공통(자동) 대시보드 ─────────────────────────────────

def compute_generic(conn: sqlite3.Connection, table: str) -> dict | None:
    """gui/main.js :: getGenericDashboard 와 동일 구조"""
    cols = _cols(conn, table)
    if not cols: return None
    idx_cols = _indexed_cols(conn, table)

    ts_col = "date_time" if "date_time" in cols else ("timestamp" if "timestamp" in cols else None)

    # 대용량 비인덱스 풀스캔 방지용 행수 상한 체크
    probe = _safe_get(
        conn, f'SELECT COUNT(*) FROM (SELECT 1 FROM "{table}" LIMIT {GENERIC_SCAN_LIMIT + 1})'
    )
    allow_scan = (probe[0] if probe else 0) <= GENERIC_SCAN_LIMIT

    range_obj = {"min": None, "max": None}
    if ts_col and (ts_col in idx_cols or allow_scan):
        r = _safe_get(conn, f'SELECT MIN("{ts_col}"), MAX("{ts_col}") FROM "{table}"')
        if r:
            range_obj = {"min": r[0], "max": r[1]}

    key_cols = [
        c for c in GENERIC_KEY_COLS
        if c in cols and c not in GENERIC_SKIP_COLS and (c in idx_cols or allow_scan)
    ][:4]

    breakdowns = []
    for col in key_cols:
        items = _safe_all(
            conn,
            f'''SELECT "{col}", COUNT(*) FROM "{table}"
                WHERE "{col}" IS NOT NULL AND CAST("{col}" AS TEXT) != ''
                GROUP BY "{col}" ORDER BY COUNT(*) DESC LIMIT 8'''
        )
        if items:
            breakdowns.append({
                "column": col,
                "items":  [{"val": v, "cnt": c} for v, c in items],
            })

    return {
        "table":       table,
        "tsCol":       ts_col,
        "range":       range_obj,
        "breakdowns":  breakdowns,
        "scanLimited": not allow_scan,
    }


# ── 디스패치 + 진입점 ───────────────────────────────────

BESPOKE = {
    "audit":   compute_audit,
    "authlog": compute_authlog,
    "syslog":  compute_syslog,
    "apache2": compute_apache2,
}

# 대시보드를 만들지 않을(혹은 별도 처리되는) 시스템 테이블
SKIP_TABLES = {"sqlite_sequence", "dashboard", "info", "sysinfo"}


def _store(conn: sqlite3.Connection, table: str, payload: dict):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        f"INSERT OR REPLACE INTO {TABLE} (table_name, payload, computed_at) VALUES (?, ?, ?)",
        (table, json.dumps(payload, ensure_ascii=False, default=str), now),
    )


def run(conn: sqlite3.Connection):
    """파싱 종료 후 호출. 데이터가 있는 모든 테이블의 대시보드 페이로드 산출 → 저장."""
    ensure_db(conn)

    tables = [
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        if r[0] not in SKIP_TABLES
    ]

    n_stored = 0
    for tbl in tables:
        try:
            # 비어 있는 테이블은 스킵
            if not _safe_get(conn, f'SELECT 1 FROM "{tbl}" LIMIT 1'):
                continue
            compute = BESPOKE.get(tbl, lambda c, t=tbl: compute_generic(c, t))
            payload = compute(conn)
            if payload is None:
                continue
            _store(conn, tbl, payload)
            n_stored += 1
        except Exception as e:
            print(f"  [WARN] dashboard {tbl}: {e}")

    conn.commit()
    print(f"[DASHBOARD] {n_stored}개 테이블 사전계산 완료")
