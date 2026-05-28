"""
analyzer/ip_summary.py - 크로스-테이블 IP 활동 집계 사전계산

여러 소스 테이블에 흩어진 IP 활동을 IP 1개당 1행으로 묶어 `ip_summary`
테이블에 저장한다. 뷰어 'IP 분석' 화면에서 그대로 페이지네이션·정렬해서
보고, 행을 클릭하면 해당 IP 의 테이블별 상세를 라이브 SQL 로 드릴다운한다.

집계 소스:
    apache2.src_ip           : web_2xx/3xx/4xx/5xx, web_total
    apache2_error.client_ip  : web_total (상태코드 분류 없음)
    nginx.src_ip             : web (동일)
    nginx_error.client_ip    : web_total
    authlog.src_ip           : auth_success / auth_fail
    audit.addr               : audit_login / audit_err

저장 스키마:
    ip TEXT PK, total_count, first_seen, last_seen,
    web_total, web_2xx, web_3xx, web_4xx, web_5xx,
    auth_success, auth_fail,
    audit_login, audit_err
"""

from __future__ import annotations

import sqlite3


TABLE = "ip_summary"

# 무의미한 placeholder 들 — 집계 대상에서 제외
_BAD_IPS = ("", "-", "?", "0.0.0.0")


def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE} (
            ip            TEXT PRIMARY KEY,
            total_count   INTEGER NOT NULL DEFAULT 0,
            first_seen    TEXT,
            last_seen     TEXT,
            web_total     INTEGER NOT NULL DEFAULT 0,
            web_2xx       INTEGER NOT NULL DEFAULT 0,
            web_3xx       INTEGER NOT NULL DEFAULT 0,
            web_4xx       INTEGER NOT NULL DEFAULT 0,
            web_5xx       INTEGER NOT NULL DEFAULT 0,
            auth_success  INTEGER NOT NULL DEFAULT 0,
            auth_fail     INTEGER NOT NULL DEFAULT 0,
            audit_login   INTEGER NOT NULL DEFAULT 0,
            audit_err     INTEGER NOT NULL DEFAULT 0
        )
    """)
    # 정렬 필터에 자주 쓰일 컬럼들에 인덱스 (DESC 키워드는 SQLite 에서 무시되지만 가독성)
    for col in ("total_count", "web_total", "web_4xx", "web_5xx", "auth_fail", "audit_err"):
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_{col} ON {TABLE}({col} DESC)")
    conn.commit()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _safe_all(conn, sql, params=()):
    try:    return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError: return []


def run(conn: sqlite3.Connection):
    """모든 소스 테이블에서 IP 활동을 모아 ip_summary 를 재구축."""
    ensure_db(conn)
    # 재계산이므로 전부 비우고 시작 (간단·정확)
    conn.execute(f"DELETE FROM {TABLE}")

    agg: dict[str, dict] = {}

    def _merge(ip: str | None, n: int, fmin: str | None, fmax: str | None, **delta):
        if ip is None: return
        ip = ip.strip()
        if ip in _BAD_IPS: return
        rec = agg.setdefault(ip, {
            "total_count": 0, "first_seen": None, "last_seen": None,
            "web_total": 0, "web_2xx": 0, "web_3xx": 0, "web_4xx": 0, "web_5xx": 0,
            "auth_success": 0, "auth_fail": 0,
            "audit_login": 0, "audit_err": 0,
        })
        rec["total_count"] += n
        if fmin is not None:
            rec["first_seen"] = fmin if rec["first_seen"] is None else min(rec["first_seen"], fmin)
        if fmax is not None:
            rec["last_seen"]  = fmax if rec["last_seen"]  is None else max(rec["last_seen"], fmax)
        for k, v in delta.items():
            rec[k] = rec.get(k, 0) + (v or 0)

    # ── apache2 (status 별 분류) ──────────────────────
    if _table_exists(conn, "apache2"):
        for ip, n, fmin, fmax, s2, s3, s4, s5 in _safe_all(conn, """
            SELECT src_ip, COUNT(*), MIN(date_time), MAX(date_time),
                   SUM(CASE WHEN status>=200 AND status<300 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status>=300 AND status<400 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status>=400 AND status<500 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status>=500 AND status<600 THEN 1 ELSE 0 END)
            FROM apache2
            WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','-','?','0.0.0.0')
            GROUP BY src_ip
        """):
            _merge(ip, n, fmin, fmax,
                   web_total=n, web_2xx=s2 or 0, web_3xx=s3 or 0, web_4xx=s4 or 0, web_5xx=s5 or 0)

    # ── nginx (status 별 분류) ───────────────────────
    if _table_exists(conn, "nginx"):
        for ip, n, fmin, fmax, s2, s3, s4, s5 in _safe_all(conn, """
            SELECT src_ip, COUNT(*), MIN(date_time), MAX(date_time),
                   SUM(CASE WHEN status>=200 AND status<300 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status>=300 AND status<400 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status>=400 AND status<500 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status>=500 AND status<600 THEN 1 ELSE 0 END)
            FROM nginx
            WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','-','?','0.0.0.0')
            GROUP BY src_ip
        """):
            _merge(ip, n, fmin, fmax,
                   web_total=n, web_2xx=s2 or 0, web_3xx=s3 or 0, web_4xx=s4 or 0, web_5xx=s5 or 0)

    # ── apache2_error / nginx_error (상태코드 없음) ─
    for tbl, col in (("apache2_error", "client_ip"), ("nginx_error", "client_ip")):
        if not _table_exists(conn, tbl): continue
        for ip, n, fmin, fmax in _safe_all(conn, f"""
            SELECT {col}, COUNT(*), MIN(date_time), MAX(date_time)
            FROM {tbl}
            WHERE {col} IS NOT NULL AND {col} NOT IN ('','-','?')
            GROUP BY {col}
        """):
            _merge(ip, n, fmin, fmax, web_total=n)

    # ── authlog (성공 / 실패) ────────────────────────
    if _table_exists(conn, "authlog"):
        for ip, n, fmin, fmax, ok, fail in _safe_all(conn, """
            SELECT src_ip, COUNT(*), MIN(date_time), MAX(date_time),
                   SUM(CASE WHEN event_type IN ('sshd_accepted_password','sshd_accepted_publickey') THEN 1 ELSE 0 END),
                   SUM(CASE WHEN event_type IN ('sshd_failed_password','sshd_invalid_user','sshd_max_auth') THEN 1 ELSE 0 END)
            FROM authlog
            WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','-','?')
            GROUP BY src_ip
        """):
            _merge(ip, n, fmin, fmax, auth_success=ok or 0, auth_fail=fail or 0)

    # ── audit (USER_LOGIN/AUTH vs USER_ERR) ──────────
    if _table_exists(conn, "audit"):
        for ip, n, fmin, fmax, login, err in _safe_all(conn, """
            SELECT addr, COUNT(*), MIN(date_time), MAX(date_time),
                   SUM(CASE WHEN type IN ('USER_LOGIN','USER_AUTH') THEN 1 ELSE 0 END),
                   SUM(CASE WHEN type='USER_ERR' THEN 1 ELSE 0 END)
            FROM audit
            WHERE addr IS NOT NULL AND addr NOT IN ('','?','0.0.0.0')
              AND addr NOT GLOB '*:*'
            GROUP BY addr
        """):
            _merge(ip, n, fmin, fmax, audit_login=login or 0, audit_err=err or 0)

    # ── 일괄 삽입 ────────────────────────────────────
    if agg:
        conn.executemany(f"""
            INSERT INTO {TABLE}
              (ip, total_count, first_seen, last_seen,
               web_total, web_2xx, web_3xx, web_4xx, web_5xx,
               auth_success, auth_fail, audit_login, audit_err)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, [
            (ip, r["total_count"], r["first_seen"], r["last_seen"],
             r["web_total"], r["web_2xx"], r["web_3xx"], r["web_4xx"], r["web_5xx"],
             r["auth_success"], r["auth_fail"], r["audit_login"], r["audit_err"])
            for ip, r in agg.items()
        ])
    conn.commit()
    print(f"[IP SUMMARY] {len(agg)}개 IP 집계 완료")
