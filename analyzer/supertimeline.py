"""
analyzer/supertimeline.py — 위협 이벤트 통합 타임라인

analysis.db 의 위협 분석 결과 테이블들을 읽어
탐지된 위협/의심 이벤트를 단일 테이블(supertimeline)로 통합·시간순 정렬합니다.

수집 대상 (위협 판단 기준):
  authlog_bruteforce  : 브루트포스 (burst: 60s/10회 이상 | sustained: 누적 50회+ & 10:1비율)
  authlog (parser.db) : 외부망 SSH 로그인 성공 개별 이벤트 (내부 IP 제외)
  authlog_sudo        : sudo 권한 상승
  syslog_ufw          : UFW 방화벽 차단 (10회 이상)
  apache2_attack      : 웹 공격 페이로드 탐지
  apache2_webshell    : 웹쉘 의심 파일 접근
  mysql_sqli          : SQL Injection 탐지

타임존 정규화 → 모두 KST (UTC+9) 기준:
  authlog / syslog / apache2 : 이미 KST (+0900) → 변환 없음
  mysql_sqli                 : UTC (Z suffix) → +9h 변환

컬럼:
  date_time   TEXT  — KST 정규화 시각 (YYYY-MM-DD HH:MM:SS)
  event_type  TEXT  — 이벤트 유형
  ip          TEXT  — 관련 IP 주소 (없으면 '-')
  description TEXT  — 이벤트 요약 (한 줄)
  ref         TEXT  — 출처 테이블명
"""

import sqlite3
from datetime import datetime, timedelta

TABLE = "supertimeline"

# ── 타임존 변환 ───────────────────────────────────────
_KST_DELTA = timedelta(hours=9)


def _parse_dt_flex(dt_str: str) -> datetime:
    """'YYYY-MM-DD HH:MM:SS[.mmm]' → datetime (ms suffix 허용)"""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            pass
    raise ValueError(f"Cannot parse datetime: {dt_str!r}")


def _fmt_ms(dt: datetime) -> str:
    """datetime → 'YYYY-MM-DD HH:MM:SS.mmm'"""
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _to_kst(dt_str: str) -> str:
    """UTC 문자열 → KST (+9h) 변환. ms 포함 형식 허용. 실패 시 원본 반환."""
    if not dt_str:
        return dt_str
    try:
        dt = _parse_dt_flex(dt_str)
        return _fmt_ms(dt + _KST_DELTA)
    except ValueError:
        return dt_str


def _trunc(s, n: int) -> str:
    if not s:
        return ""
    s = str(s)
    return s[:n] + ("…" if len(s) > n else "")


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


# 내부망 IP 프리픽스 (공통)
_INTERNAL_PREFIX = (
    '127.', '::1',
    '10.', '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
    '100.64.',   # Tailscale CGNAT 대역
)


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in _INTERNAL_PREFIX)


# ── 이벤트 수집 함수 ──────────────────────────────────
# 공통 반환 형식: (date_time, event_type, ip, description, ref)

def _collect_bruteforce(conn: sqlite3.Connection) -> list[tuple]:
    """브루트포스 — burst(60s/10회)와 sustained(누적 50회+) 구분 표시."""
    rows = conn.execute("""
        SELECT burst_start, burst_end, src_ip, attempt_count, success_count
        FROM authlog_bruteforce
        ORDER BY burst_start
    """).fetchall()

    out = []
    for burst_start, burst_end, src_ip, attempt, success in rows:
        # burst vs sustained 구분 (지속 시간으로 판단, ms 포함 형식 허용)
        try:
            t0 = _parse_dt_flex(burst_start)
            t1 = _parse_dt_flex(burst_end)
            dur_s = (t1 - t0).total_seconds()
        except ValueError:
            dur_s = 0

        if dur_s <= 60:
            desc = f"SSH 브루트포스 (burst): {attempt}회 시도 (60s 내)"
        else:
            hrs  = int(dur_s // 3600)
            mins = int((dur_s % 3600) // 60)
            dur_str = f"{hrs}시간 {mins}분" if hrs else f"{mins}분"
            desc = f"SSH 브루트포스 (sustained): {attempt:,}회 실패 / {dur_str}"

        if success:
            desc += f" — 로그인 성공 {success}회"

        out.append((burst_start, "brute_force", src_ip or "-", desc, "authlog_bruteforce"))
    return out


def _collect_login(conn: sqlite3.Connection,
                   src_conn: sqlite3.Connection | None = None) -> list[tuple]:
    """외부 IP에서의 SSH 로그인 성공 — 개별 이벤트 1건씩.
    src_conn(parser.db) 있으면 raw 이벤트 직접 조회,
    없으면 authlog_login 집계 테이블에서 폴백.
    """
    out = []

    if src_conn is not None and _table_exists(src_conn, "authlog"):
        # ── parser.db: 개별 이벤트 (1건 = 1행) ──────────
        rows = src_conn.execute("""
            SELECT date_time, src_ip, user, event_type
            FROM authlog
            WHERE event_type IN ('sshd_accepted_password', 'sshd_accepted_publickey')
              AND src_ip != ''
            ORDER BY date_time
        """).fetchall()
        for date_time, src_ip, user, event_type in rows:
            if _is_internal(src_ip):
                continue
            method = "publickey" if event_type == "sshd_accepted_publickey" else "password"
            desc = f"SSH 로그인 성공: {user} ({method})"
            out.append((date_time, "remote_login", src_ip, desc, "authlog_login"))

    elif _table_exists(conn, "authlog_login"):
        # ── analysis.db 폴백: 집계 테이블 (count > 0만) ──
        rows = conn.execute("""
            SELECT last_seen, src_ip, user, auth_method, count
            FROM authlog_login
            WHERE count > 0
            ORDER BY last_seen
        """).fetchall()
        for last_seen, src_ip, user, method, count in rows:
            if _is_internal(src_ip):
                continue
            desc = f"SSH 로그인 성공: {user} ({method})"
            out.append((last_seen, "remote_login", src_ip, desc, "authlog_login"))

    return out


def _collect_sudo(conn: sqlite3.Connection) -> list[tuple]:
    """sudo 권한 상승 — last_seen 기준 (KST)"""
    rows = conn.execute("""
        SELECT last_seen, user, command, count
        FROM authlog_sudo
        ORDER BY last_seen
    """).fetchall()

    out = []
    for last_seen, user, command, count in rows:
        desc = f"sudo: {user} → {_trunc(command, 80)} ({count}회)"
        out.append((last_seen, "privilege_escalation", "-", desc, "authlog_sudo"))
    return out


def _collect_ufw(conn: sqlite3.Connection) -> list[tuple]:
    """UFW 방화벽 차단 — last_seen 기준 (KST), 10회 이상만"""
    rows = conn.execute("""
        SELECT last_seen, src_ip, dst_port, proto, in_iface, count
        FROM syslog_ufw
        WHERE count >= 10
        ORDER BY last_seen
    """).fetchall()

    out = []
    for last_seen, src_ip, dst_port, proto, iface, count in rows:
        desc = f"UFW 차단: → 포트 {dst_port}/{proto} ({count:,}회, {iface})"
        out.append((last_seen, "firewall_block", src_ip or "-", desc, "syslog_ufw"))
    return out


def _collect_apache2_attack(conn: sqlite3.Connection) -> list[tuple]:
    """Apache2 공격 페이로드 탐지 — date_time 기준 (KST)"""
    rows = conn.execute("""
        SELECT date_time, vhost, src_ip, attack_type, decoded_uri, matched_str
        FROM apache2_attack
        ORDER BY date_time
    """).fetchall()

    out = []
    for date_time, vhost, src_ip, attack_type, decoded_uri, matched in rows:
        site = f"[{vhost}] " if vhost else ""
        desc = f"{site}웹 공격 ({attack_type}): {_trunc(decoded_uri or '', 70)}"
        out.append((date_time, "web_attack", src_ip or "-", desc, "apache2_attack"))
    return out


def _collect_apache2_webshell(conn: sqlite3.Connection) -> list[tuple]:
    """Apache2 웹쉘 탐지 — first_seen 기준 (KST)"""
    rows = conn.execute("""
        SELECT first_seen, vhost, file_path, src_ip,
               suspicion_score, suspicion_flags, access_count
        FROM apache2_webshell
        ORDER BY first_seen
    """).fetchall()

    out = []
    for first_seen, vhost, file_path, src_ip, score, flags, cnt in rows:
        site = f"[{vhost}] " if vhost else ""
        desc = f"{site}웹쉘 의심: {file_path} (위험도 {score}점, {cnt}회 접근)"
        out.append((first_seen, "web_webshell", src_ip or "-", desc, "apache2_webshell"))
    return out


def _collect_mysql_sqli(conn: sqlite3.Connection) -> list[tuple]:
    """MySQL SQL Injection 탐지 — date_time UTC → KST 변환"""
    rows = conn.execute("""
        SELECT date_time, sqli_reason, query
        FROM mysql_sqli
        ORDER BY date_time
    """).fetchall()

    out = []
    for date_time, reason, query in rows:
        kst_dt = _to_kst(date_time)   # UTC → KST
        desc   = f"SQL Injection: {_trunc(reason or '', 80)}"
        out.append((kst_dt, "mysql_sqli", "-", desc, "mysql_sqli"))
    return out


# ── DB ───────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT NOT NULL,
        event_type  TEXT NOT NULL,
        ip          TEXT NOT NULL DEFAULT '-',
        description TEXT NOT NULL,
        ref         TEXT NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_st_dt   ON {TABLE}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_st_type ON {TABLE}(event_type)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_st_ip   ON {TABLE}(ip)")
    conn.commit()


# ── 메인 진입점 ───────────────────────────────────────
def run(conn: sqlite3.Connection,
        src_conn: sqlite3.Connection | None = None) -> int:
    """
    analysis.db 를 읽고 supertimeline 테이블 생성.
    src_conn: parser.db 연결 (있으면 SSH 로그인을 개별 이벤트로 수집)
    Returns: 저장된 이벤트 수
    """
    ensure_db(conn)

    all_rows: list[tuple] = []
    skipped:  list[str]   = []

    # ① 브루트포스 (burst + sustained)
    if _table_exists(conn, "authlog_bruteforce"):
        all_rows.extend(_collect_bruteforce(conn))
    else:
        skipped.append("authlog_bruteforce")

    # ② 외부 SSH 로그인 (개별 이벤트)
    all_rows.extend(_collect_login(conn, src_conn))

    # ③ sudo 권한 상승
    if _table_exists(conn, "authlog_sudo"):
        all_rows.extend(_collect_sudo(conn))
    else:
        skipped.append("authlog_sudo")

    # ④ UFW 차단
    if _table_exists(conn, "syslog_ufw"):
        all_rows.extend(_collect_ufw(conn))
    else:
        skipped.append("syslog_ufw")

    # ⑤ 웹 공격
    if _table_exists(conn, "apache2_attack"):
        all_rows.extend(_collect_apache2_attack(conn))
    else:
        skipped.append("apache2_attack")

    # ⑥ 웹쉘
    if _table_exists(conn, "apache2_webshell"):
        all_rows.extend(_collect_apache2_webshell(conn))
    else:
        skipped.append("apache2_webshell")

    # ⑦ MySQL SQLi
    if _table_exists(conn, "mysql_sqli"):
        all_rows.extend(_collect_mysql_sqli(conn))
    else:
        skipped.append("mysql_sqli")

    # KST 시간순 정렬 (None-safe)
    all_rows.sort(key=lambda r: r[0] or "0000-00-00 00:00:00")

    conn.executemany(f"""
    INSERT INTO {TABLE} (date_time, event_type, ip, description, ref)
    VALUES (?,?,?,?,?)
    """, all_rows)
    conn.commit()

    if skipped:
        print(f"  [SKIP] 없는 테이블: {', '.join(skipped)}")

    # 이벤트 유형별 통계
    from collections import Counter
    type_counts = Counter(r[1] for r in all_rows)
    for etype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {etype:<25}: {cnt:,}건")

    return len(all_rows)
