"""
analyzer/ipinfo.py - IPinfo 로 웹 로그의 IP 를 enrich (토큰 불필요)

웹 접근 로그(apache2 / nginx / 각 error) 에서 등장한 고유 IP 를 모아
`https://ipinfo.io/{ip}/json` 에 단건 질의해 국가·ASN·회사명을 받아온다.
이 엔드포인트는 토큰 없이 동작(무료 한도 ~1000/day, 토큰 있으면 50k/month).
VPN 여부는 응답에 없으므로 as_name 기반 휴리스틱으로 표시.

토큰(선택):
    환경변수 `IPINFO_TOKEN` 또는 프로젝트 루트의 `.ipinfo_token` 파일.
    있으면 자동으로 `?token=...` 붙여 호출 → 일일 한도가 크게 늘어남.

캐시:
    parser.db 의 `ipinfo` 테이블 — 동일 IP 는 재질의 안 함.

오프라인:
    네트워크 오류 / 타임아웃 / HTTP 에러 발생 시 그 IP 만 스킵.
    전부 실패해도 파싱 자체엔 영향 X.

API:  https://ipinfo.io/developers
응답 필드(주요): ip, country(2자 ISO), org="AS<n> <회사명>", city, region,
                hostname, loc, timezone, anycast (toplevel).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path


TABLE        = "ipinfo"
HTTP_TIMEOUT = 8                  # 초
MAX_WORKERS  = 8                  # 동시 요청 수
TOKEN_FILE   = Path(".ipinfo_token")
SINGLE_URL   = "https://ipinfo.io/{ip}/json"

# 무의미한 placeholder
_BAD_IPS = ("", "-", "?", "0.0.0.0")

# as_name 안에 들어가면 VPN/프록시/Tor/호스팅 의심으로 표시 (대소문자 무관 부분일치)
_VPN_HINT_TOKENS = (
    "vpn", "nordvpn", "expressvpn", "protonvpn", "surfshark", "mullvad",
    "cyberghost", "tunnelbear", "ivpn", "windscribe", "vyprvpn",
    "private internet access", "hide.me", "hidemyass",
    "tor exit", "tor relay", "anonymous",
    "digitalocean", "vultr", "linode", "ovh", "hetzner", "choopa",
    "m247", "datacamp", "leaseweb", "contabo", "ramnode",
    "amazon technologies", "amazon-02", "amazon data services",
    "google cloud", "microsoft corporation", "microsoft-corp", "azure",
    "alibaba", "tencent cloud", "oracle corporation",
)

# org 필드 형식: "AS15169 Google LLC"
_ORG_RE = re.compile(r"^(AS\d+)\s+(.+)$")


# ── 스키마 ──────────────────────────────────────────────

def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE} (
            ip             TEXT PRIMARY KEY,
            country_code   TEXT,
            country        TEXT,
            continent_code TEXT,
            continent      TEXT,
            asn            TEXT,
            as_name        TEXT,
            as_domain      TEXT,
            vpn_suspect    INTEGER NOT NULL DEFAULT 0,
            fetched_at     TEXT NOT NULL
        )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_country ON {TABLE}(country_code)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_vpn     ON {TABLE}(vpn_suspect)")
    conn.commit()


# ── 토큰 로드 (선택) ────────────────────────────────────

def _load_token() -> str | None:
    """env > 파일. 둘 다 없으면 None — 호출 자체는 정상 진행 (무토큰 한도 적용)."""
    tok = os.environ.get("IPINFO_TOKEN", "").strip()
    if tok:
        return tok
    if TOKEN_FILE.exists():
        try:
            t = TOKEN_FILE.read_text(encoding="utf-8").strip()
            if t:
                return t
        except Exception:
            return None
    return None


# ── 유틸 ────────────────────────────────────────────────

def _is_public_ip(ip: str) -> bool:
    """사설/루프백/링크로컬/멀티캐스트/예약 대역은 질의 대상에서 제외."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def _is_vpn_suspect(as_name: str | None) -> int:
    if not as_name:
        return 0
    s = as_name.lower()
    return 1 if any(tok in s for tok in _VPN_HINT_TOKENS) else 0


def _parse_org(org: str | None) -> tuple[str, str]:
    """'AS15169 Google LLC' → ('AS15169', 'Google LLC'). ASN 없으면 ('', org)."""
    if not org:
        return ("", "")
    m = _ORG_RE.match(org.strip())
    if m:
        return (m.group(1), m.group(2))
    return ("", org.strip())


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


# ── IP 수집 ────────────────────────────────────────────

def _collect_ips(conn: sqlite3.Connection) -> set[str]:
    """웹 로그 테이블들에서 고유 IP 수집 — placeholder/사설 IP 제외."""
    sources = (
        ("apache2",       "src_ip"),
        ("apache2_error", "client_ip"),
        ("nginx",         "src_ip"),
        ("nginx_error",   "client_ip"),
    )
    out: set[str] = set()
    for table, col in sources:
        if not _table_exists(conn, table):
            continue
        try:
            for (ip,) in conn.execute(f'SELECT DISTINCT "{col}" FROM "{table}"'):
                if not ip or ip in _BAD_IPS:
                    continue
                if _is_public_ip(ip):
                    out.add(ip)
        except sqlite3.OperationalError:
            continue
    return out


def _already_cached(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute(f"SELECT ip FROM {TABLE}").fetchall()}


# ── HTTP ────────────────────────────────────────────────

def _query_one(ip: str, token: str | None) -> dict | None:
    """단건 조회 — 실패하면 None (해당 IP 만 스킵)."""
    url = SINGLE_URL.format(ip=ip)
    if token:
        url += f"?token={token}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, dict) and "ip" in data:
                return data
            return None
    except (urllib.error.HTTPError, urllib.error.URLError,
            TimeoutError, json.JSONDecodeError, OSError):
        return None


# ── 저장 ────────────────────────────────────────────────

def _to_row(ip: str, data: dict, now: str) -> tuple:
    asn, as_name = _parse_org(data.get("org"))
    cc = (data.get("country") or "").strip()
    return (
        ip,
        cc,
        # 토큰 없는 엔드포인트는 country 풀네임을 안 줌 — code 그대로 두 번째 칼럼에도
        # 두기보다 비워두고 UI 에서 코드 + 국기로 표시
        "",
        "", "",                    # continent_code, continent 도 무토큰 응답에 없음
        asn, as_name,
        (data.get("org_domain") or "") if isinstance(data.get("org_domain"), str) else "",
        _is_vpn_suspect(as_name),
        now,
    )


def _store(conn: sqlite3.Connection, rows: list[tuple]):
    if not rows:
        return
    conn.executemany(f"""
        INSERT OR REPLACE INTO {TABLE}
        (ip, country_code, country, continent_code, continent,
         asn, as_name, as_domain, vpn_suspect, fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()


# ── 진입점 ─────────────────────────────────────────────

def run(conn: sqlite3.Connection):
    ensure_db(conn)

    ips = _collect_ips(conn)
    if not ips:
        print("  [INFO] 웹 로그에 공인 IP 없음 — 질의 대상 0개.")
        return

    cached = _already_cached(conn)
    todo   = sorted(ips - cached)
    print(f"  [INFO] 웹 로그 공인 IP {len(ips):,}개 (캐시 {len(cached):,} / 신규 {len(todo):,})")
    if not todo:
        return

    token = _load_token()
    if not token:
        print("  [INFO] 토큰 없이 진행 (무토큰 한도 ~1000/day).")
        print("         더 큰 한도가 필요하면 https://ipinfo.io/signup 무료 가입 후")
        print("         환경변수 IPINFO_TOKEN 또는 .ipinfo_token 에 토큰 저장.")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows: list[tuple] = []
    n_ok = n_fail = 0
    # 동시 요청 — 단건 엔드포인트라 ThreadPool 로 병렬화
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for ip, data in zip(todo, ex.map(lambda x: _query_one(x, token), todo)):
            if data is None:
                n_fail += 1
                continue
            rows.append(_to_row(ip, data, now))
            n_ok += 1
            # 200건 모일 때마다 중간 저장 — 큰 작업에서 중단되도 진행분 보존
            if len(rows) >= 200:
                _store(conn, rows)
                rows.clear()

    _store(conn, rows)
    if n_fail:
        print(f"[IPINFO] {n_ok:,}개 enrich, {n_fail:,}개 실패(네트워크/한도/잘못된 IP)")
    else:
        print(f"[IPINFO] {n_ok:,}개 IP enrich 완료")
