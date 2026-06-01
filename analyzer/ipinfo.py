"""
analyzer/ipinfo.py - IPinfo Lite API 로 웹 로그의 IP 를 enrich

웹 접근 로그(apache2 / nginx / 각 error) 에서 등장한 고유 IP 를 모아
IPinfo Lite Batch API 에 질의해 국가·ASN·회사명을 받아온다. VPN 여부는
Lite 가 제공하지 않으므로 as_name 기반 휴리스틱 으로 표시.

토큰:
    환경변수 `IPINFO_TOKEN` 우선, 없으면 프로젝트 루트의 `.ipinfo_token`
    파일에서 한 줄로 읽음. 둘 다 없으면 친절히 안내하고 skip.

캐시:
    parser.db 의 `ipinfo` 테이블 — 동일 IP 는 재질의 안 함.

오프라인:
    네트워크 오류 / 타임아웃 / 404 등 발생 시 조용히 종료(파싱 자체엔 영향 X).

API 참고: https://ipinfo.io/developers/lite-api
  - 단일:  GET  https://api.ipinfo.io/lite/{ip}?token=...
  - 배치:  POST https://api.ipinfo.io/batch/lite?token=...  (최대 1000개)
  - 무료 + 한도 무제한
  - 응답 필드: ip, asn, as_name, as_domain, country, country_code,
              continent, continent_code  (VPN 필드 없음)
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


TABLE        = "ipinfo"
BATCH_SIZE   = 1000
HTTP_TIMEOUT = 10   # 초
TOKEN_FILE   = Path(".ipinfo_token")
BATCH_URL    = "https://api.ipinfo.io/batch/lite"

# 무의미한 placeholder
_BAD_IPS = ("", "-", "?", "0.0.0.0")

# as_name 안에 들어가면 VPN/프록시/Tor/호스팅 의심으로 표시할 키워드
# (case-insensitive 부분 일치). 호스팅 업체는 정상 사용자가 거의 없으므로
# 포렌식 맥락에선 의심 신호로 가치 있음.
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


# ── 토큰 로드 ───────────────────────────────────────────

def _load_token() -> str | None:
    """env IPINFO_TOKEN 우선, 없으면 .ipinfo_token 파일에서 한 줄."""
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


# ── API 호출 ───────────────────────────────────────────

def _query_batch(token: str, ips: list[str]) -> list[dict] | None:
    """배치 요청 1회 — 실패 시 None."""
    body = json.dumps(ips).encode("utf-8")
    url  = f"{BATCH_URL}?token={token}"
    req  = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        print(f"  [WARN] IPinfo 호출 실패: {e.__class__.__name__}: {e}")
        return None

    # 응답은 list[dict] 형태로 IP 별 객체. 일부 응답은 dict-of-dict 형태일 수도
    # 있어 둘 다 허용.
    if isinstance(data, dict):
        # {ip: {...}, ip: {...}} → list 로 정규화
        return list(data.values())
    if isinstance(data, list):
        return data
    return None


def _store(conn: sqlite3.Connection, entries: list[dict]):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        ip = e.get("ip")
        if not ip:
            continue
        as_name = e.get("as_name") or ""
        rows.append((
            ip,
            e.get("country_code")   or "",
            e.get("country")        or "",
            e.get("continent_code") or "",
            e.get("continent")      or "",
            e.get("asn")            or "",
            as_name,
            e.get("as_domain")      or "",
            _is_vpn_suspect(as_name),
            now,
        ))
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

    token = _load_token()
    if not token:
        print("  [SKIP] IPINFO_TOKEN 미설정 — IP enrich 단계 건너뜀.")
        print("         (활성화 방법: https://ipinfo.io/signup 무료 가입 → 토큰을")
        print("          환경변수 IPINFO_TOKEN 또는 프로젝트 루트 .ipinfo_token 에 저장)")
        return

    ips = _collect_ips(conn)
    if not ips:
        print("  [INFO] 웹 로그에 공인 IP 없음 — 질의 대상 0개.")
        return

    cached = _already_cached(conn)
    todo   = sorted(ips - cached)
    print(f"  [INFO] 웹 로그 공인 IP {len(ips):,}개 (캐시됨 {len(cached):,} / 신규 {len(todo):,})")

    if not todo:
        return

    n_ok = 0
    for i in range(0, len(todo), BATCH_SIZE):
        chunk   = todo[i:i + BATCH_SIZE]
        result  = _query_batch(token, chunk)
        if result is None:
            print(f"  [WARN] 배치 {i // BATCH_SIZE + 1} 실패 — 이후 배치도 건너뜀.")
            break
        _store(conn, result)
        n_ok += len(result)
        print(f"  [BATCH] {i // BATCH_SIZE + 1}: {len(chunk)}개 요청 → {len(result)}개 응답")

    print(f"[IPINFO] {n_ok:,}개 IP enrich 완료")
