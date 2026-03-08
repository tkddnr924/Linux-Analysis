"""
analyzer/dpkg.py - 설치된 패키지 목록에서 공격 도구/의심 패키지 탐지

NonVolatile/dpkg_dmp (dpkg -l 출력) 에서 알려진 해킹 도구가
설치되어 있는지 확인합니다.

저장: analysis.db :: dpkg_suspicious
"""

import re
import sqlite3
from pathlib import Path

_NONVOLATILE = Path("target/NonVolatile")

TABLE = "dpkg_suspicious"

# 탐지할 패키지 키워드 → (위험 설명, 위험도)
_ATTACK_TOOLS: dict[str, tuple[str, str]] = {
    # ── 포트/네트워크 스캐닝 ──────────────────────────
    'nmap':          ('포트/서비스 스캐너',              '중'),
    'masscan':       ('초고속 포트 스캐너',              '중'),
    'zmap':          ('인터넷 규모 스캐너',              '중'),
    # ── 취약점 / 익스플로잇 프레임워크 ──────────────────
    'metasploit':    ('침투테스트 프레임워크',            '높음'),
    'sqlmap':        ('SQL 인젝션 자동화 도구',           '높음'),
    'nikto':         ('웹 취약점 스캐너',                '중'),
    'beef-xss':      ('XSS 익스플로잇 프레임워크',       '높음'),
    # ── 패스워드 크래킹 ───────────────────────────────
    'john':          ('패스워드 크래커 (John the Ripper)', '높음'),
    'hashcat':       ('GPU 패스워드 크래커',             '높음'),
    'hydra':         ('네트워크 브루트포스 도구',         '높음'),
    'medusa':        ('네트워크 브루트포스 도구',         '높음'),
    'thc-hydra':     ('네트워크 브루트포스 도구',         '높음'),
    # ── 네트워크 도구 (악용 가능) ─────────────────────
    'netcat':        ('범용 네트워크 도구 (백도어 악용)', '중'),
    'ncat':          ('범용 네트워크 도구',              '중'),
    'socat':         ('다목적 네트워크 릴레이',           '중'),
    # ── 패킷 스니핑 / MITM ───────────────────────────
    'ettercap':      ('MITM / ARP Poisoning 도구',      '높음'),
    'dsniff':        ('네트워크 스니퍼 / 크래커',        '높음'),
    'arpspoof':      ('ARP Spoofing 도구',              '높음'),
    'bettercap':     ('MITM 공격 프레임워크',            '높음'),
    # ── 무선 네트워크 공격 ────────────────────────────
    'aircrack-ng':   ('무선 WEP/WPA 크래커',            '높음'),
    'airbase-ng':    ('무선 네트워크 공격 도구',         '높음'),
    # ── 웹 퍼징 / 디렉토리 브루트포스 ─────────────────
    'dirb':          ('웹 디렉토리 브루트포서',          '중'),
    'gobuster':      ('디렉토리/DNS 브루트포서',         '중'),
    'ffuf':          ('웹 퍼저',                        '중'),
    'wfuzz':         ('웹 퍼저',                        '중'),
    'wpscan':        ('WordPress 취약점 스캐너',        '중'),
    # ── 터널링 / 프록시 / 우회 ───────────────────────
    'proxychains':   ('프록시 체이닝 도구',              '낮음'),
    'chisel':        ('HTTP 터널 도구',                  '중'),
    'frp':           ('리버스 프록시 도구',              '중'),
    # ── 시스템 점검 도구 (역용 가능) ─────────────────
    'chkrootkit':    ('루트킷 탐지 도구 (역용 주의)',    '낮음'),
    'rkhunter':      ('루트킷 탐지 도구 (역용 주의)',    '낮음'),
    # ── 기타 익스플로잇 도구 ──────────────────────────
    'exploitdb':     ('Exploit Database',               '높음'),
    'commix':        ('명령어 인젝션 자동화',             '높음'),
    'maltego':       ('OSINT / 정보수집 도구',           '낮음'),
}

# dpkg -l 한 줄 패턴: "ii  package  version  arch  description"
_RE_PKG = re.compile(r'^([a-z][a-z])\s+(\S+)\s+(\S+)\s+\S+\s+(.*)')


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        package     TEXT NOT NULL,
        version     TEXT,
        status      TEXT,
        description TEXT,
        risk_reason TEXT,
        risk_level  TEXT
    )
    """)
    conn.commit()


# ── 분석 ──────────────────────────────────────────────
def analyze() -> list:
    text = _read(_NONVOLATILE / "dpkg_dmp")
    if not text:
        return []

    rows = []
    for line in text.splitlines():
        m = _RE_PKG.match(line)
        if not m:
            continue
        status, pkg, ver, desc = m.groups()
        # 설치된 패키지만 (ii)
        if status != 'ii':
            continue

        pkg_lower = pkg.lower()
        for keyword, (reason, level) in _ATTACK_TOOLS.items():
            if keyword in pkg_lower:
                rows.append((pkg, ver, status, desc.strip(), reason, level))
                break

    return rows


# ── 저장 ──────────────────────────────────────────────
def insert_all(conn: sqlite3.Connection, result: list):
    if result:
        conn.executemany(f"""
        INSERT INTO {TABLE} (package, version, status, description, risk_reason, risk_level)
        VALUES (?,?,?,?,?,?)
        """, result)
        conn.commit()


def run(conn: sqlite3.Connection) -> list:
    ensure_db(conn)
    result = analyze()
    insert_all(conn, result)
    return result
