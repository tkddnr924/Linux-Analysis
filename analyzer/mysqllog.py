"""
analyzer/mysqllog.py - MySQL Query Log 분석기

parser.db :: mysql_query 테이블을 읽어
SQL Injection 의심 쿼리를 탐지 후
analysis.db :: mysql_sqli 테이블에 저장합니다.

컬럼:
  date_time   : 쿼리 실행 시간
  query       : 쿼리 전문 (argument)
  sqli_reason : 탐지된 공격 유형
  raw_line    : 원본 로그 라인

탐지 패턴:
  union_based    : UNION SELECT (컬럼 수 파악 / 데이터 추출 시도)
  time_based     : SLEEP() / BENCHMARK() / WAITFOR DELAY (시간 기반 블라인드)
  error_based    : EXTRACTVALUE() / UPDATEXML() / EXP(~) (에러 기반 데이터 추출)
  out_of_band    : INTO OUTFILE/DUMPFILE / LOAD_FILE() (파일 R/W 악용)
  stacked_query  : ; 이후 DDL/DML 삽입 (적층 쿼리 주입)
  auth_bypass    : OR 1=1 / AND 1=2 / 항진식 문자열 (인증 우회)
  hex_payload    : 0x... 긴 hex 인코딩 (문자열 필터 우회)
  db_fingerprint : USER() / VERSION() / @@version 등 단독 실행 (DB 정보 수집)

제외(화이트리스트):
  /* mysql-connector-j...     → JDBC 드라이버 내부 쿼리
  /* ApplicationName=...      → IntelliJ / DataGrip 등 IDE 쿼리
  (db_fingerprint / hex_payload 패턴에 한해 적용)
"""

import re
import sqlite3

SRC_TABLE  = "mysql_query"
TABLE_SQLI = "mysql_sqli"


# ──────────────────────────────────────────────────────────────────────────────
# 화이트리스트 prefix (일부 패턴에서 정상 도구 제외용)
# ──────────────────────────────────────────────────────────────────────────────
_WHITELIST_PREFIXES: tuple[str, ...] = (
    "/* mysql-connector-j",   # JDBC 드라이버 내부 쿼리
    "/* ApplicationName=",    # IntelliJ / DataGrip
)


def _is_tool_query(arg: str) -> bool:
    """알려진 DB 도구의 쿼리 prefix 여부 확인"""
    return arg.lstrip().startswith(_WHITELIST_PREFIXES)


# ──────────────────────────────────────────────────────────────────────────────
# 탐지 패턴 정의
# ──────────────────────────────────────────────────────────────────────────────
_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    # (이름, 패턴, whitelist_제외_여부)
    # whitelist_제외=True : 알려진 도구라도 이 패턴이 나오면 무조건 탐지

    # UNION-based: 컬럼 수 파악 또는 데이터 추출
    ("union_based", re.compile(
        r'\bunion\b\s*(?:all\s+)?\bselect\b',
        re.I
    ), False),

    # Time-based blind SQLi
    ("time_based", re.compile(
        r'\bsleep\s*\(\s*\d'
        r'|\bbenchmark\s*\(\s*\d'
        r'|\bwaitfor\b.{0,15}\bdelay\b',
        re.I
    ), False),

    # Error-based SQLi (에러 메시지로 데이터 추출)
    ("error_based", re.compile(
        r'\bextractvalue\s*\('
        r'|\bupdatexml\s*\('
        r'|\bexp\s*\(\s*~\s*\(',
        re.I
    ), False),

    # Out-of-band SQLi (파일 R/W)
    ("out_of_band", re.compile(
        r'\binto\s+(?:outfile|dumpfile)\b'
        r'|\bload_file\s*\(',
        re.I
    ), False),

    # Stacked query (세미콜론 뒤 DDL/DML 삽입)
    ("stacked_query", re.compile(
        r';\s*(?:'
        r'drop\s+(?:table|database|index|procedure|function|view|trigger)'
        r'|insert\s+into'
        r'|update\s+\w.{0,40}\bset\b'
        r'|delete\s+from'
        r'|create\s+(?:table|database|user)'
        r'|alter\s+(?:table|user)'
        r'|exec(?:ute)?\b'
        r'|call\s+\w'
        r'|rename\s+table'
        r'|truncate\s+table'
        r')',
        re.I
    ), False),

    # Auth bypass (인증 우회 패턴)
    # ※ BETWEEN 'date' AND 'date' 오탐 방지: = 비교 연산자 포함 여부로 구분
    ("auth_bypass", re.compile(
        # ' OR '1'='1' 또는 ' AND '1'='1' 스타일 (등호 비교 필수)
        r"'\s*(?:or|and)\s+'[^']{0,15}'\s*=\s*'[^']{0,15}'"
        # OR 1=1 / AND 1=2 — 따옴표 없는 숫자 항진식
        r"|\bor\s+1\s*=\s*1\b"
        r"|\band\s+1\s*=\s*[02]\b"
        # HAVING 1=1 (에러 기반 칼럼 노출)
        r"|\bhaving\s+1\s*=\s*1\b",
        re.I
    ), False),

    # Hex payload (0x로 인코딩된 긴 문자열 - 필터 우회)
    # 단순 0xHH 색상값/숫자는 제외, 8자리 이상만 탐지
    ("hex_payload", re.compile(
        r'\b0x[0-9a-fA-F]{8,}\b',
        re.I
    ), True),   # ← 알려진 도구 쿼리 제외

    # DB fingerprinting (DB 정보 수집 — 앱 쿼리에선 불필요)
    ("db_fingerprint", re.compile(
        r'\b(?:user|version|database)\s*\(\s*\)'
        r'|@@(?:version|datadir|basedir|hostname|global\.version)',
        re.I
    ), True),   # ← 알려진 도구 쿼리 제외
]


# ──────────────────────────────────────────────────────────────────────────────
# 탐지 함수
# ──────────────────────────────────────────────────────────────────────────────
def _detect(argument: str) -> tuple[str, str]:
    """
    argument 에서 SQL Injection 패턴을 탐지.
    Returns: (sqli_reason, matched_str) or ("", "")
    """
    is_tool = _is_tool_query(argument)

    for name, rx, skip_if_tool in _PATTERNS:
        if skip_if_tool and is_tool:
            continue
        m = rx.search(argument)
        if m:
            # 매칭 전후 문맥 포함 (최대 100자)
            start = max(0, m.start() - 30)
            end   = min(len(argument), m.end() + 30)
            snippet = argument[start:end].strip()[:100]
            return name, snippet

    return "", ""


# ──────────────────────────────────────────────────────────────────────────────
# DB
# ──────────────────────────────────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_SQLI} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT,
        query       TEXT,
        sqli_reason TEXT,
        raw_line    TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_sqli_dt     ON {TABLE_SQLI}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_mysql_sqli_reason ON {TABLE_SQLI}(sqli_reason)")
    conn.commit()


def insert_all(conn: sqlite3.Connection, results: dict):
    if results.get("sqli"):
        conn.executemany(f"""
        INSERT INTO {TABLE_SQLI} (date_time, query, sqli_reason, raw_line)
        VALUES (?,?,?,?)
        """, results["sqli"])
        conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# 분석 로직
# ──────────────────────────────────────────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    rows = src_conn.execute(f"""
        SELECT date_time, command, argument, raw_line
        FROM {SRC_TABLE}
        WHERE command IN ('Query', 'Execute')
          AND argument IS NOT NULL
          AND argument != ''
        ORDER BY date_time
    """).fetchall()

    sqli_rows: list[tuple] = []

    for date_time, _cmd, argument, raw_line in rows:
        reason, matched = _detect(argument)
        if not reason:
            continue

        # sqli_reason 에 매칭 스니펫 포함: "union_based: UNION SELECT NULL..."
        full_reason = f"{reason}: {matched}" if matched else reason

        sqli_rows.append((
            date_time,
            argument,
            full_reason,
            raw_line,
        ))

    return {"sqli": sqli_rows}
