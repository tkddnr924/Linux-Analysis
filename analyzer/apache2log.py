"""
analyzer/apache2log.py - Apache2 access.log 분석기

parser.db 의 apache2 테이블(2xx 성공 요청)을 읽어
analysis.db 에 아래 테이블로 저장합니다.

  apache2_top_ip    : 공격 탐지된 IP별 집계
  apache2_attack    : 실제 공격 페이로드가 탐지된 성공 요청
  apache2_webshell  : 웹쉘 의심 파일 + 접근 행위 분석

탐지 패턴 (URI 이중 URL 디코딩 적용):
  - sql_injection   : UNION SELECT + 컬럼 추출, 시스템 메타정보(information_schema/@@version/user() 등),
                      DML(INSERT/UPDATE/DELETE), DDL(DROP/TRUNCATE), 파일 I/O, 코드 실행, 블라인드(SLEEP/BENCHMARK) 등
  - xss             : <script>, onerror=, javascript: 등
  - path_traversal  : ../ 경로 탈출 + /etc/passwd 접근 시도
  - lfi_rfi         : php://, file://, expect://, /proc/self/environ 등
  - shell_injection : ;id, |whoami, `uname`, wget/curl 원격 다운로드 등
  - log4shell       : ${jndi:ldap://} 및 인코딩 우회 변형
  - spring4shell    : class.module.classLoader, Spring RCE 파라미터
  - php_injection   : base64_decode(, eval(, system( 등 코드 실행

웹쉘 탐지 기준 (POST + 200 요청 대상):
  - variable_response  : 동일 URI 반복 접근 시 응답 크기가 계속 변함
  - persistent_access  : 단일 IP에서 동일 URI 3회 이상 지속 접근
  - high_freq_access   : 단일 IP에서 동일 URI 10회 이상 고빈도 접근
  - known_webshell     : c99, r57, shell, cmd, backdoor 등 알려진 웹쉘 파일명
  - suspicious_path    : /uploads/, /tmp/, /cache/ 등 업로드 경로에 스크립트 확장자
  - script_in_media    : 이미지/미디어 디렉토리에 .php/.jsp 등 서버사이드 스크립트
"""

import re
import sqlite3
from collections import defaultdict
from pathlib import PurePosixPath
from urllib.parse import unquote

SRC_TABLE      = "apache2"
TABLE_TOP_IP   = "apache2_top_ip"
TABLE_ATTACK   = "apache2_attack"
TABLE_WEBSHELL = "apache2_webshell"

TABLES = [TABLE_TOP_IP, TABLE_ATTACK, TABLE_WEBSHELL, "apache2_error"]


# ──────────────────────────────────────────────────────────────────────────────
# 웹쉘 탐지 상수
# ──────────────────────────────────────────────────────────────────────────────

_SCRIPT_EXTS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml",
    ".jsp", ".jspx", ".jspf",
    ".asp", ".aspx", ".ascx", ".ashx",
    ".cfm", ".cgi", ".pl", ".py", ".rb", ".sh",
}

_KNOWN_WEBSHELL_RE = re.compile(
    r"(?:^|/)(?:"
    r"c99|r57|b374k|wso|indoxploit|alfa|fi?s?h(?:er)?"
    r"|shell|webshell|cmd|command|backdoor|rootkit"
    r"|hack|hacked|owned|pwned"
    r"|eval|base64|encode|decode"
    r"|upload|uploader|filemanager|file_manager"
    r"|adminer|phpmy|myadmin"
    r"|test|tmp|temp|temp\d*|1|2|3"
    r"|(?:pass|password)(?:wd)?"
    r")(?:\.|$)",
    re.I
)

_SUSPICIOUS_PATH_RE = re.compile(
    r"/(?:upload[s]?|tmp|temp|cache|backup[s]?|bak"
    r"|image[s]?|img|photo[s]?|thumb[s]?|media"
    r"|static|assets|files|data|content"
    r"|public|www|html)/.*\.",
    re.I
)

_MEDIA_DIR_RE = re.compile(
    r"/(?:image[s]?|img|photo[s]?|thumb[s]?|gallery|avatar[s]?|icon[s]?|banner[s]?)/",
    re.I
)

_SCORE_TABLE = {
    "known_webshell":    4,
    "variable_response": 3,
    "script_in_media":   3,
    "suspicious_path":   2,
    "high_freq_access":  2,
    "persistent_access": 1,
}

_MIN_SCORE = 2


# ──────────────────────────────────────────────────────────────────────────────
# 공격 페이로드 패턴
# ──────────────────────────────────────────────────────────────────────────────
_ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [

    ("log4shell", re.compile(
        r"\$\{.*?j.*?n.*?d.*?i.*?:"
        r"|%24%7[Bb].*?jndi"
        r"|\$\{(?:lower|upper|::-[a-z])",
        re.I
    )),

    ("spring4shell", re.compile(
        r"class\.module\.classLoader"
        r"|class\.classLoader"
        r"|suffix=%25"
        r"|c1\.getClass\(\)"
        r"|\.classLoader\.resources\.context"
        r"|spring\.xml\.ignore"
        r"|requestMappingHandlerMapping",
        re.I
    )),

    # ── SQL Injection ─────────────────────────────────────────────────────────
    ("sql_injection", re.compile(
        # UNION SELECT 기반 데이터 추출 (컬럼/테이블 조회 징후 필요)
        r"\bunion\b.{0,50}\bselect\b.{0,60}\b(?:from|null|0x|char\(|concat\()"
        # 시스템 메타데이터 조회 — DB 구조·계정 정보 탈취
        r"|\bfrom\s+information_schema\b"
        r"|\bfrom\s+(?:pg_catalog|pg_tables|pg_user|sqlite_master|sys\.tables|sysobjects)\b"
        r"|@@(?:version|datadir|hostname|global\.|session\.)"
        r"|\b(?:user|database|schema|version)\s*\(\s*\)"
        # DML — 데이터 직접 삽입·수정·삭제
        r"|\binsert\s+into\b.{0,80}\bvalues\s*\("
        r"|\bupdate\b.{0,60}\bset\b.{0,60}="
        r"|\bdelete\s+from\b"
        # DDL — 테이블·DB 구조 파괴
        r"|\bdrop\s+(?:table|database|schema|index|view|procedure|function)\b"
        r"|\btruncate\s+(?:table\s+)?\w"
        # 파일 I/O
        r"|\bload_file\s*\("
        r"|\binto\s+(?:outfile|dumpfile)\b"
        # 코드 실행 (MSSQL 중심)
        r"|\bexec(?:ute)?\s*\("
        r"|\bxp_cmdshell\b"
        r"|\bsp_executesql\b"
        # 블라인드 SQLi — 시간 지연 (공격 의도 명확)
        r"|\bsleep\s*\(\s*\d"
        r"|\bwaitfor\s+delay\b"
        r"|\bbenchmark\s*\(\s*\d"
        r"|\bpg_sleep\s*\(\s*\d",
        re.I
    )),

    ("xss", re.compile(
        r"<script[\s>]"
        r"|</script>"
        r"|<iframe[\s>]"
        r"|<img[^>]+\bon\w+\s*="
        r"|on(?:error|load|click|mouseover|focus)\s*="
        r"|javascript\s*:"
        r"|vbscript\s*:"
        r"|expression\s*\(",
        re.I
    )),

    ("path_traversal", re.compile(
        r"(?:\.\.[\\/]){2,}"
        r"|(?:%2e%2e[\\/]|%252e%252e){2,}"
        r"|/etc/(?:passwd|shadow|group|hosts|crontab)"
        r"|/proc/self/(?:environ|cmdline|exe)"
        r"|/windows/(?:system32|win\.ini)"
        r"|\.\./\.\./.*\.(?:conf|ini|log|bak|xml)",
        re.I
    )),

    ("lfi_rfi", re.compile(
        r"(?:php|expect|data|zip|phar|glob)://"
        r"|file:///(?:etc|proc|windows)"
        r"|http(?:s)?://.{4,}\.(?:php|txt|sh|pl|py)"
        r"|\binclude\s*\(\s*[\"']?http",
        re.I
    )),

    ("shell_injection", re.compile(
        r"(?:;|\|)\s*(?:id|whoami|uname|cat\s+/etc|ls\s+-)"
        r"|`(?:id|whoami|uname)`"
        r"|\$\((?:id|whoami|curl|wget)"
        r"|/bin/(?:sh|bash)\b"
        r"|cmd\.exe"
        r"|wget\s+https?://\S+\s+-[Oqo]"
        r"|curl\s+-[sS]*[Oo]\s+https?://"
        r"|nc\s+-[elv]*\s+\d+\.\d+\.\d+",
        re.I
    )),

    ("php_injection", re.compile(
        r"<%3[Ff]php"
        r"|%3c%3fphp"
        r"|\beval\s*\("
        r"|\bbase64_decode\s*\("
        r"|\bsystem\s*\(\s*[\"']"
        r"|\bpassthru\s*\("
        r"|\bshell_exec\s*\("
        r"|\bassert\s*\(\s*\$_",
        re.I
    )),
]


# ──────────────────────────────────────────────────────────────────────────────
# 공격 탐지 함수
# ──────────────────────────────────────────────────────────────────────────────
def _detect_attack(uri: str, user_agent: str) -> tuple[str, str]:
    try:
        decoded = unquote(unquote(uri))
    except Exception:
        decoded = uri

    for attack_type, rx in _ATTACK_PATTERNS:
        m = rx.search(decoded)
        if m:
            start = max(0, m.start() - 20)
            end   = min(len(decoded), m.end() + 20)
            return attack_type, decoded[start:end].strip()[:120]

    return "", ""


# ──────────────────────────────────────────────────────────────────────────────
# 웹쉘 의심 점수 계산
# ──────────────────────────────────────────────────────────────────────────────
def _score_webshell(uri: str, access_count: int, bytes_distinct: int) -> tuple[int, list[str]]:
    flags = []
    path_part = uri.split("?")[0]
    try:
        ext = PurePosixPath(path_part).suffix.lower()
    except Exception:
        ext = ""

    if ext not in _SCRIPT_EXTS:
        return 0, []

    if _KNOWN_WEBSHELL_RE.search(path_part):
        flags.append("known_webshell")

    if _MEDIA_DIR_RE.search(path_part):
        flags.append("script_in_media")
    elif _SUSPICIOUS_PATH_RE.search(path_part):
        flags.append("suspicious_path")

    if access_count >= 10:
        flags.append("high_freq_access")
    elif access_count >= 3:
        flags.append("persistent_access")

    if bytes_distinct >= 3:
        flags.append("variable_response")

    score = sum(_SCORE_TABLE.get(f, 0) for f in flags)
    return score, flags


# ──────────────────────────────────────────────────────────────────────────────
# DB
# ──────────────────────────────────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    # ── apache2_top_ip
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_TOP_IP} (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip       TEXT NOT NULL UNIQUE,
        first_seen   TEXT NOT NULL,
        last_seen    TEXT NOT NULL,
        attack_count INTEGER NOT NULL,
        attack_types TEXT NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_top_ip_ip    ON {TABLE_TOP_IP}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_top_ip_count ON {TABLE_TOP_IP}(attack_count DESC)")

    # ── apache2_attack
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_ATTACK} (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time    TEXT,
        vhost        TEXT,
        src_ip       TEXT,
        method       TEXT,
        uri          TEXT,
        decoded_uri  TEXT,
        status       INTEGER,
        attack_type  TEXT,
        matched_str  TEXT,
        user_agent   TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_attack_ip    ON {TABLE_ATTACK}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_attack_type  ON {TABLE_ATTACK}(attack_type)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_attack_dt    ON {TABLE_ATTACK}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_attack_vhost ON {TABLE_ATTACK}(vhost)")

    # ── apache2_webshell
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_WEBSHELL} (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        vhost            TEXT NOT NULL,
        file_name        TEXT NOT NULL,
        file_path        TEXT NOT NULL,
        src_ip           TEXT NOT NULL,
        first_seen       TEXT NOT NULL,
        last_seen        TEXT NOT NULL,
        access_count     INTEGER NOT NULL,
        bytes_min        INTEGER NOT NULL,
        bytes_max        INTEGER NOT NULL,
        bytes_distinct   INTEGER NOT NULL,
        suspicion_score  INTEGER NOT NULL,
        suspicion_flags  TEXT NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_ws_ip    ON {TABLE_WEBSHELL}(src_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_ws_path  ON {TABLE_WEBSHELL}(file_path)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_apache2_ws_score ON {TABLE_WEBSHELL}(suspicion_score DESC)")

    conn.commit()
    # 에러 로그 테이블 (lazy: 함수 정의는 파일 하단에 있음)
    _ensure_error_table(conn)


# ──────────────────────────────────────────────────────────────────────────────
# INSERT
# ──────────────────────────────────────────────────────────────────────────────
def insert_all(conn: sqlite3.Connection, results: dict):
    if results.get("top_ip"):
        conn.executemany(f"""
        INSERT INTO {TABLE_TOP_IP} (src_ip, first_seen, last_seen, attack_count, attack_types)
        VALUES (?,?,?,?,?)
        """, results["top_ip"])

    if results.get("attack"):
        conn.executemany(f"""
        INSERT INTO {TABLE_ATTACK}
            (date_time, vhost, src_ip, method, uri, decoded_uri, status,
             attack_type, matched_str, user_agent)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """, results["attack"])

    if results.get("webshell"):
        conn.executemany(f"""
        INSERT INTO {TABLE_WEBSHELL}
            (vhost, file_name, file_path, src_ip, first_seen, last_seen,
             access_count, bytes_min, bytes_max, bytes_distinct,
             suspicion_score, suspicion_flags)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, results["webshell"])

    if results.get("error"):
        conn.executemany(f"""
        INSERT INTO {TABLE_ERROR}
            (date_time, level, module, client_ip, error_type, message)
        VALUES (?,?,?,?,?,?)
        """, results["error"])

    conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# 분석 로직
# ──────────────────────────────────────────────────────────────────────────────
def analyze(src_conn: sqlite3.Connection) -> dict[str, list]:
    attack   = _analyze_attack(src_conn)
    webshell = _analyze_webshell(src_conn)
    error    = _analyze_error(src_conn)
    return {
        "top_ip":   _analyze_top_ip(attack),
        "attack":   attack,
        "webshell": webshell,
        "error":    error,
    }


def _analyze_top_ip(attack_rows: list[tuple]) -> list[tuple]:
    """
    공격 탐지 IP별 집계.
    attack_rows 컬럼: (date_time, vhost, src_ip, method, uri, decoded_uri,
                       status, attack_type, matched_str, user_agent)
    """
    bucket: dict[str, dict] = defaultdict(lambda: {
        "first_seen": None, "last_seen": None,
        "req_count": 0, "attack_types": set(),
    })

    for date_time, _, src_ip, _, _, _, _, attack_type, _, _ in attack_rows:
        if not src_ip:
            continue
        b = bucket[src_ip]
        b["req_count"] += 1
        b["attack_types"].add(attack_type)
        if b["first_seen"] is None or date_time < b["first_seen"]:
            b["first_seen"] = date_time
        if b["last_seen"] is None or date_time > b["last_seen"]:
            b["last_seen"] = date_time

    return [
        (ip, v["first_seen"], v["last_seen"], v["req_count"],
         ", ".join(sorted(v["attack_types"])))
        for ip, v in sorted(bucket.items(), key=lambda x: -x[1]["req_count"])
    ]


def _analyze_attack(src_conn: sqlite3.Connection) -> list[tuple]:
    rows = src_conn.execute(f"""
        SELECT date_time, vhost, src_ip, method, uri, status, user_agent
        FROM {SRC_TABLE}
        ORDER BY date_time
    """).fetchall()

    results = []
    for date_time, vhost, src_ip, method, uri, status, user_agent in rows:
        attack_type, matched_str = _detect_attack(uri or "", user_agent or "")
        if not attack_type:
            continue
        try:
            decoded_uri = unquote(unquote(uri or ""))
        except Exception:
            decoded_uri = uri or ""
        results.append((
            date_time, vhost, src_ip, method, uri, decoded_uri,
            status, attack_type, matched_str, user_agent,
        ))
    return results


def _analyze_webshell(src_conn: sqlite3.Connection) -> list[tuple]:
    """POST + 200 요청을 (vhost, src_ip, uri) 단위로 그룹핑하여 웹쉘 의심 항목 탐지."""
    rows = src_conn.execute(f"""
        SELECT date_time, vhost, src_ip, uri, bytes_sent
        FROM {SRC_TABLE}
        WHERE method = 'POST'
          AND status BETWEEN 200 AND 299
        ORDER BY date_time
    """).fetchall()

    # (vhost, src_ip, uri) → 접근 기록 누적
    groups: dict[tuple, dict] = defaultdict(lambda: {
        "vhost": "", "datetimes": [], "bytes": [],
    })
    for date_time, vhost, src_ip, uri, bytes_sent in rows:
        key = (vhost or "", src_ip or "", uri or "")
        groups[key]["vhost"] = vhost or ""
        groups[key]["datetimes"].append(date_time)
        groups[key]["bytes"].append(bytes_sent or 0)

    results = []
    for (vhost, src_ip, uri), data in groups.items():
        access_count   = len(data["datetimes"])
        bytes_list     = data["bytes"]
        bytes_min      = min(bytes_list)
        bytes_max      = max(bytes_list)
        bytes_distinct = len(set(bytes_list))

        score, flags = _score_webshell(uri, access_count, bytes_distinct)
        if score < _MIN_SCORE:
            continue

        path_part = uri.split("?")[0]
        try:
            file_name = PurePosixPath(path_part).name
        except Exception:
            file_name = path_part

        results.append((
            vhost,
            file_name,
            path_part,
            src_ip,
            data["datetimes"][0],    # first_seen
            data["datetimes"][-1],   # last_seen
            access_count,
            bytes_min,
            bytes_max,
            bytes_distinct,
            score,
            ", ".join(flags),
        ))

    results.sort(key=lambda r: (-r[10], -r[6]))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 에러 로그 분석 (apache2_error parser 테이블 → analysis.db apache2_error 테이블)
# ──────────────────────────────────────────────────────────────────────────────

SRC_ERROR_TABLE = "apache2_error"
TABLE_ERROR     = "apache2_error"

# 에러 메시지 분류 패턴 (순서가 곧 우선순위)
_ERROR_CLASSIFY: list[tuple[str, re.Pattern]] = [
    ("attack", re.compile(
        r"(?:\.\.[\\/]){1,}"                   # path traversal
        r"|(?:%2e%2e|%252e%252e)"
        r"|\beval\s*\("                         # code injection
        r"|\bbase64_decode\s*\("
        r"|union\b.{0,30}\bselect\b"            # SQLi
        r"|\$\{.*?jndi"                         # Log4Shell
        r"|/etc/(?:passwd|shadow)"
        r"|/bin/(?:sh|bash)\b"
        r"|cmd\.exe",
        re.I
    )),
    ("php_error", re.compile(
        r"(?:PHP\s+(?:Fatal|Parse|Warning|Notice|Deprecated|Strict)\s+error)"
        r"|(?:Uncaught\s+(?:Error|Exception|TypeError))",
        re.I
    )),
    ("file_not_found", re.compile(
        r"(?:File does not exist|No such file or directory|script not found"
        r"|does not exist in the file system|Symbolic link not allowed)",
        re.I
    )),
    ("permission_denied", re.compile(
        r"(?:Permission denied|access denied|Forbidden|client denied"
        r"|directory index forbidden)",
        re.I
    )),
    ("ssl_tls", re.compile(
        r"(?:SSL|TLS|certificate|handshake|cipher|SNI)",
        re.I
    )),
    ("auth_failure", re.compile(
        r"(?:user .+ authentication failure"
        r"|invalid password|password mismatch"
        r"|failed login|login failed)",
        re.I
    )),
]


def _classify_error(module: str, message: str) -> str:
    for label, rx in _ERROR_CLASSIFY:
        if rx.search(message):
            return label
    # 모듈 기반 폴백
    mod_lower = module.lower()
    if mod_lower.startswith("php"):
        return "php_error"
    if mod_lower in ("ssl", "socache_shmcb"):
        return "ssl_tls"
    return "other"


def _ensure_error_table(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_ERROR} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        date_time   TEXT,
        level       TEXT,
        module      TEXT,
        client_ip   TEXT,
        error_type  TEXT,
        message     TEXT
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_a2err_dt   ON {TABLE_ERROR}(date_time)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_a2err_ip   ON {TABLE_ERROR}(client_ip)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_a2err_type ON {TABLE_ERROR}(error_type)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_a2err_lvl  ON {TABLE_ERROR}(level)")
    conn.commit()


def _analyze_error(src_conn: sqlite3.Connection) -> list[tuple]:
    """
    parser.db apache2_error → 분류된 에러 이벤트 목록 반환.
    비슷한 연속 메시지는 dedup (동일 client_ip + error_type + message[:60]).
    """
    cur = src_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (SRC_ERROR_TABLE,)
    )
    if not cur.fetchone():
        return []

    rows = src_conn.execute(f"""
        SELECT date_time, level, module, client_ip, message
        FROM   {SRC_ERROR_TABLE}
        ORDER  BY date_time
    """).fetchall()

    seen: set[tuple] = set()
    results: list[tuple] = []

    for date_time, level, module, client_ip, message in rows:
        error_type = _classify_error(module or "", message or "")
        dedup_key  = (client_ip or "", error_type, (message or "")[:60])

        # 공격·PHP 에러는 전부 기록, 나머지는 dedup
        if error_type not in ("attack", "php_error") and dedup_key in seen:
            continue
        seen.add(dedup_key)

        results.append((
            date_time,
            level,
            module,
            client_ip or "",
            error_type,
            (message or "")[:300],
        ))

    return results
