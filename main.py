"""
main.py - Linux-Analysis 진입점

[1단계] 파싱: target 폴더에서 로그 탐색 후 parser.db 에 저장
[2단계] 분석: parser.db 를 읽어 보안 위협 분석 후 analysis.db 에 저장

지원 로그:
  - audit.log*   → parser.db :: audit   테이블
  - auth.log*    → parser.db :: authlog 테이블
  - access.log*  → parser.db :: nginx   테이블 (2xx 성공 요청만 저장)

parser.db 공통:
  - info 테이블: 파싱한 파일의 메타정보 (파일명, MD5, 크기)
    → 동일 MD5 파일은 재파싱 건너뜀

분석기:
  - sysinfo     → analysis.db :: info 테이블
  - authlog     → analysis.db :: authlog_* 테이블
  - audit       → analysis.db :: audit_* 테이블
  - cron        → analysis.db :: cron_info 테이블 (audit 테이블 기반)
  - nginx       → analysis.db :: nginx_* 테이블

실행 시:
  - analysis.db 는 항상 새로 생성 (기존 파일 삭제)
  - .gz / .tar.gz / .tgz 압축 파일은 임시 디렉토리에 해제 후 파싱
"""

import shutil
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

import parser.auditlog    as auditlog
import parser.authlog     as authlog
import parser.nginxlog    as nginxlog
import parser.syslog      as syslogmod
import parser.apache2log  as apache2log
import parser.mysqllog    as mysqllog
import parser.kernlog     as kernlogmod
import analyzer.authlog   as authlog_analyzer
import analyzer.auditlog  as auditlog_analyzer
import analyzer.cron      as cron_analyzer
import analyzer.sysinfo   as sysinfo_analyzer
import analyzer.nginxlog  as nginxlog_analyzer
import analyzer.syslog    as syslog_analyzer
import analyzer.apache2log as apache2log_analyzer
import analyzer.mysqllog  as mysqllog_analyzer
import analyzer.kernlog   as kernlog_analyzer
import analyzer.volatile  as volatile_analyzer
import analyzer.dpkg      as dpkg_analyzer
import analyzer.loginfo       as loginfo_analyzer
import analyzer.supertimeline as supertimeline_analyzer
from parser.utils.files import md5 as file_md5, is_compressed, decompress

# ── 설정 ──────────────────────────────────────────────
TARGET_DIR   = Path("target")
PARSER_DB    = Path("parser.db")
ANALYSIS_DB  = Path("analysis.db")
DECOMP_DIR   = Path(".decomp")   # 압축 해제 임시 디렉토리

LOG_TARGETS = [
    {"name": "audit",   "glob": auditlog.AUDIT_LOG_GLOB,   "module": auditlog},
    {"name": "authlog", "glob": authlog.AUTH_LOG_GLOB,     "module": authlog},
    # nginx: access.log* glob 충돌 방지 → nginx 디렉토리만 탐색
    # find_log_dir 로 NonVolatile/var/log/ 없어도 자동 탐색
    {"name": "nginx",   "glob": nginxlog.NGINX_LOG_GLOB,   "module": nginxlog,
     "search_dir": lambda: find_log_dir("nginx")},
    {"name": "syslog",  "glob": syslogmod.SYSLOG_LOG_GLOB, "module": syslogmod},
    # apache2 접근 로그: .log / _log 변형 모두 처리, 디렉토리 동적 탐색
    {"name": "apache2", "globs": apache2log.APACHE2_ACCESS_GLOBS, "module": apache2log,
     "search_dir": lambda: find_log_dir("apache2")},
    # apache2 에러 로그: error.log / error_log 변형 모두 처리
    {"name": "apache2_error", "globs": apache2log.APACHE2_ERROR_GLOBS, "module": apache2log,
     "parse_fn":      apache2log.parse_error,
     "to_row_fn":     apache2log.to_row_error,
     "insert_fn":     apache2log.insert_rows_error,
     "ensure_db_fn":  apache2log.ensure_db_error,
     "search_dir":    lambda: find_log_dir("apache2")},
    # mysql: query.log / error.log 를 각각 파싱
    {"name": "mysql_query", "glob": mysqllog.MYSQL_QUERY_GLOB, "module": mysqllog,
     "parse_fn": mysqllog.parse_query, "to_row_fn": mysqllog.to_row_query,
     "insert_fn": mysqllog.insert_rows_query,
     "search_dir": lambda: find_log_dir("mysql")},
    {"name": "mysql_error", "glob": mysqllog.MYSQL_ERROR_GLOB, "module": mysqllog,
     "parse_fn": mysqllog.parse_error, "to_row_fn": mysqllog.to_row_error,
     "insert_fn": mysqllog.insert_rows_error,
     "search_dir": lambda: find_log_dir("mysql")},
    # kern.log: syslog 와 같은 디렉토리, UFW 제외한 커널 이벤트
    {"name": "kernlog", "glob": kernlogmod.KERN_LOG_GLOB, "module": kernlogmod,
     "search_dir": lambda: find_log_dir("log") or TARGET_DIR / "NonVolatile/var/log"},
]

ANALYZERS = [
    {"name": "authlog", "src_table": "authlog", "module": authlog_analyzer},
    {"name": "audit",   "src_table": "audit",   "module": auditlog_analyzer},
    {"name": "cron",    "src_table": "audit",   "module": cron_analyzer},
    {"name": "nginx",   "src_table": "nginx",   "module": nginxlog_analyzer},
    {"name": "syslog",  "src_table": "syslog",  "module": syslog_analyzer},
    {"name": "apache2", "src_table": "apache2",     "module": apache2log_analyzer},
    {"name": "mysql",   "src_table": "mysql_query", "module": mysqllog_analyzer},
    {"name": "kernlog", "src_table": "kernlog",     "module": kernlog_analyzer},
]


# ── info 테이블 ───────────────────────────────────────
def ensure_info_table(conn: sqlite3.Connection):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS info (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        file_name   TEXT NOT NULL,
        file_path   TEXT NOT NULL,
        md5         TEXT NOT NULL UNIQUE,
        file_size   INTEGER NOT NULL,
        log_type    TEXT NOT NULL,
        parsed_at   TEXT NOT NULL
    )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_info_md5      ON info(md5)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_info_log_type ON info(log_type)")
    conn.commit()


def is_already_parsed(conn: sqlite3.Connection, checksum: str) -> bool:
    cur = conn.execute("SELECT 1 FROM info WHERE md5 = ?", (checksum,))
    return cur.fetchone() is not None


def insert_info(conn: sqlite3.Connection, file_path: Path, checksum: str, log_type: str):
    conn.execute("""
    INSERT INTO info (file_name, file_path, md5, file_size, log_type, parsed_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        file_path.name,
        str(file_path),
        checksum,
        file_path.stat().st_size,
        log_type,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()


# ── 유틸 ──────────────────────────────────────────────
def find_files(base: Path | None, globs: str | list[str]) -> list[Path]:
    """
    glob 패턴(단일 str 또는 list[str])으로 파일 탐색.
    .gz 압축본도 자동 포함. base 가 None 이거나 존재하지 않으면 빈 리스트 반환.
    """
    if isinstance(globs, str):
        globs = [globs]
    if not base or not base.exists() or not base.is_dir():
        return []
    seen: set[Path] = set()
    result: list[Path] = []
    for glob in globs:
        for f in sorted(base.rglob(glob)):
            if f.is_file() and f not in seen:
                seen.add(f); result.append(f)
        # .gz 압축본: auth.log.2.gz 등
        for f in sorted(base.rglob(glob + ".gz")):
            if f.is_file() and f not in seen:
                seen.add(f); result.append(f)
    return result


def find_log_dir(dirname: str) -> Path | None:
    """
    target/ 하위 어디서든 dirname 이름의 디렉토리를 탐색하여 반환.
    NonVolatile/var/log/ 접두사가 없어도 발견 가능.
    예: find_log_dir("apache2") → target/NonVolatile/var/log/apache2
                                또는 target/apache2 등
    """
    for d in sorted(TARGET_DIR.rglob(dirname)):
        if d.is_dir():
            return d
    return None


def reset_analysis_db():
    """analysis.db 를 항상 새로 시작"""
    if ANALYSIS_DB.exists():
        ANALYSIS_DB.unlink()
        print(f"[RESET] {ANALYSIS_DB} 삭제 완료")


def cleanup_decomp():
    """임시 압축 해제 디렉토리 정리"""
    if DECOMP_DIR.exists():
        shutil.rmtree(DECOMP_DIR)


# ── 1단계: 파싱 ───────────────────────────────────────
def scan(base: Path) -> dict:
    found = {}
    for target in LOG_TARGETS:
        sd = target.get("search_dir", base)
        # callable → 실행 시점에 경로 결정 (find_log_dir 람다)
        if callable(sd):
            sd = sd()
        search_base = sd if sd is not None else base
        globs = target.get("globs") or target.get("glob", "")
        files = find_files(search_base, globs)
        found[target["name"]] = {
            "files":  files,
            "module": target["module"],
            "target": target,   # parse_fn / to_row_fn / insert_fn / ensure_db_fn 오버라이드 포함
        }
    return found


def parse_logs():
    if not TARGET_DIR.exists() or not TARGET_DIR.is_dir():
        print(f"[ERROR] target 폴더를 찾을 수 없습니다: {TARGET_DIR.resolve()}")
        sys.exit(1)

    print(f"[TARGET] {TARGET_DIR.resolve()}")

    found       = scan(TARGET_DIR)
    available   = {k: v for k, v in found.items() if v["files"]}
    unavailable = [k for k, v in found.items() if not v["files"]]

    if unavailable:
        print(f"[SKIP] 파일 없음: {', '.join(unavailable)}")

    if not available:
        print("[INFO] 파싱할 로그 파일이 없습니다.")
        sys.exit(0)

    print(f"[FOUND] 파싱 대상: {', '.join(available.keys())}")

    PARSER_DB.touch(exist_ok=True)
    conn = sqlite3.connect(PARSER_DB)
    ensure_info_table(conn)

    try:
        for name, info in available.items():
            _process_parse(conn, name, info["files"], info["module"], info["target"])
    finally:
        conn.close()
        cleanup_decomp()

    print(f"\n[PARSE DONE] {PARSER_DB.resolve()}")


def _resolve_file(f: Path) -> tuple[Path, bool]:
    """
    압축 파일이면 임시 디렉토리에 해제 후 (해제된 파일 경로, True) 반환.
    일반 파일이면 (원본 경로, False) 반환.
    해제된 파일이 여러 개인 경우 첫 번째만 반환 (단일 gz 는 항상 1개).
    """
    if not is_compressed(f):
        return f, False

    dest = DECOMP_DIR / f.stem  # 각 압축 파일마다 고유 서브디렉토리
    extracted = decompress(f, dest)
    if not extracted:
        return f, False
    return extracted[0], True


def _process_parse(conn: sqlite3.Connection, name: str, files: list[Path], mod,
                   target: dict | None = None):
    print(f"\n[{name.upper()}] {len(files)}개 파일 확인 중...")
    # ensure_db_fn 오버라이드: 동일 모듈의 서브 파서(apache2_error 등)에서 사용
    ensure_db_fn = target.get("ensure_db_fn", mod.ensure_db) if target else mod.ensure_db
    ensure_db_fn(conn)

    # parse_fn / to_row_fn / insert_fn 은 LOG_TARGET 에서 오버라이드 가능
    # (mysql_query / mysql_error 처럼 동일 모듈에서 다른 함수 사용 시)
    # ※ dict.get(key, mod.attr) 은 default 를 항상 평가하므로 조건식 사용
    target    = target or {}
    parse_fn  = target["parse_fn"]   if "parse_fn"   in target else mod.parse
    to_row_fn = target["to_row_fn"]  if "to_row_fn"  in target else mod.to_row
    insert_fn = target["insert_fn"]  if "insert_fn"  in target else mod.insert_rows

    total = 0
    for f in files:
        # 압축 파일이면 MD5는 원본 압축 파일 기준으로 체크
        checksum = file_md5(f)

        if is_already_parsed(conn, checksum):
            print(f"  [SKIP] {f.name} (MD5: {checksum[:8]}... 이미 파싱됨)")
            continue

        # 원본 파일의 mtime 기록 (압축 해제 전)
        file_mtime = datetime.fromtimestamp(f.stat().st_mtime)

        # 압축 해제 (필요 시)
        parse_target, was_decompressed = _resolve_file(f)
        label = f"{f.name} → {parse_target.name}" if was_decompressed else f.name
        print(f"  [PARSING] {label}  MD5: {checksum}  SIZE: {f.stat().st_size:,} bytes")

        try:
            batch = []
            # authlog / syslog 모듈은 file_mtime 을 받아 연도를 추론
            parse_kwargs = {}
            if name in ("authlog", "syslog"):
                parse_kwargs["file_mtime"] = file_mtime

            for entry in parse_fn(parse_target, **parse_kwargs):
                batch.append(to_row_fn(entry))
                if len(batch) >= 1000:
                    insert_fn(conn, batch)
                    total += len(batch)
                    batch.clear()
            if batch:
                insert_fn(conn, batch)
                total += len(batch)

            insert_info(conn, f, checksum, name)

        except Exception as e:
            print(f"  [WARN] {f.name}: {e}")

    print(f"[{name.upper()}] {total}건 신규 저장 완료")


# ── 2단계: 분석 ───────────────────────────────────────
def analyze_logs():
    if not PARSER_DB.exists():
        print(f"[ERROR] parser.db 없음. 먼저 파싱을 실행하세요.")
        sys.exit(1)

    print(f"\n[ANALYZE] {PARSER_DB.resolve()} 분석 시작")

    src_conn  = sqlite3.connect(PARSER_DB)
    ANALYSIS_DB.touch(exist_ok=True)
    dest_conn = sqlite3.connect(ANALYSIS_DB)

    # ── 서버 기본 정보 info 테이블 (아티팩트가 있을 때만) ──
    if Path("target/Volatile").exists() or Path("target/NonVolatile").exists():
        print("\n[INFO] 서버 기본 정보 수집 중...")
        sysinfo_analyzer.run(dest_conn)
    else:
        print("\n[INFO] Volatile/NonVolatile 없음 → sysinfo 건너뜁니다.")

    for item in ANALYZERS:
        name = item["name"]
        mod  = item["module"]

        cur = src_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (item["src_table"],)
        )
        if not cur.fetchone():
            print(f"[SKIP] {name}: parser.db 에 '{item['src_table']}' 테이블 없음")
            continue

        print(f"\n[{name.upper()}] 분석 중...")
        mod.ensure_db(dest_conn)

        result = mod.analyze(src_conn)
        mod.insert_all(dest_conn, result)

        table_labels = {
            "authlog": [("login", "authlog_login"), ("sudo", "authlog_sudo"),
                        ("attack_ip", "authlog_attack_ip"), ("su", "authlog_su"),
                        ("bruteforce", "authlog_bruteforce")],
            "audit":   [("login", "audit_login"), ("cmd", "audit_cmd"),
                        ("file", "audit_file")],
            "cron":    [("info", "cron_info")],
            "nginx":   [("top_ip", "nginx_top_ip"), ("attack", "nginx_attack"), ("webshell", "nginx_webshell")],
            "syslog":  [("cron", "syslog_cron"), ("ufw", "syslog_ufw"), ("service", "syslog_service")],
            "apache2": [("top_ip", "apache2_top_ip"), ("attack", "apache2_attack"),
                        ("webshell", "apache2_webshell"), ("error", "apache2_error")],
            "mysql":   [("sqli", "mysql_sqli")],
            "kernlog": [("apparmor", "kernlog_apparmor"), ("boot", "kernlog_boot")],
        }
        for key, label in table_labels.get(name, []):
            cnt = len(result.get(key, []))
            if cnt:
                print(f"  {label}: {cnt}건")

    # ── Volatile 아티팩트 분석 ────────────────────────────
    if Path("target/Volatile").exists():
        print("\n[VOLATILE] 소켓/프로세스/모듈 분석 중...")
        vr = volatile_analyzer.run(dest_conn)
        print(f"  volatile_sockets  : {len(vr['sockets']):,}건  "
              f"(위험: {sum(1 for r in vr['sockets']   if r[7])}건)")
        print(f"  volatile_processes: {len(vr['processes']):,}건  "
              f"(위험: {sum(1 for r in vr['processes'] if r[5])}건)")
        print(f"  volatile_modules  : {len(vr['modules']):,}건  "
              f"(위험: {sum(1 for r in vr['modules']   if r[3])}건)")
    else:
        print("\n[VOLATILE] target/Volatile 없음 → 건너뜁니다.")

    # ── dpkg 패키지 분석 ──────────────────────────────────
    dpkg_src = Path("target/NonVolatile/dpkg_dmp")
    if dpkg_src.exists():
        print("\n[DPKG] 설치된 패키지에서 공격 도구 탐지 중...")
        dr = dpkg_analyzer.run(dest_conn)
        print(f"  dpkg_suspicious   : {len(dr):,}건")
        for row in dr:
            print(f"    {row[0]:<30}  [{row[5]}]  {row[4]}")
    else:
        print("\n[DPKG] dpkg_dmp 없음 → 건너뜁니다.")

    # ── 로그 요약 log 테이블 ─────────────────────────────
    print("\n[LOG] 로그 요약 정보 수집 중...")
    loginfo_analyzer.run(dest_conn, src_conn)

    # ── 위협 통합 타임라인 (모든 분석 완료 후 마지막 실행) ─
    print("\n[SUPERTIMELINE] 위협 통합 타임라인 생성 중...")
    st_cnt = supertimeline_analyzer.run(dest_conn, src_conn)   # src_conn: 개별 로그인 이벤트
    print(f"[SUPERTIMELINE] {st_cnt:,}건 저장 완료")

    src_conn.close()
    dest_conn.close()
    print(f"\n[ANALYZE DONE] {ANALYSIS_DB.resolve()}")


# ── 메인 ──────────────────────────────────────────────
def run():
    reset_analysis_db()   # analysis.db 항상 새로 시작
    parse_logs()
    analyze_logs()


if __name__ == "__main__":
    run()
