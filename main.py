"""
main.py - Linux-Analysis 진입점

target 폴더에서 로그를 탐색·파싱하여 parser.db 에 저장.

지원 로그 → parser.db 테이블:
  audit        : audit.log, audit.log-*
  authlog      : auth.log* (Debian) / secure, secure-* (RHEL)
  wtmp         : wtmp, wtmp.[0-9]*, wtmp-*
  btmp         : btmp, btmp.[0-9]*, btmp-*
  journal      : *.journal
  cron         : cron, cron-* (RHEL) / cron.log, cron.log.[0-9]* (Debian)
  shell_history: .bash_history, .zsh_history
  syslog       : syslog, syslog.[0-9]* (Debian) / messages, messages-* (RHEL)
  apache2      : *access.log*, *access_log*
  apache2_error: *error.log*, *error_log*
  nginx        : access.log*, access_log*
  nginx_error  : error.log*, error_log*
  kernlog      : kern.log*
  mysql_query  : query.log*
  mysql_error  : error.log*

parser.db 공통:
  - info    테이블: 파싱한 파일의 메타정보 (파일명, MD5, 크기) — 동일 MD5 재파싱 방지
  - sysinfo 테이블: 호스트명·IP·OS·커널·CPU·디스크·부팅 시각 등 (Volatile/NonVolatile 덤프 기반)
  - .gz / .tar.gz / .tgz 압축 파일은 임시 디렉토리에 해제 후 파싱
"""

import shutil
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

import parser.auditlog     as auditlog
import parser.authlog      as authlog
import parser.wtmp         as wtmpmod
import parser.journald     as journald
import parser.cron         as cronmod
import parser.shellhistory as shellhistory
import parser.syslog       as syslogmod
import parser.apache2log   as apache2log
import parser.nginxlog     as nginxlog
import parser.kernlog      as kernlog
import parser.mysqllog     as mysqlmod
import analyzer.sysinfo   as sysinfo_analyzer
import analyzer.dashboard as dashboard_analyzer
from parser.utils.files import md5 as file_md5, is_compressed, decompress

# ── 설정 ──────────────────────────────────────────────
TARGET_DIR = Path("target")
PARSER_DB  = Path("parser.db")
DECOMP_DIR = Path(".decomp")   # 압축 해제 임시 디렉토리

LOG_TARGETS = [
    {"name": "audit",   "glob": auditlog.AUDIT_LOG_GLOB, "module": auditlog},
    # Debian: auth.log, auth.log.1 ...  /  RHEL: secure, secure-20240101
    {"name": "authlog", "globs": [authlog.AUTH_LOG_GLOB,
                                   authlog.SECURE_LOG,
                                   authlog.SECURE_LOG_GLOB], "module": authlog},
    # wtmp: 로그인/로그아웃/부팅 이력 (바이너리)
    {"name": "wtmp",    "globs": [wtmpmod.WTMP_LOG,
                                   wtmpmod.WTMP_GLOB_NUM,
                                   wtmpmod.WTMP_GLOB_DATE], "module": wtmpmod},
    # btmp: 실패한 로그인 시도 (바이너리, wtmp와 동일 포맷)
    {"name": "btmp",    "globs": [wtmpmod.BTMP_LOG,
                                   wtmpmod.BTMP_GLOB_NUM,
                                   wtmpmod.BTMP_GLOB_DATE], "module": wtmpmod,
     "ensure_db_fn": wtmpmod.ensure_db_btmp,
     "to_row_fn":    wtmpmod.to_row_btmp,
     "insert_fn":    wtmpmod.insert_rows_btmp},
    # journald: systemd 바이너리 저널 (target/ 하위 *.journal 전체 탐색)
    {"name": "journal", "glob": journald.JOURNAL_GLOB, "module": journald},
    # cron: RHEL(cron, cron-*) / Debian(cron.log, cron.log.N)
    {"name": "cron", "globs": [cronmod.CRON_LOG,
                                cronmod.CRON_LOG_GLOB,
                                cronmod.CRON_LOG_DEBIAN,
                                cronmod.CRON_LOG_DEB_GLOB], "module": cronmod},
    # shell history: bash (.bash_history) / zsh (.zsh_history)
    {"name": "shell_history", "globs": [shellhistory.BASH_HISTORY,
                                         shellhistory.ZSH_HISTORY], "module": shellhistory},
    # syslog/messages: Debian(syslog, syslog.N) / RHEL(messages, messages-YYYYMMDD)
    {"name": "syslog", "globs": [syslogmod.SYSLOG_LOG,
                                  syslogmod.SYSLOG_LOG_GLOB,
                                  syslogmod.MESSAGES_LOG,
                                  syslogmod.MESSAGES_LOG_GLOB], "module": syslogmod},
    # apache2 접근 로그: *access.log* / *access_log*
    {"name": "apache2", "globs": apache2log.APACHE2_ACCESS_GLOBS, "module": apache2log,
     "defer_commit":      True,
     "ensure_indexes_fn": apache2log.ensure_indexes},
    # apache2 에러 로그: *error.log* / *error_log*
    {"name": "apache2_error", "globs": apache2log.APACHE2_ERROR_GLOBS, "module": apache2log,
     "parse_fn":          apache2log.parse_error,
     "to_row_fn":         apache2log.to_row_error,
     "insert_fn":         apache2log.insert_rows_error,
     "ensure_db_fn":      apache2log.ensure_db_error,
     "defer_commit":      True,
     "ensure_indexes_fn": apache2log.ensure_indexes_error},
    # nginx 접근 로그: access.log* / access_log*
    {"name": "nginx", "globs": nginxlog.NGINX_ACCESS_GLOBS, "module": nginxlog,
     "defer_commit":      True,
     "ensure_indexes_fn": nginxlog.ensure_indexes},
    # nginx 에러 로그: error.log* / error_log*
    {"name": "nginx_error", "globs": nginxlog.NGINX_ERROR_GLOBS, "module": nginxlog,
     "parse_fn":          nginxlog.parse_error,
     "to_row_fn":         nginxlog.to_row_error,
     "insert_fn":         nginxlog.insert_rows_error,
     "ensure_db_fn":      nginxlog.ensure_db_error,
     "defer_commit":      True,
     "ensure_indexes_fn": nginxlog.ensure_indexes_error},
    # kern.log: Debian ISO 8601 커널 메시지
    {"name": "kernlog", "glob": kernlog.KERN_LOG_GLOB, "module": kernlog},
    # MySQL General Query Log: query.log*
    {"name": "mysql_query", "glob": mysqlmod.MYSQL_QUERY_GLOB, "module": mysqlmod,
     "parse_fn":  mysqlmod.parse_query,
     "to_row_fn": mysqlmod.to_row_query,
     "insert_fn": mysqlmod.insert_rows_query},
    # MySQL Error Log: error.log*
    {"name": "mysql_error", "glob": mysqlmod.MYSQL_ERROR_GLOB, "module": mysqlmod,
     "parse_fn":  mysqlmod.parse_error,
     "to_row_fn": mysqlmod.to_row_error,
     "insert_fn": mysqlmod.insert_rows_error},
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
        for f in sorted(base.rglob(glob + ".gz")):
            if f.is_file() and f not in seen:
                seen.add(f); result.append(f)
    return result


def cleanup_decomp():
    if DECOMP_DIR.exists():
        shutil.rmtree(DECOMP_DIR)


# 경로 힌트로 파서 간 글로브 충돌 해소 (특히 apache2 vs nginx).
# apache2 글로브 `*access.log*` 는 nginx 파일까지 잡아채므로,
# 디렉토리에 /nginx/ 가 들어가면 apache2 후보에서 제거하고 반대도 동일.
_PARSER_PATH_EXCLUDE = {
    "apache2":       ("/nginx/",),
    "apache2_error": ("/nginx/",),
    "nginx":         ("/apache2/", "/httpd/"),
    "nginx_error":   ("/apache2/", "/httpd/"),
}

def _filter_by_parser_path(name: str, files: list[Path]) -> list[Path]:
    excludes = _PARSER_PATH_EXCLUDE.get(name)
    if not excludes:
        return files
    def keep(p: Path) -> bool:
        s = str(p).replace("\\", "/").lower()
        return not any(ex in s for ex in excludes)
    return [f for f in files if keep(f)]


# 대량 삽입 동안 한 트랜잭션에 묶을 행 수. WAL 크기를 제한하면서
# commit(=fsync) 횟수를 (기존 1,000행마다 → 10만 행마다)로 대폭 줄임.
COMMIT_EVERY = 100_000


def _tune_connection(conn: sqlite3.Connection):
    """
    대량 삽입용 PRAGMA 튜닝.
      - WAL          : 쓰기/읽기 동시성↑, 롤백 저널 대비 빠름
      - synchronous=NORMAL : WAL과 함께 쓰면 충돌 안전성 유지하며 fsync 감소
      - cache_size   : 256MB 페이지 캐시 (음수 = KiB 단위)
      - temp_store   : 임시 B-tree/정렬을 메모리에 둠
    DB·연결 레벨 설정이라 모든 파서에 공통 이득 (파싱 로직은 불변).
    """
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-262144")   # 256 MiB
    conn.execute("PRAGMA temp_store=MEMORY")


# ── 파싱 ──────────────────────────────────────────────
def scan(base: Path) -> dict:
    found = {}
    for target in LOG_TARGETS:
        sd = target.get("search_dir", base)
        if callable(sd):
            sd = sd()
        search_base = sd if sd is not None else base
        globs = target.get("globs") or target.get("glob", "")
        files = find_files(search_base, globs)
        files = _filter_by_parser_path(target["name"], files)
        found[target["name"]] = {
            "files":  files,
            "module": target["module"],
            "target": target,
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
    _tune_connection(conn)
    ensure_info_table(conn)

    try:
        for name, info in available.items():
            _process_parse(conn, name, info["files"], info["module"], info["target"])

        # 시스템 정보 (Volatile/NonVolatile 덤프 파일이 있을 때만)
        if (TARGET_DIR / "Volatile").exists() or (TARGET_DIR / "NonVolatile").exists():
            print("\n[SYSINFO] 시스템 정보 수집 중...")
            sysinfo_analyzer.run(conn)
        else:
            print("\n[SYSINFO] Volatile/NonVolatile 없음 → 건너뜁니다.")

        # 대시보드 페이로드 사전 계산 → 뷰어 진입 시 즉시 렌더
        print("\n[DASHBOARD] 사전 계산 중...")
        dashboard_analyzer.run(conn)

        # 옛 DB 에 남아 있는 IP 분석 산물 정리 (현재는 미사용)
        try:
            conn.execute("DROP TABLE IF EXISTS ip_summary")
            conn.commit()
        except Exception:
            pass

        # IP enrich(IPinfo) 는 뷰어에서 'IP 정보 채우기' 버튼으로 진행 → 파서는 빠르게 끝.
    finally:
        conn.close()
        cleanup_decomp()

    print(f"\n[DONE] {PARSER_DB.resolve()}")


def _resolve_file(f: Path) -> tuple[Path, bool]:
    if not is_compressed(f):
        return f, False
    dest = DECOMP_DIR / f.stem
    extracted = decompress(f, dest)
    if not extracted:
        return f, False
    return extracted[0], True


def _process_parse(conn: sqlite3.Connection, name: str, files: list[Path], mod,
                   target: dict | None = None):
    print(f"\n[{name.upper()}] {len(files)}개 파일 확인 중...")
    ensure_db_fn = target.get("ensure_db_fn", mod.ensure_db) if target else mod.ensure_db
    ensure_db_fn(conn)

    target       = target or {}
    parse_fn     = target["parse_fn"]  if "parse_fn"  in target else mod.parse
    to_row_fn    = target["to_row_fn"] if "to_row_fn" in target else mod.to_row
    insert_fn    = target["insert_fn"] if "insert_fn" in target else mod.insert_rows
    # 웹 로그 등 insert_fn이 스스로 commit하지 않는 파서: 여기서 주기적으로 묶어 커밋
    defer_commit      = bool(target.get("defer_commit"))
    ensure_indexes_fn = target.get("ensure_indexes_fn")

    total = 0
    for f in files:
        checksum = file_md5(f)

        if is_already_parsed(conn, checksum):
            print(f"  [SKIP] {f.name} (MD5: {checksum[:8]}... 이미 파싱됨)")
            continue

        file_mtime = datetime.fromtimestamp(f.stat().st_mtime)

        parse_target, was_decompressed = _resolve_file(f)
        label = f"{f.name} → {parse_target.name}" if was_decompressed else f.name
        print(f"  [PARSING] {label}  MD5: {checksum}  SIZE: {f.stat().st_size:,} bytes")

        try:
            batch = []
            since_commit = 0
            parse_kwargs = {}
            if name in ("authlog", "syslog", "cron"):
                parse_kwargs["file_mtime"] = file_mtime

            for entry in parse_fn(parse_target, **parse_kwargs):
                batch.append(to_row_fn(entry))
                if len(batch) >= 1000:
                    insert_fn(conn, batch)
                    total        += len(batch)
                    since_commit += len(batch)
                    batch.clear()
                    # WAL이 무한정 커지지 않도록 일정 행마다 한 번씩만 커밋
                    if defer_commit and since_commit >= COMMIT_EVERY:
                        conn.commit()
                        since_commit = 0
            if batch:
                insert_fn(conn, batch)
                total += len(batch)

            # 파일 단위로 info 기록 + 커밋(남은 미커밋 행까지 함께 flush)
            insert_info(conn, f, checksum, name)

        except Exception as e:
            # 이 파일에서 아직 커밋되지 않은 부분 삽입은 폐기
            conn.rollback()
            print(f"  [WARN] {f.name}: {e}")

    # 대량 삽입이 모두 끝난 뒤 인덱스를 1회 구축 (삽입 중 B-tree 갱신 비용 제거)
    if ensure_indexes_fn:
        print(f"  [INDEX] {name} 인덱스 생성 중...")
        ensure_indexes_fn(conn)

    print(f"[{name.upper()}] {total}건 신규 저장 완료")


if __name__ == "__main__":
    parse_logs()
