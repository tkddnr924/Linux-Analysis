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

실행 시:
  - analysis.db 는 항상 새로 생성 (기존 파일 삭제)
  - .gz / .tar.gz / .tgz 압축 파일은 임시 디렉토리에 해제 후 파싱
"""

import shutil
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

import parser.auditlog   as auditlog
import parser.authlog    as authlog
import parser.nginxlog   as nginxlog
import analyzer.authlog  as authlog_analyzer
import analyzer.auditlog as auditlog_analyzer
import analyzer.sysinfo  as sysinfo_analyzer
import analyzer.nginxlog as nginxlog_analyzer
import analyzer.loginfo  as loginfo_analyzer
from parser.utils.files import md5 as file_md5, is_compressed, decompress

# ── 설정 ──────────────────────────────────────────────
TARGET_DIR   = Path("target")
PARSER_DB    = Path("parser.db")
ANALYSIS_DB  = Path("analysis.db")
DECOMP_DIR   = Path(".decomp")   # 압축 해제 임시 디렉토리

LOG_TARGETS = [
    {"name": "audit",   "glob": auditlog.AUDIT_LOG_GLOB,   "module": auditlog},
    {"name": "authlog", "glob": authlog.AUTH_LOG_GLOB,     "module": authlog},
    {"name": "nginx",   "glob": nginxlog.NGINX_LOG_GLOB,   "module": nginxlog,
     "search_dir": Path("target/NonVolatile/var/log/nginx")},
]

ANALYZERS = [
    {"name": "authlog", "src_table": "authlog", "module": authlog_analyzer},
    {"name": "audit",   "src_table": "audit",   "module": auditlog_analyzer},
    {"name": "nginx",   "src_table": "nginx",   "module": nginxlog_analyzer},
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
def find_files(base: Path, glob: str) -> list[Path]:
    """glob 패턴으로 파일 탐색 (압축 파일 포함 .gz 변형도 탐색)"""
    files = sorted(base.rglob(glob))
    # .gz 압축본도 탐색: auth.log.2.gz 등
    files += sorted(f for f in base.rglob(glob + ".gz") if f not in files)
    return files


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
        search_base = target.get("search_dir", base)
        files = find_files(search_base, target["glob"])
        found[target["name"]] = {"files": files, "module": target["module"]}
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
            _process_parse(conn, name, info["files"], info["module"])
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


def _process_parse(conn: sqlite3.Connection, name: str, files: list[Path], mod):
    print(f"\n[{name.upper()}] {len(files)}개 파일 확인 중...")
    mod.ensure_db(conn)

    total = 0
    for f in files:
        # 압축 파일이면 MD5는 원본 압축 파일 기준으로 체크
        checksum = file_md5(f)

        if is_already_parsed(conn, checksum):
            print(f"  [SKIP] {f.name} (MD5: {checksum[:8]}... 이미 파싱됨)")
            continue

        # 압축 해제 (필요 시)
        parse_target, was_decompressed = _resolve_file(f)
        label = f"{f.name} → {parse_target.name}" if was_decompressed else f.name
        print(f"  [PARSING] {label}  MD5: {checksum}  SIZE: {f.stat().st_size:,} bytes")

        try:
            batch = []
            for entry in mod.parse(parse_target):
                batch.append(mod.to_row(entry))
                if len(batch) >= 1000:
                    mod.insert_rows(conn, batch)
                    total += len(batch)
                    batch.clear()
            if batch:
                mod.insert_rows(conn, batch)
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

    # ── 서버 기본 정보 info 테이블 ──────────────────────
    print("\n[INFO] 서버 기본 정보 수집 중...")
    sysinfo_analyzer.run(dest_conn)

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
                        ("attack_ip", "authlog_attack_ip"), ("su", "authlog_su")],
            "audit":   [("login", "audit_login"), ("cmd", "audit_cmd"),
                        ("file", "audit_file")],
            "nginx":   [("top_ip", "nginx_top_ip"), ("attack", "nginx_attack"), ("webshell", "nginx_webshell")],
        }
        for key, label in table_labels.get(name, []):
            cnt = len(result.get(key, []))
            if cnt:
                print(f"  {label}: {cnt}건")

    # ── 로그 요약 log 테이블 ─────────────────────────────
    print("\n[LOG] 로그 요약 정보 수집 중...")
    loginfo_analyzer.run(dest_conn, src_conn)

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
