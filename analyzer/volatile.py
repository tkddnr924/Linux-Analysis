"""
analyzer/volatile.py - Volatile 아티팩트 분석

  openedsocket_dmp : 열린 소켓/포트 (lsof -i 출력)
                     → analysis.db :: volatile_sockets
  ps_dmp           : 실행 중인 프로세스 (ps -elf 출력)
                     → analysis.db :: volatile_processes
  module_dmp       : 커널 모듈 목록 (lsmod 출력)
                     → analysis.db :: volatile_modules

파일 시스템에서 직접 읽으므로 parser.db 를 사용하지 않습니다.
"""

import sqlite3
from pathlib import Path

_VOLATILE = Path("target/Volatile")

# ── 탐지 기준 ─────────────────────────────────────────

# 일반적으로 사용되는 정상 LISTEN 포트 (이 외의 포트는 위험 표시)
_KNOWN_PORTS = {
    '21', '22', '25', '53', '80', '110', '123', '143',
    '389', '443', '465', '587', '636', '993', '995',
    '2222',    # SSH 대체 포트 (흔히 사용)
    '3306', '3389', '5432', '5900', '6379',
    '8080', '8443', '8888', '9000', '9090', '9200', '9443',
    '27017', '33060',
}

# 의심 프로세스 이름 (정확히 일치)
_SUSP_PROC = {
    'nc', 'ncat', 'netcat', 'socat',
    'nmap', 'masscan', 'zmap',
    'hydra', 'medusa', 'john', 'hashcat',
    'sqlmap', 'nikto', 'gobuster', 'dirbuster', 'ffuf', 'wfuzz',
    'msfconsole', 'msfvenom',
    'chisel', 'frp', 'ngrok', 'pwncat',
    'mimikatz', 'crackmapexec',
}

# 프로세스 의심 실행 경로 (이 경로에서 실행된 프로세스는 위험 표시)
_SUSP_PATHS = ('/tmp/', '/dev/shm/', '/var/tmp/', '/run/shm/')

# 알려진 루트킷 커널 모듈명
_SUSP_MODULES = {
    'hide_pid', 'rootkit', 'kbeast', 'azazel', 'jynxkit',
    'reptile', 'diamorphine', 'suterusu', 'adore', 'knark',
    'modhide', 'synapsys', 'syscall_table',
}

TABLE_SOCKETS = "volatile_sockets"
TABLE_PROCS   = "volatile_processes"
TABLE_MODULES = "volatile_modules"


# ── 파일 읽기 ─────────────────────────────────────────
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


# ── IP 판별 ───────────────────────────────────────────
def _is_external_ip(ip: str) -> bool:
    """공인 IP 여부 (사설/루프백/링크로컬 아닌 것)"""
    if not ip or ip in ('-', '*', '0.0.0.0', '::'):
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a in (10, 127, 0):              return False
    if a == 172 and 16 <= b <= 31:    return False
    if a == 192 and b == 168:         return False
    if a == 169 and b == 254:         return False
    if a == 100 and 64 <= b <= 127:   return False
    return True


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_SOCKETS} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        pid         TEXT,
        user        TEXT,
        command     TEXT,
        proto       TEXT,
        local_addr  TEXT,
        remote_addr TEXT,
        state       TEXT,
        risk        TEXT,
        raw_line    TEXT
    )
    """)
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_PROCS} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        pid         TEXT,
        ppid        TEXT,
        user        TEXT,
        command     TEXT,
        exe_path    TEXT,
        risk        TEXT,
        raw_line    TEXT
    )
    """)
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_MODULES} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        module      TEXT,
        size        TEXT,
        used_by     TEXT,
        risk        TEXT
    )
    """)
    conn.commit()


# ── 소켓 파싱 (lsof -i 출력) ──────────────────────────
def _parse_sockets(text: str) -> list:
    """
    lsof -i 출력 예:
      COMMAND  PID   USER  FD  TYPE DEVICE SIZE/OFF NODE NAME
      sshd     1234  root  3u  IPv4 ...         TCP 0.0.0.0:22 (LISTEN)
      mysqld   5678  mysql 26u IPv4 ...         TCP 127.0.0.1:3306->127.0.0.1:46322 (ESTABLISHED)
    """
    rows = []
    lines = text.splitlines()
    if not lines:
        return rows

    for line in lines[1:]:   # 헤더 제외
        parts = line.split()
        if len(parts) < 9:
            continue

        cmd  = parts[0]
        pid  = parts[1]
        user = parts[2]
        typ  = parts[4]   # IPv4 / IPv6
        if typ not in ('IPv4', 'IPv6'):
            continue

        proto = parts[7]  # TCP / UDP
        name  = parts[8]  # 주소 (포트 / 연결)

        # 상태 파싱: 마지막 필드가 "(LISTEN)" 형태일 수 있음
        state = ""
        if len(parts) >= 10 and parts[9].startswith('('):
            state = parts[9].strip('()')

        # 로컬/원격 주소 분리
        local_addr = remote_addr = ""
        if '->' in name:
            local_addr, remote_addr = name.split('->', 1)
        else:
            local_addr = name

        # 위험 판단
        local_port = local_addr.rsplit(':', 1)[-1] if ':' in local_addr else ''
        remote_ip  = remote_addr.split(':')[0]     if remote_addr       else ''

        risk = ""
        if state == "LISTEN":
            if local_port and local_port not in _KNOWN_PORTS:
                risk = f"비표준 포트 LISTEN ({local_port})"
        elif state == "ESTABLISHED":
            if _is_external_ip(remote_ip):
                risk = f"외부 IP 연결 ({remote_ip})"

        rows.append((pid, user, cmd, proto, local_addr, remote_addr, state, risk, line.strip()))

    return rows


# ── 프로세스 파싱 (ps -elf 출력) ──────────────────────
def _parse_processes(text: str) -> list:
    """
    ps -elf 출력 예:
      F S UID  PID PPID C PRI NI ADDR SZ WCHAN STIME TTY TIME CMD
      4 S root   1    0 0  80  0  -  5904 ...   3월02 ?  0:16 /sbin/init splash
    """
    rows = []
    for line in text.splitlines()[1:]:   # 헤더 제외
        parts = line.split(None, 14)
        if len(parts) < 15:
            continue

        uid  = parts[2]
        pid  = parts[3]
        ppid = parts[4]
        cmd  = parts[14].strip()

        # 커널 스레드 제외 ([kworker] 형태)
        if cmd.startswith('[') and cmd.endswith(']'):
            continue

        # 실행 파일 경로/이름 추출
        exe      = cmd.split()[0] if cmd.split() else ''
        exe_name = exe.rsplit('/', 1)[-1].lstrip('-').lower()

        # 위험 판단
        risk = ""
        for sp in _SUSP_PATHS:
            if exe.startswith(sp):
                risk = f"의심 경로 실행 ({sp})"
                break
        if not risk and exe_name in _SUSP_PROC:
            risk = f"의심 프로세스명 ({exe_name})"

        rows.append((pid, ppid, uid, cmd, exe, risk, line.strip()))

    return rows


# ── 모듈 파싱 (lsmod 출력) ─────────────────────────────
def _parse_modules(text: str) -> list:
    """
    lsmod 출력 예:
      Module          Size  Used by
      tls           155648  30
      xt_MASQUERADE  16384   4
    """
    rows = []
    for line in text.splitlines()[1:]:   # 헤더 제외
        parts = line.split(None, 2)
        if len(parts) < 1:
            continue

        module = parts[0]
        size   = parts[1] if len(parts) > 1 else ""
        used   = parts[2].strip() if len(parts) > 2 else ""
        risk   = "알려진 루트킷 모듈" if module.lower() in _SUSP_MODULES else ""

        rows.append((module, size, used, risk))

    return rows


# ── 분석 + 저장 ───────────────────────────────────────
def analyze() -> dict:
    return {
        "sockets":   _parse_sockets  (_read(_VOLATILE / "openedsocket_dmp")),
        "processes": _parse_processes(_read(_VOLATILE / "ps_dmp")),
        "modules":   _parse_modules  (_read(_VOLATILE / "module_dmp")),
    }


def insert_all(conn: sqlite3.Connection, result: dict):
    if result["sockets"]:
        conn.executemany(f"""
        INSERT INTO {TABLE_SOCKETS}
            (pid, user, command, proto, local_addr, remote_addr, state, risk, raw_line)
        VALUES (?,?,?,?,?,?,?,?,?)
        """, result["sockets"])

    if result["processes"]:
        conn.executemany(f"""
        INSERT INTO {TABLE_PROCS}
            (pid, ppid, user, command, exe_path, risk, raw_line)
        VALUES (?,?,?,?,?,?,?)
        """, result["processes"])

    if result["modules"]:
        conn.executemany(f"""
        INSERT INTO {TABLE_MODULES} (module, size, used_by, risk)
        VALUES (?,?,?,?)
        """, result["modules"])

    conn.commit()


def run(conn: sqlite3.Connection) -> dict:
    ensure_db(conn)
    result = analyze()
    insert_all(conn, result)
    return result
