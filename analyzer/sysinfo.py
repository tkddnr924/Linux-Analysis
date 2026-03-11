"""
analyzer/sysinfo.py - 수집된 아티팩트에서 서버 기본 정보 추출

대상 파일 (Volatile/NonVolatile):
  uname_dmp       → 호스트명, 커널, 아키텍처
  ip_dmp          → 내부 IP, MAC, 인터페이스
  lscpu_dmp       → CPU 모델, 코어 수
  df_dmp          → 디스크 사용량 (루트 파티션)
  timezone_dmp    → 타임존
  uptime_dmp      → 업타임, 부팅 시각 (date_dmp 참조)
  date_dmp        → 수집 시각
  whoami_dmp      → 수집 권한
  last_dmp        → 마지막 재부팅 시각, wtmp 시작 시각 (OS 설치 근사)
  session_dmp     → 열린 포트 (LISTEN)

저장:
  analysis.db :: sysinfo 테이블 (단일 row)
"""

import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

TABLE = "info"

# 아티팩트 기본 경로
_VOLATILE    = Path("target/Volatile")
_NONVOLATILE = Path("target/NonVolatile")


# ── DB ────────────────────────────────────────────────
def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname         TEXT,
        internal_ip      TEXT,
        external_ip      TEXT,
        mac_address      TEXT,
        os               TEXT,
        kernel           TEXT,
        architecture     TEXT,
        cpu_model        TEXT,
        cpu_cores        TEXT,
        disk_total       TEXT,
        disk_used        TEXT,
        disk_avail       TEXT,
        disk_use_pct     TEXT,
        timezone         TEXT,
        collected_at     TEXT,
        booted_at        TEXT,
        uptime_days      TEXT,
        last_reboot      TEXT,
        wtmp_begins      TEXT,
        listen_ports     TEXT,
        collect_user     TEXT,
        analyzed_at      TEXT
    )
    """)
    conn.commit()


def table_has_data(conn: sqlite3.Connection) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    )
    if not cur.fetchone():
        return False
    return conn.execute(f"SELECT 1 FROM {TABLE} LIMIT 1").fetchone() is not None


def insert_row(conn: sqlite3.Connection, row: dict):
    cols = ", ".join(row.keys())
    placeholders = ", ".join(["?"] * len(row))
    conn.execute(
        f"INSERT INTO {TABLE} ({cols}) VALUES ({placeholders})",
        list(row.values())
    )
    conn.commit()


# ── 파일 읽기 유틸 ────────────────────────────────────
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        return ""


# ── 각 파일 파싱 ──────────────────────────────────────
def _parse_uname(text: str) -> dict:
    """
    Linux ip-172-31-47-239 6.5.0-1023-aws #23~22.04.1-Ubuntu SMP ... aarch64 aarch64 aarch64 GNU/Linux
    """
    result = {"hostname": "", "kernel": "", "architecture": "", "os": ""}
    if not text:
        return result

    parts = text.split()
    if len(parts) >= 2:
        result["hostname"] = parts[1]
    if len(parts) >= 3:
        result["kernel"] = parts[2]
    if len(parts) >= 12:
        result["architecture"] = parts[11]

    # OS 버전: 커널 문자열에서 Ubuntu 버전 추출
    m = re.search(r'(\d+\.\d+\.\d+)-Ubuntu', text)
    if m:
        result["os"] = f"Ubuntu {m.group(1)}"
    elif "Ubuntu" in text:
        result["os"] = "Ubuntu"

    return result


def _is_private_ip(ip: str) -> bool:
    """RFC 1918 사설 IP + CGNAT + 링크로컬 판별"""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    a, b = int(parts[0]), int(parts[1])
    if a == 10:                          return True   # 10.0.0.0/8
    if a == 172 and 16 <= b <= 31:       return True   # 172.16.0.0/12
    if a == 192 and b == 168:            return True   # 192.168.0.0/16
    if a == 100 and 64 <= b <= 127:      return True   # 100.64.0.0/10 (CGNAT)
    if a == 169 and b == 254:            return True   # 169.254.0.0/16 (링크로컬)
    if a == 127:                         return True   # 127.0.0.0/8
    return False


def _parse_ip(text: str) -> dict:
    """
    ip_dmp 에서 모든 scope global IP 추출 후 내부/외부 분류.
    Docker bridge (br-, docker, veth) 인터페이스는 제외.
    """
    result = {"internal_ip": "", "external_ip": "", "mac_address": ""}
    if not text:
        return result

    internal_ips = []
    external_ips = []
    current_iface = ""

    # Docker/가상 브릿지 인터페이스 패턴
    _VIRTUAL_IFACE = re.compile(r'^(br-|docker|veth|virbr)')

    for line in text.splitlines():
        # 인터페이스 이름 추출: "2: enp3s0: <BROADCAST..."
        iface_m = re.match(r'^\d+:\s+(\S+?):', line)
        if iface_m:
            current_iface = iface_m.group(1)
            continue

        line = line.strip()

        # scope global inet 만 추출
        m = re.match(r'inet ([\d.]+)/\d+.*scope global', line)
        if m:
            ip = m.group(1)
            # Docker/가상 브릿지 인터페이스 제외
            if _VIRTUAL_IFACE.match(current_iface):
                continue
            if _is_private_ip(ip):
                internal_ips.append(ip)
            else:
                external_ips.append(ip)

    result["internal_ip"] = ", ".join(internal_ips) if internal_ips else ""
    result["external_ip"] = ", ".join(external_ips) if external_ips else ""

    # MAC (첫 번째 물리 인터페이스)
    m = re.search(r'link/ether ([\da-f:]+)', text)
    if m:
        result["mac_address"] = m.group(1)

    return result


def _parse_lscpu(text: str) -> dict:
    result = {"cpu_model": "", "cpu_cores": ""}
    if not text:
        return result

    for line in text.splitlines():
        if line.startswith("Model name"):
            result["cpu_model"] = line.split(":", 1)[-1].strip()
        elif line.startswith("CPU(s):"):
            result["cpu_cores"] = line.split(":", 1)[-1].strip()

    return result


def _parse_df(text: str) -> dict:
    result = {"disk_total": "", "disk_used": "", "disk_avail": "", "disk_use_pct": ""}
    if not text:
        return result

    for line in text.splitlines():
        # 루트 파티션 (/ 마운트)
        parts = line.split()
        if len(parts) >= 6 and parts[5] == "/":
            result["disk_total"]   = parts[1]
            result["disk_used"]    = parts[2]
            result["disk_avail"]   = parts[3]
            result["disk_use_pct"] = parts[4]
            break

    return result


def _parse_timezone(text: str) -> str:
    if not text:
        return ""
    m = re.search(r'Time zone:\s+(\S+)', text)
    return m.group(1) if m else ""


def _parse_collected_at(text: str) -> str:
    """Mon Mar  2 16:01:37 UTC 2026 → 2026-03-02 16:01:37.000
    date 명령 출력에는 ms가 없으므로 .000 을 붙인다."""
    if not text:
        return ""
    try:
        dt = datetime.strptime(text, "%a %b %d %H:%M:%S %Z %Y")
        return dt.strftime("%Y-%m-%d %H:%M:%S.000")
    except ValueError:
        # 공백 두 칸 처리
        text = re.sub(r'\s+', ' ', text)
        try:
            dt = datetime.strptime(text, "%a %b %d %H:%M:%S %Z %Y")
            return dt.strftime("%Y-%m-%d %H:%M:%S.000")
        except ValueError:
            return text


def _parse_uptime(uptime_text: str, collected_at: str) -> dict:
    """
     16:01:38 up 543 days, 10:36,  2 users ...
    → uptime_days, booted_at
    """
    result = {"uptime_days": "", "booted_at": ""}
    if not uptime_text:
        return result

    m = re.search(r'up\s+(\d+)\s+days?,\s+(\d+):(\d+)', uptime_text)
    if m:
        days  = int(m.group(1))
        hours = int(m.group(2))
        mins  = int(m.group(3))
        result["uptime_days"] = str(days)

        if collected_at:
            try:
                # ms 포함 형식 (.000) 허용
                for _fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                    try:
                        col_dt = datetime.strptime(collected_at, _fmt)
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError
                boot_dt = col_dt - timedelta(days=days, hours=hours, minutes=mins)
                result["booted_at"] = boot_dt.strftime("%Y-%m-%d %H:%M:%S.000")
            except ValueError:
                pass

    return result


def _parse_last(text: str) -> dict:
    """
    reboot 라인에서 마지막 재부팅 시각,
    wtmp begins 라인에서 OS 설치 근사 시각 추출
    """
    result = {"last_reboot": "", "wtmp_begins": ""}
    if not text:
        return result

    # 가장 최근 reboot 라인 (첫 번째로 등장하는 것)
    for line in text.splitlines():
        if line.startswith("reboot"):
            # reboot   system boot  6.5.0-1023-aws   Thu Sep  5 05:24   still running
            m = re.search(r'(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2})', line)
            if m:
                result["last_reboot"] = m.group(1).strip()
                break

    # wtmp begins
    m = re.search(r'wtmp begins (.+)', text)
    if m:
        result["wtmp_begins"] = m.group(1).strip()

    return result


def _parse_listen_ports(text: str) -> str:
    """session_dmp에서 LISTEN 상태 TCP 포트만 추출"""
    if not text:
        return ""

    ports = set()
    for line in text.splitlines():
        if "LISTEN" in line and line.startswith("tcp"):
            # 0.0.0.0:443 또는 *:3000
            m = re.search(r'[*\d.]+:(\d+)\s', line)
            if m:
                ports.add(m.group(1))

    return ", ".join(sorted(ports, key=int)) if ports else ""


# ── 메인 진입 ─────────────────────────────────────────
def analyze() -> dict:
    collected_at = _parse_collected_at(_read(_VOLATILE / "date_dmp"))

    uptime_info = _parse_uptime(
        _read(_VOLATILE / "uptime_dmp"),
        collected_at
    )

    row = {
        **_parse_uname(_read(_VOLATILE / "uname_dmp")),
        **_parse_ip(_read(_VOLATILE / "ip_dmp")),
        **_parse_lscpu(_read(_VOLATILE / "lscpu_dmp")),
        **_parse_df(_read(_NONVOLATILE / "df_dmp")),
        "timezone":     _parse_timezone(_read(_VOLATILE / "timezone_dmp")),
        "collected_at": collected_at,
        **uptime_info,
        **_parse_last(_read(_NONVOLATILE / "last_dmp")),
        "listen_ports": _parse_listen_ports(_read(_VOLATILE / "session_dmp")),
        "collect_user": _read(_NONVOLATILE / "whoami_dmp"),
        "analyzed_at":  (lambda n: n.strftime("%Y-%m-%d %H:%M:%S.") + f"{n.microsecond // 1000:03d}")(datetime.now()),
    }

    return row


def run(conn: sqlite3.Connection):
    ensure_db(conn)

    if table_has_data(conn):
        print("[SYSINFO] 이미 데이터가 있어 건너뜁니다.")
        return

    row = analyze()
    insert_row(conn, row)

    print(f"[SYSINFO] 저장 완료")
    print(f"  호스트명    : {row.get('hostname')}")
    print(f"  내부 IP     : {row.get('internal_ip')}")
    print(f"  외부 IP     : {row.get('external_ip') or '(없음 / NAT 환경)'}")
    print(f"  OS          : {row.get('os')}  커널: {row.get('kernel')}")
    print(f"  CPU         : {row.get('cpu_model')} ({row.get('cpu_cores')}core)")
    print(f"  디스크      : {row.get('disk_used')}/{row.get('disk_total')} ({row.get('disk_use_pct')})")
    print(f"  부팅 시각   : {row.get('booted_at')}  (업타임 {row.get('uptime_days')}일)")
    print(f"  수집 시각   : {row.get('collected_at')}")
    print(f"  열린 포트   : {row.get('listen_ports')}")
