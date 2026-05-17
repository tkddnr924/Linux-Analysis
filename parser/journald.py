"""
journald.py — systemd journal 바이너리 파서

파일 형식: systemd binary journal (.journal)
  - 각 레코드는 ObjectHeader + type-specific body로 구성
  - 오브젝트 타입: ENTRY(로그 항목), DATA(key=value), ENTRY_ARRAY(인덱스)
  - 압축: LZ4 / XZ(lzma) / ZSTD 지원 (해당 패키지 없으면 skip)

파일 감지:
  system.journal          — 현재 시스템 저널
  system@*.journal        — 아카이브된 시스템 저널
  user-*.journal          — 사용자 저널 (현재 / 아카이브)
  ※ target/ 하위 어디서든 *.journal 파일을 모두 탐색

주요 저장 필드 (journalctl --output=json 의 키명과 동일):
  __REALTIME_TIMESTAMP → timestamp (KST)
  PRIORITY             → 0(EMERG) ~ 7(DEBUG)
  _HOSTNAME, _MACHINE_ID, _BOOT_ID
  SYSLOG_IDENTIFIER    → 프로세스/서비스 식별자
  SYSLOG_FACILITY      → syslog facility 번호
  MESSAGE
  _PID, _UID, _GID, _COMM, _EXE, _CMDLINE
  _SYSTEMD_UNIT, _SYSTEMD_SLICE, _SYSTEMD_CGROUP
  _TRANSPORT           → journal / syslog / kernel / audit / stdout / stderr

※ INCOMPATIBLE_COMPACT(flag=16, systemd 252+) 파일은 스킵
"""

import json
import mmap
import struct
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── 파일 감지 ──────────────────────────────────────────────────────────────────

JOURNAL_GLOB = "*.journal"   # rglob 으로 target/ 하위 전체 탐색

# ── 상수 ───────────────────────────────────────────────────────────────────────

_SIGNATURE = b"LPKSHHRH"
_KST       = timezone(timedelta(hours=9))

# Object types
_OBJ_DATA        = 1
_OBJ_ENTRY       = 3
_OBJ_ENTRY_ARRAY = 6

# Object flags (compression)
_FLAG_XZ   = 1
_FLAG_LZ4  = 2
_FLAG_ZSTD = 4

# Header field offsets (bytes)
_HDR_INCOMPAT_OFF       = 12   # incompatible_flags (le32)
_HDR_MACHINE_ID_OFF     = 40   # sd_id128_t (16 bytes)
_HDR_BOOT_ID_OFF        = 56   # sd_id128_t (16 bytes)
_HDR_HEADER_SIZE_OFF    = 88   # le64
_HDR_N_ENTRIES_OFF      = 152  # le64
_HDR_ENTRY_ARRAY_OFF    = 176  # le64
_HDR_MIN_SIZE           = 184

_INCOMPAT_COMPACT = 16   # systemd 252+: compact entry format (지원 안 함)

# Struct definitions
_OBJ_HDR     = struct.Struct('<BB6sQ')   # type(1)+flags(1)+reserved(6)+size(8) = 16
_ENTRY_FIXED = struct.Struct('<QQQ16sQ') # seqnum+realtime+monotonic+boot_id(16)+xor_hash = 48
_ENTRY_ITEM  = struct.Struct('<QQ')      # offset(8)+hash(8) = 16
_DATA_FIXED  = struct.Struct('<QQQQQQ')  # 6 × le64 = 48

OBJ_HDR_SIZE        = _OBJ_HDR.size       # 16
ENTRY_FIXED_SIZE    = _ENTRY_FIXED.size   # 48
ENTRY_ITEM_SIZE     = _ENTRY_ITEM.size    # 16
DATA_FIXED_SIZE     = _DATA_FIXED.size    # 48
DATA_PAYLOAD_OFFSET = OBJ_HDR_SIZE + DATA_FIXED_SIZE   # 64
ENTRY_BASE_OFFSET   = OBJ_HDR_SIZE + ENTRY_FIXED_SIZE  # 64

# ── 압축 해제 ──────────────────────────────────────────────────────────────────

def _decompress(data: bytes, flags: int) -> bytes:
    if flags & _FLAG_LZ4:
        # 구버전(~244): 8바이트 원본 크기 + LZ4 블록
        # 신버전(245+): LZ4 프레임 포맷
        try:
            import lz4.block
            orig_size = struct.unpack_from('<Q', data)[0]
            return lz4.block.decompress(data[8:], uncompressed_size=orig_size)
        except Exception:
            pass
        try:
            import lz4.frame
            return lz4.frame.decompress(data)
        except Exception:
            pass

    if flags & _FLAG_XZ:
        try:
            import lzma
            return lzma.decompress(data)
        except Exception:
            pass

    if flags & _FLAG_ZSTD:
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(data)
        except Exception:
            pass

    return data


# ── 바이너리 파싱 ──────────────────────────────────────────────────────────────

def _read_u64(mm: mmap.mmap, offset: int) -> int:
    return struct.unpack_from('<Q', mm, offset)[0]


def _read_obj_hdr(mm: mmap.mmap, offset: int) -> tuple[int, int, int]:
    """(type, flags, size) 반환. 읽기 실패 시 (0, 0, 0)."""
    try:
        t, f, _, s = _OBJ_HDR.unpack_from(mm, offset)
        return t, f, s
    except struct.error:
        return 0, 0, 0


def _read_data_kv(mm: mmap.mmap, data_offset: int) -> tuple[str, str] | None:
    """DATA 오브젝트를 읽어 (key, value) 반환."""
    t, flags, size = _read_obj_hdr(mm, data_offset)
    if t != _OBJ_DATA or size < DATA_PAYLOAD_OFFSET:
        return None

    payload_size = size - DATA_PAYLOAD_OFFSET
    payload_raw  = bytes(mm[data_offset + DATA_PAYLOAD_OFFSET:
                             data_offset + DATA_PAYLOAD_OFFSET + payload_size])

    payload = _decompress(payload_raw, flags) if flags else payload_raw

    # "KEY=value" 형식
    sep = payload.find(b'=')
    if sep < 0:
        return None
    key = payload[:sep].decode('utf-8', 'replace')
    val = payload[sep + 1:].decode('utf-8', 'replace').rstrip('\n')
    return key, val


def _iter_entry_array(mm: mmap.mmap, ea_offset: int):
    """ENTRY_ARRAY 체인을 따라 ENTRY 오브젝트 오프셋을 모두 yield."""
    while ea_offset:
        t, _, size = _read_obj_hdr(mm, ea_offset)
        if t != _OBJ_ENTRY_ARRAY or size < OBJ_HDR_SIZE + 8:
            break
        next_ea  = _read_u64(mm, ea_offset + OBJ_HDR_SIZE)
        n_items  = (size - OBJ_HDR_SIZE - 8) // 8
        base     = ea_offset + OBJ_HDR_SIZE + 8
        for i in range(n_items):
            item_off = _read_u64(mm, base + i * 8)
            if item_off:
                yield item_off
        ea_offset = next_ea


def _parse_entry(mm: mmap.mmap, entry_offset: int) -> dict | None:
    t, _, size = _read_obj_hdr(mm, entry_offset)
    if t != _OBJ_ENTRY or size < ENTRY_BASE_OFFSET:
        return None

    try:
        seqnum, realtime_us, monotonic, boot_id, _ = \
            _ENTRY_FIXED.unpack_from(mm, entry_offset + OBJ_HDR_SIZE)
    except struct.error:
        return None

    n_items = (size - ENTRY_BASE_OFFSET) // ENTRY_ITEM_SIZE
    kv: dict[str, str] = {}
    for i in range(n_items):
        item_base = entry_offset + ENTRY_BASE_OFFSET + i * ENTRY_ITEM_SIZE
        try:
            data_off, _ = _ENTRY_ITEM.unpack_from(mm, item_base)
        except struct.error:
            continue
        if not data_off:
            continue
        pair = _read_data_kv(mm, data_off)
        if pair:
            key, val = pair
            kv[key] = val

    # realtime_us: microseconds since epoch
    ts = datetime.fromtimestamp(realtime_us / 1_000_000, tz=timezone.utc).astimezone(_KST)
    ms = (realtime_us % 1_000_000) // 1000
    kv['__REALTIME_TIMESTAMP'] = f"{ts:%Y-%m-%d %H:%M:%S}.{ms:03d}"
    kv['__SEQNUM']             = str(seqnum)
    kv['__BOOT_ID']            = kv.get('_BOOT_ID') or boot_id.hex()

    return kv


# ── 파싱 진입점 ────────────────────────────────────────────────────────────────

# DB에 컬럼으로 저장하는 알려진 필드 (나머지 → extra JSON)
_KNOWN = frozenset({
    '__REALTIME_TIMESTAMP', '__SEQNUM', '__BOOT_ID',
    '_HOSTNAME', '_MACHINE_ID',
    'PRIORITY', 'SYSLOG_IDENTIFIER', 'SYSLOG_FACILITY',
    'MESSAGE',
    '_PID', '_UID', '_GID', '_COMM', '_EXE', '_CMDLINE',
    '_SYSTEMD_UNIT', '_SYSTEMD_SLICE', '_SYSTEMD_CGROUP',
    '_TRANSPORT',
    '_KERNEL_SUBSYSTEM', '_KERNEL_DEVICE',
})


def parse(file_path: Path):
    """journal 바이너리 파일 → dict 제너레이터."""
    file_size = file_path.stat().st_size
    if file_size < _HDR_MIN_SIZE:
        return

    with open(file_path, 'rb') as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, mmap.error):
            return

        try:
            # 시그니처 확인
            if bytes(mm[:8]) != _SIGNATURE:
                return

            # COMPACT 포맷 감지 (지원 안 함)
            incompat = struct.unpack_from('<I', mm, _HDR_INCOMPAT_OFF)[0]
            if incompat & _INCOMPAT_COMPACT:
                print(f"    [SKIP] COMPACT 포맷 미지원: {file_path.name}")
                return

            machine_id = bytes(mm[_HDR_MACHINE_ID_OFF:_HDR_MACHINE_ID_OFF + 16]).hex()
            ea_offset  = _read_u64(mm, _HDR_ENTRY_ARRAY_OFF)

            for entry_offset in _iter_entry_array(mm, ea_offset):
                kv = _parse_entry(mm, entry_offset)
                if kv is None:
                    continue

                if '_MACHINE_ID' not in kv:
                    kv['_MACHINE_ID'] = machine_id

                extra = {k: v for k, v in kv.items() if k not in _KNOWN}

                yield {
                    'timestamp':   kv.get('__REALTIME_TIMESTAMP', ''),
                    'seqnum':      kv.get('__SEQNUM', ''),
                    'boot_id':     kv.get('__BOOT_ID', ''),
                    'machine_id':  kv.get('_MACHINE_ID', ''),
                    'hostname':    kv.get('_HOSTNAME', ''),
                    'priority':    kv.get('PRIORITY', ''),
                    'transport':   kv.get('_TRANSPORT', ''),
                    'identifier':  kv.get('SYSLOG_IDENTIFIER', ''),
                    'facility':    kv.get('SYSLOG_FACILITY', ''),
                    'message':     kv.get('MESSAGE', ''),
                    'pid':         kv.get('_PID', ''),
                    'uid':         kv.get('_UID', ''),
                    'gid':         kv.get('_GID', ''),
                    'comm':        kv.get('_COMM', ''),
                    'exe':         kv.get('_EXE', ''),
                    'cmdline':     kv.get('_CMDLINE', ''),
                    'unit':        kv.get('_SYSTEMD_UNIT', ''),
                    'slice':       kv.get('_SYSTEMD_SLICE', ''),
                    'cgroup':      kv.get('_SYSTEMD_CGROUP', ''),
                    'kernel_sub':  kv.get('_KERNEL_SUBSYSTEM', ''),
                    'kernel_dev':  kv.get('_KERNEL_DEVICE', ''),
                    'extra':       json.dumps(extra, ensure_ascii=False) if extra else '',
                }
        finally:
            mm.close()


# ── DB ─────────────────────────────────────────────────────────────────────────

TABLE = "journal"

_COLS = [
    'timestamp', 'seqnum', 'boot_id', 'machine_id', 'hostname',
    'priority', 'transport', 'identifier', 'facility',
    'message',
    'pid', 'uid', 'gid', 'comm', 'exe', 'cmdline',
    'unit', 'slice', 'cgroup',
    'kernel_sub', 'kernel_dev',
    'extra',
]


def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        seqnum      TEXT,
        boot_id     TEXT,
        machine_id  TEXT,
        hostname    TEXT,
        priority    TEXT,   -- 0(EMERG) ~ 7(DEBUG)
        transport   TEXT,   -- journal/syslog/kernel/audit/stdout/stderr
        identifier  TEXT,   -- SYSLOG_IDENTIFIER
        facility    TEXT,
        message     TEXT,
        pid         TEXT,
        uid         TEXT,
        gid         TEXT,
        comm        TEXT,
        exe         TEXT,
        cmdline     TEXT,
        unit        TEXT,
        slice       TEXT,
        cgroup      TEXT,
        kernel_sub  TEXT,
        kernel_dev  TEXT,
        extra       TEXT    -- JSON: 나머지 모든 필드
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ts    ON {TABLE}(timestamp)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_boot  ON {TABLE}(boot_id)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_prio  ON {TABLE}(priority)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_id    ON {TABLE}(identifier)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_unit  ON {TABLE}(unit)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_pid   ON {TABLE}(pid)")
    conn.commit()


def to_row(record: dict) -> tuple:
    return tuple(record.get(c, '') for c in _COLS)


def insert_rows(conn: sqlite3.Connection, rows: list):
    sql = (
        f"INSERT INTO {TABLE} ({','.join(_COLS)}) "
        f"VALUES ({','.join('?' * len(_COLS))})"
    )
    conn.executemany(sql, rows)
    conn.commit()
