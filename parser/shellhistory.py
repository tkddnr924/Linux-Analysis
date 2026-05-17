"""
shellhistory.py — 셸 히스토리 파일 파서

지원 파일 (정확한 파일명, 어디서든 탐색):
  .bash_history  — bash 명령 이력
  .zsh_history   — zsh 명령 이력

포맷:

  [bash 단순형] — 한 줄 = 명령어
    ls -la /tmp
    cat /etc/passwd

  [bash 타임스탬프형] — HISTTIMEFORMAT 설정 시
    #1620000000
    ls -la /tmp
    #1620000060
    cat /etc/passwd

  [zsh 단순형] — EXTENDED_HISTORY 미설정
    ls -la /tmp

  [zsh 확장형] — EXTENDED_HISTORY 설정 시
    : 1620000000:0;ls -la /tmp
    : 1620000060:5;cat /etc/passwd
    형식: ': timestamp:elapsed_seconds;command'

사용자 추정: .bash_history 의 부모 디렉터리명
  /root/.bash_history       → root
  /home/john/.bash_history  → john
"""

import re
import sqlite3
from pathlib import Path

from parser.utils.times import epoch_to_iso

# ── 파일 감지 ──────────────────────────────────────────────────────────────────

BASH_HISTORY = ".bash_history"
ZSH_HISTORY  = ".zsh_history"

TABLE = "shell_history"

# zsh 확장 히스토리: ': 1620000000:0;command'
_ZSH_EXT_RE = re.compile(r'^:\s*(\d+):(\d+);(.*)')


# ── 파싱 ───────────────────────────────────────────────────────────────────────

def _infer_user(file_path: Path) -> str:
    """부모 디렉터리명을 사용자명으로 사용."""
    return file_path.parent.name


def _parse_bash(file_path: Path, user: str):
    """bash_history → dict 제너레이터.
    #epoch 줄은 다음 명령의 타임스탬프로 처리.
    """
    pending_ts = ""
    seq = 0
    with open(file_path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                pending_ts = ""
                continue

            # 타임스탬프 마커: #1620000000
            if line.startswith("#") and line[1:].isdigit():
                try:
                    pending_ts = epoch_to_iso(int(line[1:]))
                except Exception:
                    pending_ts = ""
                continue

            seq += 1
            ts, pending_ts = pending_ts, ""
            yield {
                "timestamp":   ts,
                "user":        user,
                "shell":       "bash",
                "source_file": str(file_path),
                "seq":         seq,
                "command":     line,
                "raw_line":    line,
            }


def _parse_zsh(file_path: Path, user: str):
    """zsh_history → dict 제너레이터.
    확장형(': ts:elapsed;cmd')과 단순형 모두 처리.
    """
    seq = 0
    with open(file_path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                continue

            seq += 1
            m = _ZSH_EXT_RE.match(line)
            if m:
                try:
                    ts = epoch_to_iso(int(m.group(1)))
                except Exception:
                    ts = ""
                command = m.group(3)
            else:
                ts      = ""
                command = line

            yield {
                "timestamp":   ts,
                "user":        user,
                "shell":       "zsh",
                "source_file": str(file_path),
                "seq":         seq,
                "command":     command,
                "raw_line":    line,
            }


def parse(file_path: Path, **_):
    """파일명으로 shell 종류를 판단해 파싱."""
    user = _infer_user(file_path)
    if file_path.name == ZSH_HISTORY:
        yield from _parse_zsh(file_path, user)
    else:
        yield from _parse_bash(file_path, user)


# ── DB ─────────────────────────────────────────────────────────────────────────

_COLS = [
    "timestamp", "user", "shell", "source_file", "seq",
    "command", "raw_line",
]

_INSERT_SQL = (
    f"INSERT INTO {TABLE} ({','.join(_COLS)}) "
    f"VALUES ({','.join('?' * len(_COLS))})"
)


def ensure_db(conn: sqlite3.Connection):
    conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT,       -- epoch → KST ISO, HISTTIMEFORMAT 미설정 시 빈 값
        user        TEXT,       -- 파일 경로에서 추정한 사용자명
        shell       TEXT,       -- 'bash' or 'zsh'
        source_file TEXT,       -- 원본 파일 전체 경로 (다중 사용자 구분)
        seq         INTEGER,    -- 파일 내 순서 (타임스탬프 없을 때 정렬용)
        command     TEXT NOT NULL,
        raw_line    TEXT NOT NULL
    )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_ts   ON {TABLE}(timestamp)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_user ON {TABLE}(user)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_sh   ON {TABLE}(shell)")
    conn.commit()


def to_row(record: dict) -> tuple:
    return tuple(record.get(c, "") or "" for c in _COLS)


def insert_rows(conn: sqlite3.Connection, rows: list):
    conn.executemany(_INSERT_SQL, rows)
    conn.commit()
