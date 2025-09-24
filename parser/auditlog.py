import argparse
import re
import sqlite3

from pathlib import Path
from utils.files import count_glob
from utils.strings import kv_to_dict, hex_to_text
from utils.times import epoch_to_iso

AUDIT_LOG_GLOB: str = "audit.log*"
DB_PATH = Path("result.db")
TABLE = "audit"

# Audit Log Class
class AuditMessage:
  op = ""
  grantors = ""
  acct = ""
  exe = ""
  hostname = ""
  addr = ""
  terminal = ""
  res = ""
  cmd = ""
  cwd = ""
  unit = ""
  comm = ""

  def __init__(self, msg) -> None:
    data = kv_to_dict(msg)

    self.op = data.get('op', '')
    self.grantors = data.get('grantors', '')
    self.acct = data.get('acct', '')
    self.exe = data.get('exe', '')
    self.hostname = data.get('hostname', '')
    self.addr = data.get('addr', '')
    self.terminal = data.get('terminal', '')
    self.res = data.get('res', '')
    cmd = data.get('cmd', '')
    self.cmd = hex_to_text(cmd)

    self.cwd = data.get('cwd', '')
    self.unit = data.get('unit', '')
    self.comm = data.get('comm', '')


class AuditHeader:
  type = ""
  date_time = ""
  sequence = ""

  def __init__(self, header):
    data = kv_to_dict(header)

    self.type = data.get('type', "")
    
    msg = data.get('msg', '')

    _RX = re.compile(r"audit\(([\d.]+):(\d+)\)")
    m = _RX.search(msg)

    raw = float(m.group(1))
    self.date_time = epoch_to_iso(raw)
    self.sequence = int(m.group(2))

class AuditBody:
  pid = ""
  uid = ""
  auid = ""
  ses = ""
  old_auid = ""
  tty = ""
  old_ses = ""
  res = ""
  proctitle = ""
  msg: AuditMessage = None

  def __init__(self, body):
    body = body.strip()

    parts = body.split('msg=\'')
    data = kv_to_dict(parts[0])

    self.pid = data.get('pid', "")
    self.uid = data.get('uid', '')
    self.auid = data.get('auid', '')
    self.ses = data.get('ses', '')
    self.old_auid = data.get('old-auid', '')
    self.tty = data.get('tty', '')
    self.old_ses = data.get('old-ses', '')
    self.res = data.get('res', '')
    proctitle = data.get('proctitle', '')
    self.proctitle = hex_to_text(proctitle)

    if len(parts) > 1:
      self.msg = AuditMessage(parts[1].replace('\'',''))
    else:
      self.msg = None

class AuditLog:
  header: AuditHeader = None
  body: AuditBody = None
  line = ""

  def __init__(self, line):
    self.line = str(line)

    parts = line.split(":")

    header = ":".join(parts[0:2])
    body = ":".join(parts[2:])

    self.header = AuditHeader(header)
    self.body = AuditBody(body)

  def __repr__(self) -> str:
    return self.line

# DB
def ensure_db(conn: sqlite3.Connection):
  conn.execute(f"""
  CREATE TABLE IF NOT EXISTS {TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    date_time TEXT,
    sequence INTEGER,
    pid TEXT,
    uid TEXT,
    auid TEXT,
    ses TEXT,
    old_auid TEXT,
    tty TEXT,
    old_ses TEXT,
    body_res TEXT,
    proctitle TEXT,
    op TEXT,
    grantors TEXT,
    acct TEXT,
    exe TEXT,
    hostname TEXT,
    addr TEXT,
    terminal TEXT,
    cmd TEXT,
    cwd TEXT,
    unit TEXT,
    comm TEXT,
    msg_res TEXT,
    raw_line TEXT
  )
  """)
  conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_seq ON {TABLE}(sequence)")
  conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_dt ON {TABLE}(date_time)")
  conn.commit()

def table_has_data(conn: sqlite3.Connection) -> bool:
  cur = conn.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,))
  row = cur.fetchone()
  if not row:
    return False
  cur = conn.execute(f"SELECT 1 FROM {TABLE} LIMIT 1")
  return cur.fetchone() is not None

def to_row(a: AuditLog):
  m = a.body.msg
  return (
    a.header.type,
    a.header.date_time,
    a.header.sequence,
    a.body.pid,
    a.body.uid,
    a.body.auid,
    a.body.ses,
    a.body.old_auid,
    a.body.tty,
    a.body.old_ses,
    a.body.res,
    a.body.proctitle,
    m.op if m else "",
    m.grantors if m else "",
    m.acct if m else "",
    m.exe if m else "",
    m.hostname if m else "",
    m.addr if m else "",
    m.terminal if m else "",
    m.cmd if m else "",
    m.cwd if m else "",
    m.unit if m else "",
    m.comm if m else "",
    m.res if m else "",
    a.line,
  )

def insert_rows(conn: sqlite3.Connection, rows):
  conn.executemany(f"""
  INSERT INTO {TABLE} (
    type,date_time,sequence,pid,uid,auid,ses,old_auid,tty,old_ses,body_res, proctitle,
    op,grantors,acct,exe,hostname,addr,terminal,cmd,cwd,unit,comm,msg_res,raw_line
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  """, rows)
  conn.commit()

# Parse Log
def parse(file_path):
  result = []
  with open(file_path, 'r', encoding='utf-8') as audit_file:
    for line in audit_file.readlines():
      audit = AuditLog(line)
      result.append(audit)

  return result

def config():
  parser = argparse.ArgumentParser(
    prog="auditlog.py", 
    description="Audit Log Parser",
    epilog=f'패턴: "{AUDIT_LOG_GLOB}"'
    )
  
  parser.add_argument(
        "-d", "--dir",
        dest="log_dir",
        type=Path,
        help="audit 로그 디렉터리 경로 (기본: %(default)s)"
    )

  args = parser.parse_args()

  return args

def main():
  args = config()
  
  path = Path(args.log_dir)
  print(f"[TARGET DIRECTORY] {path}")

  count = count_glob(path, AUDIT_LOG_GLOB)
  print(f"[AUDIT LOG] {count}")

  if not DB_PATH.exists():
    DB_PATH.touch()

  conn = sqlite3.connect(DB_PATH)
  ensure_db(conn)

  if table_has_data(conn):
    print("[INFO] audit 테이블에 데이터가 있어 파싱을 건너뜁니다.")
    conn.close()
    return

  batch = []
  for audit_file in path.glob(AUDIT_LOG_GLOB):
    if not audit_file.is_file():
      continue
    for audit in parse(audit_file):
      batch.append(to_row(audit))
      if len(batch) >= 1000:
        insert_rows(conn, batch)
        batch.clear()
  if batch:
    insert_rows(conn, batch)
  conn.close()
  print("[INFO] 저장 완료")


if __name__ == "__main__":
  main()
