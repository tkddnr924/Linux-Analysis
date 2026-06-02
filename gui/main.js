'use strict'

const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path     = require('path')
const fs       = require('fs')
const Database = require('better-sqlite3')

let win = null
let db  = null
let currentDbPath = null

// gui/ 의 부모(프로젝트 루트)에 있는 parser.db 자동 감지
const AUTO_DB = path.join(__dirname, '..', 'parser.db')

// ── IPinfo enrich (viewer 측) ─────────────────────────
// 토큰 로드: env > .ipinfo_token > config.ini ([ipinfo] token)
function _loadIpinfoToken () {
  const envTok = (process.env.IPINFO_TOKEN || '').trim()
  if (envTok) return envTok
  const dirs = [
    process.cwd(),
    path.resolve(__dirname, '..'),
    path.dirname(process.execPath),       // 패키징된 .exe 위치
  ]
  for (const d of dirs) {
    const tokPath = path.join(d, '.ipinfo_token')
    try {
      if (fs.existsSync(tokPath)) {
        const t = fs.readFileSync(tokPath, 'utf8').trim()
        if (t) return t
      }
    } catch {}
    const cfgPath = path.join(d, 'config.ini')
    try {
      if (fs.existsSync(cfgPath)) {
        const txt = fs.readFileSync(cfgPath, 'utf8')
        // 간단한 INI — [ipinfo] 섹션 안의 token = X 줄 탐색
        let inSection = false
        for (const raw of txt.split(/\r?\n/)) {
          const line = raw.trim()
          if (!line || line.startsWith('#') || line.startsWith(';')) continue
          if (/^\[.*\]$/.test(line)) { inSection = /^\[ipinfo\]$/i.test(line); continue }
          if (!inSection) continue
          const m = line.match(/^token\s*=\s*(.+)$/i)
          if (m) {
            const v = m[1].trim()
            if (v) return v
          }
        }
      }
    } catch {}
  }
  return null
}

// 사설/예약 IPv4 빠른 필터. IPv6 는 단순화: ::1 만 제외하고 나머지는 일단 허용.
function _isPublicIp (ip) {
  if (!ip) return false
  ip = String(ip).trim()
  if (!ip || ip === '0.0.0.0' || ip === '::' || ip === '::1') return false
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  if (!m) return ip.includes(':')   // IPv6 형태면 통과 (단순화)
  const [a, b] = m.slice(1, 5).map(Number)
  if (a === 10) return false                          // 10/8
  if (a === 127) return false                         // loopback
  if (a === 169 && b === 254) return false            // link-local
  if (a === 172 && b >= 16 && b <= 31) return false   // 172.16/12
  if (a === 192 && b === 168) return false            // 192.168/16
  if (a === 198 && (b === 18 || b === 19)) return false  // 벤치마크
  if (a === 192 && b === 0) return false              // doc + TEST-NET-1
  if (a === 198 && b === 51 && /^198\.51\.100\./.test(ip)) return false  // TEST-NET-2
  if (a === 203 && b === 0 && /^203\.0\.113\./.test(ip))  return false  // TEST-NET-3
  if (a >= 224) return false                          // multicast / 예약
  return true
}

const _VPN_HINT_TOKENS = [
  'vpn','nordvpn','expressvpn','protonvpn','surfshark','mullvad','cyberghost',
  'tunnelbear','ivpn','windscribe','vyprvpn','private internet access',
  'hide.me','hidemyass','tor exit','tor relay','anonymous',
  'digitalocean','vultr','linode','ovh','hetzner','choopa','m247','datacamp',
  'leaseweb','contabo','ramnode','amazon technologies','amazon-02',
  'amazon data services','google cloud','microsoft corporation','microsoft-corp',
  'azure','alibaba','tencent cloud','oracle corporation',
]
function _isVpnSuspect (asName) {
  if (!asName) return 0
  const s = asName.toLowerCase()
  return _VPN_HINT_TOKENS.some(t => s.includes(t)) ? 1 : 0
}

// "AS15169 Google LLC" → {asn: 'AS15169', as_name: 'Google LLC'}
function _parseOrg (org) {
  if (!org) return { asn: '', as_name: '' }
  const m = String(org).trim().match(/^(AS\d+)\s+(.+)$/)
  if (m) return { asn: m[1], as_name: m[2] }
  return { asn: '', as_name: String(org).trim() }
}

// 단일 IP 조회 — 실패하면 null
async function _fetchIpInfo (ip, token, timeoutMs = 8000) {
  let url = `https://ipinfo.io/${encodeURIComponent(ip)}/json`
  if (token) url += `?token=${encodeURIComponent(token)}`
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) return null
    const data = await res.json()
    if (!data || !data.ip) return null
    return data
  } catch {
    return null
  }
}

// 진행 중인 enrich job (취소·중복 방지)
let _enrichJob = null

ipcMain.handle('db:enrichStatus', () => {
  if (!db || !currentDbPath) return { available: false, reason: 'no-db' }
  // ipinfo 테이블이 없으면 처음 실행 — available
  let cached = 0, total = 0
  try {
    const exists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ipinfo'").get()
    if (exists) cached = db.prepare('SELECT COUNT(*) c FROM ipinfo').get().c
  } catch {}
  for (const s of _WEB_LOG_SRC) {
    try {
      const ex = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(s.table)
      if (!ex) continue
      total += db.prepare(`SELECT COUNT(DISTINCT "${s.ip}") c FROM "${s.table}"
                           WHERE "${s.ip}" IS NOT NULL AND "${s.ip}" NOT IN ('','-','?','0.0.0.0')`).get().c
    } catch {}
  }
  return {
    available: !!currentDbPath,
    cached, total,
    hasToken: !!_loadIpinfoToken(),
    running: !!_enrichJob,
  }
})

ipcMain.handle('db:cancelEnrich', () => {
  if (_enrichJob) _enrichJob.cancel = true
  return { ok: true }
})

ipcMain.handle('db:startEnrichIps', async (event, opts = {}) => {
  if (!db || !currentDbPath) return { ok: false, error: 'no DB' }
  if (_enrichJob) return { ok: false, error: '이미 실행 중' }

  const token = _loadIpinfoToken()
  // 1) 일시 RW 연결 (메인 read-only 와 분리)
  const rw = new Database(currentDbPath)
  try {
    rw.exec("PRAGMA journal_mode=WAL")
    rw.exec("PRAGMA synchronous=NORMAL")
    rw.exec(`CREATE TABLE IF NOT EXISTS ipinfo (
      ip TEXT PRIMARY KEY,
      country_code TEXT, country TEXT,
      continent_code TEXT, continent TEXT,
      asn TEXT, as_name TEXT, as_domain TEXT,
      vpn_suspect INTEGER NOT NULL DEFAULT 0,
      fetched_at TEXT NOT NULL
    )`)
    rw.exec(`CREATE INDEX IF NOT EXISTS idx_ipinfo_country ON ipinfo(country_code)`)
    rw.exec(`CREATE INDEX IF NOT EXISTS idx_ipinfo_vpn     ON ipinfo(vpn_suspect)`)

    // 2) 대상 IP 수집 — 웹 로그 4개에서 UNION 후 캐시되지 않은 + 공인 IP만
    const cached = new Set(rw.prepare('SELECT ip FROM ipinfo').all().map(r => r.ip))
    const all = new Set()
    for (const s of _WEB_LOG_SRC) {
      try {
        const ex = rw.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(s.table)
        if (!ex) continue
        for (const r of rw.prepare(`SELECT DISTINCT "${s.ip}" AS ip FROM "${s.table}"
            WHERE "${s.ip}" IS NOT NULL AND "${s.ip}" NOT IN ('','-','?','0.0.0.0')`).iterate()) {
          if (_isPublicIp(r.ip)) all.add(r.ip)
        }
      } catch {}
    }
    const todo = [...all].filter(ip => !cached.has(ip))

    if (!todo.length) {
      event.sender.send('enrich-progress', { done: 0, total: 0, ok: 0, fail: 0, finished: true })
      return { ok: true, total: 0, ok_count: 0, fail_count: 0 }
    }

    // 3) 8 동시 fetch + 50개씩 묶어서 INSERT
    _enrichJob = { cancel: false }
    const concurrency = 8
    let idx = 0, done = 0, okN = 0, failN = 0
    const buffer = []
    const flush = () => {
      if (!buffer.length) return
      const ins = rw.prepare(`INSERT OR REPLACE INTO ipinfo
        (ip, country_code, country, continent_code, continent,
         asn, as_name, as_domain, vpn_suspect, fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`)
      const now = new Date().toISOString().slice(0, 19).replace('T', ' ')
      const tx = rw.transaction((rows) => { for (const r of rows) ins.run(...r, now) })
      tx(buffer)
      buffer.length = 0
    }

    async function worker () {
      while (!_enrichJob.cancel) {
        const my = idx++
        if (my >= todo.length) break
        const ip = todo[my]
        const data = await _fetchIpInfo(ip, token)
        if (data) {
          const { asn, as_name } = _parseOrg(data.org)
          buffer.push([
            ip,
            data.country || '', '', '', '',
            asn, as_name, '', _isVpnSuspect(as_name),
          ])
          okN++
        } else {
          failN++
        }
        done++
        if (buffer.length >= 50) flush()
        if (done % 20 === 0 || done === todo.length) {
          event.sender.send('enrich-progress', {
            done, total: todo.length, ok: okN, fail: failN, finished: false
          })
        }
      }
    }
    await Promise.all(Array.from({ length: concurrency }, worker))
    flush()

    const cancelled = !!_enrichJob.cancel
    event.sender.send('enrich-progress', {
      done, total: todo.length, ok: okN, fail: failN, finished: true, cancelled
    })
    return { ok: true, total: todo.length, ok_count: okN, fail_count: failN, cancelled }
  } catch (e) {
    return { ok: false, error: e.message }
  } finally {
    try { rw.close() } catch {}
    _enrichJob = null
  }
})

// ── 검색/필터 접두어 문법 ────────────────────────────
//   foo                 → 포함  (LIKE %foo%)
//   !foo                → 제외  (NOT LIKE %foo%)
//   =foo                → 정확히 (= foo)
//   "foo bar"           → 공백 포함 그대로 한 토큰
//   ="2026-02-02 01:01" → 공백 포함 정확히
//   !"connection reset" → 공백 포함 제외
//   공백으로 구분된 여러 토큰은 AND 로 결합. ' 도 " 와 동일하게 동작.
function parseFilterTokens (raw) {
  if (raw == null) return []
  const s = String(raw)
  const out = []
  let i = 0
  while (i < s.length) {
    // 토큰 사이 공백 스킵
    while (i < s.length && /\s/.test(s[i])) i++
    if (i >= s.length) break

    // 접두어 (!, =) — 단, 그 자체로 끝나거나 공백이 이어지면 일반 토큰으로
    let op = 'contains'
    if ((s[i] === '!' || s[i] === '=') && i + 1 < s.length && !/\s/.test(s[i + 1])) {
      op = s[i] === '!' ? 'exclude' : 'exact'
      i++
    }

    // 본문 — 따옴표로 시작하면 닫는 따옴표까지(없으면 라인 끝까지), 아니면 다음 공백까지
    let term = ''
    if (i < s.length && (s[i] === '"' || s[i] === "'")) {
      const q = s[i]
      i++
      while (i < s.length && s[i] !== q) { term += s[i]; i++ }
      if (i < s.length) i++   // 닫는 따옴표 소비
    } else {
      while (i < s.length && !/\s/.test(s[i])) { term += s[i]; i++ }
    }

    if (term) out.push({ op, term })
  }
  return out
}

// 단일 컬럼 조건: 토큰들을 AND 로 묶음
function buildColumnCondition (col, raw) {
  const c = `CAST("${col}" AS TEXT)`
  const clauses = [], params = []
  for (const t of parseFilterTokens(raw)) {
    if (t.op === 'exclude') { clauses.push(`${c} NOT LIKE ?`); params.push(`%${t.term}%`) }
    else if (t.op === 'exact') { clauses.push(`${c} = ?`); params.push(t.term) }
    else { clauses.push(`${c} LIKE ?`); params.push(`%${t.term}%`) }
  }
  return { clause: clauses.length ? clauses.join(' AND ') : '', params }
}

// 전체 컬럼 검색 조건: 토큰 단위로
//   포함/정확히 → 컬럼 OR,  제외 → 컬럼 AND(어느 컬럼에도 없음),  토큰끼리 AND
function buildSearchCondition (cols, raw) {
  const clauses = [], params = []
  for (const t of parseFilterTokens(raw)) {
    if (t.op === 'exclude') {
      clauses.push('(' + cols.map(c => `CAST("${c}" AS TEXT) NOT LIKE ?`).join(' AND ') + ')')
      cols.forEach(() => params.push(`%${t.term}%`))
    } else if (t.op === 'exact') {
      clauses.push('(' + cols.map(c => `CAST("${c}" AS TEXT) = ?`).join(' OR ') + ')')
      cols.forEach(() => params.push(t.term))
    } else {
      clauses.push('(' + cols.map(c => `CAST("${c}" AS TEXT) LIKE ?`).join(' OR ') + ')')
      cols.forEach(() => params.push(`%${t.term}%`))
    }
  }
  return { clause: clauses.length ? clauses.join(' AND ') : '', params }
}

// ── 대시보드 사전계산 캐시 ───────────────────────────
// 파서(analyzer/dashboard.py) 가 미리 채워둔 dashboard 테이블에서
// 페이로드를 즉시 읽어옴. 캐시가 없거나 깨졌으면 라이브 폴백.
function readDashboardCache(name) {
  if (!db) return null
  try {
    const row = db.prepare("SELECT payload FROM dashboard WHERE table_name = ?").get(name)
    if (!row || !row.payload) return null
    return JSON.parse(row.payload)
  } catch { return null }   // dashboard 테이블 없음 = 옛 DB
}

function getDashboardPayload(name, liveFn) {
  const cached = readDashboardCache(name)
  if (cached) return cached
  try { return liveFn() } catch { return null }
}

// ── 공통(자동) 대시보드 ──────────────────────────────
// 집계할 핵심 컬럼 우선순위(존재하는 것 중 앞에서부터 최대 4개)
const GENERIC_KEY_COLS = [
  'status', 'level', 'severity', 'event_type', 'type', 'service', 'facility', 'unit',
  'src_ip', 'client_ip', 'addr', 'ip', 'user', 'acct', 'username', 'method', 'vhost',
  'exe', 'comm', 'command', 'terminal', 'tty', 'hostname', 'log_type', 'pid',
]
// 고-카디널리티/장문이라 집계 제외
const GENERIC_SKIP_COLS = new Set([
  'id', 'raw_line', 'message', 'msg', 'uri', 'referer', 'user_agent', 'cmdline', 'args', 'line',
])
// 인덱스 없는 컬럼을 GROUP BY 풀스캔하면 대용량에서 UI가 멈추므로,
// 비인덱스 컬럼 집계는 이 행수 이하에서만 수행
const GENERIC_SCAN_LIMIT = 2_000_000

// 테이블에 인덱스가 걸린 컬럼 집합
function indexedColumns (table) {
  const set = new Set()
  try {
    for (const ix of db.prepare(`PRAGMA index_list("${table}")`).all()) {
      for (const ic of db.prepare(`PRAGMA index_info("${ix.name}")`).all()) {
        if (ic.name) set.add(ic.name)
      }
    }
  } catch { /* noop */ }
  return set
}

// ── 윈도우 생성 ──────────────────────────────────────
function createWindow () {
  win = new BrowserWindow({
    width:     1440,
    height:    900,
    minWidth:  900,
    minHeight: 600,
    backgroundColor: '#f0f4f8',
    title: 'Linux Analysis Viewer',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  })

  win.setMenuBarVisibility(false)
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'))
}

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
  closeDb()
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})

// ── DB 유틸 ──────────────────────────────────────────
function closeDb () {
  if (db) {
    try { db.close() } catch (_) {}
    db = null
    currentDbPath = null
  }
}

function openDb (filePath) {
  closeDb()
  db = new Database(filePath, { readonly: true, fileMustExist: true })
  currentDbPath = filePath
}

// ── IPC: 파일 다이얼로그 ─────────────────────────────
ipcMain.handle('dialog:openFile', async () => {
  const result = await dialog.showOpenDialog(win, {
    title: 'parser.db 열기',
    filters: [
      { name: 'SQLite Database', extensions: ['db', 'sqlite', 'sqlite3'] },
      { name: 'All Files',       extensions: ['*'] },
    ],
    defaultPath: path.join(__dirname, '..'),
    properties: ['openFile'],
  })
  return result.canceled ? null : result.filePaths[0]
})

// ── IPC: 자동 감지 경로 ──────────────────────────────
ipcMain.handle('db:getAutoPath', () =>
  fs.existsSync(AUTO_DB) ? AUTO_DB : null
)

// ── IPC: DB 열기 ─────────────────────────────────────
ipcMain.handle('db:open', (_e, filePath) => {
  try {
    openDb(filePath)
    const stat = fs.statSync(filePath)
    return { success: true, path: filePath, size: stat.size, mtime: stat.mtime.toISOString() }
  } catch (e) {
    return { success: false, error: e.message }
  }
})

// ── IPC: DB 닫기 ─────────────────────────────────────
ipcMain.handle('db:close', () => {
  closeDb()
  return { success: true }
})

// 사이드바에 노출하지 않는 내부 캐시/메타 테이블
const _HIDDEN_TABLES = new Set(['dashboard', 'ip_summary', 'ipinfo'])

// ── IPC: 테이블 목록 + 행 수 ─────────────────────────
// 큰 테이블(예: apache2 26M 행) 의 COUNT(*) 는 사이드바 렌더를 지연시키므로,
// 사전계산된 dashboard 캐시의 overview.total 을 우선 사용.
ipcMain.handle('db:getTables', () => {
  if (!db) return []
  try {
    const rows = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all().filter(r => !_HIDDEN_TABLES.has(r.name))

    // dashboard 캐시 일괄 로드 (테이블당 SELECT 한 번 피하기 위해)
    const cachedTotals = new Map()
    try {
      const dashRows = db.prepare("SELECT table_name, payload FROM dashboard").all()
      for (const r of dashRows) {
        try {
          const p = JSON.parse(r.payload)
          const t = p?.overview?.total
          if (Number.isFinite(t)) cachedTotals.set(r.table_name, t)
        } catch { /* skip */ }
      }
    } catch { /* dashboard 테이블 없음 */ }

    return rows.map(r => {
      // 1) 사전계산된 dashboard total
      if (cachedTotals.has(r.name)) return { name: r.name, count: cachedTotals.get(r.name) }
      // 2) 폴백: live COUNT (작은 테이블만 해당)
      try {
        const { c } = db.prepare(`SELECT COUNT(*) as c FROM "${r.name}"`).get()
        return { name: r.name, count: c }
      } catch {
        return { name: r.name, count: 0 }
      }
    })
  } catch {
    return []
  }
})

// ── IPC: 테이블 데이터 (페이지네이션 + 검색 + 정렬 + 날짜 범위 + 컬럼 필터 + 타입/상태/메서드 필터) ─
// skipCount: true 이면 COUNT(*) 스킵하고 total 은 null. 페이지 이동·정렬만 변경됐을 때
// 호출측이 이전 total 을 재사용하면 큰 테이블에서 페이지 넘기는 비용을 크게 줄임.
ipcMain.handle('db:getTableData', (_e, { table, search, limit, offset, sortCol, sortDir, dateFrom, dateTo, colFilters, typeFilters, statusFilter, methodFilters, skipCount }) => {
  if (!db) return { rows: [], total: 0, columns: [] }
  try {
    const cols = db.prepare(`PRAGMA table_info("${table}")`).all().map(r => r.name)

    // 날짜 범위 필터용 타임스탬프 컬럼 탐색
    const tsCol = cols.includes('date_time') ? 'date_time'
                : cols.includes('timestamp')  ? 'timestamp'
                : null

    const conditions = []
    const params = []

    if (search && search.trim()) {
      const { clause, params: sp } = buildSearchCondition(cols, search)
      if (clause) { conditions.push(clause); params.push(...sp) }
    }
    if (tsCol && dateFrom) {
      conditions.push(`"${tsCol}" >= ?`)
      params.push(dateFrom + ' 00:00:00')
    }
    if (tsCol && dateTo) {
      conditions.push(`"${tsCol}" <= ?`)
      params.push(dateTo + ' 23:59:59.999')
    }
    if (colFilters && typeof colFilters === 'object') {
      for (const [col, val] of Object.entries(colFilters)) {
        if (val && val.trim() && cols.includes(col)) {
          const { clause, params: cp } = buildColumnCondition(col, val)
          if (clause) { conditions.push(clause); params.push(...cp) }
        }
      }
    }
    // 타입 IN 필터 — 'type' / 'event_type' / 'service' 컬럼 자동 탐지
    if (typeFilters && Array.isArray(typeFilters) && typeFilters.length) {
      const typeCol = cols.includes('type')       ? 'type'
                    : cols.includes('event_type') ? 'event_type'
                    : cols.includes('service')    ? 'service'
                    : null
      if (typeCol) {
        const ph = typeFilters.map(() => '?').join(',')
        conditions.push(`"${typeCol}" IN (${ph})`)
        typeFilters.forEach(t => params.push(t))
      }
    }
    // 상태코드 필터 (Apache 등 status 컬럼 보유 테이블)
    if (statusFilter != null && cols.includes('status')) {
      conditions.push(`"status" = ?`)
      params.push(statusFilter)
    }
    // 메서드 IN 필터 (Apache 등 method 컬럼 보유 테이블)
    if (methodFilters && Array.isArray(methodFilters) && methodFilters.length && cols.includes('method')) {
      const ph = methodFilters.map(() => '?').join(',')
      conditions.push(`"method" IN (${ph})`)
      methodFilters.forEach(m => params.push(m))
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : ''

    let order = ''
    if (sortCol && cols.includes(sortCol)) {
      const dir = sortDir === 'DESC' ? 'DESC' : 'ASC'
      order = `ORDER BY "${sortCol}" ${dir}`
    } else if (tsCol) {
      // 기본 정렬: 시간 컬럼 오래된순(ASC)
      order = `ORDER BY "${tsCol}" ASC`
    }

    const total = skipCount
      ? null
      : db.prepare(`SELECT COUNT(*) as c FROM "${table}" ${where}`).get(...params).c
    const rows  = db.prepare(`SELECT * FROM "${table}" ${where} ${order} LIMIT ? OFFSET ?`).all(...params, limit, offset)

    return { rows, total, columns: cols }
  } catch (e) {
    return { rows: [], total: 0, columns: [], error: e.message }
  }
})

// ── IPC: 타임스탬프 컬럼 최솟값·최댓값 ──────────────
ipcMain.handle('db:getDateRange', (_e, table) => {
  if (!db) return { min: null, max: null }
  try {
    const cols  = db.prepare(`PRAGMA table_info("${table}")`).all().map(r => r.name)
    const tsCol = cols.includes('date_time') ? 'date_time'
                : cols.includes('timestamp')  ? 'timestamp'
                : null
    if (!tsCol) return { min: null, max: null }

    const row = db.prepare(`SELECT MIN("${tsCol}") as mn, MAX("${tsCol}") as mx FROM "${table}"`).get()
    return {
      min: row.mn ? row.mn.slice(0, 10) : null,
      max: row.mx ? row.mx.slice(0, 10) : null,
    }
  } catch {
    return { min: null, max: null }
  }
})

// ── IPC: sysinfo 테이블 단일 행 ──────────────────────
ipcMain.handle('db:getSysinfo', () => {
  if (!db) return null
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='sysinfo'"
    ).get()
    if (!exists) return null
    return db.prepare('SELECT * FROM sysinfo LIMIT 1').get() || null
  } catch { return null }
})

// ── IPC: Audit 대시보드 통계 ─────────────────────────
ipcMain.handle('db:getAuditDashboard', () => {
  if (!db) return null
  // 1) 사전계산 캐시 우선
  const cached = readDashboardCache('audit')
  if (cached) return cached
  // 2) 캐시 없으면 라이브 계산 (옛 DB 호환)
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='audit'"
    ).get()
    if (!exists) return null

    const safe    = sql       => { try { return db.prepare(sql).all()  } catch { return [] } }
    const safeGet = (sql, ...a) => { try { return db.prepare(sql).get(...a) } catch { return null } }

    // 개요: 총 건수, 기간, 타입 종류
    const overview = safeGet(
      "SELECT COUNT(*) as total, MIN(date_time) as first_dt, MAX(date_time) as last_dt, COUNT(DISTINCT type) as type_count FROM audit"
    )

    // 타입 분포 (상위 20개)
    const typeDist = safe(
      "SELECT type, COUNT(*) as cnt FROM audit WHERE type!='' GROUP BY type ORDER BY cnt DESC LIMIT 20"
    )

    // 인증/로그인 계열 카운트
    const loginStats = {
      auth:  safeGet("SELECT COUNT(*) as c FROM audit WHERE type='USER_AUTH'")?.c  ?? 0,
      login: safeGet("SELECT COUNT(*) as c FROM audit WHERE type='USER_LOGIN'")?.c ?? 0,
      err:   safeGet("SELECT COUNT(*) as c FROM audit WHERE type='USER_ERR'")?.c   ?? 0,
      start: safeGet("SELECT COUNT(*) as c FROM audit WHERE type='USER_START'")?.c ?? 0,
      end:   safeGet("SELECT COUNT(*) as c FROM audit WHERE type='USER_END'")?.c   ?? 0,
    }

    // 상위 IP (인증 이벤트 기준, IPv6/로컬 제외)
    const topIPs = safe(`
      SELECT addr, COUNT(*) as cnt FROM audit
      WHERE addr NOT IN ('','?') AND addr NOT GLOB '*:*' AND addr!='0.0.0.0'
        AND type IN ('USER_AUTH','USER_LOGIN','USER_ERR','USER_START')
      GROUP BY addr ORDER BY cnt DESC LIMIT 5
    `)

    // 상위 계정
    const topAccts = safe(`
      SELECT acct, COUNT(*) as cnt FROM audit
      WHERE acct != '' AND type IN ('USER_AUTH','USER_LOGIN','USER_ERR')
      GROUP BY acct ORDER BY cnt DESC LIMIT 5
    `)

    // 명령 실행
    const execve  = safeGet("SELECT COUNT(*) as c FROM audit WHERE type='EXECVE'")?.c   ?? 0
    const userCmd = safeGet("SELECT COUNT(*) as c FROM audit WHERE type='USER_CMD'")?.c ?? 0

    // 상위 실행 파일 (SYSCALL의 exe 기준)
    const topExe = safe(`
      SELECT exe, COUNT(*) as cnt FROM audit
      WHERE exe NOT IN ('','?') AND type='SYSCALL'
      GROUP BY exe ORDER BY cnt DESC LIMIT 5
    `)

    // 이상 징후
    const avcCount    = safeGet("SELECT COUNT(*) as c FROM audit WHERE type='AVC'")?.c          ?? 0
    const failCount   = safeGet("SELECT COUNT(*) as c FROM audit WHERE body_res='failed'")?.c   ?? 0
    const syscallFail = safeGet("SELECT COUNT(*) as c FROM audit WHERE type='SYSCALL' AND body_res='no'")?.c ?? 0
    const userErrIP   = safeGet(`
      SELECT addr FROM audit
      WHERE addr NOT IN ('','?') AND type='USER_ERR'
      GROUP BY addr ORDER BY COUNT(*) DESC LIMIT 1
    `)?.addr ?? ''

    // 필터용 전체 타입 목록
    const allTypes = safe(
      "SELECT type, COUNT(*) as cnt FROM audit WHERE type!='' GROUP BY type ORDER BY cnt DESC"
    )

    return {
      overview, typeDist, loginStats,
      topIPs, topAccts,
      execve, userCmd, topExe,
      avcCount, failCount, syscallFail, userErrIP,
      allTypes,
    }
  } catch { return null }
})

// ── IPC: Authlog 대시보드 통계 ───────────────────────
ipcMain.handle('db:getAuthlogDashboard', () => {
  if (!db) return null
  const cached = readDashboardCache('authlog')
  if (cached) return cached
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='authlog'"
    ).get()
    if (!exists) return null

    const safe    = sql => { try { return db.prepare(sql).all()  } catch { return [] } }
    const safeGet = sql => { try { return db.prepare(sql).get()  } catch { return null } }

    // 개요
    const overview = safeGet(
      "SELECT COUNT(*) as total, MIN(date_time) as first_dt, MAX(date_time) as last_dt, COUNT(DISTINCT event_type) as type_count FROM authlog"
    )

    // 이벤트 타입 분포 (상위 20개)
    const eventDist = safe(
      "SELECT event_type as type, COUNT(*) as cnt FROM authlog WHERE event_type!='' GROUP BY event_type ORDER BY cnt DESC LIMIT 20"
    )

    // SSH 인증 통계
    const cnt = type => safeGet(`SELECT COUNT(*) as c FROM authlog WHERE event_type='${type}'`)?.c ?? 0
    const sshStats = {
      accepted_password:  cnt('sshd_accepted_password'),
      accepted_publickey: cnt('sshd_accepted_publickey'),
      failed_password:    cnt('sshd_failed_password'),
      invalid_user:       cnt('sshd_invalid_user'),
      max_auth:           cnt('sshd_max_auth'),
      session_opened:     cnt('sshd_session_opened'),
    }

    // 공격 IP (실패 로그인 기준 상위 5개)
    const topAttackIPs = safe(`
      SELECT src_ip, COUNT(*) as cnt FROM authlog
      WHERE src_ip != '' AND event_type IN ('sshd_failed_password','sshd_invalid_user','sshd_max_auth')
      GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
    `)

    // 성공 로그인 IP
    const topSuccessIPs = safe(`
      SELECT src_ip, COUNT(*) as cnt FROM authlog
      WHERE src_ip != '' AND event_type IN ('sshd_accepted_password','sshd_accepted_publickey')
      GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
    `)

    // 성공 로그인 계정
    const topUsers = safe(`
      SELECT user, COUNT(*) as cnt FROM authlog
      WHERE user != '' AND event_type IN ('sshd_accepted_password','sshd_accepted_publickey')
      GROUP BY user ORDER BY cnt DESC LIMIT 5
    `)

    // 실패 대상 계정
    const topFailUsers = safe(`
      SELECT user, COUNT(*) as cnt FROM authlog
      WHERE user != '' AND event_type IN ('sshd_failed_password','sshd_invalid_user')
      GROUP BY user ORDER BY cnt DESC LIMIT 5
    `)

    // sudo 통계
    const sudoCount    = cnt('sudo_command')
    const topSudoUsers = safe(`
      SELECT user, COUNT(*) as cnt FROM authlog
      WHERE user != '' AND event_type='sudo_command'
      GROUP BY user ORDER BY cnt DESC LIMIT 5
    `)

    // su 횟수
    const suCount = safeGet(
      "SELECT COUNT(*) as c FROM authlog WHERE event_type IN ('su_to','su_session_opened')"
    )?.c ?? 0

    // 필터용 전체 이벤트 타입
    const allTypes = safe(
      "SELECT event_type as type, COUNT(*) as cnt FROM authlog WHERE event_type!='' GROUP BY event_type ORDER BY cnt DESC"
    )

    return {
      overview, eventDist, sshStats,
      topAttackIPs, topSuccessIPs, topUsers, topFailUsers,
      sudoCount, topSudoUsers, suCount,
      allTypes,
    }
  } catch { return null }
})

// ── IPC: Syslog 대시보드 통계 ───────────────────────
ipcMain.handle('db:getSyslogDashboard', () => {
  if (!db) return null
  const cached = readDashboardCache('syslog')
  if (cached) return cached
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='syslog'"
    ).get()
    if (!exists) return null

    const safe    = sql       => { try { return db.prepare(sql).all()  } catch { return [] } }
    const safeGet = (sql, ...a) => { try { return db.prepare(sql).get(...a) } catch { return null } }

    // 개요
    const overview = safeGet(
      "SELECT COUNT(*) as total, MIN(timestamp) as first_dt, MAX(timestamp) as last_dt, COUNT(DISTINCT service) as svc_count FROM syslog"
    )

    // 상위 서비스 (상위 15개, 바차트용)
    const topServices = safe(
      "SELECT service, COUNT(*) as cnt FROM syslog WHERE service!='' GROUP BY service ORDER BY cnt DESC LIMIT 15"
    )

    // 키워드별 오류/경고 카운트 (message LIKE)
    const errCount   = safeGet("SELECT COUNT(*) as c FROM syslog WHERE message LIKE '%error%'")?.c   ?? 0
    const warnCount  = safeGet("SELECT COUNT(*) as c FROM syslog WHERE message LIKE '%warn%'")?.c    ?? 0
    const failCount  = safeGet("SELECT COUNT(*) as c FROM syslog WHERE message LIKE '%fail%'")?.c    ?? 0
    const critCount  = safeGet("SELECT COUNT(*) as c FROM syslog WHERE message LIKE '%critical%'")?.c ?? 0
    const killedCount= safeGet("SELECT COUNT(*) as c FROM syslog WHERE message LIKE '%killed%'")?.c  ?? 0
    const panicCount = safeGet("SELECT COUNT(*) as c FROM syslog WHERE message LIKE '%panic%'")?.c   ?? 0

    // 오류 발생 상위 서비스
    const topErrServices = safe(
      "SELECT service, COUNT(*) as cnt FROM syslog WHERE message LIKE '%error%' AND service!='' GROUP BY service ORDER BY cnt DESC LIMIT 6"
    )

    // 분류별 집계
    const kernelCount  = safeGet("SELECT COUNT(*) as c FROM syslog WHERE service='kernel'")?.c          ?? 0
    const systemdCount = safeGet("SELECT COUNT(*) as c FROM syslog WHERE service LIKE 'systemd%'")?.c   ?? 0
    const sshdCount    = safeGet("SELECT COUNT(*) as c FROM syslog WHERE service='sshd'")?.c            ?? 0
    const sudoCount    = safeGet("SELECT COUNT(*) as c FROM syslog WHERE service='sudo'")?.c            ?? 0
    const cronCount    = safeGet("SELECT COUNT(*) as c FROM syslog WHERE service IN ('cron','CRON','crond','anacron')")?.c ?? 0
    const nmCount      = safeGet("SELECT COUNT(*) as c FROM syslog WHERE service='NetworkManager'")?.c  ?? 0

    // 칩용 전체 서비스 목록
    const allTypes = safe(
      "SELECT service as type, COUNT(*) as cnt FROM syslog WHERE service!='' GROUP BY service ORDER BY cnt DESC"
    )

    return {
      overview, topServices,
      errCount, warnCount, failCount, critCount, killedCount, panicCount,
      topErrServices,
      kernelCount, systemdCount, sshdCount, sudoCount, cronCount, nmCount,
      allTypes,
    }
  } catch { return null }
})

// ── IPC: Apache2 대시보드 통계 ──────────────────────
ipcMain.handle('db:getApache2Dashboard', () => {
  if (!db) return null
  const cached = readDashboardCache('apache2')
  if (cached) return cached
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='apache2'"
    ).get()
    if (!exists) return null

    const safe    = sql       => { try { return db.prepare(sql).all()  } catch { return [] } }
    const safeGet = (sql, ...a) => { try { return db.prepare(sql).get(...a) } catch { return null } }

    // 개요
    const overview = safeGet(
      "SELECT COUNT(*) as total, MIN(date_time) as first_dt, MAX(date_time) as last_dt, COUNT(DISTINCT src_ip) as ip_count, COUNT(DISTINCT uri) as uri_count FROM apache2"
    )

    // 상태코드별 카운트 (상위 20개)
    const statusDist = safe(
      "SELECT status, COUNT(*) as cnt FROM apache2 GROUP BY status ORDER BY cnt DESC LIMIT 20"
    )

    // 상태코드 범주 집계
    const s2xx = safeGet("SELECT COUNT(*) as c FROM apache2 WHERE status >= 200 AND status < 300")?.c ?? 0
    const s3xx = safeGet("SELECT COUNT(*) as c FROM apache2 WHERE status >= 300 AND status < 400")?.c ?? 0
    const s4xx = safeGet("SELECT COUNT(*) as c FROM apache2 WHERE status >= 400 AND status < 500")?.c ?? 0
    const s5xx = safeGet("SELECT COUNT(*) as c FROM apache2 WHERE status >= 500 AND status < 600")?.c ?? 0

    // 200 응답 메서드 분포
    const methodDist200 = safe(
      "SELECT method, COUNT(*) as cnt FROM apache2 WHERE status=200 AND method!='' GROUP BY method ORDER BY cnt DESC"
    )

    // 200 응답 상위 URI (상위 10개)
    const topUri200 = safe(
      "SELECT uri, COUNT(*) as cnt FROM apache2 WHERE status=200 GROUP BY uri ORDER BY cnt DESC LIMIT 10"
    )

    // 상위 IP (전체 요청 기준 상위 5개)
    const topIPs = safe(
      "SELECT src_ip, COUNT(*) as cnt FROM apache2 WHERE src_ip!='' GROUP BY src_ip ORDER BY cnt DESC LIMIT 5"
    )

    // 오류 상위 IP (4xx/5xx 기준 상위 5개)
    const topErrIPs = safe(
      "SELECT src_ip, COUNT(*) as cnt FROM apache2 WHERE status >= 400 AND src_ip!='' GROUP BY src_ip ORDER BY cnt DESC LIMIT 5"
    )

    // vhost 분포 (복수 vhost가 있을 경우)
    const vhosts = safe(
      "SELECT vhost, COUNT(*) as cnt FROM apache2 WHERE vhost!='' GROUP BY vhost ORDER BY cnt DESC LIMIT 10"
    )

    return {
      overview, statusDist, s2xx, s3xx, s4xx, s5xx,
      methodDist200, topUri200, topIPs, topErrIPs, vhosts,
    }
  } catch { return null }
})

// ── IPC: 공통(자동) 대시보드 ─────────────────────────
// 전용 대시보드가 없는 테이블용. 기간 + 핵심 컬럼 Top-N 자동 집계.
// 총 건수는 렌더러가 이미 보유(getTableData total)하므로 여기서 COUNT 재실행하지 않음.
ipcMain.handle('db:getGenericDashboard', (_e, table) => {
  if (!db) return null
  const cached = readDashboardCache(table)
  if (cached) return cached
  try {
    const cols = db.prepare(`PRAGMA table_info("${table}")`).all().map(r => r.name)
    if (!cols.length) return null

    const safeGet = (sql, ...a) => { try { return db.prepare(sql).get(...a) } catch { return null } }
    const safeAll = (sql, ...a) => { try { return db.prepare(sql).all(...a) } catch { return [] } }

    const tsCol = cols.includes('date_time') ? 'date_time'
                : cols.includes('timestamp')  ? 'timestamp'
                : null

    const idxCols   = indexedColumns(table)
    // 대용량 비인덱스 풀스캔 회피용 행수 추정(인덱스/통계 없이 빠른 상한 확인)
    const probe     = safeGet(`SELECT COUNT(*) AS c FROM (SELECT 1 FROM "${table}" LIMIT ${GENERIC_SCAN_LIMIT + 1})`)
    const allowScan = (probe?.c ?? 0) <= GENERIC_SCAN_LIMIT

    let range = { min: null, max: null }
    if (tsCol && (idxCols.has(tsCol) || allowScan)) {
      const r = safeGet(`SELECT MIN("${tsCol}") AS mn, MAX("${tsCol}") AS mx FROM "${table}"`)
      if (r) range = { min: r.mn, max: r.mx }
    }

    const keyCols = GENERIC_KEY_COLS
      .filter(c => cols.includes(c) && !GENERIC_SKIP_COLS.has(c))
      .filter(c => idxCols.has(c) || allowScan)
      .slice(0, 4)

    const breakdowns = keyCols.map(col => ({
      column: col,
      items: safeAll(
        `SELECT "${col}" AS val, COUNT(*) AS cnt FROM "${table}"
         WHERE "${col}" IS NOT NULL AND CAST("${col}" AS TEXT) != ''
         GROUP BY "${col}" ORDER BY cnt DESC LIMIT 8`
      ),
    })).filter(b => b.items.length)

    return { table, tsCol, range, breakdowns, scanLimited: !allowScan }
  } catch { return null }
})

// ── 웹 로그 IP 뷰 헬퍼 ───────────────────────────────
// 웹 로그 4개 테이블의 IP 컬럼/UNION 가능한 컬럼 매핑.
// 존재하지 않는 테이블은 자동 스킵.
const _WEB_LOG_SRC = [
  { table: 'apache2',       ip: 'src_ip'    },
  { table: 'nginx',         ip: 'src_ip'    },
  { table: 'apache2_error', ip: 'client_ip' },
  { table: 'nginx_error',   ip: 'client_ip' },
]
const _WEB_TABLES_EXIST = () => _WEB_LOG_SRC.filter(s => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(s.table) }
  catch { return false }
})

// ── IPC: 웹 로그 4개 테이블에서 IP 중복제거 + 카운트 ──
ipcMain.handle('db:getWebIps', () => {
  if (!db) return []
  const counts = new Map()    // ip → totalCount
  for (const s of _WEB_TABLES_EXIST()) {
    try {
      const rows = db.prepare(
        `SELECT "${s.ip}" AS ip, COUNT(*) AS cnt FROM "${s.table}"
         WHERE "${s.ip}" IS NOT NULL AND "${s.ip}" NOT IN ('','-','?','0.0.0.0')
         GROUP BY "${s.ip}"`
      ).all()
      for (const { ip, cnt } of rows) counts.set(ip, (counts.get(ip) || 0) + cnt)
    } catch { /* 컬럼 미존재 등 — 스킵 */ }
  }
  return [...counts.entries()]
    .map(([ip, cnt]) => ({ ip, cnt }))
    .sort((a, b) => b.cnt - a.cnt)
})

// ── IPC: 선택된 IP/CIDR 의 웹 로그 records UNION (페이지네이션 + 정렬 + 컬럼 필터) ─
//   selector: { mode: 'exact'|'prefix', value: '1.2.3.4' | '1.2.3.' | '1.2.' }
// 모든 테이블의 공통 컬럼만 UNION (각 테이블의 고유 컬럼은 NULL 로 채움).
ipcMain.handle('db:getWebRecords', (_e, { selector, limit, offset, sortCol, sortDir, search, colFilters, skipCount }) => {
  const empty = { rows: [], total: 0, columns: [] }
  if (!db || !selector?.value) return empty

  // ip 매칭 조건 (정확 = / 접두어 LIKE) — 각 테이블의 ip 컬럼에 동일 패턴 적용
  const ipPredicate = (col) => selector.mode === 'prefix'
    ? { sql: `"${col}" LIKE ?`, param: selector.value + '%' }
    : { sql: `"${col}" = ?`,    param: selector.value }

  // 공통 컬럼 (UNION 형태로 노출)
  const COMMON = ['source', 'date_time', 'ip', 'status', 'method', 'uri', 'user_agent']
  const present = _WEB_TABLES_EXIST()
  if (!present.length) return empty

  // 각 테이블별 SELECT — 컬럼이 없으면 NULL.
  const subqueries = []
  const subparams  = []
  for (const s of present) {
    try {
      const cols = db.prepare(`PRAGMA table_info("${s.table}")`).all().map(r => r.name)
      const pick = (c) => cols.includes(c) ? `"${c}"` : 'NULL'
      const pred = ipPredicate(s.ip)
      subqueries.push(`SELECT
        '${s.table}' AS source,
        ${pick('date_time')} AS date_time,
        "${s.ip}" AS ip,
        ${pick('status')} AS status,
        ${pick('method')} AS method,
        ${pick('uri')} AS uri,
        ${pick('user_agent')} AS user_agent
        FROM "${s.table}" WHERE ${pred.sql}`)
      subparams.push(pred.param)
    } catch { /* skip */ }
  }
  if (!subqueries.length) return empty

  const union = subqueries.join(' UNION ALL ')

  // 추가 조건 (검색 / colFilters) — UNION 의 결과에 부착
  const conds = []
  const condParams = []
  if (search && search.trim()) {
    const { clause, params: sp } = buildSearchCondition(COMMON, search)
    if (clause) { conds.push(clause); condParams.push(...sp) }
  }
  if (colFilters && typeof colFilters === 'object') {
    for (const [col, val] of Object.entries(colFilters)) {
      if (val && val.trim() && COMMON.includes(col)) {
        const { clause, params: cp } = buildColumnCondition(col, val)
        if (clause) { conds.push(clause); condParams.push(...cp) }
      }
    }
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : ''

  // 정렬 — sortCol 미지정이면 date_time ASC
  let order = 'ORDER BY "date_time" ASC'
  if (sortCol && COMMON.includes(sortCol)) {
    order = `ORDER BY "${sortCol}" ${sortDir === 'DESC' ? 'DESC' : 'ASC'}`
  }

  try {
    const total = skipCount
      ? null
      : db.prepare(`SELECT COUNT(*) AS c FROM (${union}) ${where}`).get(...subparams, ...condParams).c
    const rows  = db.prepare(`SELECT * FROM (${union}) ${where} ${order} LIMIT ? OFFSET ?`)
                       .all(...subparams, ...condParams, limit, offset)
    return { rows, total, columns: COMMON }
  } catch (e) {
    return { rows: [], total: 0, columns: COMMON, error: e.message }
  }
})

// ── IPC: IP enrich 캐시 일괄 로드 (DB 열 때 1회) ─────
// ipinfo 테이블 전체를 {ip: {country_code, country, asn, as_name, vpn_suspect}} 맵으로.
ipcMain.handle('db:getIpInfo', () => {
  if (!db) return {}
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='ipinfo'"
    ).get()
    if (!exists) return {}
    const rows = db.prepare(
      "SELECT ip, country_code, country, asn, as_name, vpn_suspect FROM ipinfo"
    ).all()
    const map = {}
    for (const r of rows) {
      map[r.ip] = {
        cc:  r.country_code || '',
        cn:  r.country      || '',
        asn: r.asn          || '',
        co:  r.as_name      || '',
        vpn: !!r.vpn_suspect,
      }
    }
    return map
  } catch { return {} }
})

// ── IPC: 전체 테이블 통합 검색 ───────────────────────
ipcMain.handle('db:globalSearch', (_e, query) => {
  if (!db || !query || !query.trim()) return []
  const q = query.trim()

  let tableNames
  try {
    tableNames = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all().map(r => r.name)
  } catch { return [] }

  const results = []
  for (const table of tableNames) {
    try {
      const cols = db.prepare(`PRAGMA table_info("${table}")`).all().map(r => r.name)
      if (!cols.length) continue

      const { clause, params } = buildSearchCondition(cols, q)
      if (!clause) continue
      const where = clause

      const total = db.prepare(`SELECT COUNT(*) as c FROM "${table}" WHERE ${where}`).get(...params).c
      if (total === 0) continue

      const rows = db.prepare(`SELECT * FROM "${table}" WHERE ${where} LIMIT 20`).all(...params)
      results.push({ table, columns: cols, rows, total })
    } catch { /* 접근 오류 무시 */ }
  }
  return results
})
