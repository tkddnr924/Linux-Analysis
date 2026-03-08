/**
 * main.js — Electron 메인 프로세스
 *
 * - BrowserWindow 생성
 * - better-sqlite3 기반 analysis.db 읽기 (읽기 전용)
 * - IPC 핸들러 등록
 * - 기동 시 ../analysis.db 자동 감지
 */

'use strict'

const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path  = require('path')
const fs    = require('fs')
const Database = require('better-sqlite3')

let win = null
let db  = null
let currentDbPath = null

// gui/ 의 부모(프로젝트 루트)에 있는 analysis.db 자동 감지
const AUTO_DB = path.join(__dirname, '..', 'analysis.db')

// ── 윈도우 생성 ──────────────────────────────────────
function createWindow () {
  win = new BrowserWindow({
    width:    1440,
    height:   900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0d1117',
    title: 'Linux Analysis Viewer',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,           // better-sqlite3 preload 접근 허용
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
    title: 'analysis.db 열기',
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

// ── IPC: 테이블 목록 + 행 수 ─────────────────────────
ipcMain.handle('db:getTables', () => {
  if (!db) return []
  try {
    const rows = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all()
    return rows.map(r => {
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

// ── IPC: 테이블 데이터 (페이지네이션 + 검색 + 정렬 + 날짜 범위) ─
ipcMain.handle('db:getTableData', (_e, { table, search, limit, offset, sortCol, sortDir, dateFrom, dateTo }) => {
  if (!db) return { rows: [], total: 0, columns: [] }
  try {
    const cols = db.prepare(`PRAGMA table_info("${table}")`).all().map(r => r.name)

    const conditions = []
    const params = []

    if (search && search.trim()) {
      conditions.push('(' + cols.map(c => `CAST("${c}" AS TEXT) LIKE ?`).join(' OR ') + ')')
      cols.forEach(() => params.push(`%${search.trim()}%`))
    }
    if (dateFrom) {
      conditions.push('"date_time" >= ?')
      params.push(dateFrom + ' 00:00:00')
    }
    if (dateTo) {
      conditions.push('"date_time" <= ?')
      params.push(dateTo + ' 23:59:59')
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : ''

    // ORDER BY: sortCol이 실제 컬럼명인지 검증 후 적용
    let order = ''
    if (sortCol && cols.includes(sortCol)) {
      const dir = sortDir === 'DESC' ? 'DESC' : 'ASC'
      order = `ORDER BY "${sortCol}" ${dir}`
    }

    const total = db.prepare(`SELECT COUNT(*) as c FROM "${table}" ${where}`).get(...params).c
    const rows  = db.prepare(`SELECT * FROM "${table}" ${where} ${order} LIMIT ? OFFSET ?`).all(...params, limit, offset)

    return { rows, total, columns: cols }
  } catch (e) {
    return { rows: [], total: 0, columns: [], error: e.message }
  }
})

// ── IPC: 세션 목록 조회 ───────────────────────────────
ipcMain.handle('db:getLoginSessions', () => {
  if (!db) return { sessions: [], has_data: false }
  try {
    const exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='authlog_login'"
    ).get()
    if (!exists) return { sessions: [], has_data: false }

    const sessions = db.prepare(`
      SELECT id, src_ip, user, auth_method, first_seen, last_seen, count
      FROM authlog_login
      WHERE src_ip != '' AND user != ''
      ORDER BY first_seen ASC
    `).all()
    return { sessions, has_data: sessions.length > 0 }
  } catch { return { sessions: [], has_data: false } }
})

// ── IPC: 세션 활동 상세 조회 ─────────────────────────
ipcMain.handle('db:getSessionActivity', (_e, { user, src_ip, first_seen, last_seen }) => {
  if (!db) return {}
  const result = { sudo: [], cmd: [], su: [], bruteforce: [] }

  // sudo 명령 (같은 사용자, 시간 오버랩)
  try {
    result.sudo = db.prepare(`
      SELECT user, command, first_seen, last_seen, count
      FROM authlog_sudo
      WHERE user = ?
        AND last_seen  >= ?
        AND first_seen <= ?
      ORDER BY first_seen
    `).all(user, first_seen, last_seen)
  } catch {}

  // audit 명령 실행 (uid 또는 auid 가 사용자명과 일치, 시간 오버랩)
  try {
    result.cmd = db.prepare(`
      SELECT uid, auid, cmd, cwd, first_seen, last_seen, count
      FROM audit_cmd
      WHERE (uid = ? OR auid = ?)
        AND last_seen  >= ?
        AND first_seen <= ?
      ORDER BY first_seen
      LIMIT 60
    `).all(user, user, first_seen, last_seen)
  } catch {}

  // 계정 전환 su (같은 사용자, 시간 오버랩)
  try {
    result.su = db.prepare(`
      SELECT from_user, to_user, first_seen, last_seen, count
      FROM authlog_su
      WHERE from_user = ?
        AND last_seen  >= ?
        AND first_seen <= ?
      ORDER BY first_seen
    `).all(user, first_seen, last_seen)
  } catch {}

  // 동일 IP 브루트포스 기록
  try {
    result.bruteforce = db.prepare(`
      SELECT src_ip, burst_start, burst_end, attempt_count, success_count
      FROM authlog_bruteforce
      WHERE src_ip = ?
      ORDER BY burst_start
    `).all(src_ip)
  } catch {}

  return result
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

      const where  = '(' + cols.map(c => `CAST("${c}" AS TEXT) LIKE ?`).join(' OR ') + ')'
      const params = cols.map(() => `%${q}%`)

      const total = db.prepare(`SELECT COUNT(*) as c FROM "${table}" WHERE ${where}`).get(...params).c
      if (total === 0) continue

      const rows = db.prepare(`SELECT * FROM "${table}" WHERE ${where} LIMIT 20`).all(...params)
      results.push({ table, columns: cols, rows, total })
    } catch { /* 테이블 접근 오류 무시 */ }
  }
  return results
})

// ── IPC: IP 기반 공격자 종합 프로파일 ────────────────
/**
 * 분석 DB의 여러 테이블을 src_ip 기준으로 집계하여
 * 공격자 프로파일 배열을 반환한다.
 * 존재하지 않는 테이블은 자동으로 스킵한다.
 */
ipcMain.handle('db:getAttackerProfiles', () => {
  if (!db) return []

  // 존재하는 테이블 집합
  const existingTables = new Set(
    db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name)
  )
  const has  = t => existingTables.has(t)
  const safe = (sql) => { try { return db.prepare(sql).all() } catch { return [] } }

  const ipMap = new Map()
  const ensure = ip => {
    if (!ipMap.has(ip)) ipMap.set(ip, { src_ip: ip })
    return ipMap.get(ip)
  }

  // ① 브루트포스 burst 집계
  if (has('authlog_bruteforce')) {
    for (const r of safe(`
      SELECT src_ip,
        COUNT(*)            AS bf_bursts,
        SUM(attempt_count)  AS bf_attempts,
        SUM(success_count)  AS bf_success,
        MIN(burst_start)    AS bf_first,
        MAX(burst_end)      AS bf_last
      FROM authlog_bruteforce
      WHERE src_ip != ''
      GROUP BY src_ip
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ② 공격 IP 통계 (authlog_attack_ip)
  if (has('authlog_attack_ip')) {
    for (const r of safe(`
      SELECT src_ip,
        total_count   AS atk_total,
        success_count AS atk_success,
        fail_count    AS atk_fail,
        first_seen    AS atk_first,
        last_seen     AS atk_last
      FROM authlog_attack_ip
      WHERE src_ip != ''
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ③ SSH 로그인 성공 (authlog_login)
  if (has('authlog_login')) {
    for (const r of safe(`
      SELECT src_ip,
        COUNT(*)                        AS login_combos,
        SUM(count)                      AS login_total,
        GROUP_CONCAT(DISTINCT user)     AS login_users,
        GROUP_CONCAT(DISTINCT auth_method) AS login_methods,
        MIN(first_seen)                 AS login_first,
        MAX(last_seen)                  AS login_last
      FROM authlog_login
      WHERE src_ip != ''
      GROUP BY src_ip
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ④ Nginx 웹 공격
  if (has('nginx_attack')) {
    for (const r of safe(`
      SELECT src_ip,
        COUNT(*)                           AS natk_count,
        GROUP_CONCAT(DISTINCT attack_type) AS natk_types,
        MIN(date_time)                     AS natk_first,
        MAX(date_time)                     AS natk_last
      FROM nginx_attack
      WHERE src_ip IS NOT NULL AND src_ip != ''
      GROUP BY src_ip
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ⑤ Apache 웹 공격
  if (has('apache2_attack')) {
    for (const r of safe(`
      SELECT src_ip,
        COUNT(*)                           AS aatk_count,
        GROUP_CONCAT(DISTINCT attack_type) AS aatk_types,
        MIN(date_time)                     AS aatk_first,
        MAX(date_time)                     AS aatk_last
      FROM apache2_attack
      WHERE src_ip IS NOT NULL AND src_ip != ''
      GROUP BY src_ip
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ⑥ Nginx 웹쉘
  if (has('nginx_webshell')) {
    for (const r of safe(`
      SELECT src_ip,
        COUNT(DISTINCT file_path)      AS ws_files,
        SUM(access_count)              AS ws_hits,
        MAX(suspicion_score)           AS ws_score,
        MIN(first_seen)                AS ws_first,
        MAX(last_seen)                 AS ws_last,
        GROUP_CONCAT(DISTINCT file_name) AS ws_names
      FROM nginx_webshell
      WHERE src_ip != ''
      GROUP BY src_ip
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ⑦ Apache 웹쉘
  if (has('apache2_webshell')) {
    for (const r of safe(`
      SELECT src_ip,
        COUNT(DISTINCT file_path)        AS ws2_files,
        SUM(access_count)                AS ws2_hits,
        MAX(suspicion_score)             AS ws2_score,
        MIN(first_seen)                  AS ws2_first,
        MAX(last_seen)                   AS ws2_last,
        GROUP_CONCAT(DISTINCT file_name) AS ws2_names
      FROM apache2_webshell
      WHERE src_ip != ''
      GROUP BY src_ip
    `)) Object.assign(ensure(r.src_ip), r)
  }

  // ⑧ UFW 방화벽 차단 — 기존 공격 IP만 보강 (새 IP는 추가하지 않음)
  if (has('syslog_ufw')) {
    for (const r of safe(`
      SELECT src_ip,
        SUM(count)               AS ufw_blocks,
        COUNT(DISTINCT dst_port) AS ufw_ports,
        MIN(first_seen)          AS ufw_first,
        MAX(last_seen)           AS ufw_last
      FROM syslog_ufw
      WHERE src_ip != '' AND src_ip != '0.0.0.0'
      GROUP BY src_ip
    `)) {
      if (ipMap.has(r.src_ip)) Object.assign(ipMap.get(r.src_ip), r)
    }
  }

  return Array.from(ipMap.values())
})

// ── IPC: 테이블 date_time 컬럼 최솟값·최댓값 ─────────
ipcMain.handle('db:getDateRange', (_e, table) => {
  if (!db) return { min: null, max: null }
  try {
    const row = db.prepare(`SELECT MIN(date_time) as mn, MAX(date_time) as mx FROM "${table}"`).get()
    return {
      min: row.mn ? row.mn.slice(0, 10) : null,
      max: row.mx ? row.mx.slice(0, 10) : null,
    }
  } catch {
    return { min: null, max: null }
  }
})
