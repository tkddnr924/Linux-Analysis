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

// ── IPC: 테이블 데이터 (페이지네이션 + 검색 + 정렬) ─
ipcMain.handle('db:getTableData', (_e, { table, search, limit, offset, sortCol, sortDir }) => {
  if (!db) return { rows: [], total: 0, columns: [] }
  try {
    const cols = db.prepare(`PRAGMA table_info("${table}")`).all().map(r => r.name)

    let where = ''
    const params = []

    if (search && search.trim()) {
      where = 'WHERE ' + cols.map(c => `CAST("${c}" AS TEXT) LIKE ?`).join(' OR ')
      cols.forEach(() => params.push(`%${search.trim()}%`))
    }

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
