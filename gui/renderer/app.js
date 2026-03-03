/**
 * app.js — 렌더러 프로세스 UI 로직
 *
 * - DB 열기 / 테이블 목록 사이드바 렌더링
 * - 테이블 데이터 페이지네이션 + 실시간 검색
 * - 행 클릭 → 상세 모달
 * - 값 타입 자동 감지로 컬러 하이라이팅
 */

'use strict'

// ── 상수 ─────────────────────────────────────────────
const PAGE_SIZE = 150

/** 사이드바 그룹 정의 (순서 유지) */
const GROUPS = [
  { label: '📊 요약',       icon: '📊', tables: ['info', 'log'] },
  { label: '🔐 인증 로그',  icon: '🔐', tables: ['authlog_login', 'authlog_sudo', 'authlog_attack_ip', 'authlog_su'] },
  { label: '🔍 감사 로그',  icon: '🔍', tables: ['audit_login', 'audit_cmd', 'audit_file'] },
  { label: '⏰ Cron',       icon: '⏰', tables: ['cron_info'] },
  { label: '🌐 Nginx',      icon: '🌐', tables: ['nginx_top_ip', 'nginx_attack', 'nginx_webshell'] },
]

/** 테이블별 한글 레이블 */
const TABLE_LABEL = {
  info:               '서버 정보',
  log:                '로그 요약',
  authlog_login:      'SSH 로그인 성공',
  authlog_sudo:       'sudo 실행',
  authlog_attack_ip:  '공격 시도 IP',
  authlog_su:         'su 전환',
  audit_login:        '인증 이벤트',
  audit_cmd:          '명령 실행',
  audit_file:         '파일 접근',
  cron_info:          'Cron 실행 통계',
  nginx_top_ip:       '공격 탐지 IP',
  nginx_attack:       '공격 페이로드',
  nginx_webshell:     '웹쉘 탐지',
}

// ── 컬럼 타입 힌트 (컬럼명 키워드 기반) ──────────────
const MONO_COLS    = ['raw_line', 'cmd', 'proctitle', 'comm', 'exe', 'command', 'uri',
                      'decoded_uri', 'user_agent', 'referer', 'listen_ports',
                      'matched_str', 'suspicion_flags', 'attack_types', 'commands']
const IP_COLS      = ['src_ip', 'internal_ip', 'addr', 'hostname']
const DATE_COLS    = ['date_time', 'first_seen', 'last_seen', 'collected_at',
                      'booted_at', 'last_reboot', 'parsed_at', 'start_time', 'end_time']
const PATH_COLS    = ['file_path', 'cwd', 'exe']
const NUMBER_COLS  = ['count', 'exec_count', 'total_count', 'success_count', 'fail_count',
                      'attack_count', 'access_count', 'bytes_sent', 'bytes_min',
                      'bytes_max', 'file_size', 'cpu_cores', 'uptime_days',
                      'suspicion_score', 'total_records', 'file_count',
                      'avg_duration_sec', 'total_duration_sec']

// 공격 유형 키워드
const ATTACK_KEYWORDS = ['sql_injection', 'xss', 'path_traversal', 'lfi_rfi',
                         'shell_injection', 'php_injection', 'log4shell', 'spring4shell',
                         'attack', 'webshell', 'known_webshell']

// ── 상태 ─────────────────────────────────────────────
let currentTable   = null
let currentPage    = 0
let currentSearch  = ''
let currentTotal   = 0
let currentColumns = []
let searchTimer    = null
let tableCountMap  = new Map()  // name → count

// ── DOM 참조 ─────────────────────────────────────────
const $ = id => document.getElementById(id)

const elDbPath       = $('db-path')
const elSidebar      = $('sidebar-content')
const elWelcome      = $('welcome')
const elTableView    = $('table-view')
const elTableTitle   = $('table-title')
const elTotalBadge   = $('total-badge')
const elDataTable    = $('data-table')
const elSearchInput  = $('search-input')
const elBtnClear     = $('btn-clear')
const elBtnPrev      = $('btn-prev')
const elBtnNext      = $('btn-next')
const elPageInfo     = $('page-info')
const elPagCount     = $('pagination-info')
const elStatusLeft   = $('status-left')
const elStatusRight  = $('status-right')
const elModal        = $('row-modal')
const elModalOverlay = $('modal-overlay')
const elModalClose   = $('modal-close')
const elModalBody    = $('modal-body')

// ── 유틸 ─────────────────────────────────────────────
function escHtml (s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function fmtSize (bytes) {
  if (bytes < 1024)        return bytes + ' B'
  if (bytes < 1024 ** 2)   return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 ** 2).toFixed(1) + ' MB'
}

function isIPv4 (s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) }
function isIPv6 (s) { return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s) }
function isDateStr(s) {
  return /^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?/.test(s)
}

function setStatus (msg) { elStatusLeft.textContent = msg }

// ── DB 열기 흐름 ──────────────────────────────────────
async function openDB (filePath) {
  setStatus('DB 열기 중…')
  const res = await window.api.openDB(filePath)
  if (!res.success) {
    alert(`DB 열기 실패:\n${res.error}`)
    setStatus('열기 실패')
    return
  }
  elDbPath.textContent = res.path
  elStatusRight.textContent = fmtSize(res.size)
  setStatus(`로드 완료: ${res.path.split(/[/\\]/).pop()}`)
  await loadTables()
}

async function onClickOpen () {
  const filePath = await window.api.openFile()
  if (filePath) await openDB(filePath)
}

// ── 테이블 목록 ──────────────────────────────────────
async function loadTables () {
  const tables = await window.api.getTables()
  tableCountMap = new Map(tables.map(t => [t.name, t.count]))
  renderSidebar(tables)
  if (tables.length > 0) {
    // 우선순위: cron_info → authlog_login → 첫 번째
    const priority = ['cron_info', 'authlog_login', 'authlog_attack_ip', 'nginx_attack']
    const first = priority.find(n => tableCountMap.has(n)) || tables[0].name
    await selectTable(first)
  }
  elWelcome.classList.add('hidden')
  elTableView.classList.remove('hidden')
}

// ── 사이드바 렌더링 ───────────────────────────────────
function renderSidebar (tables) {
  const available = new Set(tables.map(t => t.name))
  const rendered  = new Set()
  let html = ''

  for (const g of GROUPS) {
    const gt = g.tables.filter(n => available.has(n))
    if (!gt.length) continue

    html += `<div class="sidebar-group">`
    html += `<div class="sidebar-group-header">${g.label}</div>`
    for (const name of gt) {
      const label = TABLE_LABEL[name] || name
      const count = tableCountMap.get(name) ?? 0
      html += sidebarItem(name, label, count)
      rendered.add(name)
    }
    html += `</div>`
  }

  // 그룹에 없는 테이블 (기타)
  const extra = tables.filter(t => !rendered.has(t.name))
  if (extra.length) {
    html += `<div class="sidebar-group">`
    html += `<div class="sidebar-group-header">기타</div>`
    for (const t of extra) {
      html += sidebarItem(t.name, t.name, t.count)
    }
    html += `</div>`
  }

  elSidebar.innerHTML = html
}

function sidebarItem (name, label, count) {
  const c = Number(count).toLocaleString()
  return `<div class="sidebar-item" data-table="${escHtml(name)}"
               title="${escHtml(label)} (${c}건)">
    <span class="sidebar-item-name">${escHtml(label)}</span>
    <span class="sidebar-item-count">${c}</span>
  </div>`
}

// ── 테이블 선택 ──────────────────────────────────────
async function selectTable (name) {
  currentTable  = name
  currentPage   = 0
  currentSearch = ''
  elSearchInput.value = ''
  elBtnClear.classList.add('hidden')

  // 사이드바 활성 상태
  document.querySelectorAll('.sidebar-item').forEach(el => {
    el.classList.toggle('active', el.dataset.table === name)
  })

  await loadData()
}

// ── 데이터 로드 ──────────────────────────────────────
async function loadData () {
  if (!currentTable) return
  setStatus('로딩 중…')

  const res = await window.api.getTableData({
    table:  currentTable,
    search: currentSearch,
    limit:  PAGE_SIZE,
    offset: currentPage * PAGE_SIZE,
  })

  if (res.error) {
    setStatus(`오류: ${res.error}`)
    return
  }

  currentTotal   = res.total
  currentColumns = res.columns

  renderToolbar()
  renderTable(res.columns, res.rows)
  renderPagination()
  setStatus(`${currentTable} — ${currentTotal.toLocaleString()}건`)
}

// ── 툴바 ─────────────────────────────────────────────
function renderToolbar () {
  const label = TABLE_LABEL[currentTable] || currentTable
  elTableTitle.textContent  = label
  elTotalBadge.textContent  =
    (currentSearch ? `${currentTotal.toLocaleString()}건 / ` : '') +
    `${(tableCountMap.get(currentTable) ?? 0).toLocaleString()}건 전체`
}

// ── 테이블 렌더링 ─────────────────────────────────────
function renderTable (columns, rows) {
  if (!columns.length) {
    elDataTable.innerHTML = '<div class="empty-state">데이터가 없습니다.</div>'
    return
  }

  let html = '<table><thead><tr>'
  for (const col of columns) html += `<th>${escHtml(col)}</th>`
  html += '</tr></thead><tbody>'

  if (!rows.length) {
    html += `<tr><td class="empty-cell" colspan="${columns.length}">검색 결과 없음</td></tr>`
  } else {
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]
      html += `<tr data-row="${i}">`
      for (const col of columns) {
        const raw = row[col]
        const { display, cls } = formatCell(col, raw)
        const title = raw === null ? '' : escHtml(String(raw))
        html += `<td class="${cls}" title="${title}">${display}</td>`
      }
      html += '</tr>'
    }
  }
  html += '</tbody></table>'
  elDataTable.innerHTML = html

  // 행 클릭 → 모달
  elDataTable.querySelectorAll('tbody tr[data-row]').forEach((tr, i) => {
    tr.addEventListener('click', () => openModal(columns, rows[i]))
  })
}

// ── 셀 값 포맷 ───────────────────────────────────────
function formatCell (col, raw) {
  if (raw === null || raw === undefined || raw === '') {
    return { display: '<span class="val-null">—</span>', cls: '' }
  }

  const s   = String(raw)
  const low = col.toLowerCase()

  // NULL 문자열
  if (s.toUpperCase() === 'NULL') return { display: '<span class="val-null">NULL</span>', cls: '' }

  // 공격 유형
  if (ATTACK_KEYWORDS.some(k => s.toLowerCase().includes(k) && low.includes('type'))) {
    return { display: escHtml(truncate(s, 60)), cls: 'val-attack' }
  }

  // IP 주소 컬럼
  if (IP_COLS.includes(low) && (isIPv4(s) || isIPv6(s))) {
    return { display: escHtml(s), cls: 'val-ip' }
  }

  // 날짜 컬럼
  if (DATE_COLS.includes(low) && isDateStr(s)) {
    return { display: escHtml(s), cls: 'val-date' }
  }

  // 숫자 컬럼
  if (NUMBER_COLS.includes(low) && !isNaN(raw)) {
    return { display: Number(raw).toLocaleString(), cls: 'val-number' }
  }

  // 경로 컬럼
  if (PATH_COLS.includes(low) && (s.startsWith('/') || s.includes('\\'))) {
    return { display: escHtml(truncate(s, 60)), cls: 'val-path' }
  }

  // 모노 폰트 컬럼
  if (MONO_COLS.includes(low)) {
    return { display: escHtml(truncate(s, 80)), cls: 'val-mono' }
  }

  // 성공/실패
  if (/^(success|accepted|opened)$/i.test(s)) return { display: escHtml(s), cls: 'val-success' }
  if (/^(fail|failed|error)$/i.test(s))        return { display: escHtml(s), cls: 'val-attack' }

  return { display: escHtml(truncate(s, 80)), cls: '' }
}

function truncate (s, max) {
  return s.length > max ? s.slice(0, max) + '…' : s
}

// ── 페이지네이션 ─────────────────────────────────────
function renderPagination () {
  const total  = currentTotal
  const pages  = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const start  = total === 0 ? 0 : currentPage * PAGE_SIZE + 1
  const end    = Math.min((currentPage + 1) * PAGE_SIZE, total)

  elPageInfo.textContent  = `${currentPage + 1} / ${pages}`
  elPagCount.textContent  =
    total > 0 ? `${start.toLocaleString()} – ${end.toLocaleString()} / ${total.toLocaleString()}건` : '0건'
  elBtnPrev.disabled = currentPage === 0
  elBtnNext.disabled = currentPage >= pages - 1
}

// ── 검색 ─────────────────────────────────────────────
function onSearchInput () {
  const val = elSearchInput.value
  elBtnClear.classList.toggle('hidden', !val)
  clearTimeout(searchTimer)
  searchTimer = setTimeout(async () => {
    currentSearch = val.trim()
    currentPage   = 0
    await loadData()
  }, 300)
}

function onClearSearch () {
  elSearchInput.value = ''
  elBtnClear.classList.add('hidden')
  currentSearch = ''
  currentPage   = 0
  loadData()
}

// ── 행 상세 모달 ─────────────────────────────────────
function openModal (columns, row) {
  let html = ''
  for (const col of columns) {
    const raw = row[col]
    const isNull = raw === null || raw === undefined
    const display = isNull ? 'NULL' : escHtml(String(raw))
    html += `<div class="modal-row">
      <div class="modal-col-name">${escHtml(col)}</div>
      <div class="modal-col-val ${isNull ? 'is-null' : ''}">${display}</div>
    </div>`
  }
  elModalBody.innerHTML = html
  elModal.classList.remove('hidden')
}

function closeModal () {
  elModal.classList.add('hidden')
  elModalBody.innerHTML = ''
}

// ── 이벤트 바인딩 ─────────────────────────────────────

// 사이드바 클릭 — 이벤트 위임 (CSP inline onclick 차단 우회)
elSidebar.addEventListener('click', async e => {
  const item = e.target.closest('.sidebar-item')
  if (item && item.dataset.table) {
    await selectTable(item.dataset.table)
  }
})

$('btn-open').addEventListener('click', onClickOpen)
$('btn-open-2').addEventListener('click', onClickOpen)
elSearchInput.addEventListener('input', onSearchInput)
elBtnClear.addEventListener('click', onClearSearch)

elBtnPrev.addEventListener('click', async () => {
  if (currentPage > 0) { currentPage--; await loadData() }
})
elBtnNext.addEventListener('click', async () => {
  const pages = Math.ceil(currentTotal / PAGE_SIZE)
  if (currentPage < pages - 1) { currentPage++; await loadData() }
})

// 모달 닫기
elModalClose.addEventListener('click', closeModal)
elModalOverlay.addEventListener('click', closeModal)
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal() })

// 검색 단축키 (Ctrl+F / Cmd+F)
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    e.preventDefault()
    elSearchInput.focus()
    elSearchInput.select()
  }
})

// ── 기동 시 자동 감지 ────────────────────────────────
;(async () => {
  const autoPath = await window.api.getAutoPath()
  if (autoPath) {
    const hint = $('auto-hint')
    hint.style.display = 'block'
    await openDB(autoPath)
  }
})()

