'use strict'

// ── 상수 ──────────────────────────────────────────────
const PAGE_SIZE = 100

const TABLE_META = {
  sysinfo:       { label: '시스템 정보',       group: '시스템' },
  info:          { label: '파싱 파일 목록',     group: '시스템' },
  authlog:       { label: 'Auth 로그',          group: '인증' },
  wtmp:          { label: 'WTMP (로그인이력)',   group: '인증' },
  btmp:          { label: 'BTMP (실패로그인)',   group: '인증' },
  audit:         { label: 'Audit 로그',          group: '감사' },
  shell_history: { label: '셸 히스토리',         group: '감사' },
  journal:       { label: 'Journald',            group: '감사' },
  cron:          { label: 'Cron 로그',           group: '시스템 로그' },
  syslog:        { label: 'Syslog / Messages',   group: '시스템 로그' },
  kernlog:       { label: '커널 로그',            group: '시스템 로그' },
  apache2:       { label: 'Apache2 접근',        group: '웹 서버' },
  apache2_error: { label: 'Apache2 에러',        group: '웹 서버' },
  nginx:         { label: 'Nginx 접근',          group: '웹 서버' },
  nginx_error:   { label: 'Nginx 에러',          group: '웹 서버' },
  mysql_query:   { label: 'MySQL 쿼리',          group: '데이터베이스' },
  mysql_error:   { label: 'MySQL 에러',          group: '데이터베이스' },
}

const GROUP_ORDER = ['시스템', '인증', '감사', '시스템 로그', '웹 서버', '데이터베이스']

// 대시보드를 가진 테이블
const ARTIFACT_TABLES = new Set(['audit', 'authlog', 'apache2', 'syslog'])

// ── 아티팩트별 빠른 필터 그룹 ─────────────────────────
const AUDIT_QUICK_GROUPS = [
  { label: '로그인 관련', types: ['USER_LOGIN','USER_AUTH','USER_ACCT','USER_ERR','USER_START','USER_END','CRED_ACQ','CRED_DISP','CRED_REFR'] },
  { label: '명령 실행',   types: ['EXECVE','PROCTITLE','USER_CMD'] },
  { label: '파일 접근',   types: ['PATH','CWD'] },
  { label: '서비스',      types: ['SERVICE_START','SERVICE_STOP','DAEMON_START','DAEMON_END','DAEMON_ABORT','DAEMON_CONFIG'] },
  { label: '보안 이상',   types: ['AVC','CONFIG_CHANGE','SECCOMP','NETFILTER_PKT','ANOMALY_ABEND'] },
]

const AUTHLOG_QUICK_GROUPS = [
  { label: 'SSH 인증 성공', types: ['sshd_accepted_password','sshd_accepted_publickey','sshd_session_opened','sshd_session_closed'] },
  { label: 'SSH 인증 실패', types: ['sshd_failed_password','sshd_invalid_user','sshd_max_auth','pam_auth_failure'] },
  { label: 'SSH 연결',      types: ['sshd_conn_closed','sshd_conn_reset','sshd_disconnected','sshd_no_id_string','sshd_kex_error','sshd_banner_exchange','sshd_unable_negotiate'] },
  { label: 'sudo',          types: ['sudo_command','sudo_auth_failure'] },
  { label: 'su / CRON',    types: ['su_to','su_session_opened','su_session_closed','cron_session_opened','cron_session_closed'] },
]

const SYSLOG_QUICK_GROUPS = [
  { label: '커널',     types: ['kernel'] },
  { label: '네트워크', types: ['NetworkManager', 'dhclient', 'dhcpcd', 'wpa_supplicant', 'firewalld', 'nftables', 'pppd', 'networkd', 'ifup', 'ifdown'] },
  { label: '시스템',   types: ['systemd', 'systemd-journald', 'systemd-udevd', 'systemd-resolved', 'systemd-logind', 'systemd-networkd', 'systemd-timesyncd', 'init', 'snapd', 'dbus', 'dbus-daemon'] },
  { label: '인증',     types: ['sshd', 'sudo', 'su', 'login', 'gdm', 'gdm3', 'lightdm', 'polkitd', 'pam', 'useradd', 'usermod', 'passwd'] },
  { label: 'Cron',    types: ['cron', 'CRON', 'crond', 'anacron', 'atd'] },
]

const SYSLOG_KW_FILTERS = [
  { label: 'error',    value: 'error'    },
  { label: 'warn',     value: 'warn'     },
  { label: 'fail',     value: 'fail'     },
  { label: 'critical', value: 'critical' },
  { label: 'killed',   value: 'killed'   },
  { label: 'panic',    value: 'panic'    },
]

const QUICK_GROUPS = { audit: AUDIT_QUICK_GROUPS, authlog: AUTHLOG_QUICK_GROUPS }

// ── 상태 ──────────────────────────────────────────────
const S = {
  currentTable: null,
  page: 0, search: '', sortCol: null, sortDir: 'ASC',
  dateFrom: '', dateTo: '', colFilters: {},
  totalRows: 0, columns: [],
}

const A = {
  currentTable: null,
  page: 0, search: '', sortCol: null, sortDir: 'ASC',
  typeFilters: [], activeQuickGroup: null,
  statusFilter: null, methodFilters: [],
  colFilters: {},
  totalRows: 0, columns: [],
}

// ── DOM 헬퍼 ──────────────────────────────────────────
const $   = id => document.getElementById(id)
const esc = s  => String(s ?? '')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;')

function show(id, visible) {
  const el = $(id); if (el) el.classList.toggle('hidden', !visible)
}
function setStatus(msg, isError = false) {
  const el = $('status-left'); el.textContent = msg; el.style.color = isError ? 'var(--danger)' : ''
}
function formatBytes(bytes) {
  if (bytes < 1024)      return bytes + ' B'
  if (bytes < 1024**2)   return (bytes/1024).toFixed(1)+' KB'
  if (bytes < 1024**3)   return (bytes/1024**2).toFixed(1)+' MB'
  return (bytes/1024**3).toFixed(1)+' GB'
}
function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(()=>fn(...a), ms) }
}
function fmtDt(dt) { return dt ? dt.slice(0,16).replace('T',' ') : '—' }

// 테이블에서 시간 컬럼 자동 탐지 (main.js 의 tsCol 규칙과 동일)
function detectTsCol(columns) {
  if (columns.includes('date_time')) return 'date_time'
  if (columns.includes('timestamp')) return 'timestamp'
  return null
}

// 컬럼별 기본 폭(px) — table-layout:fixed 에서 사용
function defaultColWidth(col) {
  if (col === 'id') return 64
  if (['status','pid','tid','cid','bytes_sent','uid','gid'].includes(col)) return 84
  if (col === 'date_time' || col === 'timestamp') return 165
  if (['method','level','protocol','severity','facility'].includes(col)) return 92
  if (['raw_line','message','msg','cmdline','args'].includes(col)) return 460
  if (['uri','referer','user_agent','exe','command','line'].includes(col)) return 300
  if (col.endsWith('_ip') || col === 'addr' || col === 'ip') return 132
  return 150
}

// ── 초기화 ────────────────────────────────────────────
async function init() {
  $('btn-open').addEventListener('click', openDb)
  $('btn-open-2').addEventListener('click', openDb)
  $('btn-global-search').addEventListener('click', openGlobalSearch)
  $('gs-close').addEventListener('click', closeGlobalSearch)
  $('gs-overlay').addEventListener('click', closeGlobalSearch)
  $('gs-input').addEventListener('input', debounce(doGlobalSearch, 400))

  $('search-input').addEventListener('input', debounce(onSearch, 300))
  $('btn-clear').addEventListener('click', clearSearch)
  $('btn-prev').addEventListener('click', ()=>goPage(-1))
  $('btn-next').addEventListener('click', ()=>goPage(1))
  $('tl-date-from').addEventListener('change', onDateChange)
  $('tl-date-to').addEventListener('change', onDateChange)
  $('tl-date-clear').addEventListener('click', clearDateFilter)

  $('artifact-search').addEventListener('input', debounce(onArtifactSearch, 300))
  $('artifact-search-clear').addEventListener('click', clearArtifactSearch)
  $('artifact-btn-prev').addEventListener('click', ()=>goArtifactPage(-1))
  $('artifact-btn-next').addEventListener('click', ()=>goArtifactPage(1))
  $('artifact-filter-clear').addEventListener('click', clearArtifactTypeFilter)

  $('modal-close').addEventListener('click', closeModal)
  $('modal-overlay').addEventListener('click', closeModal)
  initDecodePopup()

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (!$('gs-panel').classList.contains('hidden'))  { closeGlobalSearch(); return }
      if (!$('row-modal').classList.contains('hidden')) { closeModal();        return }
    }
    if ((e.ctrlKey||e.metaKey) && e.shiftKey && e.key==='F') { e.preventDefault(); openGlobalSearch() }
  })

  const autoPath = await window.api.getAutoPath()
  if (autoPath) {
    $('auto-hint').classList.remove('hidden')
    await loadDb(autoPath)
  }
}

// ── DB 열기 ───────────────────────────────────────────
async function openDb() {
  const fp = await window.api.openFile()
  if (fp) await loadDb(fp)
}

async function loadDb(filePath) {
  const r = await window.api.openDB(filePath)
  if (!r.success) { setStatus(`오류: ${r.error}`, true); return }
  const name = filePath.split(/[\\/]/).pop()
  $('db-path').textContent = `${name}  (${formatBytes(r.size)})`
  $('db-path').title = filePath
  setStatus(`${name} 열림`)
  show('welcome', false)
  await renderSidebar()
}

// ── 사이드바 ──────────────────────────────────────────
async function renderSidebar() {
  const tables = await window.api.getTables()
  if (!tables.length) {
    $('sidebar-content').innerHTML = '<div class="sidebar-empty"><p>테이블이 없습니다.</p></div>'
    return
  }
  const groups = new Map(); const ungrouped = []
  for (const t of tables) {
    const m = TABLE_META[t.name]
    if (m) {
      if (!groups.has(m.group)) groups.set(m.group, [])
      groups.get(m.group).push({ ...t, ...m })
    } else {
      ungrouped.push({ ...t, label: t.name })
    }
  }
  const ordered = GROUP_ORDER.filter(g=>groups.has(g)).map(g=>[g,groups.get(g)])
  if (ungrouped.length) ordered.push(['기타', ungrouped])

  let html = ''
  for (const [g, items] of ordered) {
    html += `<div class="sidebar-group"><div class="sidebar-group-label">${g}</div>`
    for (const item of items)
      html += `<button class="sidebar-item" data-table="${item.name}">
        <span class="si-label">${item.label}</span>
        <span class="si-count">${item.count.toLocaleString()}</span>
      </button>`
    html += '</div>'
  }
  $('sidebar-content').innerHTML = html
  $('sidebar-content').querySelectorAll('.sidebar-item').forEach(btn =>
    btn.addEventListener('click', () => selectTable(btn.dataset.table))
  )
  const first = tables.find(t=>t.name==='sysinfo') || tables[0]
  if (first) selectTable(first.name)
}

function setActiveItem(name) {
  $('sidebar-content').querySelectorAll('.sidebar-item').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.table === name)
  )
}

// ── 테이블 선택 라우터 ────────────────────────────────
async function selectTable(tableName) {
  setActiveItem(tableName)
  show('welcome', false); show('sysinfo-view', false)
  show('tab-empty', false); show('table-view', false)
  show('artifact-view', false)

  if (tableName === 'sysinfo')         { await renderSysinfo(); return }
  if (ARTIFACT_TABLES.has(tableName))  { await selectArtifact(tableName); return }

  S.currentTable = tableName
  S.page = 0; S.search = ''; S.sortCol = null; S.sortDir = 'ASC'
  S.dateFrom = ''; S.dateTo = ''; S.colFilters = {}; S.colWidths = {}
  $('search-input').value = ''
  $('btn-clear').classList.add('hidden')
  $('table-title').textContent = TABLE_META[tableName]?.label || tableName
  $('tl-date-from').value = ''; $('tl-date-to').value = ''
  $('tl-date-clear').classList.add('hidden')
  $('table-dashboard').innerHTML = ''
  await setupDateFilter(tableName)
  await loadTable()
  await loadGenericDashboard(tableName)
}

// ── 일반 테이블 뷰 ────────────────────────────────────
async function setupDateFilter(tableName) {
  const { min, max } = await window.api.getDateRange(tableName)
  const df = $('tl-date-filter')
  if (min || max) {
    df.classList.remove('hidden')
    if (min) $('tl-date-from').min = min
    if (max) $('tl-date-to').max   = max
  } else {
    df.classList.add('hidden')
  }
}

async function loadTable() {
  if (!S.currentTable) return
  const { rows, total, columns, error } = await window.api.getTableData({
    table: S.currentTable, search: S.search, limit: PAGE_SIZE,
    offset: S.page * PAGE_SIZE, sortCol: S.sortCol, sortDir: S.sortDir,
    dateFrom: S.dateFrom, dateTo: S.dateTo, colFilters: S.colFilters,
  })
  if (error) { setStatus(`오류: ${error}`, true); return }
  S.totalRows = total; S.columns = columns

  if (!rows.length && !S.search && !S.dateFrom && !S.dateTo) {
    show('table-view', false); show('tab-empty', true)
    $('tab-empty-title').textContent = TABLE_META[S.currentTable]?.label || S.currentTable
    $('tab-empty-desc').textContent  = '이 로그 파일이 수집되지 않았거나 파싱 데이터가 없습니다.'
    return
  }
  show('table-view', true); show('tab-empty', false)
  $('total-badge').textContent = `${total.toLocaleString()}건`
  renderTableData('data-table', columns, rows, loadTable)
  renderPagination('btn-prev','btn-next','page-info','pagination-info', total, S)
  setStatus(`${TABLE_META[S.currentTable]?.label||S.currentTable}: ${total.toLocaleString()}건`)
}

function onSearch() {
  S.search = $('search-input').value
  $('btn-clear').classList.toggle('hidden', !S.search)
  S.page = 0; loadTable()
}
function clearSearch() {
  $('search-input').value = ''; S.search = ''
  $('btn-clear').classList.add('hidden'); S.page = 0; loadTable()
}
function goPage(d) { S.page = Math.max(0, S.page+d); loadTable() }
function onDateChange() {
  S.dateFrom = $('tl-date-from').value; S.dateTo = $('tl-date-to').value
  $('tl-date-clear').classList.toggle('hidden', !S.dateFrom && !S.dateTo)
  S.page = 0; loadTable()
}
function clearDateFilter() {
  $('tl-date-from').value=''; $('tl-date-to').value=''
  S.dateFrom=''; S.dateTo=''
  $('tl-date-clear').classList.add('hidden'); S.page=0; loadTable()
}

// ── 공통(자동) 대시보드 ───────────────────────────────
async function loadGenericDashboard(tableName) {
  const el = $('table-dashboard')
  if (!el) return
  if (!S.totalRows) { el.innerHTML = ''; return }   // 빈 탭이면 표시 안 함
  const data = await window.api.getGenericDashboard(tableName)
  if (S.currentTable !== tableName) return            // 그새 다른 테이블로 이동
  renderGenericDashboard(el, data, S.totalRows)
}

function renderGenericDashboard(el, data, total) {
  if (!data) { el.innerHTML = ''; return }
  const { range, breakdowns, scanLimited } = data

  const rangeBlock = (range && (range.min || range.max)) ? `
    <div class="dsb-sep"></div>
    <div class="dsb-item dsb-range">
      <div class="dsb-val" style="font-size:13px">${fmtDt(range.min)}</div>
      <div class="dsb-key">첫 기록</div>
    </div>
    <div class="dsb-arrow">→</div>
    <div class="dsb-item dsb-range">
      <div class="dsb-val" style="font-size:13px">${fmtDt(range.max)}</div>
      <div class="dsb-key">마지막 기록</div>
    </div>` : ''

  const cards = (breakdowns || []).map(b => {
    const max = b.items.length ? b.items[0].cnt : 1
    const rows = b.items.map(it => {
      const v    = String(it.val ?? '')
      const disp = v.length > 42 ? v.slice(0, 42) + '…' : v
      const pct  = Math.round((it.cnt / max) * 100)
      return `<div class="gd-row" data-col="${esc(b.column)}" data-val="${esc(v)}" title="${esc(v)}  (클릭 → 필터)">
        <div class="gd-bar" style="width:${pct}%"></div>
        <span class="gd-val">${esc(disp)}</span>
        <span class="gd-cnt">${it.cnt.toLocaleString()}</span>
      </div>`
    }).join('')
    return `<div class="dash-card">
      <div class="dc-title">${esc(b.column)} 상위 ${b.items.length} (클릭 → 필터)</div>
      <div class="gd-list">${rows}</div>
    </div>`
  }).join('')

  el.innerHTML = `
    <div class="dash-summary-bar">
      <div class="dsb-item">
        <div class="dsb-val">${(total || 0).toLocaleString()}</div>
        <div class="dsb-key">총 건수</div>
      </div>
      ${rangeBlock}
      ${scanLimited ? `<div class="dsb-sep"></div><div class="dsb-item dsb-warn"><div class="dsb-val" style="font-size:12px">대용량</div><div class="dsb-key">집계 일부 생략</div></div>` : ''}
    </div>
    ${cards ? `<div class="dash-cards">${cards}</div>` : ''}`

  // 항목 클릭 → 해당 컬럼 '정확히(=)' 필터 토글
  el.querySelectorAll('.gd-row[data-col]').forEach(row => {
    row.addEventListener('click', () => {
      const col   = row.dataset.col
      const exact = '=' + row.dataset.val
      if (!S.colFilters) S.colFilters = {}
      if (S.colFilters[col] === exact) delete S.colFilters[col]
      else S.colFilters[col] = exact
      S.page = 0
      loadTable()
    })
  })
}

// ── 아티팩트 뷰 (대시보드 + 타입 필터 + 테이블) ──────
async function selectArtifact(tableName) {
  A.currentTable   = tableName
  A.page           = 0; A.search = ''
  A.sortCol        = null; A.sortDir = 'ASC'
  A.typeFilters    = []; A.activeQuickGroup = null
  A.statusFilter   = null; A.methodFilters = []
  A.colFilters     = {}; A.colWidths = {}

  $('artifact-search').value = ''
  $('artifact-search-clear').classList.add('hidden')
  $('artifact-title').textContent = TABLE_META[tableName]?.label || tableName

  show('artifact-view', true)
  clearArtifactFilterTag()

  if (tableName === 'audit')   await loadAuditDashboard()
  if (tableName === 'authlog') await loadAuthlogDashboard()
  if (tableName === 'apache2') await loadApache2Dashboard()
  if (tableName === 'syslog')  await loadSyslogDashboard()
  await loadArtifactTable()
}

async function loadAuditDashboard() {
  const data = await window.api.getAuditDashboard()
  renderAuditDashboard(data)
  renderTypeFilter(AUDIT_QUICK_GROUPS, data?.allTypes ?? [])
}

async function loadAuthlogDashboard() {
  const data = await window.api.getAuthlogDashboard()
  renderAuthlogDashboard(data)
  renderTypeFilter(AUTHLOG_QUICK_GROUPS, data?.allTypes ?? [])
}

async function loadArtifactTable() {
  const { rows, total, columns, error } = await window.api.getTableData({
    table: A.currentTable, search: A.search, limit: PAGE_SIZE,
    offset: A.page * PAGE_SIZE, sortCol: A.sortCol, sortDir: A.sortDir,
    typeFilters: A.typeFilters, colFilters: A.colFilters,
    statusFilter: A.statusFilter, methodFilters: A.methodFilters,
  })
  if (error) { setStatus(`오류: ${error}`, true); return }
  A.totalRows = total; A.columns = columns
  $('artifact-badge').textContent = `${total.toLocaleString()}건`
  renderTableData('artifact-data-table', columns, rows, loadArtifactTable)
  renderPagination('artifact-btn-prev','artifact-btn-next','artifact-page-info','artifact-pagination-info', total, A)
  setStatus(`${TABLE_META[A.currentTable]?.label||A.currentTable}: ${total.toLocaleString()}건`)
}

function onArtifactSearch() {
  A.search = $('artifact-search').value
  $('artifact-search-clear').classList.toggle('hidden', !A.search)
  A.page = 0; loadArtifactTable()
}
function clearArtifactSearch() {
  $('artifact-search').value=''; A.search=''
  $('artifact-search-clear').classList.add('hidden'); A.page=0; loadArtifactTable()
}
function goArtifactPage(d) { A.page = Math.max(0, A.page+d); loadArtifactTable() }

function setArtifactTypeFilter(types, labelText, quickGroup = null) {
  A.typeFilters = types; A.activeQuickGroup = quickGroup; A.page = 0
  if (types.length) {
    $('artifact-filter-label').textContent = labelText
    show('artifact-filter-tag', true)
  } else {
    clearArtifactFilterTag()
  }
  $('artifact-type-chips')?.querySelectorAll('.type-chip').forEach(chip =>
    chip.classList.toggle('active', types.length === 1 && chip.dataset.type === types[0])
  )
  $('artifact-quick-filters')?.querySelectorAll('.quick-btn').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.group === quickGroup)
  )
  loadArtifactTable()
}

function clearArtifactTypeFilter() {
  A.typeFilters=[]; A.activeQuickGroup=null
  A.statusFilter=null; A.methodFilters=[]
  A.page=0
  clearArtifactFilterTag()
  $('artifact-type-chips')?.querySelectorAll('.type-chip').forEach(c=>c.classList.remove('active'))
  $('artifact-quick-filters')?.querySelectorAll('.quick-btn').forEach(b=>b.classList.remove('active'))
  loadArtifactTable()
}
function clearArtifactFilterTag() {
  show('artifact-filter-tag', false); $('artifact-filter-label').textContent = ''
}

// ── Syslog 대시보드 ───────────────────────────────────
async function loadSyslogDashboard() {
  const data = await window.api.getSyslogDashboard()
  renderSyslogDashboard(data)
  renderSyslogQuickFilters(data)
}

function renderSyslogQuickFilters(data) {
  $('artifact-type-bar').classList.remove('hidden')
  const quickEl = $('artifact-quick-filters')

  quickEl.innerHTML =
    `<button class="quick-btn" data-group="__all__">전체</button>` +
    SYSLOG_QUICK_GROUPS.map(g =>
      `<button class="quick-btn" data-group="${esc(g.label)}">${esc(g.label)}</button>`
    ).join('') +
    `<span class="qf-sep"></span>` +
    SYSLOG_KW_FILTERS.map(k =>
      `<button class="quick-btn quick-btn-kw" data-kw="${esc(k.value)}">${esc(k.label)}</button>`
    ).join('')

  // 서비스 그룹 버튼
  quickEl.querySelectorAll('.quick-btn:not(.quick-btn-kw)').forEach(btn => {
    btn.addEventListener('click', () => {
      const grp = btn.dataset.group
      if (grp === '__all__') { clearArtifactTypeFilter(); return }
      const group = SYSLOG_QUICK_GROUPS.find(g => g.label === grp)
      if (!group) return
      if (A.activeQuickGroup === grp) { clearArtifactTypeFilter(); return }
      setArtifactTypeFilter(group.types, group.label, grp)
    })
  })

  // 키워드 버튼 (message colFilter와 연동)
  quickEl.querySelectorAll('.quick-btn-kw').forEach(btn => {
    btn.addEventListener('click', () => {
      const kw = btn.dataset.kw
      const cur = A.colFilters?.message || ''
      if (cur === kw) {
        delete A.colFilters.message
        quickEl.querySelectorAll('.quick-btn-kw').forEach(b => b.classList.remove('active'))
      } else {
        if (!A.colFilters) A.colFilters = {}
        A.colFilters.message = kw
        quickEl.querySelectorAll('.quick-btn-kw').forEach(b =>
          b.classList.toggle('active', b.dataset.kw === kw)
        )
      }
      A.page = 0
      loadArtifactTable()
    })
  })

  // 서비스 칩 (전체 서비스 목록)
  const chipsEl = $('artifact-type-chips')
  chipsEl.innerHTML = (data?.allTypes ?? []).map(t =>
    `<button class="type-chip" data-type="${esc(t.type)}">
      ${esc(t.type)}<span class="type-chip-cnt">${t.cnt.toLocaleString()}</span>
    </button>`
  ).join('')

  chipsEl.querySelectorAll('.type-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const t = chip.dataset.type
      if (A.typeFilters.length === 1 && A.typeFilters[0] === t) { clearArtifactTypeFilter(); return }
      setArtifactTypeFilter([t], t)
    })
  })
}

function renderSyslogDashboard(data) {
  const el = $('artifact-dashboard')
  if (!data) { el.innerHTML = ''; return }

  const {
    overview, topServices,
    errCount, warnCount, failCount, critCount, killedCount, panicCount,
    topErrServices,
    kernelCount, systemdCount, sshdCount, sudoCount, cronCount, nmCount,
  } = data

  const maxSvc = topServices.length ? topServices[0].cnt : 1

  const svcBars = topServices.slice(0, 12).map(s => {
    const pct = Math.round((s.cnt / maxSvc) * 100)
    return `<div class="bar-row" data-type="${esc(s.service)}" title="${esc(s.service)} 필터 적용">
      <div class="bar-label">${esc(s.service)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      <div class="bar-value">${s.cnt.toLocaleString()}</div>
    </div>`
  }).join('')

  const topList = (rows, key) => rows.length
    ? rows.map(r => `<div class="top-row">
        <span class="top-val">${esc(r[key])}</span>
        <span class="top-cnt">${r.cnt.toLocaleString()}</span>
      </div>`).join('')
    : '<div class="top-empty">데이터 없음</div>'

  const kwItem = (label, count, kw, warn = false) =>
    `<div class="kw-item${warn && count > 0 ? ' kw-warn' : ''}" data-kw="${esc(kw)}" title="${esc(kw)} 키워드 필터 적용">
      <span class="kw-label">${label}</span>
      <span class="kw-cnt">${count.toLocaleString()}</span>
    </div>`

  el.innerHTML = `
    <div class="dash-summary-bar">
      <div class="dsb-item">
        <div class="dsb-val">${(overview?.total ?? 0).toLocaleString()}</div>
        <div class="dsb-key">총 로그</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item">
        <div class="dsb-val">${overview?.svc_count ?? 0}</div>
        <div class="dsb-key">서비스 종류</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.first_dt)}</div>
        <div class="dsb-key">첫 로그</div>
      </div>
      <div class="dsb-arrow">→</div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.last_dt)}</div>
        <div class="dsb-key">마지막 로그</div>
      </div>
      ${errCount > 0 ? `<div class="dsb-sep"></div><div class="dsb-item dsb-warn"><div class="dsb-val">${errCount.toLocaleString()}</div><div class="dsb-key">error 포함</div></div>` : ''}
      ${killedCount > 0 ? `<div class="dsb-item dsb-warn"><div class="dsb-val">${killedCount.toLocaleString()}</div><div class="dsb-key">killed 포함</div></div>` : ''}
      ${panicCount > 0  ? `<div class="dsb-item dsb-warn"><div class="dsb-val">${panicCount.toLocaleString()}</div><div class="dsb-key">panic 포함</div></div>` : ''}
    </div>
    <div class="dash-cards">
      <div class="dash-card">
        <div class="dc-title">상위 서비스 (클릭 → 필터)</div>
        <div class="bar-chart">${svcBars || '<div class="top-empty">데이터 없음</div>'}</div>
      </div>
      <div class="dash-card">
        <div class="dc-title">키워드별 로그 수 (클릭 → 필터)</div>
        <div class="kw-grid">
          ${kwItem('error',    errCount,    'error',    true)}
          ${kwItem('warn',     warnCount,   'warn',     true)}
          ${kwItem('fail',     failCount,   'fail',     true)}
          ${kwItem('critical', critCount,   'critical', true)}
          ${kwItem('killed',   killedCount, 'killed',   true)}
          ${kwItem('panic',    panicCount,  'panic',    true)}
        </div>
        <div class="dc-subtitle">error 발생 상위 서비스</div>
        ${topList(topErrServices, 'service')}
      </div>
      <div class="dash-card">
        <div class="dc-title">분류별 집계</div>
        <div class="stat-grid">
          <div class="stat-item" data-svc="kernel"><div class="stat-n">${kernelCount.toLocaleString()}</div><div class="stat-k">kernel</div></div>
          <div class="stat-item" data-svc-prefix="systemd"><div class="stat-n">${systemdCount.toLocaleString()}</div><div class="stat-k">systemd</div></div>
          <div class="stat-item" data-svc="sshd"><div class="stat-n">${sshdCount.toLocaleString()}</div><div class="stat-k">sshd</div></div>
          <div class="stat-item" data-svc="sudo"><div class="stat-n">${sudoCount.toLocaleString()}</div><div class="stat-k">sudo</div></div>
          <div class="stat-item" data-svc-group="cron"><div class="stat-n">${cronCount.toLocaleString()}</div><div class="stat-k">cron</div></div>
          <div class="stat-item" data-svc="NetworkManager"><div class="stat-n">${nmCount.toLocaleString()}</div><div class="stat-k">NetworkMgr</div></div>
        </div>
      </div>
    </div>`

  // 서비스 바 클릭 → 필터
  el.querySelectorAll('.bar-row[data-type]').forEach(row =>
    row.addEventListener('click', () => setArtifactTypeFilter([row.dataset.type], row.dataset.type))
  )

  // 키워드 항목 클릭 → message colFilter
  el.querySelectorAll('.kw-item[data-kw]').forEach(item => {
    item.addEventListener('click', () => {
      const kw = item.dataset.kw
      if (!A.colFilters) A.colFilters = {}
      if (A.colFilters.message === kw) {
        delete A.colFilters.message
      } else {
        A.colFilters.message = kw
      }
      // 퀵필터 버튼 상태 동기화
      $('artifact-quick-filters')?.querySelectorAll('.quick-btn-kw').forEach(b =>
        b.classList.toggle('active', b.dataset.kw === A.colFilters.message)
      )
      A.page = 0
      loadArtifactTable()
    })
  })

  // 분류별 stat-item 클릭 → 서비스 필터
  el.querySelectorAll('.stat-item[data-svc]').forEach(item =>
    item.addEventListener('click', () =>
      setArtifactTypeFilter([item.dataset.svc], item.dataset.svc)
    )
  )
  el.querySelectorAll('.stat-item[data-svc-group="cron"]').forEach(item =>
    item.addEventListener('click', () =>
      setArtifactTypeFilter(['cron','CRON','crond','anacron','atd'], 'Cron', 'Cron')
    )
  )
}

// ── Apache2 대시보드 ──────────────────────────────────
async function loadApache2Dashboard() {
  const data = await window.api.getApache2Dashboard()
  renderApache2Dashboard(data)
  renderApacheQuickFilters(data)
}

function setApacheFilter(statusFilter, methodFilters, label, quickGroup) {
  A.statusFilter = statusFilter; A.methodFilters = methodFilters
  A.typeFilters = []; A.activeQuickGroup = quickGroup; A.page = 0
  $('artifact-filter-label').textContent = label
  show('artifact-filter-tag', true)
  $('artifact-quick-filters')?.querySelectorAll('.quick-btn').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.group === quickGroup)
  )
  $('artifact-type-chips')?.querySelectorAll('.type-chip').forEach(chip =>
    chip.classList.toggle('active', quickGroup === `s${chip.dataset.status}`)
  )
  loadArtifactTable()
}

function renderApacheQuickFilters(data) {
  $('artifact-type-bar').classList.remove('hidden')

  const etcMethods = (data?.methodDist200 ?? [])
    .filter(m => m.method !== 'GET' && m.method !== 'POST')
    .map(m => m.method)

  const quickEl = $('artifact-quick-filters')
  quickEl.innerHTML = [
    `<button class="quick-btn" data-group="__all__">전체</button>`,
    `<button class="quick-btn" data-group="200-GET">200 - GET</button>`,
    `<button class="quick-btn" data-group="200-POST">200 - POST</button>`,
    etcMethods.length ? `<button class="quick-btn" data-group="200-ETC">200 - 기타</button>` : '',
  ].join('')

  quickEl.querySelectorAll('.quick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const grp = btn.dataset.group
      if (grp === '__all__')  { clearArtifactTypeFilter(); return }
      if (A.activeQuickGroup === grp) { clearArtifactTypeFilter(); return }
      if (grp === '200-GET')  setApacheFilter(200, ['GET'],  '200 - GET',  grp)
      if (grp === '200-POST') setApacheFilter(200, ['POST'], '200 - POST', grp)
      if (grp === '200-ETC')  setApacheFilter(200, etcMethods, '200 - 기타', grp)
    })
  })

  const chipsEl = $('artifact-type-chips')
  chipsEl.innerHTML = (data?.statusDist ?? []).map(s =>
    `<button class="type-chip" data-status="${s.status}">
      ${s.status}<span class="type-chip-cnt">${s.cnt.toLocaleString()}</span>
    </button>`
  ).join('')

  chipsEl.querySelectorAll('.type-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const st = parseInt(chip.dataset.status)
      const grp = `s${st}`
      if (A.activeQuickGroup === grp) { clearArtifactTypeFilter(); return }
      setApacheFilter(st, [], String(st), grp)
    })
  })
}

function renderApache2Dashboard(data) {
  const el = $('artifact-dashboard')
  if (!data) { el.innerHTML = ''; return }

  const { overview, statusDist, s2xx, s3xx, s4xx, s5xx, methodDist200, topUri200, topIPs, topErrIPs, vhosts } = data
  const maxStatus = statusDist.length ? statusDist[0].cnt : 1

  const statusBarRows = statusDist.slice(0, 10).map(s => {
    const pct  = Math.round((s.cnt / maxStatus) * 100)
    const cls  = s.status >= 500 ? 'bar-fill bar-fill-err'
               : s.status >= 400 ? 'bar-fill bar-fill-warn'
               : s.status >= 300 ? 'bar-fill bar-fill-redir'
               : 'bar-fill'
    return `<div class="bar-row" data-status="${s.status}" title="${s.status} 필터 적용">
      <div class="bar-label">${s.status}</div>
      <div class="bar-track"><div class="${cls}" style="width:${pct}%"></div></div>
      <div class="bar-value">${s.cnt.toLocaleString()}</div>
    </div>`
  }).join('')

  const maxMethod = methodDist200.length ? methodDist200[0].cnt : 1
  const methodBarRows = methodDist200.map(m => {
    const pct = Math.round((m.cnt / maxMethod) * 100)
    return `<div class="bar-row clickable-method" data-method="${esc(m.method)}" title="${esc(m.method)} 필터 적용">
      <div class="bar-label">${esc(m.method)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      <div class="bar-value">${m.cnt.toLocaleString()}</div>
    </div>`
  }).join('')

  const topList = (rows, key, truncate = false) => rows.length
    ? rows.map(r => {
        const v = truncate && r[key].length > 50 ? r[key].slice(0, 50) + '…' : r[key]
        return `<div class="top-row"><span class="top-val" title="${esc(r[key])}">${esc(v)}</span><span class="top-cnt">${r.cnt.toLocaleString()}</span></div>`
      }).join('')
    : '<div class="top-empty">데이터 없음</div>'

  const vhostRows = vhosts.length > 1
    ? vhosts.map(v => `<div class="top-row"><span class="top-val">${esc(v.vhost)}</span><span class="top-cnt">${v.cnt.toLocaleString()}</span></div>`).join('')
    : ''

  el.innerHTML = `
    <div class="dash-summary-bar">
      <div class="dsb-item">
        <div class="dsb-val">${(overview?.total??0).toLocaleString()}</div>
        <div class="dsb-key">총 요청</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item dsb-ok">
        <div class="dsb-val">${s2xx.toLocaleString()}</div>
        <div class="dsb-key">2xx 성공</div>
      </div>
      <div class="dsb-item">
        <div class="dsb-val">${s3xx.toLocaleString()}</div>
        <div class="dsb-key">3xx 리다이렉트</div>
      </div>
      <div class="dsb-item dsb-warn">
        <div class="dsb-val">${s4xx.toLocaleString()}</div>
        <div class="dsb-key">4xx 클라이언트 오류</div>
      </div>
      <div class="dsb-item dsb-warn">
        <div class="dsb-val">${s5xx.toLocaleString()}</div>
        <div class="dsb-key">5xx 서버 오류</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.first_dt)}</div>
        <div class="dsb-key">첫 요청</div>
      </div>
      <div class="dsb-arrow">→</div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.last_dt)}</div>
        <div class="dsb-key">마지막 요청</div>
      </div>
    </div>
    <div class="dash-cards">
      <div class="dash-card">
        <div class="dc-title">상태코드 분포 (클릭 → 필터)</div>
        <div class="bar-chart">${statusBarRows}</div>
      </div>
      <div class="dash-card">
        <div class="dc-title">200 응답 메서드 (클릭 → 필터)</div>
        <div class="bar-chart">${methodBarRows || '<div class="top-empty">데이터 없음</div>'}</div>
        <div class="dc-subtitle">200 응답 상위 URI</div>
        ${topList(topUri200, 'uri', true)}
      </div>
      <div class="dash-card">
        <div class="dc-title">상위 요청 IP</div>
        ${topList(topIPs, 'src_ip')}
        <div class="dc-subtitle">오류 발생 상위 IP (4xx/5xx)</div>
        ${topList(topErrIPs, 'src_ip')}
        ${vhostRows ? `<div class="dc-subtitle">vhost</div>${vhostRows}` : ''}
      </div>
    </div>`

  el.querySelectorAll('.bar-row[data-status]').forEach(row =>
    row.addEventListener('click', () => {
      const st = parseInt(row.dataset.status)
      setApacheFilter(st, [], String(st), `s${st}`)
    })
  )
  el.querySelectorAll('.clickable-method[data-method]').forEach(row =>
    row.addEventListener('click', () => {
      const m = row.dataset.method
      if (m === 'GET')  { setApacheFilter(200, ['GET'],  '200 - GET',  '200-GET');  return }
      if (m === 'POST') { setApacheFilter(200, ['POST'], '200 - POST', '200-POST'); return }
      setApacheFilter(200, [m], `200 - ${m}`, `200-${m}`)
    })
  )
}

// ── 공통: 타입 필터 바 렌더링 ─────────────────────────
function renderTypeFilter(quickGroups, allTypes) {
  $('artifact-type-bar').classList.remove('hidden')

  const quickEl = $('artifact-quick-filters')
  quickEl.innerHTML =
    `<button class="quick-btn" data-group="__all__">전체</button>` +
    quickGroups.map(g =>
      `<button class="quick-btn" data-group="${esc(g.label)}">${esc(g.label)}</button>`
    ).join('')

  quickEl.querySelectorAll('.quick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const grp = btn.dataset.group
      if (grp === '__all__') { clearArtifactTypeFilter(); return }
      const group = quickGroups.find(g => g.label === grp)
      if (!group) return
      if (A.activeQuickGroup === grp) { clearArtifactTypeFilter(); return }
      setArtifactTypeFilter(group.types, group.label, grp)
    })
  })

  const chipsEl = $('artifact-type-chips')
  chipsEl.innerHTML = allTypes.map(t =>
    `<button class="type-chip" data-type="${esc(t.type)}">
      ${esc(t.type)}<span class="type-chip-cnt">${t.cnt.toLocaleString()}</span>
    </button>`
  ).join('')

  chipsEl.querySelectorAll('.type-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const t = chip.dataset.type
      if (A.typeFilters.length === 1 && A.typeFilters[0] === t) { clearArtifactTypeFilter(); return }
      setArtifactTypeFilter([t], t)
    })
  })
}

// ── Audit 대시보드 렌더링 ─────────────────────────────
function renderAuditDashboard(data) {
  const el = $('artifact-dashboard')
  if (!data) { el.innerHTML = ''; return }

  const { overview, typeDist, loginStats, topIPs, topAccts, execve, userCmd, topExe, avcCount, failCount } = data
  const maxCnt = typeDist.length ? typeDist[0].cnt : 1

  const barRows = typeDist.slice(0, 10).map(t => {
    const pct = Math.round((t.cnt / maxCnt) * 100)
    return `<div class="bar-row" data-type="${esc(t.type)}" title="${esc(t.type)} 필터 적용">
      <div class="bar-label">${esc(t.type)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      <div class="bar-value">${t.cnt.toLocaleString()}</div>
    </div>`
  }).join('')

  const topList = (rows, key) => rows.length
    ? rows.map(r=>`<div class="top-row"><span class="top-val">${esc(r[key])}</span><span class="top-cnt">${r.cnt.toLocaleString()}</span></div>`).join('')
    : '<div class="top-empty">데이터 없음</div>'

  const topExeRows = topExe.length
    ? topExe.map(r=>`<div class="top-row"><span class="top-val">${esc(r.exe.split('/').pop()||r.exe)}</span><span class="top-cnt">${r.cnt.toLocaleString()}</span></div>`).join('')
    : '<div class="top-empty">데이터 없음</div>'

  el.innerHTML = `
    <div class="dash-summary-bar">
      <div class="dsb-item">
        <div class="dsb-val">${(overview?.total??0).toLocaleString()}</div>
        <div class="dsb-key">총 로그</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item">
        <div class="dsb-val">${overview?.type_count??0}</div>
        <div class="dsb-key">타입 종류</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.first_dt)}</div>
        <div class="dsb-key">첫 로그</div>
      </div>
      <div class="dsb-arrow">→</div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.last_dt)}</div>
        <div class="dsb-key">마지막 로그</div>
      </div>
      ${avcCount > 0 ? `<div class="dsb-sep"></div><div class="dsb-item dsb-warn"><div class="dsb-val">${avcCount.toLocaleString()}</div><div class="dsb-key">AVC 차단</div></div>` : ''}
      ${failCount > 0 ? `<div class="dsb-item dsb-warn"><div class="dsb-val">${failCount.toLocaleString()}</div><div class="dsb-key">실패 응답</div></div>` : ''}
    </div>
    <div class="dash-cards">
      <div class="dash-card">
        <div class="dc-title">타입 분포 (상위 10)</div>
        <div class="bar-chart">${barRows}</div>
      </div>
      <div class="dash-card">
        <div class="dc-title">인증 / 로그인</div>
        <div class="stat-grid">
          <div class="stat-item"><div class="stat-n">${loginStats.auth.toLocaleString()}</div><div class="stat-k">AUTH</div></div>
          <div class="stat-item stat-ok"><div class="stat-n">${loginStats.login.toLocaleString()}</div><div class="stat-k">LOGIN</div></div>
          <div class="stat-item stat-err"><div class="stat-n">${loginStats.err.toLocaleString()}</div><div class="stat-k">ERR</div></div>
          <div class="stat-item"><div class="stat-n">${loginStats.start.toLocaleString()}</div><div class="stat-k">SESSION</div></div>
        </div>
        <div class="dc-subtitle">상위 계정</div>
        ${topList(topAccts, 'acct')}
      </div>
      <div class="dash-card">
        <div class="dc-title">상위 IP</div>
        ${topList(topIPs, 'addr')}
        <div class="dc-subtitle">명령 실행</div>
        <div class="stat-grid">
          <div class="stat-item"><div class="stat-n">${execve.toLocaleString()}</div><div class="stat-k">EXECVE</div></div>
          <div class="stat-item"><div class="stat-n">${userCmd.toLocaleString()}</div><div class="stat-k">CMD</div></div>
        </div>
        <div class="dc-subtitle">상위 exe</div>
        ${topExeRows}
      </div>
    </div>`

  el.querySelectorAll('.bar-row[data-type]').forEach(row =>
    row.addEventListener('click', () => setArtifactTypeFilter([row.dataset.type], row.dataset.type))
  )
}

// ── Authlog 대시보드 렌더링 ───────────────────────────
function renderAuthlogDashboard(data) {
  const el = $('artifact-dashboard')
  if (!data) { el.innerHTML = ''; return }

  const { overview, eventDist, sshStats, topAttackIPs, topSuccessIPs, topUsers, topFailUsers, sudoCount, topSudoUsers, suCount } = data
  const maxCnt = eventDist.length ? eventDist[0].cnt : 1

  const barRows = eventDist.slice(0, 10).map(t => {
    const pct = Math.round((t.cnt / maxCnt) * 100)
    return `<div class="bar-row" data-type="${esc(t.type)}" title="${esc(t.type)} 필터 적용">
      <div class="bar-label">${esc(t.type)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      <div class="bar-value">${t.cnt.toLocaleString()}</div>
    </div>`
  }).join('')

  const topList = (rows, key) => rows.length
    ? rows.map(r=>`<div class="top-row"><span class="top-val">${esc(r[key])}</span><span class="top-cnt">${r.cnt.toLocaleString()}</span></div>`).join('')
    : '<div class="top-empty">데이터 없음</div>'

  const sshAccepted = sshStats.accepted_password + sshStats.accepted_publickey
  const sshFailed   = sshStats.failed_password + sshStats.invalid_user + sshStats.max_auth

  el.innerHTML = `
    <div class="dash-summary-bar">
      <div class="dsb-item">
        <div class="dsb-val">${(overview?.total??0).toLocaleString()}</div>
        <div class="dsb-key">총 로그</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item">
        <div class="dsb-val">${overview?.type_count??0}</div>
        <div class="dsb-key">이벤트 종류</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.first_dt)}</div>
        <div class="dsb-key">첫 로그</div>
      </div>
      <div class="dsb-arrow">→</div>
      <div class="dsb-item dsb-range">
        <div class="dsb-val" style="font-size:13px">${fmtDt(overview?.last_dt)}</div>
        <div class="dsb-key">마지막 로그</div>
      </div>
      <div class="dsb-sep"></div>
      <div class="dsb-item dsb-ok">
        <div class="dsb-val">${sshAccepted.toLocaleString()}</div>
        <div class="dsb-key">SSH 성공</div>
      </div>
      <div class="dsb-item dsb-warn">
        <div class="dsb-val">${sshFailed.toLocaleString()}</div>
        <div class="dsb-key">SSH 실패</div>
      </div>
    </div>
    <div class="dash-cards">
      <div class="dash-card">
        <div class="dc-title">이벤트 분포 (상위 10)</div>
        <div class="bar-chart">${barRows}</div>
      </div>
      <div class="dash-card">
        <div class="dc-title">SSH 인증</div>
        <div class="stat-grid">
          <div class="stat-item stat-ok">
            <div class="stat-n">${sshStats.accepted_password.toLocaleString()}</div>
            <div class="stat-k">비밀번호 성공</div>
          </div>
          <div class="stat-item stat-ok">
            <div class="stat-n">${sshStats.accepted_publickey.toLocaleString()}</div>
            <div class="stat-k">공개키 성공</div>
          </div>
          <div class="stat-item stat-err">
            <div class="stat-n">${sshStats.failed_password.toLocaleString()}</div>
            <div class="stat-k">비밀번호 실패</div>
          </div>
          <div class="stat-item stat-err">
            <div class="stat-n">${sshStats.invalid_user.toLocaleString()}</div>
            <div class="stat-k">존재하지 않는 계정</div>
          </div>
        </div>
        <div class="dc-subtitle">성공 로그인 계정</div>
        ${topList(topUsers, 'user')}
        <div class="dc-subtitle">sudo / su</div>
        <div class="stat-grid" style="margin-bottom:0">
          <div class="stat-item"><div class="stat-n">${sudoCount.toLocaleString()}</div><div class="stat-k">sudo</div></div>
          <div class="stat-item"><div class="stat-n">${suCount.toLocaleString()}</div><div class="stat-k">su</div></div>
        </div>
      </div>
      <div class="dash-card">
        <div class="dc-title">공격 IP (실패 기준)</div>
        ${topList(topAttackIPs, 'src_ip')}
        <div class="dc-subtitle">성공 로그인 IP</div>
        ${topList(topSuccessIPs, 'src_ip')}
        <div class="dc-subtitle">주요 실패 계정</div>
        ${topList(topFailUsers, 'user')}
      </div>
    </div>`

  el.querySelectorAll('.bar-row[data-type]').forEach(row =>
    row.addEventListener('click', () => setArtifactTypeFilter([row.dataset.type], row.dataset.type))
  )
}

// ── 공통: 테이블 렌더링 ───────────────────────────────
function renderTableData(containerId, columns, rows, reloadFn) {
  const container = $(containerId)
  const st = containerId === 'data-table' ? S : A

  // 리렌더 전 포커스된 컬럼 필터 기억
  const prevActive = document.activeElement
  const focusedCol = prevActive?.classList.contains('col-filter-input')
    ? prevActive.dataset.col : null

  // 정렬 표시용 유효 정렬값 (미지정이면 기본=시간 컬럼 ASC, main.js 와 일치)
  if (!st.colWidths) st.colWidths = {}
  const effSortCol = st.sortCol || detectTsCol(columns)
  const effSortDir = st.sortCol ? st.sortDir : 'ASC'
  const widthOf = col => st.colWidths[col] || defaultColWidth(col)

  // colgroup — 고정 폭 레이아웃
  let colgroup = '<colgroup>'
  for (const col of columns) colgroup += `<col style="width:${widthOf(col)}px" />`
  colgroup += '</colgroup>'

  // 헤더 행 1 — 컬럼명 (정렬 + 리사이즈 핸들)
  let thead = '<thead><tr class="thead-cols">'
  for (const col of columns) {
    const sorted = effSortCol === col
    const arrow  = sorted ? (effSortDir === 'ASC' ? ' ▲' : ' ▼') : ''
    thead += `<th data-col="${esc(col)}" class="th-sort${sorted?' sorted':''}">
      <span class="th-label">${esc(col)}${arrow}</span>
      <span class="col-resizer" data-col="${esc(col)}"></span>
    </th>`
  }
  thead += '</tr>'

  // 헤더 행 2 — 컬럼 필터 입력 (접두어 문법)
  thead += '<tr class="thead-filters">'
  for (const col of columns) {
    const val    = st.colFilters?.[col] ?? ''
    const active = val.trim() ? ' active' : ''
    thead += `<th><input class="col-filter-input${active}" data-col="${esc(col)}"
      value="${esc(val)}" placeholder="필터  !제외  =정확히"
      title='포함: error · 제외: !debug · 정확히: =200 · 공백 포함은 "따옴표" 로 묶기 · 토큰 사이는 AND'
      autocomplete="off" spellcheck="false" /></th>`
  }
  thead += '</tr></thead>'

  // 바디
  let tbody = '<tbody>'
  if (!rows.length) {
    tbody += `<tr class="tr-empty"><td colspan="${columns.length}">검색 결과가 없습니다.</td></tr>`
  } else {
    for (const row of rows) {
      tbody += '<tr>'
      for (const col of columns) {
        const raw  = String(row[col] ?? '')
        const cell = raw.length > 120 ? raw.slice(0, 120) + '…' : raw
        tbody += `<td title="${esc(raw)}">${esc(cell)}</td>`
      }
      tbody += '</tr>'
    }
  }
  tbody += '</tbody>'

  const tbl = document.createElement('table')
  tbl.className = 'data-grid'
  tbl.innerHTML = colgroup + thead + tbody

  // 정렬 클릭 (th-sort만, 리사이즈 핸들 클릭은 제외)
  tbl.querySelectorAll('th.th-sort[data-col]').forEach(th => {
    th.addEventListener('click', e => {
      if (e.target.classList.contains('col-resizer')) return
      const col = th.dataset.col
      if (effSortCol === col) { st.sortCol = col; st.sortDir = effSortDir === 'ASC' ? 'DESC' : 'ASC' }
      else { st.sortCol = col; st.sortDir = 'ASC' }
      st.page = 0; reloadFn()
    })
  })

  // 컬럼 폭 리사이즈 (col-resizer 드래그)
  const colEls = () => [...tbl.querySelectorAll('colgroup col')]
  tbl.querySelectorAll('.col-resizer').forEach(handle => {
    handle.addEventListener('click', e => e.stopPropagation())
    handle.addEventListener('mousedown', e => {
      e.preventDefault(); e.stopPropagation()
      const col    = handle.dataset.col
      const th     = handle.closest('th')
      const colEl  = colEls()[columns.indexOf(col)]
      const startX = e.clientX
      const startW = th.offsetWidth
      document.body.classList.add('col-resizing')
      const onMove = ev => {
        const w = Math.max(56, startW + (ev.clientX - startX))
        if (colEl) colEl.style.width = w + 'px'
        st.colWidths[col] = w
      }
      const onUp = () => {
        document.removeEventListener('mousemove', onMove)
        document.removeEventListener('mouseup', onUp)
        document.body.classList.remove('col-resizing')
      }
      document.addEventListener('mousemove', onMove)
      document.addEventListener('mouseup', onUp)
    })
  })

  // 행 클릭 → 상세 모달
  if (rows.length) {
    tbl.querySelectorAll('tbody tr').forEach((tr, i) =>
      tr.addEventListener('click', () => showRowModal(columns, rows[i]))
    )
  }

  // 컬럼 필터 입력
  tbl.querySelectorAll('.col-filter-input').forEach(input => {
    input.addEventListener('click', e => e.stopPropagation())
    input.addEventListener('input', debounce(() => {
      if (!st.colFilters) st.colFilters = {}
      const col = input.dataset.col
      const val = input.value
      if (val.trim()) {
        st.colFilters[col] = val
        input.classList.add('active')
      } else {
        delete st.colFilters[col]
        input.classList.remove('active')
      }
      st.page = 0
      reloadFn()
    }, 300))
  })

  container.innerHTML = ''
  container.appendChild(tbl)

  // 포커스 복원
  if (focusedCol) {
    const inp = [...tbl.querySelectorAll('.col-filter-input')]
      .find(i => i.dataset.col === focusedCol)
    if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length) }
  }
}

function renderPagination(prevId, nextId, infoId, countId, total, st) {
  const pages = Math.ceil(total / PAGE_SIZE) || 1
  $(infoId).textContent = `${st.page+1} / ${pages}`
  $(prevId).disabled    = st.page === 0
  $(nextId).disabled    = st.page >= pages - 1
  const start = st.page * PAGE_SIZE + 1
  const end   = Math.min((st.page+1) * PAGE_SIZE, total)
  $(countId).textContent = total > 0 ? `${start}–${end} / ${total.toLocaleString()}` : ''
}

// ── 시스템 정보 카드 뷰 ───────────────────────────────
async function renderSysinfo() {
  const si = await window.api.getSysinfo()
  show('sysinfo-view', true)
  const field = (label, value) => value
    ? `<div class="si-field"><div class="si-f-label">${label}</div><div class="si-f-value">${esc(String(value))}</div></div>`
    : ''
  if (!si) {
    $('sysinfo-view').innerHTML = `
      <div class="sysinfo-empty">
        <h3>시스템 정보 없음</h3>
        <p>Volatile / NonVolatile 덤프가 없어 시스템 정보를 수집하지 못했습니다.</p>
      </div>`
    return
  }
  const diskUsed = si.disk_used ? `${si.disk_used}${si.disk_use_pct?' ('+si.disk_use_pct+')':''}` : ''
  $('sysinfo-view').innerHTML = `
    <div class="sysinfo-header">
      <div class="sysinfo-hostname">${esc(si.hostname||'알 수 없음')}</div>
      <div class="sysinfo-os">${esc(si.os||'')}${si.kernel?' · '+esc(si.kernel):''}</div>
    </div>
    <div class="sysinfo-cards">
      <div class="si-card"><div class="si-card-title">네트워크</div>
        ${field('내부 IP', si.internal_ip)}${field('외부 IP', si.external_ip||'(NAT 환경)')}
        ${field('MAC 주소', si.mac_address)}${field('열린 포트', si.listen_ports)}${field('타임존', si.timezone)}
      </div>
      <div class="si-card"><div class="si-card-title">하드웨어</div>
        ${field('아키텍처', si.architecture)}${field('CPU 모델', si.cpu_model)}
        ${field('CPU 코어', si.cpu_cores)}${field('디스크 전체', si.disk_total)}
        ${field('디스크 사용', diskUsed)}${field('디스크 여유', si.disk_avail)}
      </div>
      <div class="si-card"><div class="si-card-title">시간 / 수집</div>
        ${field('수집 시각', si.collected_at)}${field('부팅 시각', si.booted_at)}
        ${field('업타임', si.uptime_days?si.uptime_days+'일':'')}${field('마지막 재부팅', si.last_reboot)}
        ${field('WTMP 시작', si.wtmp_begins)}${field('수집 권한', si.collect_user)}
      </div>
    </div>`
}

// ── 행 상세 모달 ───────────────────────────────────────
function showRowModal(columns, row) {
  let html = '<div class="modal-fields">'
  for (const col of columns) {
    const val = row[col]
    if (val === null || val === undefined || val === '') continue
    html += `<div class="modal-field">
      <div class="mf-key">${esc(col)}</div>
      <div class="mf-val">${esc(String(val))}</div>
    </div>`
  }
  html += '</div>'
  $('modal-body').innerHTML = html
  $('row-modal').classList.remove('hidden')
}
function closeModal() {
  $('row-modal').classList.add('hidden')
  hideDecodePopup()
}


// ── 모달 내 선택 텍스트 디코드 (URL / Base64) ───────────
// 행 상세 모달 안에서 텍스트를 드래그하면 선택 영역 근처에 팝업이 떠 URL/Base64 디코드를 제공.
let _dpLastText = ''

function initDecodePopup() {
  const popup     = $('decode-popup')
  const modalBody = $('modal-body')

  // 모달 안에서 드래그/선택 종료 시 평가
  document.addEventListener('mouseup', e => {
    // 팝업 내부에서의 mouseup(=버튼 클릭) 은 selection 재평가 대상 아님.
    // 버튼 클릭 시 일부 브라우저가 selection 을 해제하면서 결과창이 닫히던 버그 방지.
    if (popup.contains(e.target)) return
    // mouseup 직후 selection 이 갱신되도록 microtask 뒤로 미룸
    setTimeout(() => {
      const sel = window.getSelection()
      const txt = sel ? sel.toString() : ''
      if (!txt || !txt.trim()) { hideDecodePopup(); return }

      const range = sel.rangeCount ? sel.getRangeAt(0) : null
      if (!range) { hideDecodePopup(); return }
      const node = range.commonAncestorContainer
      const el   = node.nodeType === 1 ? node : node.parentElement
      if (!modalBody.contains(el)) { hideDecodePopup(); return }

      _dpLastText = txt
      showDecodePopup(range.getBoundingClientRect())
    }, 0)
  })

  // 팝업 밖 클릭 시 닫기 (모달 내부 클릭은 mouseup 처리에 위임)
  document.addEventListener('mousedown', e => {
    if (popup.classList.contains('hidden')) return
    if (popup.contains(e.target))     return
    if (modalBody.contains(e.target)) return
    hideDecodePopup()
  })

  // 모달 스크롤 시 팝업 닫음(위치가 어긋남)
  modalBody.addEventListener('scroll', hideDecodePopup, { passive: true })

  // ESC 로 팝업만 먼저 닫기 (모달 닫힘 키 핸들러보다 먼저 처리)
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !popup.classList.contains('hidden')) {
      e.stopPropagation()
      hideDecodePopup()
    }
  }, true)

  $('dp-close').addEventListener('click', hideDecodePopup)
  $('dp-url') .addEventListener('click', () => doDecode('url'))
  $('dp-b64') .addEventListener('click', () => doDecode('b64'))
  $('dp-copy').addEventListener('click', () => copyToClipboard(_dpLastText, '선택 텍스트 복사됨'))
  $('dp-result-copy').addEventListener('click', () =>
    copyToClipboard($('dp-result-val').textContent, '결과 복사됨')
  )
}

function showDecodePopup(rect) {
  const popup = $('decode-popup')
  // 선택된 텍스트 프리뷰 — 너무 길면 잘라서 표시
  const t = _dpLastText || ''
  $('dp-source-text').textContent = t.length > 240 ? t.slice(0, 240) + '…' : t

  popup.classList.remove('hidden')
  $('dp-result').classList.add('hidden')

  // 레이아웃 후 폭/높이 측정 → 위치 결정 (선택 아래, 화면 넘치면 위쪽)
  const pw  = popup.offsetWidth  || 380
  const ph  = popup.offsetHeight || 120
  const pad = 8
  let x = rect.left
  let y = rect.bottom + 6
  if (x + pw > window.innerWidth  - pad) x = window.innerWidth  - pw - pad
  if (y + ph > window.innerHeight - pad) y = rect.top - ph - 6
  popup.style.left = Math.max(pad, x) + 'px'
  popup.style.top  = Math.max(pad, y) + 'px'
}

function hideDecodePopup() {
  $('decode-popup').classList.add('hidden')
  $('dp-result').classList.add('hidden')
}

function doDecode(kind) {
  let label, val
  try {
    if (kind === 'url') {
      label = 'URL 디코드'
      val   = decodeURIComponent(_dpLastText.replace(/\+/g, '%20'))
    } else {
      label = 'Base64 디코드'
      val   = base64DecodeUtf8(_dpLastText)
    }
  } catch (e) {
    label = (kind === 'url' ? 'URL' : 'Base64') + ' 디코드 실패'
    val   = e?.message || String(e)
  }
  $('dp-result-label').textContent = label
  $('dp-result-val').textContent   = val
  $('dp-result').classList.remove('hidden')
}

// Base64 디코드 — URL-safe(-_) 정규화 + 패딩 자동 보정 + UTF-8 복원
function base64DecodeUtf8(text) {
  let s = text.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/=]+$/.test(s)) throw new Error('Base64 가 아닌 문자 포함')
  const pad = (4 - s.length % 4) % 4
  s += '='.repeat(pad)
  const bin   = atob(s)
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0))
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

function copyToClipboard(text, okMsg) {
  if (!text) return
  const ok = () => setStatus(okMsg || '복사됨')
  const ng = () => setStatus('복사 실패', true)
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(ok, ng)
  else ng()
}

// ── 전체 검색 ─────────────────────────────────────────
function openGlobalSearch()  { $('gs-panel').classList.remove('hidden'); $('gs-input').focus() }
function closeGlobalSearch() {
  $('gs-panel').classList.add('hidden')
  $('gs-input').value = ''
  $('gs-body').innerHTML = '<div class="gs-hint">검색어를 입력하면 모든 파싱 테이블에서 결과를 찾아드립니다.</div>'
  $('gs-count-badge').classList.add('hidden')
}

async function doGlobalSearch() {
  const q = $('gs-input').value.trim()
  if (!q) { closeGlobalSearch(); return }
  $('gs-body').innerHTML = '<div class="gs-searching">검색 중...</div>'
  const results = await window.api.globalSearch(q)
  $('gs-count-badge').textContent = results.length + '개 테이블'
  $('gs-count-badge').classList.toggle('hidden', !results.length)
  if (!results.length) { $('gs-body').innerHTML = '<div class="gs-no-results">검색 결과가 없습니다.</div>'; return }
  let html = ''
  for (const r of results) {
    const label = TABLE_META[r.table]?.label || r.table
    html += `<div class="gs-result-group">
      <div class="gs-rg-header">
        <span class="gs-rg-table">${esc(label)}</span>
        <span class="gs-rg-count">${r.total.toLocaleString()}건</span>
      </div>
      <table class="gs-table">
        <thead><tr>${r.columns.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${r.rows.map(row=>'<tr>'+r.columns.map(c=>{
          const v=String(row[c]??''); return `<td>${esc(v.length>80?v.slice(0,80)+'…':v)}</td>`
        }).join('')+'</tr>').join('')}</tbody>
      </table>
    </div>`
  }
  $('gs-body').innerHTML = html
}

// ── 시작 ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init)
