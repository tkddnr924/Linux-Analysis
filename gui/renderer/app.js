/**
 * app.js — 렌더러 프로세스 UI 로직
 *
 * - DB 열기 / 탭 기반 네비게이션
 * - 테이블 데이터 페이지네이션 + 실시간 검색
 * - 행 클릭 → 상세 모달
 * - 값 타입 자동 감지로 컬러 하이라이팅
 * - 데이터 없는 탭/항목은 시각적으로 구분 표시
 */

'use strict'

// ── 상수 ─────────────────────────────────────────────
const PAGE_SIZE = 150

/**
 * 탭 정의 (순서 = 탭바 표시 순서)
 *  - tables  : 이 탭에 속한 테이블 이름 목록
 *  - priority: 탭 진입 시 자동 선택 우선 테이블
 */
const TABS = [
  {
    id:       'summary',
    label:    '📊 요약',
    tables:   ['info', 'log', 'supertimeline'],
    priority: 'info',
  },
  {
    id:       'auditlog',
    label:    '🔍 Auditlog',
    tables:   ['audit_login', 'audit_cmd', 'audit_file', 'cron_info'],
    priority: 'audit_cmd',
  },
  {
    id:       'authlog',
    label:    '🔐 Authlog',
    tables:   ['session_timeline', 'authlog_login', 'authlog_sudo', 'authlog_attack_ip', 'authlog_su', 'authlog_bruteforce'],
    priority: 'session_timeline',
  },
  {
    id:       'syslog',
    label:    '🖥️ Syslog',
    tables:   ['syslog_cron', 'syslog_service', 'kernlog_apparmor', 'kernlog_boot'],
    priority: 'syslog_service',
  },
  {
    id:       'nginx',
    label:    '🌐 WebLog · Nginx',
    tables:   ['nginx_top_ip', 'nginx_attack', 'nginx_webshell'],
    priority: 'nginx_attack',
  },
  {
    id:       'apache',
    label:    '🌐 WebLog · Apache',
    tables:   ['apache2_top_ip', 'apache2_attack', 'apache2_webshell'],
    priority: 'apache2_attack',
  },
  {
    id:       'mysql',
    label:    '🗄️ MySQL',
    tables:   ['mysql_sqli'],
    priority: 'mysql_sqli',
  },
  {
    id:       'ufw',
    label:    '🛡️ UFW',
    tables:   ['syslog_ufw'],
    priority: 'syslog_ufw',
  },
  {
    id:       'volatile',
    label:    '🖥️ Volatile',
    tables:   ['volatile_sockets', 'volatile_processes', 'volatile_modules', 'dpkg_suspicious'],
    priority: 'volatile_sockets',
  },
  {
    id:       'ai',
    label:    '🤖 AI 분석',
    tables:   ['attacker_profile'],
    priority: 'attacker_profile',
  },
]

/** 테이블별 한글 레이블 */
const TABLE_LABEL = {
  // 세션 분석
  session_timeline:    '세션 분석',
  // 요약
  info:                '서버 정보',
  log:                 '로그 요약',
  supertimeline:       '위협 통합 타임라인',
  // Auditlog
  audit_login:         '인증 이벤트',
  audit_cmd:           '명령 실행',
  audit_file:          '파일 접근',
  cron_info:           'Cron 실행 통계',
  // Authlog
  authlog_login:       'SSH 로그인 성공',
  authlog_sudo:        'sudo 실행',
  authlog_attack_ip:   '공격 시도 IP',
  authlog_su:          'su 전환',
  authlog_bruteforce:  '브루트포스 탐지',
  // Syslog
  syslog_cron:         'Cron 실행 기록',
  syslog_service:      '서비스 이벤트',
  // Nginx
  nginx_top_ip:        '공격 탐지 IP',
  nginx_attack:        '공격 페이로드',
  nginx_webshell:      '웹쉘 탐지',
  // Apache
  apache2_top_ip:      '공격 탐지 IP',
  apache2_attack:      '공격 페이로드',
  apache2_webshell:    '웹쉘 탐지',
  // MySQL
  mysql_sqli:          'SQL Injection 탐지',
  // UFW
  syslog_ufw:          'UFW 방화벽 로그',
  // Kern
  kernlog_apparmor:    'AppArmor 이벤트',
  kernlog_boot:        '시스템 재부팅',
  // Volatile
  volatile_sockets:    '열린 소켓/포트',
  volatile_processes:  '실행 중인 프로세스',
  volatile_modules:    '커널 모듈',
  dpkg_suspicious:     '의심 패키지',
  // AI 분석
  attacker_profile:    '공격자 프로파일',
}

// ── 컬럼 타입 힌트 (컬럼명 키워드 기반) ──────────────
const MONO_COLS   = ['raw_line', 'cmd', 'proctitle', 'comm', 'exe', 'command', 'uri',
                     'decoded_uri', 'user_agent', 'referer', 'listen_ports',
                     'matched_str', 'suspicion_flags', 'attack_types', 'commands',
                     'query', 'sqli_reason', 'message', 'event_type', 'ref',
                     // kernlog
                     'operation', 'profile', 'detail', 'kernel_ver',
                     // volatile
                     'exe_path', 'local_addr', 'remote_addr', 'proto', 'used_by', 'module',
                     // dpkg
                     'package', 'description', 'risk_reason']
const IP_COLS     = ['src_ip', 'internal_ip', 'addr', 'hostname', 'ip']
const DATE_COLS   = ['date_time', 'first_seen', 'last_seen', 'collected_at',
                     'booted_at', 'last_reboot', 'parsed_at', 'start_time', 'end_time',
                     'burst_start', 'burst_end']
const PATH_COLS   = ['file_path', 'cwd', 'exe', 'exe_path']
const NUMBER_COLS = ['count', 'exec_count', 'total_count', 'success_count', 'fail_count',
                     'attack_count', 'access_count', 'bytes_sent', 'bytes_min',
                     'bytes_max', 'file_size', 'cpu_cores', 'uptime_days',
                     'suspicion_score', 'total_records', 'file_count',
                     'avg_duration_sec', 'total_duration_sec', 'attempt_count',
                     'pid', 'ppid', 'size']
// risk 계열 컬럼 (값이 있으면 경고 색상)
const RISK_COLS   = ['risk', 'risk_reason', 'risk_level']

/** 수퍼타임라인 이벤트 타입별 메타 정보 */
const ST_TYPE_META = {
  brute_force:          { icon: '🔨', label: 'brute_force',    cls: 'st-brute-force' },
  remote_login:         { icon: '🔑', label: 'remote_login',   cls: 'st-remote-login' },
  privilege_escalation: { icon: '⬆️',  label: 'privilege_esc',  cls: 'st-privilege' },
  firewall_block:       { icon: '🛡️',  label: 'firewall_block', cls: 'st-firewall' },
  web_attack:           { icon: '🕷️',  label: 'web_attack',    cls: 'st-web-attack' },
  web_webshell:         { icon: '💀', label: 'web_webshell',   cls: 'st-webshell' },
  mysql_sqli:           { icon: '💉', label: 'mysql_sqli',     cls: 'st-sqli' },
}

// 공격 유형 키워드
const ATTACK_KEYWORDS = ['sql_injection', 'xss', 'path_traversal', 'lfi_rfi',
                         'shell_injection', 'php_injection', 'log4shell', 'spring4shell',
                         'attack', 'webshell', 'known_webshell',
                         'union_based', 'time_based', 'error_based', 'out_of_band',
                         'stacked_query', 'auth_bypass', 'hex_payload', 'db_fingerprint',
                         // supertimeline event_type 값
                         'brute_force', 'remote_login', 'privilege_escalation',
                         'firewall_block', 'web_attack', 'web_webshell', 'mysql_sqli']

/** 위협 관련 테이블 (사이드바 위협 도트 표시 대상) */
const THREAT_TABLES = new Set([
  'authlog_bruteforce',
  'authlog_attack_ip',
  'nginx_attack',
  'nginx_webshell',
  'apache2_attack',
  'apache2_webshell',
  'mysql_sqli',
  'dpkg_suspicious',
  'kernlog_apparmor',
])

// ── 상태 ─────────────────────────────────────────────
let currentTabId   = null
let currentTable   = null
let currentPage    = 0
let currentSearch  = ''
let currentTotal   = 0
let currentColumns = []
let currentSortCol = null
let currentSortDir = 'ASC'
let currentDateFrom = ''   // supertimeline 날짜 필터 시작 (YYYY-MM-DD)
let currentDateTo   = ''   // supertimeline 날짜 필터 종료 (YYYY-MM-DD)
let searchTimer    = null
let tableCountMap  = new Map()  // tableName → count

// ── DOM 참조 ─────────────────────────────────────────
const $ = id => document.getElementById(id)

const elDbPath       = $('db-path')
const elTabBar       = $('tab-bar')
const elSidebar      = $('sidebar-content')
const elWelcome      = $('welcome')
const elTabEmpty     = $('tab-empty')
const elTabEmptyTitle = $('tab-empty-title')
const elTabEmptyDesc  = $('tab-empty-desc')
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

// 날짜 필터 (supertimeline 전용)
const elDateFilter   = $('tl-date-filter')
const elDateFrom     = $('tl-date-from')
const elDateTo       = $('tl-date-to')
const elDateClearBtn = $('tl-date-clear')

// 테이블 스크롤 컨테이너
const elTableWrap    = document.querySelector('.table-wrap')

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
function isDateStr (s) {
  return /^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?/.test(s)
}

function setStatus (msg) { elStatusLeft.textContent = msg }

/** 탭의 데이터 존재 여부 (하나 이상 레코드가 있는 테이블이 있으면 true) */
function tabHasData (tab) {
  return tab.tables.some(t => (tableCountMap.get(t) ?? 0) > 0)
}

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

// ── 테이블 목록 로드 ──────────────────────────────────
async function loadTables () {
  const tables = await window.api.getTables()
  tableCountMap = new Map(tables.map(t => [t.name, t.count]))

  // 가상 테이블: authlog_login 데이터가 있으면 session_timeline 활성화
  const loginCount = tableCountMap.get('authlog_login') ?? 0
  if (loginCount > 0) tableCountMap.set('session_timeline', loginCount)

  // 가상 테이블: 공격 관련 데이터가 하나라도 있으면 attacker_profile 활성화
  const ATTACK_SOURCE_TABLES = [
    'authlog_bruteforce', 'authlog_attack_ip',
    'nginx_attack', 'apache2_attack', 'nginx_webshell', 'apache2_webshell',
  ]
  if (ATTACK_SOURCE_TABLES.some(t => (tableCountMap.get(t) ?? 0) > 0)) {
    tableCountMap.set('attacker_profile', 1)
  }

  elWelcome.classList.add('hidden')

  // 탭 바 렌더링
  renderTabBar()

  // 첫 진입 탭: 데이터 있는 첫 번째 탭 → 없으면 '요약'
  const firstTab = TABS.find(tab => tabHasData(tab)) || TABS[0]
  await switchTab(firstTab.id)
}

// ── 탭 바 렌더링 ─────────────────────────────────────
function renderTabBar () {
  let html = ''
  for (const tab of TABS) {
    const hasData  = tabHasData(tab)
    const isActive = tab.id === currentTabId
    const noDataBadge = !hasData
      ? '<span class="tab-no-data-badge">없음</span>'
      : ''
    html += `<button
      class="tab-item${isActive ? ' active' : ''}${!hasData ? ' no-data' : ''}"
      data-tab="${escHtml(tab.id)}"
    >${escHtml(tab.label)}${noDataBadge}</button>`
  }
  elTabBar.innerHTML = html
}

// ── 탭 전환 ──────────────────────────────────────────
async function switchTab (tabId) {
  const tab = TABS.find(t => t.id === tabId)
  if (!tab) return

  currentTabId = tabId
  currentTable = null
  currentPage  = 0
  currentSearch = ''
  elSearchInput.value = ''
  elBtnClear.classList.add('hidden')

  // 탭 전환 시 날짜 필터 리셋
  _resetDateFilter()

  renderTabBar()
  renderSidebar(tab)

  if (!tabHasData(tab)) {
    // 탭 전체 데이터 없음
    showTabEmpty(tab)
    return
  }

  // 우선순위 테이블 자동 선택
  let target = null
  if ((tableCountMap.get(tab.priority) ?? 0) > 0) {
    target = tab.priority
  } else {
    target = tab.tables.find(t => (tableCountMap.get(t) ?? 0) > 0)
  }

  if (target) {
    await selectTable(target)
  } else {
    showTabEmpty(tab)
  }
}

// ── 탭 데이터 없음 화면 ──────────────────────────────
function showTabEmpty (tab) {
  elTableView.classList.add('hidden')
  elTabEmpty.classList.remove('hidden')
  const name = tab.label.replace(/^[^\s]+\s/, '')   // 이모지 제거
  elTabEmptyTitle.textContent = `${name} 데이터 없음`
  elTabEmptyDesc.textContent  = '이 로그 파일이 수집되지 않았거나 파싱 데이터가 없습니다.'
  setStatus(`${tab.label} — 데이터 없음`)
}

// ── 사이드바 렌더링 (현재 탭 기준) ───────────────────
function renderSidebar (tab) {
  if (!tab) {
    elSidebar.innerHTML = '<div class="sidebar-empty"><p>DB를 열면 목록이<br/>표시됩니다.</p></div>'
    return
  }

  let html = ''
  for (const name of tab.tables) {
    const label  = TABLE_LABEL[name] || name
    const exists = tableCountMap.has(name)
    const count  = tableCountMap.get(name) ?? 0
    html += sidebarItem(name, label, count, exists)
  }

  elSidebar.innerHTML = html || '<div class="sidebar-empty"><p>이 탭에 데이터가 없습니다.</p></div>'
}

function sidebarItem (name, label, count, exists) {
  const noData    = !exists || count === 0
  const cls       = noData ? ' no-data' : ''
  const isThreat  = !noData && THREAT_TABLES.has(name)
  const countStr  = !exists ? '없음' : Number(count).toLocaleString()
  const threatDot = isThreat ? '<span class="sidebar-threat-dot"></span>' : ''
  return `<div class="sidebar-item${cls}" data-table="${escHtml(name)}"
               title="${escHtml(label)} (${countStr}건)">
    <span class="sidebar-item-name">${threatDot}${escHtml(label)}</span>
    <span class="sidebar-item-count">${countStr}</span>
  </div>`
}

// ── 날짜 필터 유틸 ────────────────────────────────────
function _resetDateFilter () {
  currentDateFrom     = ''
  currentDateTo       = ''
  elDateFrom.value    = ''
  elDateTo.value      = ''
  elDateFilter.classList.add('hidden')
  elDateClearBtn.classList.add('hidden')
}

function _updateDateClearBtn () {
  const active = currentDateFrom || currentDateTo
  elDateClearBtn.classList.toggle('hidden', !active)
}

// ── 테이블 선택 ──────────────────────────────────────
async function selectTable (name) {
  currentPage    = 0
  currentSearch  = ''
  currentSortCol = null
  currentSortDir = 'ASC'
  elSearchInput.value = ''
  elBtnClear.classList.add('hidden')

  // supertimeline 전용: 날짜 필터 표시 + 범위 조회
  if (name === 'supertimeline') {
    elDateFilter.classList.remove('hidden')
    // 이전 테이블과 다를 때만 날짜 범위 조회 (필터값은 유지)
    if (currentTable !== 'supertimeline') {
      currentDateFrom  = ''
      currentDateTo    = ''
      elDateFrom.value = ''
      elDateTo.value   = ''
      elDateClearBtn.classList.add('hidden')
    }
    const range = await window.api.getDateRange('supertimeline')
    if (range.min) { elDateFrom.min = range.min; elDateTo.min = range.min }
    if (range.max) { elDateFrom.max = range.max; elDateTo.max = range.max }
  } else {
    _resetDateFilter()
  }

  currentTable = name

  // 탭 빈 화면 숨기고 테이블 뷰 표시
  elTabEmpty.classList.add('hidden')
  elTableView.classList.remove('hidden')

  // 사이드바 활성 상태
  document.querySelectorAll('.sidebar-item').forEach(el => {
    el.classList.toggle('active', el.dataset.table === name)
  })

  // 세션 분석은 커스텀 뷰
  if (name === 'session_timeline') { await loadSessionView();   return }
  // AI 공격자 프로파일은 커스텀 뷰
  if (name === 'attacker_profile') { await loadAttackerView(); return }

  await loadData()
}

// ── 데이터 로드 ──────────────────────────────────────
async function loadData () {
  if (!currentTable) return
  setStatus('로딩 중…')

  const res = await window.api.getTableData({
    table:    currentTable,
    search:   currentSearch,
    limit:    PAGE_SIZE,
    offset:   currentPage * PAGE_SIZE,
    sortCol:  currentSortCol,
    sortDir:  currentSortDir,
    dateFrom: currentDateFrom || undefined,
    dateTo:   currentDateTo   || undefined,
  })

  if (res.error) {
    // 테이블이 존재하지 않는 경우
    currentTotal   = 0
    currentColumns = []
    elTableTitle.textContent = TABLE_LABEL[currentTable] || currentTable
    elTotalBadge.textContent = '없음'
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">📭</div>
      <div>데이터가 없습니다</div>
      <div class="empty-state-sub">이 로그가 파싱되지 않았거나 탐지 결과가 없습니다.</div>
    </div>`
    renderPagination()
    setStatus(`${currentTable} — 데이터 없음`)
    return
  }

  currentTotal   = res.total
  currentColumns = res.columns

  renderToolbar()
  renderTable(res.columns, res.rows)
  renderPagination()
  if (elTableWrap) elTableWrap.scrollTop = 0
  setStatus(`${currentTable} — ${currentTotal.toLocaleString()}건`)
}

// ── 툴바 ─────────────────────────────────────────────
function renderToolbar () {
  const label = TABLE_LABEL[currentTable] || currentTable
  elTableTitle.textContent = label

  const grandTotal = (tableCountMap.get(currentTable) ?? 0).toLocaleString()
  const hasFilter  = currentSearch || currentDateFrom || currentDateTo

  elTotalBadge.textContent = hasFilter
    ? `${currentTotal.toLocaleString()}건 / ${grandTotal}건 전체`
    : `${grandTotal}건 전체`
}

// ── 테이블 렌더링 ─────────────────────────────────────
function renderTable (columns, rows) {
  // supertimeline → 전용 타임라인 피드 뷰
  if (currentTable === 'supertimeline') { renderTimeline(columns, rows); return }
  // info / log → 전용 카드 뷰
  if (currentTable === 'info') { renderInfoCards(rows); return }
  if (currentTable === 'log')  { renderLogCards(rows);  return }

  if (!columns.length) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">📭</div>
      <div>데이터가 없습니다</div>
    </div>`
    return
  }

  let html = '<table><thead><tr>'
  for (const col of columns) {
    const isActive = col === currentSortCol
    const arrow    = isActive ? (currentSortDir === 'ASC' ? ' ↑' : ' ↓') : ''
    const cls      = isActive ? ' class="th-sorted"' : ''
    html += `<th${cls} data-col="${escHtml(col)}">${escHtml(col)}<span class="th-sort-icon">${arrow}</span></th>`
  }
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

// ── 타임라인 렌더링 (supertimeline 전용) ──────────────
function renderTimeline (columns, rows) {
  if (!rows.length) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">🕓</div>
      <div>탐지된 위협 이벤트가 없습니다</div>
      <div class="empty-state-sub">검색 조건을 변경하거나 분석 결과를 확인하세요.</div>
    </div>`
    return
  }

  let html = '<div class="tl-feed">'
  let lastDate = null

  for (let i = 0; i < rows.length; i++) {
    const row      = rows[i]
    const dt       = row['date_time'] || ''
    const datePart = dt.slice(0, 10)    // YYYY-MM-DD
    const timePart = dt.slice(11, 19)   // HH:MM:SS
    const evType   = row['event_type'] || ''
    const ip       = row['ip'] || '-'
    const desc     = row['description'] || ''
    const ref      = row['ref'] || ''
    const meta     = ST_TYPE_META[evType] || { icon: '❓', label: evType, cls: 'st-unknown' }

    // 날짜 구분선
    if (datePart && datePart !== lastDate) {
      const dayLabel = datePart
      html += `<div class="tl-date-sep">
        <span class="tl-date-sep-line"></span>
        <span class="tl-date-sep-label">📅 ${escHtml(dayLabel)}</span>
        <span class="tl-date-sep-line"></span>
      </div>`
      lastDate = datePart
    }

    const ipHtml = (ip && ip !== '-')
      ? `<span class="tl-ip">${escHtml(ip)}</span>`
      : `<span class="tl-no-ip">—</span>`

    html += `<div class="tl-item ${escHtml(meta.cls)}" data-row="${i}">
      <div class="tl-bar"></div>
      <div class="tl-body">
        <div class="tl-header">
          <span class="tl-icon">${meta.icon}</span>
          <span class="tl-badge ${escHtml(meta.cls)}">${escHtml(meta.label)}</span>
          <span class="tl-time">${escHtml(timePart)}</span>
          ${ipHtml}
          <span class="tl-ref">${escHtml(ref)}</span>
        </div>
        <div class="tl-desc" title="${escHtml(desc)}">${escHtml(desc)}</div>
      </div>
    </div>`
  }

  html += '</div>'
  elDataTable.innerHTML = html

  // 클릭 → 모달
  elDataTable.querySelectorAll('.tl-item[data-row]').forEach((el, i) => {
    el.addEventListener('click', () => openModal(columns, rows[i]))
  })
}

// ── 셀 값 포맷 ───────────────────────────────────────
function formatCell (col, raw) {
  if (raw === null || raw === undefined || raw === '') {
    return { display: '<span class="val-null">—</span>', cls: '' }
  }

  const s   = String(raw)
  const low = col.toLowerCase()

  if (s.toUpperCase() === 'NULL') return { display: '<span class="val-null">NULL</span>', cls: '' }

  // risk 계열 컬럼 (값이 있으면 경고 색상)
  if (RISK_COLS.includes(low) && s) {
    const lvlCls = s === '높음' ? 'val-attack'
                 : s === '중'   ? 'val-risk-mid'
                 : s === '낮음' ? 'val-risk-low'
                 : 'val-attack'
    return { display: escHtml(truncate(s, 60)), cls: lvlCls }
  }

  // 공격 유형 (sqli_reason, attack_type 컬럼)
  if (ATTACK_KEYWORDS.some(k => s.toLowerCase().startsWith(k)) &&
      (low.includes('type') || low.includes('reason'))) {
    return { display: escHtml(truncate(s, 60)), cls: 'val-attack' }
  }

  // IP 주소
  if (IP_COLS.includes(low) && (isIPv4(s) || isIPv6(s))) {
    return { display: escHtml(s), cls: 'val-ip' }
  }

  // 날짜
  if (DATE_COLS.includes(low) && isDateStr(s)) {
    return { display: escHtml(s), cls: 'val-date' }
  }

  // 숫자
  if (NUMBER_COLS.includes(low) && !isNaN(raw)) {
    return { display: Number(raw).toLocaleString(), cls: 'val-number' }
  }

  // 경로
  if (PATH_COLS.includes(low) && (s.startsWith('/') || s.includes('\\'))) {
    return { display: escHtml(truncate(s, 60)), cls: 'val-path' }
  }

  // 모노 폰트
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

// ── 위협 요약 스트립 + 커스텀 카드 뷰 ──────────────────

/**
 * info/log 뷰 상단에 표시되는 위협 현황 요약 스트립 HTML 반환.
 * tableCountMap 기반으로 7개 지표를 표시하며, 데이터가 있는 지표는 붉게 강조.
 */
function renderThreatSummary () {
  const bf    = tableCountMap.get('authlog_bruteforce') ?? 0
  const login = tableCountMap.get('authlog_login')      ?? 0
  const atkN  = tableCountMap.get('nginx_attack')       ?? 0
  const atkA  = tableCountMap.get('apache2_attack')     ?? 0
  const wsN   = tableCountMap.get('nginx_webshell')     ?? 0
  const wsA   = tableCountMap.get('apache2_webshell')   ?? 0
  const sqli  = tableCountMap.get('mysql_sqli')         ?? 0
  const dpkg  = tableCountMap.get('dpkg_suspicious')    ?? 0
  const boot  = tableCountMap.get('kernlog_boot')       ?? 0

  const atkTable = atkN > 0 ? 'nginx_attack'   : atkA > 0 ? 'apache2_attack'   : null
  const wsTable  = wsN  > 0 ? 'nginx_webshell' : wsA  > 0 ? 'apache2_webshell' : null

  const metrics = [
    { icon: '🔨', label: '브루트포스',  count: bf,          table: 'authlog_bruteforce', warn: bf > 0 },
    { icon: '🔑', label: 'SSH 로그인', count: login,        table: 'authlog_login',      warn: login > 0 },
    { icon: '🕷️',  label: '웹 공격',   count: atkN + atkA,  table: atkTable,             warn: atkN + atkA > 0 },
    { icon: '💀', label: '웹쉘',       count: wsN  + wsA,   table: wsTable,              warn: wsN  + wsA  > 0 },
    { icon: '💉', label: 'SQL 인젝션', count: sqli,         table: 'mysql_sqli',         warn: sqli > 0 },
    { icon: '📦', label: '의심 패키지', count: dpkg,        table: 'dpkg_suspicious',    warn: dpkg > 0 },
    { icon: '🔄', label: '재부팅 기록', count: boot,        table: 'kernlog_boot',       warn: boot >= 2 },
  ]

  let html = '<div class="ts-strip">'
  for (const m of metrics) {
    const warnCls  = m.warn    ? ' ts-warn'      : ''
    const clickCls = m.table   ? ' ts-clickable' : ''
    const navAttr  = m.table   ? ` data-nav="${escHtml(m.table)}"` : ''
    html += `<div class="ts-metric${warnCls}${clickCls}"${navAttr}>
      <span class="ts-icon">${m.icon}</span>
      <span class="ts-count">${m.count.toLocaleString()}</span>
      <span class="ts-label">${escHtml(m.label)}</span>
    </div>`
  }
  return html + '</div>'
}

/** CSP 호환 이벤트 위임 — .ts-clickable[data-nav] 클릭 시 해당 테이블로 이동 */
function setupThreatStripListeners (container) {
  container.querySelectorAll('.ts-clickable[data-nav]').forEach(el => {
    el.addEventListener('click', async () => {
      if ((tableCountMap.get(el.dataset.nav) ?? 0) > 0) {
        await navigateToTable(el.dataset.nav)
      }
    })
  })
}

/** info 카드 한 행 헬퍼 (레이블 + 값) */
function infoRow (label, value, cls = '') {
  const v    = (value === null || value === undefined || value === '') ? null : String(value)
  const disp = v === null
    ? '<span class="info-val-null">—</span>'
    : `<span class="${cls}">${escHtml(v)}</span>`
  return `<div class="info-row">
    <span class="info-row-label">${escHtml(label)}</span>
    ${disp}
  </div>`
}

/** info 테이블 → 서버 정보 카드 그리드 뷰 */
function renderInfoCards (rows) {
  if (!rows || !rows.length) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">📭</div><div>서버 정보가 없습니다</div>
    </div>`
    return
  }

  const r    = rows[0]
  const dpct = parseFloat(r['disk_use_pct'])
  const diskCls = !isNaN(dpct)
    ? (dpct >= 90 ? 'val-attack' : dpct >= 70 ? 'val-risk-mid' : 'val-success')
    : ''
  const diskFillCls = dpct >= 90 ? 'disk-fill-danger' : dpct >= 70 ? 'disk-fill-warn' : 'disk-fill-ok'

  // 리슨 포트는 긴 문자열이므로 별도 처리
  const ports   = r['listen_ports']
  const portsEl = ports
    ? `<div class="info-row info-row-ports">
        <span class="info-row-label">리슨 포트</span>
        <span class="info-val-ports val-mono info-val-sm">${escHtml(ports)}</span>
       </div>`
    : infoRow('리슨 포트', null)

  // 디스크 사용률 바
  const diskBar = !isNaN(dpct)
    ? `<div class="info-disk-bar"><div class="info-disk-fill ${diskFillCls}" style="width:${Math.min(100, dpct)}%"></div></div>`
    : ''

  let html = renderThreatSummary()
  html += '<div class="info-grid">'

  // ① 서버 식별
  html += `<div class="info-card">
    <div class="info-card-title">🖥️ 서버 식별</div>
    ${infoRow('호스트명',    r['hostname'],    'info-val-host')}
    ${infoRow('운영체제',    r['os'])}
    ${infoRow('커널',        r['kernel'],      'val-mono info-val-sm')}
    ${infoRow('아키텍처',   r['architecture'])}
    ${infoRow('수집 사용자', r['collect_user'])}
  </div>`

  // ② 네트워크
  html += `<div class="info-card">
    <div class="info-card-title">🌐 네트워크</div>
    ${infoRow('내부 IP',  r['internal_ip'],  'val-ip val-mono info-val-sm')}
    ${infoRow('외부 IP',  r['external_ip'],  'info-val-ext-ip val-mono info-val-sm')}
    ${infoRow('MAC 주소', r['mac_address'],  'val-mono info-val-sm')}
    ${infoRow('타임존',   r['timezone'])}
    ${portsEl}
  </div>`

  // ③ 하드웨어 / 스토리지
  html += `<div class="info-card">
    <div class="info-card-title">⚙️ 하드웨어</div>
    ${infoRow('CPU 모델', r['cpu_model'])}
    ${infoRow('CPU 코어', r['cpu_cores'])}
    ${infoRow('전체 디스크', r['disk_total'])}
    ${infoRow('사용 디스크', r['disk_used'])}
    <div class="info-row">
      <span class="info-row-label">디스크 사용률</span>
      <span class="${diskCls}">${!isNaN(dpct) ? dpct + '%' : '—'}</span>
    </div>
    ${diskBar}
    ${infoRow('여유 디스크', r['disk_avail'])}
  </div>`

  // ④ 타임라인
  html += `<div class="info-card">
    <div class="info-card-title">🕒 타임라인</div>
    ${infoRow('수집 시각',     r['collected_at'], 'val-date val-mono info-val-sm')}
    ${infoRow('부팅 시각',     r['booted_at'],    'val-date val-mono info-val-sm')}
    ${infoRow('업타임',        r['uptime_days'] != null ? r['uptime_days'] + '일' : null)}
    ${infoRow('마지막 재부팅', r['last_reboot'],  'val-date val-mono info-val-sm')}
    ${infoRow('wtmp 시작',     r['wtmp_begins'],  'val-date val-mono info-val-sm')}
    ${infoRow('분석 시각',     r['analyzed_at'],  'val-date val-mono info-val-sm')}
  </div>`

  html += '</div>'
  elDataTable.innerHTML = html
  setupThreatStripListeners(elDataTable)
}

/** 로그 타입 아이콘 매핑 */
const LOG_ICONS = {
  authlog:     '🔐',
  audit:       '🔍',
  nginx:       '🌐',
  apache2:     '🌐',
  syslog:      '🖥️',
  mysql_query: '🗄️',
  mysql_error: '🗄️',
  kernlog:     '⚙️',
  ufw:         '🛡️',
}

/** log 테이블 → 로그 요약 카드 리스트 뷰 */
function renderLogCards (rows) {
  if (!rows || !rows.length) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">📭</div><div>로그 요약 정보가 없습니다</div>
    </div>`
    return
  }

  let html = renderThreatSummary()
  html += '<div class="log-cards">'

  for (const r of rows) {
    const name     = r['log_name'] || ''
    const icon     = LOG_ICONS[name] || '📄'
    const total    = r['total_records']
    const files    = r['file_count']
    const first    = r['first_record']  || null
    const last     = r['last_record']   || null
    const analyzed = r['analyzed_at']   || null
    const hasData  = total != null && Number(total) > 0

    html += `<div class="log-card${hasData ? '' : ' log-card-empty'}">
      <div class="log-card-icon">${icon}</div>
      <div class="log-card-body">
        <div class="log-card-name">${escHtml(name)}</div>
        <div class="log-card-range">
          ${first ? `<span class="log-card-date">${escHtml(first)}</span>` : '<span class="log-card-no-date">—</span>'}
          <span class="log-card-arrow">→</span>
          ${last  ? `<span class="log-card-date">${escHtml(last)}</span>`  : '<span class="log-card-no-date">—</span>'}
        </div>
        ${analyzed ? `<div class="log-card-analyzed">분석: ${escHtml(analyzed)}</div>` : ''}
      </div>
      <div class="log-card-stats">
        <span class="log-card-total">${hasData ? Number(total).toLocaleString() : '없음'}</span>
        ${hasData ? '<span class="log-card-unit">건</span>' : ''}
        ${files != null ? `<span class="log-card-files">${files}개 파일</span>` : ''}
      </div>
    </div>`
  }

  html += '</div>'
  elDataTable.innerHTML = html
  setupThreatStripListeners(elDataTable)
}

// ── 세션 분석 뷰 ─────────────────────────────────────

async function loadSessionView () {
  _resetDateFilter()
  elSearchInput.value = ''
  elBtnClear.classList.add('hidden')
  elTableTitle.textContent = '세션 분석'
  setStatus('세션 분석 로딩 중…')

  const { sessions, has_data } = await window.api.getLoginSessions()

  if (!has_data || !sessions.length) {
    elTotalBadge.textContent = '없음'
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">🔐</div>
      <div>로그인 기록이 없습니다</div>
      <div class="empty-state-sub">authlog 파싱 결과가 없거나 로그인 이벤트가 탐지되지 않았습니다.</div>
    </div>`
    elBtnPrev.disabled = true
    elBtnNext.disabled = true
    elPageInfo.textContent  = '1 / 1'
    elPagCount.textContent  = '0건'
    setStatus('세션 분석 — 데이터 없음')
    if (elTableWrap) elTableWrap.scrollTop = 0
    return
  }

  const totalLogins = sessions.reduce((s, r) => s + r.count, 0)
  elTotalBadge.textContent = `${sessions.length}개 발원지 · 총 ${totalLogins.toLocaleString()}회`
  elBtnPrev.disabled = true
  elBtnNext.disabled = true
  elPageInfo.textContent  = ''
  elPagCount.textContent  = `${sessions.length}개 IP / ${totalLogins.toLocaleString()}회 접속`

  renderSessionView(sessions)
  if (elTableWrap) elTableWrap.scrollTop = 0
  setStatus(`세션 분석 — ${sessions.length}개 발원지`)
}

/** 내부 사설 IP 여부 판단 */
function isPrivateIP (ip) {
  return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)
}

function renderSessionView (sessions) {
  let html = '<div class="sess-list">'
  for (let i = 0; i < sessions.length; i++) {
    const s = sessions[i]
    const external  = !isPrivateIP(s.src_ip)
    const riskCls   = external ? 'sess-card-external' : 'sess-card-internal'
    const authIcon  = s.auth_method === 'publickey' ? '🔑' : '🔏'
    const timeRange = s.count > 1
      ? `${escHtml(s.first_seen)} → ${escHtml(s.last_seen)}`
      : escHtml(s.first_seen)

    html += `<div class="sess-card ${riskCls}" data-sess="${i}">
      <div class="sess-card-header" data-sess="${i}">
        <span class="sess-num">[${i + 1}]</span>
        <span class="sess-user">${escHtml(s.user)}</span>
        <span class="sess-auth">${authIcon} ${escHtml(s.auth_method)}</span>
        <span class="sess-ip${external ? ' sess-ip-ext' : ''}">${escHtml(s.src_ip)}</span>
        <div class="sess-meta">
          <span class="sess-time">${timeRange}</span>
          <span class="sess-badge">${s.count.toLocaleString()}회</span>
        </div>
        <button class="sess-expand-btn" data-sess="${i}">활동 보기 ▾</button>
      </div>
      <div class="sess-activity hidden" id="sess-act-${i}">
        <div class="sess-loading">🔄 로딩 중…</div>
      </div>
    </div>`
  }
  html += '</div>'
  elDataTable.innerHTML = html

  // 헤더 및 버튼 클릭 → 활동 펼치기/접기
  elDataTable.querySelectorAll('[data-sess]').forEach(el => {
    if (!el.classList.contains('sess-card')) {
      el.addEventListener('click', async e => {
        const idx    = parseInt(el.dataset.sess)
        const actEl  = document.getElementById(`sess-act-${idx}`)
        const btn    = el.closest('.sess-card')?.querySelector('.sess-expand-btn')
        if (!actEl) return

        const isOpen = !actEl.classList.contains('hidden')
        if (isOpen) {
          actEl.classList.add('hidden')
          if (btn) btn.textContent = '활동 보기 ▾'
        } else {
          actEl.classList.remove('hidden')
          if (btn) btn.textContent = '접기 ▴'
          if (actEl.querySelector('.sess-loading')) {
            await loadSessionActivity(sessions[idx], actEl)
          }
        }
      })
    }
  })
}

async function loadSessionActivity (sess, actEl) {
  const activity = await window.api.getSessionActivity({
    user:        sess.user,
    src_ip:      sess.src_ip,
    first_seen:  sess.first_seen,
    last_seen:   sess.last_seen,
  })
  renderSessionActivity(activity, sess, actEl)
}

function renderSessionActivity (act, sess, actEl) {
  const { sudo, cmd, su, bruteforce } = act
  const hasAny = sudo.length || cmd.length || su.length || bruteforce.length

  if (!hasAny) {
    actEl.innerHTML = `<div class="sess-no-act">
      이 기간 동안 연관된 활동 기록이 없습니다.<br>
      <span style="font-size:11px;color:var(--text-muted)">audit.log / authlog 에서 해당 사용자 기록을 찾지 못했습니다.</span>
    </div>`
    return
  }

  let html = '<div class="sess-act-inner">'

  // 브루트포스 경고 (같은 IP의 공격 기록)
  if (bruteforce.length) {
    const totalAttempts = bruteforce.reduce((s, r) => s + r.attempt_count, 0)
    html += `<div class="sess-act-section sess-bf-warn">
      <div class="sess-act-title">⚠️ 로그인 전 브루트포스 탐지 (${bruteforce.length}회 burst · 총 ${totalAttempts}회 시도)</div>`
    for (const b of bruteforce.slice(0, 5)) {
      html += `<div class="sess-act-item">
        <span class="sess-act-cmd val-attack">${escHtml(b.src_ip)}</span>
        <span class="sess-act-time">${escHtml(b.burst_start)} ~ ${escHtml(b.burst_end)}</span>
        <span class="sess-act-cnt val-attack">${b.attempt_count}회 시도</span>
      </div>`
    }
    if (bruteforce.length > 5) {
      html += `<div class="sess-act-more">…외 ${bruteforce.length - 5}건</div>`
    }
    html += '</div>'
  }

  // sudo 명령
  if (sudo.length) {
    html += `<div class="sess-act-section">
      <div class="sess-act-title">⚡ sudo 명령 (${sudo.length}건)</div>`
    for (const item of sudo) {
      const timeStr = item.count > 1
        ? `${escHtml(item.first_seen)} ~ ${escHtml(item.last_seen)}`
        : escHtml(item.first_seen)
      html += `<div class="sess-act-item">
        <span class="sess-act-cmd">${escHtml(truncate(item.command, 100))}</span>
        <span class="sess-act-time">${timeStr}</span>
        ${item.count > 1 ? `<span class="sess-act-cnt">${item.count}회</span>` : ''}
      </div>`
    }
    html += '</div>'
  }

  // audit 명령 실행
  if (cmd.length) {
    html += `<div class="sess-act-section">
      <div class="sess-act-title">💻 실행 명령 (${cmd.length}건 · audit 기준)</div>`
    for (const item of cmd) {
      const timeStr = item.count > 1
        ? `${escHtml(item.first_seen)} ~ ${escHtml(item.last_seen)}`
        : escHtml(item.first_seen)
      html += `<div class="sess-act-item">
        <span class="sess-act-cmd">${escHtml(truncate(item.cmd, 100))}</span>
        ${item.cwd ? `<span class="sess-act-cwd">${escHtml(truncate(item.cwd, 40))}</span>` : ''}
        <span class="sess-act-time">${timeStr}</span>
        ${item.count > 1 ? `<span class="sess-act-cnt">${item.count}회</span>` : ''}
      </div>`
    }
    html += '</div>'
  }

  // 계정 전환 su
  if (su.length) {
    html += `<div class="sess-act-section">
      <div class="sess-act-title">👤 계정 전환 (${su.length}건)</div>`
    for (const item of su) {
      const timeStr = item.count > 1
        ? `${escHtml(item.first_seen)} ~ ${escHtml(item.last_seen)}`
        : escHtml(item.first_seen)
      html += `<div class="sess-act-item">
        <span class="sess-act-cmd">
          <span style="color:var(--text-secondary)">${escHtml(item.from_user)}</span>
          <span style="color:var(--text-muted)"> → </span>
          <span style="color:var(--accent-orange);font-weight:600">${escHtml(item.to_user)}</span>
        </span>
        <span class="sess-act-time">${timeStr}</span>
        ${item.count > 1 ? `<span class="sess-act-cnt">${item.count}회</span>` : ''}
      </div>`
    }
    html += '</div>'
  }

  html += '</div>'
  actEl.innerHTML = html
}

// ── AI 공격자 프로파일 분석 ───────────────────────────

/** 위험도 레벨 메타 */
const AP_LEVEL = {
  critical: { label: 'CRITICAL', cls: 'ap-level-critical', barCls: 'ap-bar-critical' },
  high:     { label: 'HIGH',     cls: 'ap-level-high',     barCls: 'ap-bar-high'     },
  medium:   { label: 'MEDIUM',   cls: 'ap-level-medium',   barCls: 'ap-bar-medium'   },
  low:      { label: 'LOW',      cls: 'ap-level-low',      barCls: 'ap-bar-low'      },
}

/**
 * IP 데이터를 입력받아 점수·위험도·판정·공격벡터·발견사항을 계산.
 *
 * 점수 기준:
 *  🔨 브루트포스 burst당 +5 (최대 25)
 *  🚨 브루트포스 성공 시   +55
 *  🔑 SSH 로그인 성공      +20
 *  🕷️  웹 공격 100건당     +2  (최대 20)
 *  💀 웹쉘 접근            +45
 *  🛡️  UFW 차단 포트당     +1  (최대 8)
 *
 * 위험도:  CRITICAL ≥ 70  /  HIGH ≥ 40  /  MEDIUM ≥ 20  /  LOW < 20
 */
function scoreAttacker (d) {
  let score      = 0
  const vectors  = []
  const findings = []

  // ① 브루트포스
  if (d.bf_bursts) {
    score += Math.min(25, d.bf_bursts * 5)
    vectors.push({ key: 'brute', label: '브루트포스', cls: 'vec-brute' })
    findings.push({
      icon: '🔨',
      text: `${d.bf_bursts}회 burst · ${Number(d.bf_attempts || 0).toLocaleString()}회 시도`,
      time: d.bf_first,
      cls:  '',
    })
    if ((d.bf_success || 0) > 0) {
      score += 55   // 브루트포스 후 로그인 성공 — 가장 치명적
      findings.unshift({
        icon: '🚨',
        text: `브루트포스 성공 ${d.bf_success}회 — 계정 탈취 확인`,
        cls:  'af-critical',
      })
    }
  }

  // ② authlog_attack_ip 의 success_count (브루트포스 외 별도 성공)
  if ((d.atk_success || 0) > 0 && !(d.bf_success > 0)) {
    score += 30
    findings.push({
      icon: '🔑',
      text: `공격 IP 로그인 성공 ${d.atk_success}회`,
      time: d.atk_first,
      cls:  'af-warn',
    })
  }

  // ③ SSH 로그인 성공 (authlog_login)
  if ((d.login_total || 0) > 0) {
    score += d.bf_bursts ? 10 : 20   // 브루트포스와 겹치면 보너스만
    if (!vectors.find(v => v.key === 'login')) {
      vectors.push({ key: 'login', label: 'SSH 로그인', cls: 'vec-login' })
    }
    const userList = d.login_users
      ? d.login_users.split(',').slice(0, 3).join(', ')
      : '-'
    findings.push({
      icon: '🔑',
      text: `로그인 성공 ${d.login_total}회 · 계정: ${userList} · 방식: ${d.login_methods || '-'}`,
      time: d.login_first,
      cls:  '',
    })
  }

  // ④ 웹 공격
  const webAtk = (d.natk_count || 0) + (d.aatk_count || 0)
  if (webAtk > 0) {
    score += Math.min(20, Math.max(5, Math.ceil(webAtk / 50)))
    vectors.push({ key: 'web', label: '웹 공격', cls: 'vec-web' })
    const allTypes = [d.natk_types, d.aatk_types].filter(Boolean).join(',')
    const uniqTypes = [...new Set(allTypes.split(',').map(s => s.trim()).filter(Boolean))]
      .slice(0, 4).join(', ')
    findings.push({
      icon: '🕷️',
      text: `웹 공격 ${webAtk.toLocaleString()}건 · 유형: ${uniqTypes || '-'}`,
      time: d.natk_first || d.aatk_first,
      cls:  '',
    })
  }

  // ⑤ 웹쉘
  const wsFiles = (d.ws_files  || 0) + (d.ws2_files  || 0)
  const wsHits  = (d.ws_hits   || 0) + (d.ws2_hits   || 0)
  if (wsFiles > 0) {
    score += 45
    vectors.push({ key: 'shell', label: '웹쉘', cls: 'vec-shell' })
    const allNames = [d.ws_names, d.ws2_names].filter(Boolean).join(',')
    const nameList = [...new Set(allNames.split(',').filter(Boolean))].slice(0, 3).join(', ')
    findings.push({
      icon: '💀',
      text: `웹쉘 ${wsFiles}개 파일 · ${wsHits.toLocaleString()}회 접속`,
      sub:  nameList || null,
      cls:  'af-critical',
    })
  }

  // ⑥ UFW 방화벽 차단
  if ((d.ufw_blocks || 0) > 0) {
    score += Math.min(8, d.ufw_ports || 1)
    if (!vectors.length) {
      vectors.push({ key: 'scan', label: '포트 스캔', cls: 'vec-scan' })
    }
    findings.push({
      icon: '🛡️',
      text: `방화벽 차단 ${Number(d.ufw_blocks).toLocaleString()}회 · ${d.ufw_ports || 0}개 포트`,
      time: d.ufw_first,
      cls:  '',
    })
  }

  score = Math.min(100, score)

  // ── 위험도 레벨
  const level = score >= 70 ? 'critical'
              : score >= 40 ? 'high'
              : score >= 20 ? 'medium'
              :               'low'

  // ── 판정 (규칙 기반 verdict)
  const hasBreach  = (d.bf_success  || 0) > 0 || (d.atk_success || 0) > 0
  const hasShell   = wsFiles > 0
  const hasWebAtk  = webAtk > 0
  const hasBrute   = (d.bf_bursts   || 0) > 0
  const hasLogin   = (d.login_total || 0) > 0
  const multiVec   = [hasBrute, hasWebAtk, hasLogin].filter(Boolean).length >= 2

  let verdict, verdictCls
  if      (hasShell  && hasBreach)  { verdict = '웹쉘 침투 + 계정 탈취';    verdictCls = 'verdict-critical' }
  else if (hasShell  && hasWebAtk)  { verdict = '웹쉘 침투 + 지속 공격';    verdictCls = 'verdict-critical' }
  else if (hasShell)                { verdict = '웹쉘 침투 의심';            verdictCls = 'verdict-critical' }
  else if (hasBreach && hasWebAtk)  { verdict = '계정 탈취 + 웹 공격';      verdictCls = 'verdict-critical' }
  else if (hasBreach)               { verdict = '브루트포스 계정 탈취';      verdictCls = 'verdict-critical' }
  else if (multiVec)                { verdict = '다중 벡터 공격자';          verdictCls = 'verdict-high'     }
  else if (hasLogin  && hasWebAtk)  { verdict = '웹 공격 + 로그인 성공';    verdictCls = 'verdict-high'     }
  else if (hasLogin  && hasBrute)   { verdict = '브루트포스 중 로그인 성공'; verdictCls = 'verdict-high'     }
  else if (hasLogin)                { verdict = '외부 IP 로그인 성공';       verdictCls = 'verdict-high'     }
  else if (hasBrute  && hasWebAtk)  { verdict = '다중 채널 스캐닝';          verdictCls = 'verdict-medium'   }
  else if (hasBrute)                { verdict = '브루트포스 시도 (실패)';    verdictCls = 'verdict-medium'   }
  else if (hasWebAtk)               { verdict = '웹 취약점 스캐닝';          verdictCls = 'verdict-medium'   }
  else                              { verdict = '포트 스캔 / 정찰';          verdictCls = 'verdict-low'      }

  return { score, level, verdict, verdictCls, vectors, findings }
}

/** AI 분석 탭 — 데이터 로드 후 렌더링 */
async function loadAttackerView () {
  _resetDateFilter()
  elSearchInput.value = ''
  elBtnClear.classList.add('hidden')
  elTableTitle.textContent = '공격자 프로파일'
  setStatus('AI 분석 중…')

  const raw = await window.api.getAttackerProfiles()

  // 스코어링 + 필터 (점수 > 0) + 내림차순 정렬
  const profiles = raw
    .map(d => ({ ...d, ...scoreAttacker(d) }))
    .filter(p => p.score > 0)
    .sort((a, b) => b.score - a.score)

  const criticals = profiles.filter(p => p.level === 'critical').length
  const highs     = profiles.filter(p => p.level === 'high').length

  elTotalBadge.textContent = `${profiles.length}개 IP · CRITICAL ${criticals} · HIGH ${highs}`
  elBtnPrev.disabled = true
  elBtnNext.disabled = true
  elPageInfo.textContent = ''
  elPagCount.textContent = `${profiles.length}개 의심 IP 탐지`

  renderAttackerProfiles(profiles)
  if (elTableWrap) elTableWrap.scrollTop = 0
  setStatus(`AI 분석 — ${profiles.length}개 IP · CRITICAL ${criticals}`)
}

/** 공격자 프로파일 카드 리스트 렌더링 */
function renderAttackerProfiles (profiles) {
  if (!profiles.length) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">🛡️</div>
      <div>탐지된 공격자 IP가 없습니다</div>
      <div class="empty-state-sub">공격 관련 로그 파싱 결과가 없거나 모든 공격이 차단되었습니다.</div>
    </div>`
    return
  }

  // ── 헤더 + 범례
  let html = `<div class="ap-header">
    <div class="ap-header-left">
      <div class="ap-header-title">🤖 AI 공격자 프로파일 분석</div>
      <div class="ap-header-sub">규칙 기반 점수 엔진 · ${profiles.length}개 의심 IP 탐지</div>
    </div>
    <div class="ap-score-legend">
      <span class="ap-legend-item ap-legend-critical">CRITICAL ≥70</span>
      <span class="ap-legend-item ap-legend-high">HIGH 40-69</span>
      <span class="ap-legend-item ap-legend-medium">MEDIUM 20-39</span>
      <span class="ap-legend-item ap-legend-low">LOW &lt;20</span>
    </div>
  </div>`

  // ── 스코어링 기준 설명 스트립
  html += `<div class="ap-methodology">
    <span class="ap-method-label">📐 점수 기준</span>
    <span class="ap-method-item">🔨 브루트포스: burst당 +5 (최대 25)</span>
    <span class="ap-method-item ap-method-crit">🚨 브루트포스 성공: +55</span>
    <span class="ap-method-item">🔑 SSH 로그인: +20</span>
    <span class="ap-method-item">🕷️ 웹 공격: +5~20</span>
    <span class="ap-method-item ap-method-crit">💀 웹쉘: +45</span>
    <span class="ap-method-item">🛡️ 방화벽 차단: +1~8</span>
  </div>`

  // ── 카드 리스트
  html += '<div class="ap-list">'

  for (const p of profiles) {
    const lv      = AP_LEVEL[p.level] || AP_LEVEL.low
    const verdPfx = p.verdictCls === 'verdict-critical' ? '🔴'
                  : p.verdictCls === 'verdict-high'     ? '🟠'
                  : p.verdictCls === 'verdict-medium'   ? '🟡' : '⚪'

    html += `<div class="ap-card ap-card-${p.level}">`

    // 상단: 레벨 배지 + IP + 점수
    html += `<div class="ap-card-top">
      <span class="ap-level-badge ${lv.cls}">${lv.label}</span>
      <span class="ap-ip">${escHtml(p.src_ip)}</span>
      <span class="ap-score-num">${p.score}<span class="ap-score-unit">점</span></span>
    </div>`

    // 점수 바
    html += `<div class="ap-score-bar ${lv.barCls}">
      <div class="ap-score-fill" style="width:${p.score}%"></div>
    </div>`

    // 판정
    html += `<div class="ap-verdict ${p.verdictCls}">${verdPfx} ${escHtml(p.verdict)}</div>`

    // 공격 벡터 배지
    if (p.vectors.length) {
      html += '<div class="ap-vectors">'
      for (const v of p.vectors) {
        html += `<span class="ap-vec ${v.cls}">${escHtml(v.label)}</span>`
      }
      html += '</div>'
    }

    // 발견 사항 목록
    html += '<div class="ap-findings">'
    for (const f of p.findings) {
      html += `<div class="ap-finding${f.cls ? ' ' + f.cls : ''}">
        <span class="ap-finding-icon">${f.icon}</span>
        <div class="ap-finding-body">
          <span class="ap-finding-text">${escHtml(f.text)}</span>
          ${f.sub  ? `<span class="ap-finding-sub val-mono">${escHtml(f.sub)}</span>` : ''}
          ${f.time ? `<span class="ap-finding-time">${escHtml(f.time)}</span>` : ''}
        </div>
      </div>`
    }
    html += '</div>'

    html += '</div>' // .ap-card
  }

  html += '</div>' // .ap-list
  elDataTable.innerHTML = html
}

// ── 전체 검색 ─────────────────────────────────────────
let gsTimer = null

function openGlobalSearch () {
  if (!tableCountMap.size) return   // DB 미열림
  $('gs-panel').classList.remove('hidden')
  const inp = $('gs-input')
  inp.focus()
  inp.select()
}

function closeGlobalSearch () {
  $('gs-panel').classList.add('hidden')
}

async function runGlobalSearch (query) {
  const body  = $('gs-body')
  const badge = $('gs-count-badge')

  if (!query.trim()) {
    badge.classList.add('hidden')
    body.innerHTML = `<div class="gs-hint">
      <span class="gs-hint-icon">💡</span>
      검색어를 입력하면 모든 분석 테이블에서 결과를 찾아드립니다.
    </div>`
    return
  }

  body.innerHTML = `<div class="gs-loading">🔄 검색 중…</div>`
  badge.classList.add('hidden')

  const results = await window.api.globalSearch(query.trim())
  renderGlobalResults(results, query.trim())
}

function renderGlobalResults (results, query) {
  const body  = $('gs-body')
  const badge = $('gs-count-badge')

  if (!results.length) {
    badge.classList.add('hidden')
    body.innerHTML = `<div class="gs-empty">
      <span class="gs-empty-icon">🔍</span>
      <span>"${escHtml(query)}"에 대한 검색 결과가 없습니다.</span>
    </div>`
    return
  }

  const totalMatch = results.reduce((s, r) => s + r.total, 0)
  badge.textContent = `${totalMatch.toLocaleString()}건`
  badge.classList.remove('hidden')

  let html = ''
  for (const { table, columns, rows, total } of results) {
    const label    = TABLE_LABEL[table] || table
    const dispCols = columns.filter(c => c !== 'id').slice(0, 5)
    const moreText = total > rows.length ? ` (상위 ${rows.length}건 표시)` : ''

    html += `<div class="gs-group">`

    // 그룹 헤더
    html += `<div class="gs-group-header">
      <span class="gs-group-label">${escHtml(label)}</span>
      <span class="gs-group-table">${escHtml(table)}</span>
      <span class="gs-group-count">${total.toLocaleString()}건${escHtml(moreText)}</span>
      <button class="gs-goto-btn" data-table="${escHtml(table)}">이 테이블로 →</button>
    </div>`

    // 컬럼 헤더
    html += `<div class="gs-col-row gs-col-header">`
    for (const col of dispCols) {
      html += `<span class="gs-col-cell gs-col-head">${escHtml(col)}</span>`
    }
    html += `</div>`

    // 결과 행
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]
      html += `<div class="gs-col-row gs-result-row" data-table="${escHtml(table)}" data-row="${i}">`
      for (const col of dispCols) {
        const val = row[col]
        const str = (val === null || val === undefined) ? '' : String(val)
        html += `<span class="gs-col-cell" title="${escHtml(str)}">${highlightQuery(str, query)}</span>`
      }
      html += `</div>`
    }

    html += `</div>`
  }

  body.innerHTML = html

  // "이 테이블로" 버튼
  body.querySelectorAll('.gs-goto-btn').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation()
      closeGlobalSearch()
      await navigateToTable(btn.dataset.table)
    })
  })

  // 결과 행 클릭
  body.querySelectorAll('.gs-result-row').forEach(el => {
    el.addEventListener('click', async () => {
      closeGlobalSearch()
      await navigateToTable(el.dataset.table)
    })
  })
}

/** 검색어를 HTML 안전하게 하이라이트 */
function highlightQuery (str, query) {
  if (!str && str !== 0) return '<span class="val-null">—</span>'
  const s = String(str)
  if (!query) return escHtml(s)

  const lowerS = s.toLowerCase()
  const lowerQ = query.toLowerCase()
  let result = ''
  let pos = 0

  while (pos < s.length) {
    const idx = lowerS.indexOf(lowerQ, pos)
    if (idx === -1) { result += escHtml(s.slice(pos)); break }
    result += escHtml(s.slice(pos, idx))
    result += `<mark class="gs-hl">${escHtml(s.slice(idx, idx + query.length))}</mark>`
    pos = idx + query.length
  }
  return result || escHtml(s)
}

/** 테이블이 속한 탭으로 이동 후 해당 테이블 선택 */
async function navigateToTable (tableName) {
  const tab = TABS.find(t => t.tables.includes(tableName))
  if (!tab) return
  if (currentTabId !== tab.id) {
    await switchTab(tab.id)
  }
  if (currentTable !== tableName) {
    await selectTable(tableName)
  }
}

// ── 이벤트 바인딩 ─────────────────────────────────────

// 탭 바 클릭
elTabBar.addEventListener('click', async e => {
  const tabEl = e.target.closest('[data-tab]')
  if (tabEl) await switchTab(tabEl.dataset.tab)
})

// 사이드바 클릭 (no-data 아이템 제외)
elSidebar.addEventListener('click', async e => {
  const item = e.target.closest('.sidebar-item')
  if (item && item.dataset.table && !item.classList.contains('no-data')) {
    await selectTable(item.dataset.table)
  }
})

// 테이블 헤더 클릭 → 정렬 토글
elDataTable.addEventListener('click', async e => {
  const th = e.target.closest('th[data-col]')
  if (!th) return
  const col = th.dataset.col
  if (currentSortCol === col) {
    currentSortDir = currentSortDir === 'ASC' ? 'DESC' : 'ASC'
    if (currentSortDir === 'ASC') currentSortCol = null   // 두 번 토글 시 해제
  } else {
    currentSortCol = col
    currentSortDir = 'ASC'
  }
  currentPage = 0
  await loadData()
})

$('btn-open').addEventListener('click', onClickOpen)
$('btn-open-2').addEventListener('click', onClickOpen)
elSearchInput.addEventListener('input', onSearchInput)
elBtnClear.addEventListener('click', onClearSearch)

// 날짜 필터 이벤트
elDateFrom.addEventListener('change', async () => {
  currentDateFrom = elDateFrom.value
  // 시작일이 종료일보다 크면 종료일 자동 조정
  if (currentDateTo && currentDateFrom > currentDateTo) {
    currentDateTo    = currentDateFrom
    elDateTo.value   = currentDateFrom
  }
  elDateTo.min = currentDateFrom || elDateTo.getAttribute('data-min') || ''
  _updateDateClearBtn()
  currentPage = 0
  await loadData()
})

elDateTo.addEventListener('change', async () => {
  currentDateTo = elDateTo.value
  // 종료일이 시작일보다 작으면 시작일 자동 조정
  if (currentDateFrom && currentDateTo < currentDateFrom) {
    currentDateFrom  = currentDateTo
    elDateFrom.value = currentDateTo
  }
  elDateFrom.max = currentDateTo || elDateFrom.getAttribute('data-max') || ''
  _updateDateClearBtn()
  currentPage = 0
  await loadData()
})

elDateClearBtn.addEventListener('click', async () => {
  // min/max 속성은 유지하고 값만 초기화
  const minVal = elDateFrom.min
  const maxVal = elDateTo.max
  currentDateFrom  = ''
  currentDateTo    = ''
  elDateFrom.value = ''
  elDateTo.value   = ''
  elDateFrom.max   = maxVal
  elDateTo.min     = minVal
  elDateClearBtn.classList.add('hidden')
  currentPage = 0
  await loadData()
})

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

// 전체 검색 버튼
$('btn-global-search').addEventListener('click', () => openGlobalSearch())

// 전체 검색 패널 내부 이벤트
$('gs-close').addEventListener('click', closeGlobalSearch)
$('gs-overlay').addEventListener('click', closeGlobalSearch)
$('gs-input').addEventListener('input', () => {
  clearTimeout(gsTimer)
  gsTimer = setTimeout(() => runGlobalSearch($('gs-input').value), 300)
})
$('gs-input').addEventListener('keydown', e => {
  if (e.key === 'Escape') { e.stopPropagation(); closeGlobalSearch() }
})

// 단축키: Ctrl+Shift+F / Cmd+Shift+F → 전체 검색 열기/닫기
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'f') {
    e.preventDefault()
    const panel = $('gs-panel')
    if (panel.classList.contains('hidden')) {
      openGlobalSearch()
    } else {
      closeGlobalSearch()
    }
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
