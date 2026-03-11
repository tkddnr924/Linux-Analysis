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
  {
    id:       'ioc',
    label:    '🔗 IoC',
    tables:   ['ioc_list'],
    priority: 'ioc_list',
  },
  {
    id:       'threat_graph',
    label:    '🕸 관계도',
    tables:   ['threat_graph'],
    priority: 'threat_graph',
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
  // IoC
  ioc_list:            'IoC 목록',
  // 위협 관계도
  threat_graph:        '위협 관계도',
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
let currentDateFrom   = ''   // supertimeline 날짜 필터 시작 (YYYY-MM-DD)
let currentDateTo     = ''   // supertimeline 날짜 필터 종료 (YYYY-MM-DD)
let currentColFilters = {}   // 컬럼별 필터 { colName: text, ... }
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
  // DB 교체 시 IoC 캐시 및 그래프 세대 초기화
  iocCache      = null
  iocGraphData  = null
  _graphInitGen = 0

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

  // 가상 테이블: IoC 소스가 하나라도 있으면 ioc_list 활성화
  const IOC_SOURCE_TABLES = [
    'authlog_bruteforce', 'authlog_attack_ip', 'authlog_login',
    'nginx_attack', 'apache2_attack', 'nginx_webshell', 'apache2_webshell', 'syslog_ufw',
  ]
  if (IOC_SOURCE_TABLES.some(t => (tableCountMap.get(t) ?? 0) > 0)) {
    tableCountMap.set('ioc_list', 1)
    tableCountMap.set('threat_graph', 1)
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

  // 탭 전환 시 그래프 인스턴스 정리
  destroyGraph()
  destroySummaryGraph()

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
  currentPage       = 0
  currentSearch     = ''
  currentSortCol    = null
  currentSortDir    = 'ASC'
  currentColFilters = {}
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
  if (name === 'session_timeline') { await loadSessionView();       return }
  // AI 공격자 프로파일은 커스텀 뷰
  if (name === 'attacker_profile') { await loadAttackerView();     return }
  // IoC 목록 커스텀 뷰
  if (name === 'nginx_webshell' || name === 'apache2_webshell') { await loadWebshellView(); return }
  if (name === 'ioc_list') { await loadIoCView(); return }
  // 위협 관계도 커스텀 뷰
  if (name === 'threat_graph') { loadThreatGraphView(); return }

  await loadData()
}

// ── 데이터 로드 ──────────────────────────────────────
// 커스텀 뷰 테이블: 가상 테이블이거나 자체 렌더러가 있어 loadData() 호출 불가
const CUSTOM_VIEW_TABLES = new Set([
  'threat_graph', 'ioc_list', 'session_timeline', 'attacker_profile',
  'nginx_webshell', 'apache2_webshell',
])

async function loadData () {
  if (!currentTable) return
  // 커스텀 뷰(가상 테이블 포함)는 loadData()로 렌더링하지 않음
  // → 검색창 입력, 페이지 버튼, 날짜 필터 등이 그래프/커스텀 뷰를 덮어쓰는 사고 방지
  if (CUSTOM_VIEW_TABLES.has(currentTable)) return
  setStatus('로딩 중…')

  const res = await window.api.getTableData({
    table:      currentTable,
    search:     currentSearch,
    limit:      PAGE_SIZE,
    offset:     currentPage * PAGE_SIZE,
    sortCol:    currentSortCol,
    sortDir:    currentSortDir,
    dateFrom:   currentDateFrom || undefined,
    dateTo:     currentDateTo   || undefined,
    colFilters: Object.keys(currentColFilters).length ? currentColFilters : undefined,
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

  const grandTotal    = (tableCountMap.get(currentTable) ?? 0).toLocaleString()
  const activeColFilters = Object.values(currentColFilters).filter(v => v && v.trim()).length
  const hasFilter     = currentSearch || currentDateFrom || currentDateTo || activeColFilters > 0

  let badge = hasFilter
    ? `${currentTotal.toLocaleString()}건 / ${grandTotal}건 전체`
    : `${grandTotal}건 전체`
  if (activeColFilters > 0) badge += ` · 열 필터 ${activeColFilters}개`
  elTotalBadge.textContent = badge
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
  html += '</tr><tr class="filter-row">'
  for (const col of columns) {
    const val     = currentColFilters[col] || ''
    const hasVal  = val.trim().length > 0
    const inpCls  = hasVal ? ' col-filter active' : ' col-filter'
    html += `<th class="filter-th"><input class="${inpCls.trim()}" data-col="${escHtml(col)}" placeholder="필터…" value="${escHtml(val)}" spellcheck="false"></th>`
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
  currentSearch     = ''
  currentColFilters = {}
  currentPage       = 0
  loadData()
}

// ── 행 상세 모달 ─────────────────────────────────────
function openModal (columns, row) {
  let html = ''
  for (const col of columns) {
    const raw     = row[col]
    const isNull  = raw === null || raw === undefined
    const display = isNull ? 'NULL' : escHtml(String(raw))
    // data-copy 에 원본 값을 저장 (NULL → 빈 문자열, 나머지는 raw 그대로)
    const copyVal = isNull ? '' : escHtml(String(raw))
    html += `<div class="modal-row">
      <div class="modal-col-name">${escHtml(col)}</div>
      <div class="modal-col-val ${isNull ? 'is-null' : ''}">${display}</div>
      <button class="modal-copy-btn" data-copy="${copyVal}" title="클립보드에 복사" tabindex="-1">
        <svg class="copy-icon" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="5" y="5" width="9" height="10" rx="1.5" stroke="currentColor" stroke-width="1.3"/>
          <path d="M11 5V3.5A1.5 1.5 0 0 0 9.5 2h-7A1.5 1.5 0 0 0 1 3.5v7A1.5 1.5 0 0 0 2.5 12H4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
        <svg class="check-icon" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <polyline points="2,8 6,12 14,4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
    </div>`
  }
  elModalBody.innerHTML = html
  elModal.classList.remove('hidden')
}

function closeModal () {
  elModal.classList.add('hidden')
  elModalBody.innerHTML = ''
}

// 모달 내 복사 버튼 클릭 → 클립보드 저장
elModalBody.addEventListener('click', async e => {
  const btn = e.target.closest('.modal-copy-btn')
  if (!btn) return
  const text = btn.dataset.copy ?? ''
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // fallback: execCommand (샌드박스 환경 대응)
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
  // 복사 완료 피드백: 체크 아이콘으로 교체 후 1.5초 뒤 원복
  btn.classList.add('copied')
  setTimeout(() => btn.classList.remove('copied'), 1500)
})

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

// ══════════════════════════════════════════════════════
// ── IoC & 관계 그래프 ──────────────────────────────────
// ══════════════════════════════════════════════════════

/** 위협 태그 메타데이터 */
const IOC_TAG = {
  brute_force:  { label: 'SSH 브루트포스',  cls: 'itag-red',    icon: '🔨', edgeColor: '#f85149' },
  ssh_login:    { label: 'SSH 로그인 성공', cls: 'itag-orange', icon: '🔑', edgeColor: '#ff7b72' },
  ssh_attempt:  { label: 'SSH 접근 시도',  cls: 'itag-green',  icon: '🔌', edgeColor: '#3fb950' },
  web_attack:   { label: '웹 공격',        cls: 'itag-yellow', icon: '🕷',  edgeColor: '#d29922' },
  webshell:     { label: '웹쉘 접근',      cls: 'itag-purple', icon: '💀', edgeColor: '#bc8cff' },
  ufw_block:    { label: '방화벽 차단',    cls: 'itag-gray',   icon: '🛡',  edgeColor: '#6e7681' },
}

/** 출처 테이블 → 설명 매핑 */
const SOURCE_DESC = {
  authlog_bruteforce: { icon: '🔨', text: 'SSH 브루트포스 공격 탐지' },
  authlog_login:      { icon: '🔑', text: 'SSH 로그인 성공 기록' },
  authlog_attack_ip:  { icon: '🔌', text: 'SSH 접근 시도 기록' },
  nginx_attack:       { icon: '🕷', text: 'Nginx 웹 공격 탐지' },
  apache2_attack:     { icon: '🕷', text: 'Apache 웹 공격 탐지' },
  nginx_webshell:     { icon: '💀', text: 'Nginx 웹쉘 접근 탐지' },
  apache2_webshell:   { icon: '💀', text: 'Apache 웹쉘 접근 탐지' },
  syslog_ufw:         { icon: '🛡', text: 'UFW 방화벽 차단 기록' },
}

/** 위협 태그 우선순위로 노드 색상 결정 */
function iocNodeColor (tags) {
  if (tags.includes('webshell'))    return '#bc8cff'
  if (tags.includes('brute_force') && tags.includes('ssh_login')) return '#f85149'
  if (tags.includes('ssh_login'))   return '#ff7b72'
  if (tags.includes('brute_force')) return '#d29922'
  if (tags.includes('web_attack'))  return '#388bfd'
  if (tags.includes('ssh_attempt')) return '#3fb950'
  return '#6e7681'
}

let iocCache        = null   // 캐시된 IoC 데이터 배열
let iocGraphData    = null   // 캐시된 그래프 데이터
let currentGraph    = null   // IoC 상세 패널 미니 ForceGraph
let summaryGraph    = null   // 요약 탭 ForceGraph
let _graphInitGen   = 0      // 요약 그래프 초기화 세대 번호 (race condition 방지)
let iocTypeFilter   = 'ip'   // 'ip' | 'domain'
let iocSearch       = ''
let iocSelectedItem = null

// ── 위협 관계도 뷰 (전체 화면 그래프) ──────────────────
function loadThreatGraphView () {
  destroySummaryGraph()
  elTableTitle.textContent = '위협 관계도'
  elTotalBadge.textContent = ''
  setStatus('')

  elDataTable.innerHTML = `
    <div class="threat-graph-page">
      <div class="summary-graph-legend" id="summary-graph-legend"></div>
      <div class="summary-graph-wrap threat-graph-canvas" id="summary-graph-wrap">
        <div class="summary-graph-loading">그래프 데이터 로딩 중…</div>
      </div>
    </div>`

  // requestAnimationFrame: DOM 삽입 후 브라우저가 레이아웃을 한 번 계산하도록
  // → getBoundingClientRect()가 올바른 캔버스 크기를 반환하게 됨
  requestAnimationFrame(() => _initSummaryGraph())
}

// ── IoC 진입점 ────────────────────────────────────────
async function loadIoCView () {
  destroyGraph()
  elTableTitle.textContent = 'IoC 목록'
  elTotalBadge.textContent = '…'
  setStatus('IoC 데이터 로딩 중…')

  if (!iocCache) {
    iocCache = await window.api.getIoC()
  }
  elTotalBadge.textContent = `${iocCache.length}개 IP`
  setStatus('')
  iocSelectedItem = null
  renderIoCContainer()
}

// ── IoC 컨테이너 ──────────────────────────────────────
function renderIoCContainer () {
  const ipCount = iocCache ? iocCache.length : 0

  elDataTable.innerHTML = `
    <div class="ioc-wrap">
      <div class="ioc-toolbar">
        <div class="ioc-type-tabs">
          <button class="ioc-ttab ${iocTypeFilter === 'ip'     ? 'active' : ''}" data-type="ip">🌐 IP <span class="ioc-cnt">${ipCount}</span></button>
          <button class="ioc-ttab ${iocTypeFilter === 'domain' ? 'active' : ''}" data-type="domain">🔤 Domain <span class="ioc-cnt">0</span></button>
        </div>
        <div class="ioc-search-wrap">
          <span class="ioc-search-icon">🔍</span>
          <input class="ioc-search" id="ioc-search-input"
            placeholder="IP · 위협 유형 검색…"
            value="${escHtml(iocSearch)}" />
        </div>
      </div>
      <div class="ioc-main">
        <div class="ioc-list-pane" id="ioc-list-pane"></div>
        <div class="ioc-detail-pane hidden" id="ioc-detail-pane"></div>
      </div>
    </div>`

  elDataTable.querySelectorAll('.ioc-ttab').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.type === iocTypeFilter) return
      iocTypeFilter = btn.dataset.type
      iocSelectedItem = null
      destroyGraph()
      elDataTable.querySelectorAll('.ioc-ttab').forEach(b =>
        b.classList.toggle('active', b.dataset.type === iocTypeFilter))
      document.getElementById('ioc-detail-pane')?.classList.add('hidden')
      renderIoCList()
    })
  })

  document.getElementById('ioc-search-input')?.addEventListener('input', e => {
    iocSearch = e.target.value.trim().toLowerCase()
    renderIoCList()
  })

  renderIoCList()
}

// ── IoC 목록 테이블 ───────────────────────────────────
function renderIoCList () {
  const pane = document.getElementById('ioc-list-pane')
  if (!pane) return

  if (iocTypeFilter === 'domain') {
    pane.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">🔤</div>
      <div>Domain IoC는 현재 지원되지 않습니다</div>
      <div class="empty-state-sub">수집된 로그에서 도메인 데이터가 없습니다</div>
    </div>`
    return
  }

  if (!iocCache || !iocCache.length) {
    pane.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><div>수집된 IoC IP가 없습니다</div></div>`
    return
  }

  const filtered = iocCache.filter(d => {
    if (!iocSearch) return true
    const tags = (d.threat_tags || []).map(t => IOC_TAG[t]?.label || t).join(' ')
    return d.ip.toLowerCase().includes(iocSearch) || tags.toLowerCase().includes(iocSearch)
  })

  if (!filtered.length) {
    pane.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div>
      <div>"${escHtml(iocSearch)}" 검색 결과 없음</div></div>`
    return
  }

  const rows = filtered.map(d => {
    const priv = isPrivateIP(d.ip)
    const badge = priv
      ? `<span class="ioc-badge ioc-priv">🏠 사설</span>`
      : `<span class="ioc-badge ioc-pub">🌐 공인</span>`
    const tags = (d.threat_tags || []).map(t => {
      const m = IOC_TAG[t] || { label: t, cls: 'itag-gray', icon: '•' }
      return `<span class="ioc-tag ${m.cls}">${m.icon} ${m.label}</span>`
    }).join('')
    const active = iocSelectedItem?.ip === d.ip ? ' active' : ''
    return `<tr class="ioc-row${active}" data-ip="${escHtml(d.ip)}">
      <td class="ioc-ip-cell">${escHtml(d.ip)}</td>
      <td>${badge}</td>
      <td class="ioc-tags-cell">${tags || '<span class="val-null">—</span>'}</td>
    </tr>`
  }).join('')

  pane.innerHTML = `
    <table class="ioc-table">
      <colgroup>
        <col style="width:140px"><col style="width:76px"><col>
      </colgroup>
      <thead><tr>
        <th>IP 주소</th><th>구분</th><th>위협 유형</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`

  pane.querySelectorAll('.ioc-row').forEach(tr => {
    tr.addEventListener('click', () => {
      const item = filtered.find(d => d.ip === tr.dataset.ip)
      if (!item) return
      iocSelectedItem = item
      pane.querySelectorAll('.ioc-row').forEach(r => r.classList.remove('active'))
      tr.classList.add('active')
      renderIoCDetail(item)
    })
  })
}

// ── IoC 상세 패널 ─────────────────────────────────────
function renderIoCDetail (item) {
  const pane = document.getElementById('ioc-detail-pane')
  if (!pane) return
  pane.classList.remove('hidden')
  destroyGraph()

  const priv = isPrivateIP(item.ip)
  const tags = (item.threat_tags || []).map(t => {
    const m = IOC_TAG[t] || { label: t, cls: 'itag-gray', icon: '•' }
    return `<span class="ioc-tag ${m.cls}">${m.icon} ${m.label}</span>`
  }).join('')

  const srcItems = (item.sources || []).map(s => {
    const d = SOURCE_DESC[s] || { icon: '📋', text: s }
    return `<div class="ioc-source-item">
      <span class="ioc-source-icon">${d.icon}</span>
      <div class="ioc-source-info">
        <div class="ioc-source-desc">${escHtml(d.text)}</div>
        <code class="ioc-source-table">${escHtml(s)}</code>
      </div>
    </div>`
  }).join('')

  pane.innerHTML = `
    <div class="ioc-detail-header">
      <div class="ioc-detail-hinfo">
        <div class="gd-title">${escHtml(item.ip)}</div>
        <span class="ioc-badge ${priv ? 'ioc-priv' : 'ioc-pub'}">${priv ? '🏠 사설 IP' : '🌐 공인 IP'}</span>
      </div>
      <button class="ioc-detail-close" id="ioc-detail-close">✕</button>
    </div>
    <div class="ioc-detail-scroll">
      <div class="gd-section">
        <div class="gd-sec-title">위협 유형</div>
        <div class="gd-tags">${tags || '<span class="val-null">탐지된 위협 없음</span>'}</div>
      </div>
      <div class="gd-section">
        <div class="gd-sec-title">탐지 출처 — 어디 서버에서 어떤 이유로</div>
        <div class="ioc-source-list">${srcItems || '<span class="val-null">—</span>'}</div>
      </div>
      <button class="gd-search-btn" id="ioc-detail-search" data-ip="${escHtml(item.ip)}">
        🔍 전역 검색에서 찾기
      </button>
      <div class="gd-section">
        <div class="gd-sec-title">관계 그래프</div>
        <div class="ioc-mini-graph" id="ioc-mini-graph"></div>
      </div>
    </div>`

  document.getElementById('ioc-detail-close')?.addEventListener('click', () => {
    pane.classList.add('hidden')
    iocSelectedItem = null
    destroyGraph()
    document.getElementById('ioc-list-pane')
      ?.querySelectorAll('.ioc-row').forEach(r => r.classList.remove('active'))
  })

  document.getElementById('ioc-detail-search')?.addEventListener('click', e => {
    elSearchInput.value = e.currentTarget.dataset.ip
    onSearchInput()
  })

  _initMiniGraph(item)
}

// ── 미니 그래프 (상세 패널용) ─────────────────────────
async function _initMiniGraph (item) {
  const wrap = document.getElementById('ioc-mini-graph')
  if (!wrap) return

  if (!iocGraphData) {
    iocGraphData = await window.api.getGraphData()
  }
  const serverNode  = iocGraphData?.nodes?.find(n => n.type === 'server')
  const serverLabel = serverNode?.label || '분석 서버'

  // server → [공격유형 노드] → ip 구조
  const atkNodes = (item.threat_tags || []).map(tag => ({
    id: `atk:${tag}`, type: 'attack', label: tag, threat_tags: [tag], sources: [],
  }))
  const nodes = [
    { id: 'server', type: 'server', label: serverLabel, threat_tags: [], sources: [] },
    ...atkNodes,
    { id: `ip:${item.ip}`, type: 'ip', label: item.ip,
      threat_tags: item.threat_tags, sources: item.sources },
  ]
  const edges = [
    ...(item.threat_tags || []).map(tag => ({ source: 'server',      target: `atk:${tag}`,      type: tag })),
    ...(item.threat_tags || []).map(tag => ({ source: `atk:${tag}`, target: `ip:${item.ip}`, type: tag })),
  ]

  currentGraph = new ForceGraph(wrap, { nodes, edges }, { compact: true, onSelect: () => {} })
}


// ── 웹쉘 뷰 ──────────────────────────────────────────
let _wsCache    = null   // Map<filePath, {file_name,file_path,vhost,suspicion_score,suspicion_flags,ips:[]}>
let _wsSelected = null   // 현재 선택된 file_path

async function loadWebshellView () {
  destroyGraph()
  elTableTitle.textContent = '웹쉘 탐지'
  elTotalBadge.textContent = '…'
  setStatus('웹쉘 데이터 로딩 중…')

  const res = await window.api.getTableData({
    table: currentTable, page: 1, pageSize: 9999,
    search: '', sortCol: '', sortDir: 'ASC',
  })

  setStatus('')
  if (!res || res.error) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">⚠️</div>
      <div>${escHtml(res?.error || '데이터 로드 실패')}</div></div>`
    return
  }

  // ── file_path 기준 그룹화 ────────────────────────────
  const groupMap = new Map()
  for (const row of (res.rows || [])) {
    const fp = row['file_path'] || ''
    if (!groupMap.has(fp)) {
      groupMap.set(fp, {
        file_name:       row['file_name']       || fp,
        file_path:       fp,
        vhost:           row['vhost']           || '',
        suspicion_score: row['suspicion_score'] || 0,
        suspicion_flags: row['suspicion_flags'] || '',
        ips: [],
      })
    }
    const g = groupMap.get(fp)
    if ((row['suspicion_score'] || 0) > g.suspicion_score) {
      g.suspicion_score = row['suspicion_score'] || 0
      g.suspicion_flags = row['suspicion_flags'] || ''
    }
    g.ips.push({
      src_ip:       row['src_ip']       || '',
      access_count: row['access_count'] || 0,
      first_seen:   row['first_seen']   || '',
      last_seen:    row['last_seen']    || '',
    })
  }

  elTotalBadge.textContent = `${groupMap.size}개 파일`
  _wsCache    = groupMap
  _wsSelected = null
  _renderWsContainer()
}

function _renderWsContainer () {
  if (!_wsCache || !_wsCache.size) {
    elDataTable.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">✅</div>
      <div>탐지된 웹쉘이 없습니다</div></div>`
    return
  }
  elDataTable.innerHTML = `
    <div class="ws-wrap">
      <div class="ws-list-pane" id="ws-list-pane"></div>
      <div class="ws-detail-pane hidden" id="ws-detail-pane"></div>
    </div>`
  _renderWsList()
}

function _renderWsList () {
  const pane = document.getElementById('ws-list-pane')
  if (!pane || !_wsCache) return

  const sorted = [..._wsCache.values()]
    .sort((a, b) => b.suspicion_score - a.suspicion_score)

  const rows = sorted.map(g => {
    const active = _wsSelected === g.file_path ? ' active' : ''
    const sc     = g.suspicion_score
    const scCls  = sc >= 5 ? 'ws-score-h' : sc >= 3 ? 'ws-score-m' : 'ws-score-l'
    const flags  = (g.suspicion_flags || '').split(',').map(f => f.trim()).filter(Boolean)
    const fHtml  = flags.map(f => `<span class="ws-flag">${escHtml(f)}</span>`).join('')
    const ipCnt  = g.ips.length
    return `<tr class="ws-row${active}" data-path="${escHtml(g.file_path)}">
      <td class="ws-name-cell">
        <div class="ws-name-row">
          <span class="ws-icon">💀</span>
          <span class="ws-name">${escHtml(g.file_name)}</span>
          <span class="ws-score ${scCls}">${sc}</span>
        </div>
        <div class="ws-flags">${fHtml}</div>
      </td>
      <td class="ws-path-cell">
        <span class="ws-path" title="${escHtml(g.file_path)}">${escHtml(g.file_path)}</span>
        <span class="ws-ip-cnt">${ipCnt}개 IP</span>
      </td>
    </tr>`
  }).join('')

  pane.innerHTML = `
    <table class="ws-table">
      <colgroup><col style="width:50%"><col></colgroup>
      <thead><tr>
        <th>파일명</th>
        <th>경로</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`

  pane.querySelectorAll('.ws-row').forEach(tr => {
    tr.addEventListener('click', () => {
      _wsSelected = tr.dataset.path
      pane.querySelectorAll('.ws-row').forEach(r => r.classList.remove('active'))
      tr.classList.add('active')
      _renderWsDetail(_wsCache.get(_wsSelected))
    })
  })
}

function _renderWsDetail (g) {
  const pane = document.getElementById('ws-detail-pane')
  if (!pane || !g) return
  pane.classList.remove('hidden')

  const totalAcc = g.ips.reduce((s, ip) => s + (ip.access_count || 0), 0)
  const flags    = (g.suspicion_flags || '').split(',').map(f => f.trim()).filter(Boolean)
  const fHtml    = flags.map(f => `<span class="ws-flag">${escHtml(f)}</span>`).join('')
  const sc       = g.suspicion_score
  const scCls    = sc >= 5 ? 'ws-score-h' : sc >= 3 ? 'ws-score-m' : 'ws-score-l'

  const ipRows = [...g.ips]
    .sort((a, b) => (b.access_count || 0) - (a.access_count || 0))
    .map(ip => `<tr>
      <td class="ws-d-ip">${escHtml(ip.src_ip)}</td>
      <td class="ws-d-cnt">${ip.access_count || 0}</td>
      <td class="ws-d-time" title="${escHtml(ip.first_seen)}">${escHtml((ip.first_seen || '').slice(0, 16) || '—')}</td>
      <td class="ws-d-time" title="${escHtml(ip.last_seen)}">${escHtml((ip.last_seen  || '').slice(0, 16) || '—')}</td>
    </tr>`).join('')

  pane.innerHTML = `
    <div class="ws-d-header">
      <div class="ws-d-hinfo">
        <span class="ws-icon">💀</span>
        <div>
          <div class="ws-d-name">${escHtml(g.file_name)}</div>
          <div class="ws-d-path">${escHtml(g.file_path)}</div>
        </div>
      </div>
      <button class="ws-d-close" id="ws-d-close">✕</button>
    </div>
    <div class="ws-d-meta">
      <span class="ws-score ${scCls}">위험도 ${sc}</span>
      ${fHtml}
    </div>
    <div class="ws-d-stats">IP ${g.ips.length}개 &middot; 총 접근 ${totalAcc}회</div>
    <div class="ws-d-body">
      <table class="ws-d-table">
        <thead><tr>
          <th>IP 주소</th><th>횟수</th><th>최초 접근</th><th>마지막 접근</th>
        </tr></thead>
        <tbody>${ipRows}</tbody>
      </table>
    </div>`

  document.getElementById('ws-d-close')?.addEventListener('click', () => {
    pane.classList.add('hidden')
    _wsSelected = null
    document.getElementById('ws-list-pane')
      ?.querySelectorAll('.ws-row').forEach(r => r.classList.remove('active'))
  })
}

// ── 요약 탭 전체 그래프 ───────────────────────────────
async function _initSummaryGraph () {
  // 세대 번호 발급 — await 이후 더 새로운 호출이 있었으면 중단
  const gen = ++_graphInitGen
  destroySummaryGraph()
  const wrap = document.getElementById('summary-graph-wrap')
  if (!wrap) return

  try {
    if (!iocGraphData) {
      iocGraphData = await window.api.getGraphData()
    }
    // await 이후: 이미 더 새 호출이 시작됐거나 wrap이 교체된 경우 중단
    if (gen !== _graphInitGen) return
    if (document.getElementById('summary-graph-wrap') !== wrap) return

    let { nodes, edges } = (iocGraphData || { nodes: [], edges: [] })
    const MAX = 80
    const ipNodes     = nodes.filter(n => n.type === 'ip')
    const subnetNodes = nodes.filter(n => n.type === 'subnet')
    const atkNodes    = nodes.filter(n => n.type === 'attack')

    if (ipNodes.length === 0) {
      wrap.innerHTML = `<div class="summary-graph-empty">위협 IP 데이터 없음</div>`
      return
    }
    if (ipNodes.length > MAX) {
      const score = t =>
        (t.includes('webshell') ? 6 : 0) +
        (t.includes('brute_force') ? 3 : 0) +
        (t.includes('ssh_login') ? 2 : 0) +
        t.length
      const ranked = [...ipNodes].sort((a, b) =>
        score(b.threat_tags || []) - score(a.threat_tags || [])
      ).slice(0, MAX)
      const allowedIpIds = new Set(ranked.map(n => n.id))
      // 구조 노드(server, atk, subnet)는 항상 유지
      const allowed = new Set([
        'server',
        ...allowedIpIds,
        ...atkNodes.map(n => n.id),
        ...subnetNodes.map(n => n.id),
      ])
      nodes = nodes.filter(n => allowed.has(n.id))
      edges = edges.filter(e => allowed.has(e.source) && allowed.has(e.target))
    }

    wrap.innerHTML = ''  // 로딩 텍스트 지움

    // 범례 렌더링
    const legendEl = document.getElementById('summary-graph-legend')
    if (legendEl) {
      legendEl.innerHTML =
        Object.entries(IOC_TAG).map(([, m]) =>
          `<span class="gl-item"><span class="gl-dot" style="background:${m.edgeColor}"></span>${m.label}</span>`
        ).join('') +
        `<span class="gl-sep"></span>` +
        `<span class="gl-item"><span class="gl-node-dot" style="background:#388bfd"></span>분석 서버</span>` +
        `<span class="gl-item">⚡ 공격 유형 노드</span>` +
        `<span class="gl-item">📡 /24 서브넷 그룹</span>` +
        `<span class="gl-item gl-hint">스크롤: 줌 · 드래그: 이동 · 클릭: 상세</span>`

      if (ipNodes.length > MAX) {
        legendEl.insertAdjacentHTML('beforeend',
          `<span class="graph-cap-banner">위협 점수 상위 ${MAX}개 IP 표시</span>`)
      }
    }

    summaryGraph = new ForceGraph(wrap, { nodes, edges }, {
      compact: false,
      onSelect: node => {
        if (!node || node.type === 'server' || node.type === 'subnet' || node.type === 'attack') return
        navigateToTable('ioc_list').then(() => {
          setTimeout(() => {
            document.querySelectorAll('.ioc-row').forEach(r => {
              if (r.dataset.ip === node.label) r.click()
            })
          }, 350)
        })
      },
    })
  } catch (err) {
    console.error('summary graph error:', err)
    const wrap2 = document.getElementById('summary-graph-wrap')
    if (wrap2) wrap2.innerHTML = `<div class="summary-graph-empty">그래프 로딩 실패</div>`
  }
}

// ── 그래프 정리 ───────────────────────────────────────
function destroyGraph () {
  if (currentGraph) { currentGraph.destroy(); currentGraph = null }
}
function destroySummaryGraph () {
  if (summaryGraph) { summaryGraph.destroy(); summaryGraph = null }
}

// ── Force-Directed Graph Engine ───────────────────────
class ForceGraph {
  static EDGE_COLOR  = Object.fromEntries(Object.entries(IOC_TAG).map(([k, v]) => [k, v.edgeColor]))
  static EDGE_LABEL  = Object.fromEntries(Object.entries(IOC_TAG).map(([k, v]) => [k, v.label]))

  constructor (container, data, { onSelect, compact = false } = {}) {
    this.container = container
    this.onSelect  = onSelect || (() => {})
    this.compact   = compact  // compact=true: 미니 그래프 모드

    // Canvas + tooltip overlay
    this.canvas  = document.createElement('canvas')
    this.canvas.style.cssText = 'position:absolute;inset:0;cursor:grab'
    this.tooltip = document.createElement('div')
    this.tooltip.className = 'graph-tooltip'
    container.style.position = 'relative'
    container.appendChild(this.canvas)
    container.appendChild(this.tooltip)

    // compact 모드: 노드 크기 축소
    // 계층: server(중심) → attack(1차) → subnet(2차) → ip(외부)
    const srvR    = compact ? 18 : 26
    const atkR    = compact ? 13 : 18   // 공격 유형 중간 노드
    const subnetR = compact ? 12 : 16   // 서브넷 그룹 노드
    const ipR     = compact ?  9 : 12   // IP 노드 (가장 바깥)

    // Process nodes — compute edge group indices for parallel edge curves
    this.nodes = data.nodes.map(n => ({
      ...n,
      color: n.type === 'server' ? '#388bfd'
           : n.type === 'attack' ? (IOC_TAG[n.label]?.edgeColor || '#6e7681')
           : iocNodeColor(n.threat_tags || []),
      is_private: n.type === 'ip' ? isPrivateIP(n.label) : false,
      radius: n.type === 'server' ? srvR
            : n.type === 'attack' ? atkR
            : n.type === 'subnet' ? subnetR
            : ipR,
      x: 0, y: 0, vx: 0, vy: 0, fx: 0, fy: 0,
      fixed: n.type === 'server',
    }))
    this.nodeById  = new Map(this.nodes.map(n => [n.id, n]))

    // Assign group index for parallel edges (same src+tgt pair)
    const groupMap = new Map()
    for (const e of data.edges) {
      const key = [e.source, e.target].sort().join('||')
      if (!groupMap.has(key)) groupMap.set(key, [])
      groupMap.get(key).push(e)
    }
    this.edges = data.edges.map(e => {
      const key   = [e.source, e.target].sort().join('||')
      const group = groupMap.get(key)
      return { ...e, _gi: group.indexOf(e), _gs: group.length,
        sourceNode: this.nodeById.get(e.source),
        targetNode: this.nodeById.get(e.target) }
    })

    // Per-node edge list for hit highlight
    this.nodeEdges = new Map(this.nodes.map(n => [n.id, []]))
    this.edges.forEach(e => {
      this.nodeEdges.get(e.source)?.push(e)
      this.nodeEdges.get(e.target)?.push(e)
    })

    // State
    this.selected   = null
    this.hovered    = null
    this.dragged    = null
    this.pan        = { x: 0, y: 0 }
    this.scale      = 1
    this.isPanning  = false
    this.panStart   = { x: 0, y: 0 }
    this.alpha      = 1
    this.destroyed  = false

    this._dpr = window.devicePixelRatio || 1
    this.W    = 0
    this.H    = 0

    this._userInteracted = false  // 사용자가 직접 pan/zoom 했는지 여부

    this._resizeObs = new ResizeObserver(() => this._resize())
    this._resizeObs.observe(container)
    this._resize()
    this._initPositions()
    // 초기 배치 후 즉시 auto-fit: 모든 노드가 캔버스에 맞게 보이도록
    if (this.W > 0 && this.H > 0) this._autoFit()
    this._bindEvents()
    this._startLoop()
  }

  // ── Layout ─────────────────────────────────────────
  _resize () {
    const dpr  = window.devicePixelRatio || 1
    const rect = this.container.getBoundingClientRect()
    this.W = rect.width; this.H = rect.height
    this.canvas.width  = rect.width  * dpr
    this.canvas.height = rect.height * dpr
    this.canvas.style.width  = rect.width  + 'px'
    this.canvas.style.height = rect.height + 'px'
    this._dpr  = dpr
    this.alpha = Math.max(this.alpha, 0.3)
  }

  _initPositions () {
    const cx = this.W / 2 || 400, cy = this.H / 2 || 300
    // safeR: 컨테이너 반경의 68% — 초기 배치를 화면 중앙에 촘촘히 모음 (0.80→0.68)
    const safeR = Math.min((this.W || 800) / 2, (this.H || 600) / 2) * 0.68

    const server = this.nodes.find(n => n.type === 'server')
    if (server) { server.x = cx; server.y = cy }

    const atkNodes    = this.nodes.filter(n => n.type === 'attack')
    const subnetNodes = this.nodes.filter(n => n.type === 'subnet')
    const ipNodes     = this.nodes.filter(n => n.type === 'ip')

    if (atkNodes.length === 0) {
      // 공격 유형 노드 없음 — 단순 원형 배치
      const others = this.nodes.filter(n => n.type !== 'server')
      const r = safeR * 0.68
      others.forEach((n, i) => {
        const a = (2 * Math.PI * i) / Math.max(others.length, 1) - Math.PI / 2
        n.x = cx + r * Math.cos(a) + (Math.random() - 0.5) * 50
        n.y = cy + r * Math.sin(a) + (Math.random() - 0.5) * 50
      })
      return
    }

    // ① atk 노드 → 1단 링 (중심 가까이)
    const rAtk = safeR * 0.22
    const atkAngleMap = new Map()
    atkNodes.forEach((n, i) => {
      const a = (2 * Math.PI * i) / atkNodes.length - Math.PI / 2
      n.x = cx + rAtk * Math.cos(a)
      n.y = cy + rAtk * Math.sin(a)
      atkAngleMap.set(n.id, a)
    })

    // ② subnet 노드 → 2단 링 (연결된 atk 방향으로 클러스터)
    const rSub = safeR * 0.52
    const subnetAngleMap = new Map()
    subnetNodes.forEach((n, i) => {
      // 이 서브넷으로 들어오는 atk→subnet 엣지의 source 탐색
      const pEdge = this.edges.find(e =>
        e.target === n.id && this.nodeById.get(e.source)?.type === 'attack'
      )
      const baseA = pEdge && atkAngleMap.has(pEdge.source)
        ? atkAngleMap.get(pEdge.source)
        : (2 * Math.PI * i) / Math.max(subnetNodes.length, 1) - Math.PI / 2

      n.x = cx + rSub * Math.cos(baseA) + (Math.random() - 0.5) * 16
      n.y = cy + rSub * Math.sin(baseA) + (Math.random() - 0.5) * 16
      subnetAngleMap.set(n.id, baseA)
    })

    // ③ ip 노드 → 3단 링 (부모 subnet 또는 atk 방향으로 클러스터)
    // safeR * 0.88 → 컨테이너 안에 완전히 들어오는 최외각 링
    const rIp = safeR * 0.88
    const jitterIp = this.compact ? 12 : 24
    ipNodes.forEach((n, i) => {
      // 이 IP로 들어오는 엣지 (subnet→ip 또는 atk→ip)
      const pEdge = this.edges.find(e => e.target === n.id)
      const pId   = pEdge?.source || null
      const pType = pId ? this.nodeById.get(pId)?.type : null

      let baseA
      if (pType === 'subnet' && subnetAngleMap.has(pId))
        baseA = subnetAngleMap.get(pId)
      else if (pType === 'attack' && atkAngleMap.has(pId))
        baseA = atkAngleMap.get(pId)
      else
        baseA = (2 * Math.PI * i) / Math.max(ipNodes.length, 1) - Math.PI / 2

      n.x = cx + rIp * Math.cos(baseA) + (Math.random() - 0.5) * jitterIp
      n.y = cy + rIp * Math.sin(baseA) + (Math.random() - 0.5) * jitterIp
    })
  }

  // ── Physics ─────────────────────────────────────────
  _tick () {
    if (this.alpha < 0.001) return
    const REP  = this.compact ? 2000 : 3000   // 반발력 ↓ (5000→3000)
    const K    = this.compact ? 0.06  : 0.055  // 스프링 강성 ↑ (0.035→0.055)
    const LEN  = this.compact ? 80    : 120    // 자연 길이 ↓ (150→120)
    const DAMP = 0.78

    this.nodes.forEach(n => { n.fx = 0; n.fy = 0 })

    // Coulomb repulsion
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const a = this.nodes[i], b = this.nodes[j]
        const dx = (b.x - a.x) || 0.1, dy = (b.y - a.y) || 0.1
        const d2 = Math.max(dx * dx + dy * dy, 1)
        const d  = Math.sqrt(d2)
        const f  = REP / d2, fx = f * dx / d, fy = f * dy / d
        if (!a.fixed) { a.fx -= fx; a.fy -= fy }
        if (!b.fixed) { b.fx += fx; b.fy += fy }
      }
    }

    // Hooke spring (노드 타입 쌍별 자연 길이 조정)
    for (const e of this.edges) {
      if (!e.sourceNode || !e.targetNode) continue
      const a = e.sourceNode, b = e.targetNode
      const dx = b.x - a.x, dy = b.y - a.y
      const d  = Math.sqrt(dx * dx + dy * dy) + 0.01

      // server → atk → subnet → ip 계층 스프링
      const typePair = [a.type, b.type].sort().join('-')
      let edgeLen = LEN
      if      (typePair === 'attack-server')  edgeLen = LEN * 0.55  // server ↔ atk
      else if (typePair === 'attack-subnet')  edgeLen = LEN * 0.55  // atk ↔ subnet
      else if (typePair === 'attack-ip')      edgeLen = LEN * 0.70  // atk ↔ ip (직접)
      else if (typePair === 'ip-subnet')      edgeLen = LEN * 0.38  // subnet ↔ ip (짧게)

      const f  = K * (d - edgeLen), fx = f * dx / d, fy = f * dy / d
      if (!a.fixed) { a.fx += fx; a.fy += fy }
      if (!b.fixed) { b.fx -= fx; b.fy -= fy }
    }

    // Centre gravity — 컨테이너가 아직 0×0이면 폴백 중심 사용
    const cx = (this.W || 800) / 2, cy = (this.H || 600) / 2
    this.nodes.forEach(n => {
      if (n.fixed) return
      n.fx += (cx - n.x) * 0.02   // gravity ↑ (0.01→0.02)
      n.fy += (cy - n.y) * 0.02
    })

    // Integrate
    this.nodes.forEach(n => {
      if (n.fixed || n === this.dragged) return
      n.vx = (n.vx + n.fx) * DAMP
      n.vy = (n.vy + n.fy) * DAMP
      n.x += n.vx * this.alpha
      n.y += n.vy * this.alpha
    })
    this.alpha *= 0.993
  }

  // ── Rendering ───────────────────────────────────────
  _draw () {
    const ctx = this.canvas.getContext('2d')
    const dpr = this._dpr
    ctx.save()
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height)
    ctx.scale(dpr, dpr)
    ctx.translate(this.pan.x, this.pan.y)
    ctx.scale(this.scale, this.scale)

    // ── Edges ──
    for (const e of this.edges) {
      const a = e.sourceNode, b = e.targetNode
      if (!a || !b) continue
      const isMember = e.type === 'member'
      const hl  = this.selected && (e.sourceNode === this.selected || e.targetNode === this.selected)
      const dim = !!this.selected && !hl
      const col = isMember ? '#4d5562' : (ForceGraph.EDGE_COLOR[e.type] || '#555')

      // Bezier offset for parallel edges
      const dx = b.x - a.x, dy = b.y - a.y
      const len = Math.sqrt(dx * dx + dy * dy) + 0.01
      const nx = -dy / len, ny = dx / len
      const offset = (e._gi - (e._gs - 1) / 2) * 22
      const cpx = (a.x + b.x) / 2 + nx * offset
      const cpy = (a.y + b.y) / 2 + ny * offset

      ctx.beginPath()
      ctx.moveTo(a.x, a.y)
      ctx.quadraticCurveTo(cpx, cpy, b.x, b.y)
      ctx.strokeStyle = col
      ctx.lineWidth   = hl ? 2.2 : (isMember ? 0.7 : 1.2)
      ctx.globalAlpha = dim ? 0.05 : (hl ? 0.90 : (isMember ? 0.22 : 0.42))
      ctx.stroke()

      // 엣지 레이블: 공격 유형 중간 노드가 레이블 역할을 하므로
      // member 엣지·구조 노드(server/attack) 인접 엣지는 레이블 생략
      const srcType = a.type, tgtType = b.type
      const skipLabel = isMember
        || srcType === 'server' || tgtType === 'server'
        || srcType === 'attack' || tgtType === 'attack'
      if (!dim && !skipLabel) {
        const lx = (a.x + b.x) / 4 + cpx / 2
        const ly = (a.y + b.y) / 4 + cpy / 2
        const fs = Math.max(7, Math.min(10, 10 / this.scale))
        ctx.font         = `${fs}px Inter, sans-serif`
        ctx.fillStyle    = col
        ctx.globalAlpha  = hl ? 0.9 : 0.35
        ctx.textAlign    = 'center'
        ctx.textBaseline = 'bottom'
        ctx.fillText(ForceGraph.EDGE_LABEL[e.type] || e.type, lx, ly - 2)
      }
    }
    ctx.globalAlpha = 1

    // ── Nodes ──
    for (const n of this.nodes) {
      const isSel  = n === this.selected
      const isHov  = n === this.hovered
      const connected = this.selected && this.nodeEdges.get(n.id)?.some(
        e => e.sourceNode === this.selected || e.targetNode === this.selected
      )
      const dim = !!this.selected && !isSel && !connected

      ctx.globalAlpha = dim ? 0.15 : 1

      // Glow ring
      if (isSel || isHov) {
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.radius + 8, 0, Math.PI * 2)
        ctx.fillStyle = n.color + '28'
        ctx.fill()
      }

      // Circle
      ctx.beginPath()
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2)
      ctx.fillStyle   = n.color
      ctx.globalAlpha = dim ? 0.15 : (n.type === 'attack' ? 0.92 : 1)
      ctx.fill()
      ctx.strokeStyle = isSel ? '#ffffff'
        : n.type === 'attack' ? 'rgba(255,255,255,0.55)'
        : 'rgba(255,255,255,0.22)'
      ctx.lineWidth   = isSel ? 2.5 : (n.type === 'attack' ? 1.8 : 1)
      ctx.globalAlpha = dim ? 0.15 : 1
      ctx.stroke()

      // Icon
      const iconSz = n.type === 'server' ? 15 : (n.type === 'attack' ? 11 : 9)
      ctx.font          = `${iconSz}px sans-serif`
      ctx.textAlign     = 'center'
      ctx.textBaseline  = 'middle'
      ctx.fillStyle     = 'rgba(255,255,255,0.92)'
      let nodeIcon
      if      (n.type === 'server') nodeIcon = '🖥'
      else if (n.type === 'attack') nodeIcon = IOC_TAG[n.label]?.icon || '⚡'
      else if (n.type === 'subnet') nodeIcon = '📡'
      else                          nodeIcon = n.is_private ? '🏠' : '🌐'
      ctx.fillText(nodeIcon, n.x, n.y + 1)

      // Label below
      const ls = Math.max(8, Math.min(11, 10 / this.scale))
      ctx.font          = `${ls}px "SF Mono", "Fira Code", monospace`
      ctx.textAlign     = 'center'
      ctx.textBaseline  = 'top'
      ctx.globalAlpha   = dim ? 0.12 : 0.88
      // 공격 유형 노드: 태그 키 대신 한글 이름 표시
      const displayLabel = n.type === 'attack'
        ? (IOC_TAG[n.label]?.label || n.label)
        : n.label
      ctx.fillStyle = n.type === 'attack' ? (n.color + 'ee') : '#c9d1d9'
      ctx.fillText(displayLabel, n.x, n.y + n.radius + 4)

      // 서브넷 노드: IP 개수 표시
      if (n.type === 'subnet' && n.ip_count) {
        const ls2 = Math.max(7, Math.min(9, 8 / this.scale))
        ctx.font      = `${ls2}px Inter, sans-serif`
        ctx.fillStyle = '#8b949e'
        ctx.fillText(`×${n.ip_count} IPs`, n.x, n.y + n.radius + 4 + ls + 2)
      }

      ctx.globalAlpha = 1
    }
    ctx.restore()
  }

  // ── Coordinate transforms ────────────────────────────
  _toGraph (clientX, clientY) {
    const rect = this.canvas.getBoundingClientRect()
    return {
      x: (clientX - rect.left - this.pan.x) / this.scale,
      y: (clientY - rect.top  - this.pan.y) / this.scale,
    }
  }

  _hitTest (gx, gy) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i]
      const dx = n.x - gx, dy = n.y - gy
      if (dx * dx + dy * dy <= (n.radius + 5) ** 2) return n
    }
    return null
  }

  // ── Public: select node by id ────────────────────────
  selectNodeById (id) {
    const n = this.nodeById.get(id)
    if (n) { this.selected = n; this.onSelect(n) }
  }

  // ── Auto-fit ────────────────────────────────────────
  /** 모든 노드가 화면에 들어오도록 scale·pan 자동 조정.
   *  사용자가 직접 pan/zoom 한 뒤에는 호출하지 않음. */
  _autoFit (padding = 48) {
    if (!this.nodes.length || !this.W || !this.H) return
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
    for (const n of this.nodes) {
      minX = Math.min(minX, n.x - n.radius)
      maxX = Math.max(maxX, n.x + n.radius)
      minY = Math.min(minY, n.y - n.radius)
      maxY = Math.max(maxY, n.y + n.radius)
    }
    const gW = maxX - minX, gH = maxY - minY
    if (gW <= 0 || gH <= 0) return
    const newScale = Math.min(
      (this.W - padding * 2) / gW,
      (this.H - padding * 2) / gH,
      2.5
    )
    this.scale = Math.max(newScale, 0.1)
    this.pan.x = this.W / 2 - ((minX + maxX) / 2) * this.scale
    this.pan.y = this.H / 2 - ((minY + maxY) / 2) * this.scale
  }

  // ── Events ──────────────────────────────────────────
  _bindEvents () {
    const c = this.canvas
    let mouseDownX = 0, mouseDownY = 0, didMove = false

    c.addEventListener('mousemove', e => {
      if (this.dragged) {
        const g = this._toGraph(e.clientX, e.clientY)
        this.dragged.x = g.x; this.dragged.y = g.y
        this.alpha = Math.max(this.alpha, 0.2); return
      }
      if (this.isPanning) {
        this.pan.x += e.clientX - this.panStart.x
        this.pan.y += e.clientY - this.panStart.y
        this.panStart = { x: e.clientX, y: e.clientY }; return
      }
      const { x, y } = this._toGraph(e.clientX, e.clientY)
      const hit = this._hitTest(x, y)
      this.hovered = hit
      c.style.cursor = hit ? 'pointer' : 'grab'
      if (hit) {
        if      (hit.type === 'subnet') this.tooltip.textContent = `${hit.label}  (${hit.ip_count || '?'}개 IP)`
        else if (hit.type === 'attack') this.tooltip.textContent = `공격 유형: ${IOC_TAG[hit.label]?.label || hit.label}`
        else                            this.tooltip.textContent = hit.label
        this.tooltip.classList.add('visible')
        // position:absolute, container가 relative — 컨테이너 기준 좌표
        const rect = this.canvas.getBoundingClientRect()
        let tx = e.clientX - rect.left + 14
        let ty = e.clientY - rect.top  - 36
        if (tx + 200 > this.W) tx = e.clientX - rect.left - 208
        if (ty < 4) ty = e.clientY - rect.top + 16
        this.tooltip.style.left = tx + 'px'
        this.tooltip.style.top  = ty + 'px'
      } else {
        this.tooltip.classList.remove('visible')
      }
    })

    c.addEventListener('mousedown', e => {
      mouseDownX = e.clientX; mouseDownY = e.clientY; didMove = false
      const { x, y } = this._toGraph(e.clientX, e.clientY)
      const hit = this._hitTest(x, y)
      if (hit && hit.type !== 'server') {
        this.dragged = hit; hit.fixed = true
        this._userInteracted = true
      } else {
        this.isPanning = true
        this.panStart  = { x: e.clientX, y: e.clientY }
        this._userInteracted = true
      }
    })

    c.addEventListener('mouseup', e => {
      const dx = e.clientX - mouseDownX, dy = e.clientY - mouseDownY
      didMove = Math.sqrt(dx * dx + dy * dy) > 6
      if (this.dragged) {
        this.dragged.fixed = false
        this.dragged.vx = 0; this.dragged.vy = 0
        if (!didMove) {
          this.selected = (this.selected === this.dragged) ? null : this.dragged
          this.onSelect(this.selected)
        }
        this.dragged = null
        this.alpha = Math.max(this.alpha, 0.25)
      } else if (!didMove) {
        this.selected = null; this.onSelect(null)
      }
      this.isPanning = false
    })

    c.addEventListener('mouseleave', () => {
      this.hovered = null
      this.tooltip.classList.remove('visible')
      if (this.dragged) { this.dragged.fixed = false; this.dragged = null }
      this.isPanning = false
    })

    c.addEventListener('wheel', e => {
      e.preventDefault()
      this._userInteracted = true
      const { x: gx, y: gy } = this._toGraph(e.clientX, e.clientY)
      const delta    = e.deltaY > 0 ? 0.88 : 1.14
      const newScale = Math.max(0.15, Math.min(5, this.scale * delta))
      const rect     = c.getBoundingClientRect()
      const cx = e.clientX - rect.left
      const cy = e.clientY - rect.top
      this.pan.x = cx - gx * newScale
      this.pan.y = cy - gy * newScale
      this.scale = newScale
    }, { passive: false })
  }

  // ── Animation loop ────────────────────────────────────
  _startLoop () {
    let _fitDone = false  // 시뮬레이션 안정 후 1회만 auto-fit
    const loop = () => {
      if (this.destroyed) return
      try {
        this._tick()
        // 시뮬레이션이 안정되면 사용자가 조작하지 않은 경우에 한해 auto-fit
        if (!_fitDone && this.alpha < 0.08 && !this._userInteracted) {
          this._autoFit()
          _fitDone = true
        }
        this._draw()
      } catch (err) {
        console.error('[ForceGraph] render error:', err)
      }
      this._frame = requestAnimationFrame(loop)
    }
    this._frame = requestAnimationFrame(loop)
  }

  destroy () {
    this.destroyed = true
    if (this._frame)    cancelAnimationFrame(this._frame)
    if (this._resizeObs) this._resizeObs.disconnect()
    this.canvas.remove()
    this.tooltip.remove()
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

// 테이블 헤더 클릭 → 정렬 토글 (필터 입력 클릭은 무시)
elDataTable.addEventListener('click', async e => {
  if (e.target.closest('.col-filter')) return   // 필터 input 클릭 → 정렬 무시
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

// 컬럼 필터 입력 (디바운스 300ms)
let colFilterTimer = null
elDataTable.addEventListener('input', e => {
  const inp = e.target.closest('.col-filter')
  if (!inp) return
  const col = inp.dataset.col
  clearTimeout(colFilterTimer)
  colFilterTimer = setTimeout(async () => {
    const val = inp.value
    if (val && val.trim()) {
      currentColFilters[col] = val
      inp.classList.add('active')
    } else {
      delete currentColFilters[col]
      inp.classList.remove('active')
    }
    currentPage = 0
    await loadData()
    // 페이지 다시 그려도 해당 필터 input에 포커스 유지
    const restored = elDataTable.querySelector(`.col-filter[data-col="${CSS.escape(col)}"]`)
    if (restored) { restored.focus(); restored.setSelectionRange(restored.value.length, restored.value.length) }
  }, 300)
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
