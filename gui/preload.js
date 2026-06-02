'use strict'

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('api', {
  /** 파일 선택 다이얼로그 */
  openFile: () => ipcRenderer.invoke('dialog:openFile'),

  /** 자동 감지 parser.db 경로 반환 (없으면 null) */
  getAutoPath: () => ipcRenderer.invoke('db:getAutoPath'),

  /** DB 열기 → { success, path, size, mtime } | { success:false, error } */
  openDB: (filePath) => ipcRenderer.invoke('db:open', filePath),

  /** DB 닫기 */
  closeDB: () => ipcRenderer.invoke('db:close'),

  /** 테이블 목록 → [{ name, count }] */
  getTables: () => ipcRenderer.invoke('db:getTables'),

  /**
   * 테이블 데이터 조회
   * @param {{ table, search, limit, offset, sortCol, sortDir, dateFrom, dateTo, colFilters }}
   * @returns {{ rows, total, columns, error? }}
   */
  getTableData: (opts) => ipcRenderer.invoke('db:getTableData', opts),

  /**
   * 타임스탬프 컬럼 최솟값·최댓값 (YYYY-MM-DD)
   * date_time 또는 timestamp 컬럼을 자동 탐지
   */
  getDateRange: (table) => ipcRenderer.invoke('db:getDateRange', table),

  /** sysinfo 테이블의 단일 행 */
  getSysinfo: () => ipcRenderer.invoke('db:getSysinfo'),

  /** Audit 대시보드 통계 */
  getAuditDashboard: () => ipcRenderer.invoke('db:getAuditDashboard'),

  /** Authlog 대시보드 통계 */
  getAuthlogDashboard: () => ipcRenderer.invoke('db:getAuthlogDashboard'),

  /** Syslog 대시보드 통계 */
  getSyslogDashboard: () => ipcRenderer.invoke('db:getSyslogDashboard'),

  /** Apache2 대시보드 통계 */
  getApache2Dashboard: () => ipcRenderer.invoke('db:getApache2Dashboard'),

  /** 공통(자동) 대시보드 — 전용 대시보드가 없는 테이블용 { tsCol, range, breakdowns, scanLimited } */
  getGenericDashboard: (table) => ipcRenderer.invoke('db:getGenericDashboard', table),

  /** IP enrich 캐시 — {ip: {cc, cn, asn, co, vpn}} */
  getIpInfo: () => ipcRenderer.invoke('db:getIpInfo'),

  /** 웹 로그 4개 테이블 IP 중복제거 + 카운트 → [{ip, cnt}] */
  getWebIps: () => ipcRenderer.invoke('db:getWebIps'),

  /** 선택된 IP/CIDR 의 웹 로그 records UNION — pagination + 정렬 + 컬럼 필터 */
  getWebRecords: (opts) => ipcRenderer.invoke('db:getWebRecords', opts),

  // ── IP enrich (사용자 트리거) ─────────────────────
  /** 현재 enrich 상태 → { available, cached, total, hasToken, running } */
  enrichStatus:   () => ipcRenderer.invoke('db:enrichStatus'),
  /** enrich 시작 — 비동기, 끝나면 결과 반환. 진행은 onEnrichProgress 로 받음 */
  startEnrichIps: () => ipcRenderer.invoke('db:startEnrichIps'),
  /** 현재 진행 중 enrich 취소 */
  cancelEnrich:   () => ipcRenderer.invoke('db:cancelEnrich'),
  /** 진행률 이벤트 구독: cb({done, total, ok, fail, finished, cancelled}) — 해제 함수 반환 */
  onEnrichProgress: (cb) => {
    const h = (_e, payload) => cb(payload)
    ipcRenderer.on('enrich-progress', h)
    return () => ipcRenderer.removeListener('enrich-progress', h)
  },

  /**
   * 전체 테이블 통합 검색
   * @returns {{ table, columns, rows, total }[]}
   */
  globalSearch: (query) => ipcRenderer.invoke('db:globalSearch', query),
})
