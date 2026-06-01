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

  /**
   * 전체 테이블 통합 검색
   * @returns {{ table, columns, rows, total }[]}
   */
  globalSearch: (query) => ipcRenderer.invoke('db:globalSearch', query),
})
