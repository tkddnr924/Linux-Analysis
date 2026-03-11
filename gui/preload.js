/**
 * preload.js — contextBridge로 렌더러에 안전한 API 노출
 */

'use strict'

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('api', {
  /** 파일 선택 다이얼로그 */
  openFile: ()               => ipcRenderer.invoke('dialog:openFile'),

  /** 자동 감지 analysis.db 경로 반환 (없으면 null) */
  getAutoPath: ()            => ipcRenderer.invoke('db:getAutoPath'),

  /** DB 열기 → { success, path, size, mtime } | { success:false, error } */
  openDB:  (filePath)        => ipcRenderer.invoke('db:open', filePath),

  /** DB 닫기 */
  closeDB: ()                => ipcRenderer.invoke('db:close'),

  /** 테이블 목록 → [{ name, count }] */
  getTables: ()              => ipcRenderer.invoke('db:getTables'),

  /**
   * 테이블 데이터 조회
   * @param {{ table:string, search:string, limit:number, offset:number, dateFrom?:string, dateTo?:string }}
   * @returns {{ rows:object[], total:number, columns:string[], error?:string }}
   */
  getTableData: (opts)       => ipcRenderer.invoke('db:getTableData', opts),

  /**
   * 테이블의 date_time 컬럼 최솟값·최댓값 (YYYY-MM-DD)
   * @param {string} table
   * @returns {{ min:string|null, max:string|null }}
   */
  getDateRange: (table)      => ipcRenderer.invoke('db:getDateRange', table),

  /**
   * 전체 테이블 통합 검색
   * @param {string} query  검색어
   * @returns {{ table:string, columns:string[], rows:object[], total:number }[]}
   */
  globalSearch: (query)      => ipcRenderer.invoke('db:globalSearch', query),

  /**
   * 로그인 세션 목록 (authlog_login 기반)
   * @returns {{ sessions: object[], has_data: boolean }}
   */
  getLoginSessions: ()       => ipcRenderer.invoke('db:getLoginSessions'),

  /**
   * 특정 세션 기간의 관련 활동 조회
   * @param {{ user:string, src_ip:string, first_seen:string, last_seen:string }}
   * @returns {{ sudo:object[], cmd:object[], su:object[], bruteforce:object[] }}
   */
  getSessionActivity: (opts) => ipcRenderer.invoke('db:getSessionActivity', opts),

  /**
   * IP 기반 공격자 종합 프로파일 (AI 분석)
   * @returns {object[]} IP별 집계 데이터 배열 (스코어링은 렌더러에서 수행)
   */
  getAttackerProfiles: () => ipcRenderer.invoke('db:getAttackerProfiles'),

  /**
   * 전체 IoC (위협 IP) 수집
   * @returns {{ ip, sources, threat_tags, first_seen, last_seen }[]}
   */
  getIoC: () => ipcRenderer.invoke('db:getIoC'),

  /**
   * 그래프용 노드+엣지 데이터
   * @returns {{ nodes: object[], edges: object[] }}
   */
  getGraphData: () => ipcRenderer.invoke('db:getGraphData'),
})
