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
   * @param {{ table:string, search:string, limit:number, offset:number }}
   * @returns {{ rows:object[], total:number, columns:string[], error?:string }}
   */
  getTableData: (opts)       => ipcRenderer.invoke('db:getTableData', opts),
})
