# Linux Analysis Viewer (GUI)

> Electron · Node 22 · analysis.db 뷰어

`analysis.db` 분석 결과를 시각적으로 탐색하는 데스크톱 앱입니다.

---

## 요구사항

| 항목 | 버전 |
|------|------|
| Node.js | 22 이상 |
| npm | 10 이상 |

## 설치 및 실행

```bash
cd gui/

# 의존성 설치 (better-sqlite3 자동 재빌드 포함)
npm install

# 실행
npm start
```

> `npm install` 시 `postinstall` 훅이 `electron-rebuild`를 실행하여  
> `better-sqlite3` 네이티브 모듈을 Electron용으로 자동 재빌드합니다.

---

## 기능

| 기능 | 설명 |
|------|------|
| **자동 감지** | 앱 기동 시 `../analysis.db` 자동 탐색 및 로드 |
| **DB 열기** | 임의의 `.db` 파일 수동 선택 |
| **사이드바** | 테이블 목록을 카테고리별로 그룹화, 행 수 표시 |
| **테이블 뷰** | 컬럼 헤더 고정, 타입별 색상 하이라이팅 |
| **실시간 검색** | 모든 컬럼 대상 LIKE 검색 (Ctrl+F) |
| **페이지네이션** | 150건 단위, 이전/다음 이동 |
| **행 상세 모달** | 행 클릭 시 전체 필드 값 표시 (Esc 닫기) |

---

## 테이블 그룹

| 그룹 | 테이블 |
|------|--------|
| 📊 요약 | `info`, `log` |
| 🔐 인증 로그 | `authlog_login`, `authlog_sudo`, `authlog_attack_ip`, `authlog_su` |
| 🔍 감사 로그 | `audit_login`, `audit_cmd`, `audit_file` |
| ⏰ Cron | `cron_info` |
| 🌐 Nginx | `nginx_top_ip`, `nginx_attack`, `nginx_webshell` |
