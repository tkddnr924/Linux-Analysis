# Linux Analysis

> Python 3.12 · SQLite · Linux 포렌식 자동화 분석 도구

수집된 Linux 아티팩트(로그, 시스템 정보)를 파싱하여 SQLite DB에 저장하고,
보안 위협 및 운영 이상 징후를 자동 분석합니다.

---

## 파이프라인

```
target/              ← 로그 파일을 구조 상관없이 배치
  (하위 디렉토리 포함 재귀 탐색)
        │
        ▼  [1단계: 파싱]
   parser.db         ← 원시 로그 데이터
        │
        ▼  [2단계: 분석]
  analysis.db        ← 집계·분석 결과
```

---

## 빠른 시작

```bash
# 1. 가상환경 생성 및 활성화
python3.12 -m venv venv
source venv/bin/activate

# 2. 의존성 설치
pip install -r requirements.txt

# 3. 로그 파일을 target/ 에 배치 후 실행
python main.py
```

> `analysis.db`는 실행할 때마다 새로 생성됩니다.
> `parser.db`는 MD5 체크섬 기반으로 이미 파싱된 파일을 건너뜁니다.

---

## 프로젝트 구조

```
Linux-Analysis/
├── main.py                  # 진입점
│
├── parser/                  # 로그 파서
│   ├── auditlog.py          # audit.log* 파서
│   ├── authlog.py           # auth.log* 파서
│   ├── nginxlog.py          # nginx access.log* 파서
│   └── utils/
│       ├── files.py         # MD5, glob, 압축 해제
│       ├── strings.py       # hex 디코딩, key=value 파싱
│       └── times.py         # epoch → KST 변환
│
├── analyzer/                # 분석기
│   ├── auditlog.py          # audit 로그 분석
│   ├── authlog.py           # SSH/인증 로그 분석
│   ├── cron.py              # cron 실행 이력 분석
│   ├── nginxlog.py          # nginx 공격·웹쉘 탐지
│   ├── sysinfo.py           # 서버 기본 정보 수집
│   └── loginfo.py           # 로그 요약 메타정보
│
├── target/                  # 분석 대상 로그 (하위 구조 무관)
├── parser.db                # 파싱 결과 (자동 생성)
├── analysis.db              # 분석 결과 (실행 시 재생성)
└── gui/                     # Electron 기반 analysis.db 뷰어
    ├── main.js              # Electron 메인 프로세스
    ├── preload.js           # IPC 브릿지
    ├── renderer/            # UI (HTML/CSS/JS)
    └── package.json         # Node 22 의존성
```

---

## 지원 로그 및 파싱 대상

| 로그 파일 | 파싱 테이블 | 비고 |
|---|---|---|
| `audit.log*` | `audit` | hex 인코딩 자동 디코딩 |
| `auth.log*` | `authlog` | SSH·sudo·cron·su 이벤트 분류 |
| `access.log*` | `nginx` | 2xx 성공 요청만 저장 |

- `.gz` / `.tar.gz` / `.tgz` 압축 파일 자동 해제 후 파싱
- 동일 파일(MD5 기준) 재파싱 방지

---

## DB 스키마

### parser.db

#### `info` — 파싱 파일 메타정보
| 컬럼 | 설명 |
|---|---|
| `file_name` | 파일명 |
| `file_path` | 전체 경로 |
| `md5` | MD5 체크섬 (중복 파싱 방지) |
| `file_size` | 파일 크기 (bytes) |
| `log_type` | 로그 종류 (audit / authlog / nginx) |
| `parsed_at` | 파싱 일시 |

#### `audit` — Linux Audit 로그
`type`, `date_time`, `sequence`, `pid`, `uid`, `auid`, `ses`, `exe`, `cmd`, `cwd`, `comm`, `proctitle`, `op`, `subj`, `hostname`, `addr`, `terminal`, `msg_res`, `raw_line` 외 다수

#### `authlog` — 인증 로그
`date_time`, `hostname`, `service`, `pid`, `event_type`, `user`, `src_ip`, `port`, `detail`, `raw_line`

**`event_type` 분류:**

| 분류 | 이벤트 |
|---|---|
| SSH | `sshd_accepted_password` `sshd_accepted_publickey` `sshd_failed_password` `sshd_invalid_user` `sshd_conn_closed` 외 다수 |
| sudo | `sudo_command` `sudo_auth_failure` |
| cron | `cron_session_opened` `cron_session_closed` |
| su | `su_to` `su_session_opened` `su_session_closed` |

#### `nginx` — Nginx 접근 로그 (2xx)
`date_time`, `src_ip`, `method`, `uri`, `status`, `bytes_sent`, `user_agent`, `referer`

---

### analysis.db

#### `info` — 서버 기본 정보 *(Volatile/NonVolatile 아티팩트가 있을 때만 수집)*
`hostname`, `internal_ip`, `mac_address`, `os`, `kernel`, `architecture`, `cpu_model`, `cpu_cores`, `disk_total/used/avail/use_pct`, `timezone`, `collected_at`, `booted_at`, `uptime_days`, `last_reboot`, `listen_ports`, `collect_user`

#### `log` — 로그 요약
`log_name`, `first_record`, `last_record`, `total_records`, `file_count`

---

#### `authlog_login` — SSH 로그인 성공
`src_ip`, `user`, `auth_method`, `first_seen`, `last_seen`, `count`

#### `authlog_sudo` — sudo 명령 실행
`user`, `command`, `first_seen`, `last_seen`, `count`

#### `authlog_attack_ip` — 접근 시도 IP 전체 집계
`src_ip`, `first_seen`, `last_seen`, `total_count`, `success_count`, `fail_count`

#### `authlog_su` — su 계정 전환
`from_user`, `to_user`, `first_seen`, `last_seen`, `count`

---

#### `audit_login` — 인증·로그인 이벤트
`type`, `acct`, `hostname`, `addr`, `terminal`, `res`, `first_seen`, `last_seen`, `count`

#### `audit_cmd` — 명령 실행 이력 (EXECVE)
`uid`, `auid`, `cmd`, `cwd`, `first_seen`, `last_seen`, `count`

#### `audit_file` — 파일 접근 이력 (PATH)
`uid`, `exe`, `cwd`, `first_seen`, `last_seen`, `count`

---

#### `cron_info` — cron 실행 통계
| 컬럼 | 설명 |
|---|---|
| `process` | 실행된 프로세스·커맨드명 |
| `user` | 실행 사용자 (uid) |
| `first_seen` | 최초 실행 시각 |
| `last_seen` | 마지막 실행 시각 |
| `exec_count` | 실행 횟수 |
| `avg_duration_sec` | 평균 소요시간(초) |
| `total_duration_sec` | 총 소요시간(초) |

> 프로세스명: 동일 세션의 `EXECVE cmd` → `comm` → `exe` 순으로 결정

---

#### `nginx_top_ip` — 공격 탐지 IP 집계
`src_ip`, `first_seen`, `last_seen`, `attack_count`, `attack_types`

#### `nginx_attack` — 공격 페이로드 탐지
`date_time`, `src_ip`, `method`, `uri`, `decoded_uri`, `status`, `attack_type`, `matched_str`, `user_agent`

**탐지 공격 유형:** `sql_injection` `xss` `path_traversal` `lfi_rfi` `shell_injection` `php_injection` `log4shell` `spring4shell`

#### `nginx_webshell` — 웹쉘 의심 파일
`file_name`, `file_path`, `src_ip`, `first_seen`, `last_seen`, `access_count`, `bytes_min`, `bytes_max`, `bytes_distinct`, `suspicion_score`, `suspicion_flags`

**탐지 기준:** `known_webshell` `variable_response` `script_in_media` `suspicious_path` `high_freq_access` `persistent_access`

---

## GUI 뷰어

`analysis.db` 결과를 데스크톱 앱으로 탐색합니다.

```bash
cd gui/
npm install   # 최초 1회 (better-sqlite3 자동 재빌드)
npm start
```

> **요구사항:** Node.js 22+
> 기동 시 프로젝트 루트의 `analysis.db` 자동 감지·로드합니다.

---

## 실행 흐름

```
main.py
│
├── [RESET]     analysis.db 삭제 후 재생성
│
├── [1단계] parse_logs()
│   ├── target/ 하위 audit.log*, auth.log*, access.log* 탐색
│   ├── .gz 압축 파일 자동 해제 (.decomp/ 임시 디렉토리)
│   ├── MD5 확인 → 이미 파싱된 파일 SKIP
│   └── 1,000건 단위 배치 INSERT → parser.db
│
└── [2단계] analyze_logs()
    ├── sysinfo   → analysis.db :: info  (아티팩트 있을 때만)
    ├── authlog   → analysis.db :: authlog_*
    ├── audit     → analysis.db :: audit_*
    ├── cron      → analysis.db :: cron_info
    ├── nginx     → analysis.db :: nginx_*
    └── loginfo   → analysis.db :: log
```
