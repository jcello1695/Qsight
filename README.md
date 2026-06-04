# Q-Sight

> Windows 기반 파일 위협 탐지 및 EDR(Endpoint Detection & Response) SaaS

---

## 프로젝트 개요

Q-Sight는 Windows 엔드포인트에서 다운로드되는 파일을 실시간으로 감시하고, VirusTotal 정적 분석을 통해 위협 여부를 판별하는 보안 솔루션입니다.

사용자가 파일을 다운로드하는 순간 자동으로 스캔이 시작되며, 결과를 WinUI 클라이언트에서 즉시 확인할 수 있습니다. 우클릭 컨텍스트 메뉴를 통한 수동 스캔도 지원합니다.

---

## 주요 기능

- **자동 파일 감시** — Downloads 폴더를 `FileSystemWatcher`로 실시간 모니터링, 신규 파일 감지 시 자동 스캔
- **우클릭 스캔** — Windows Shell Extension을 통한 "Q-Sight 분석" 컨텍스트 메뉴 제공
- **정적 분석 (VirusTotal)** — SHA256 해시 기반 VirusTotal API 조회, `clean / malicious / unknown` 3단계 결과 반환
- **화이트리스트 관리** — SHA256 기반 신뢰 파일 등록, 등록된 파일은 스캔 생략
- **스캔 로그** — 결과를 메모리 및 로컬 JSON 파일(Desktop/QSightLogs)에 자동 저장
- **대시보드** — 기간별 스캔 통계 및 위협 현황 조회

---

## 시스템 아키텍처

```
[Downloads 폴더]
      │ FileSystemWatcher 감지
      ▼
[WinUI Client (QSightClient)]
  ├─ WatcherService     — 파일 시스템 감시
  ├─ AgentService       — 스캔 큐 관리 및 스캔 요청 처리
  ├─ ScanEngine         — SHA256 계산 → API 호출 → 결과 Polling
  ├─ IPCService         — Named Pipe 수신 (Shell Extension 연동)
  ├─ WhiteListService   — 화이트리스트 로컬 관리
  └─ LogService         — 스캔 결과 저장/조회

[QSightShell (COM Shell Extension)]
  └─ 우클릭 메뉴 → Named Pipe 전송 → IPCService

[FastAPI Backend (main.py)]
  ├─ POST /scans                   — 스캔 레코드 생성
  ├─ POST /scans/{id}/uploads/complete — S3 업로드 완료 + VT 정적 분석 실행
  ├─ POST /scans/{id}/static/vt-refresh — VT 재분석 (수동)
  ├─ POST /scans/{id}/dynamic/start    — 동적 분석 시작 트리거 (stub)
  ├─ GET  /scans/{id}              — 스캔 결과 조회
  └─ GET  /dashboard/summary       — 대시보드 통계

[Infrastructure]
  ├─ PostgreSQL — 스캔 레코드 및 이벤트 저장
  ├─ Redis      — 스캔 큐
  └─ AWS S3     — 파일 업로드 (Presigned URL)
```

---

## 스캔 흐름

```
1. 파일 감지 (WatcherService 또는 Shell Extension IPC)
2. SHA256 계산 (ScanEngine)
3. 화이트리스트 확인 → 등록 파일이면 "clean" 즉시 반환
4. POST /scans → scan_id 발급
5. POST /scans/{id}/uploads/complete → VirusTotal API 조회
6. GET /scans/{id} polling → static_result 확인 (최대 20초, 2초 간격)
7. 결과 저장 (LogService) 및 UI 업데이트
```

**분석 결과 판정 기준**

| VT 결과 | Q-Sight 판정 |
|---------|-------------|
| malicious > 0 | `malicious` |
| suspicious > 0 | `unknown` |
| harmless 또는 undetected > 0, malicious = 0 | `clean` |
| VT 미등록 파일 (404) | `unknown` |

---

## 프로젝트 구조

```
QSight.sln
├── QSightClient/               # WinUI 3 클라이언트
│   ├── Services/
│   │   ├── AgentService.cs     # 스캔 큐 및 이벤트 처리
│   │   ├── ScanEngine.cs       # 핵심 스캔 로직
│   │   ├── WatcherService.cs   # 파일 시스템 감시
│   │   ├── ApiService.cs       # 백엔드 API 통신
│   │   ├── IPCService.cs       # Named Pipe 서버
│   │   ├── WhiteListService.cs # 화이트리스트 관리
│   │   └── LogService.cs       # 스캔 로그 저장
│   ├── Models/
│   │   ├── ScanLog.cs
│   │   ├── ScanRequest.cs
│   │   └── IPCMessage.cs
│   └── Pages/
│       ├── ScanPage.xaml       # 수동 스캔 UI
│       ├── LogsPage.xaml       # 스캔 이력
│       ├── StatusPage.xaml     # 감시 상태
│       └── AboutPage.xaml
├── QSightShell/                # COM Shell Extension (우클릭 메뉴)
│   └── QSightContextMenu.cs
├── PipeTestSender/             # IPC 테스트용 유틸리티
└── main.py                     # FastAPI 백엔드
```

---

## 기술 스택

| 영역 | 기술 |
|------|------|
| 클라이언트 | C#, WinUI 3, .NET |
| Shell Extension | SharpShell (COM), Named Pipe |
| 백엔드 | Python, FastAPI |
| 데이터베이스 | PostgreSQL, Redis |
| 스토리지 | AWS S3 (Presigned URL) |
| 보안 분석 | VirusTotal API v3 |
| 배포 | AWS EC2 (Ubuntu) |

---

## 환경 설정

### 백엔드 (`main.py`)

`.env` 파일 생성 (`/home/ubuntu/qsight-api/.env`):

```env
VT_API_KEY=your_virustotal_api_key
VT_BASE_URL=https://www.virustotal.com/api/v3

POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=qsight_db
POSTGRES_USER=qsight_app
POSTGRES_PASSWORD=your_password

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
```

### 클라이언트 (`ApiService.cs`)

`BaseUrl` 상수를 배포 서버 주소로 변경:

```csharp
private const string BaseUrl = "http://your-server-ip:8000";
```

---

## 실행 방법

### 백엔드 실행

```bash
pip install fastapi uvicorn psycopg2-binary redis requests python-dotenv
uvicorn main:app --host 0.0.0.0 --port 8000
```

상태 확인:
```
GET /health
GET /health/deep
```

### 클라이언트 실행

Visual Studio에서 `QSight.sln` 열기 → `QSightClient`를 시작 프로젝트로 설정 후 실행

### Shell Extension 등록

```powershell
# 관리자 권한 PowerShell
regasm QSightShell.dll /codebase
```

---

## API 명세

| Method | Endpoint | 설명 |
|--------|----------|------|
| `GET` | `/health` | 헬스 체크 |
| `GET` | `/health/deep` | DB/Redis 연결 확인 |
| `POST` | `/scans` | 스캔 생성 |
| `POST` | `/scans/{id}/uploads/complete` | 업로드 완료 + VT 분석 실행 |
| `GET` | `/scans/{id}` | 스캔 결과 조회 (이벤트, 리포트 포함) |
| `POST` | `/scans/{id}/static/vt-refresh` | VT 재분석 |
| `POST` | `/scans/{id}/dynamic/start` | 동적 분석 시작 (stub) |
| `GET` | `/dashboard/summary?days=30` | 대시보드 통계 |

---

## 팀

| 이름 | 역할 |
|------|------|
| 정철호 | PM / 통합, 발표 |
| 정선구 | 백엔드 (FastAPI, DB) |
| 문현규 | 동적 분석 |
| 이승용 | WinUI 프론트엔드 |

---

## 라이선스

본 프로젝트는 구름 딥다이브 부트캠프 최종 프로젝트로 제출된 결과물입니다.
