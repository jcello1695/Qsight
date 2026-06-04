# Q-Sight: 실시간 감시 기반 악성코드 이원화 분석 플랫폼

**Q-Sight**는 악성코드 분석가와 보안 엔지니어를 위한 **자동화된 악성코드 동적/정적 분석 샌드박스 플랫폼**입니다. 
기획 단계의 방대한 마일스톤 중 현재까지 실제로 구현되어 안정적으로 동작하는 **핵심 파이프라인(에이전트 제어, 동적 로그 수집, 분석 리포트 자동 생성)**을 중심으로 구성된 버전입니다.

---

## 핵심 구현 기능 (Actual Implementation)

현재 레포지토리에 구현 및 검증이 완료된 핵심 모듈은 다음과 같습니다.

### 1. 가상 환경 및 에이전트 제어 (Sandbox Environment)
* **Isolated Sandbox**: Docker 기반 인프라 및 가상 환경 내에서 악성코드를 안전하게 격리 실행합니다.
* **C# / Python 기반 분석 에이전트**: 가상 머신(VM) 내부에서 실행되어 악성코드의 행위를 실시간으로 모니터링하고 가로챕니다.

### 2. 동적 행위 및 아티팩트 수집 (Dynamic Analysis Engine)
* **프로세스 및 파일 모니터링**: 악성코드가 생성, 수정, 삭제하는 파일 시스템 변경 사항과 자식 프로세스 생성 이력을 추적합니다.
* **네트워크 커넥션 캡처**: 실행 중 발생하는 외부 IP 연결 시도, DNS 질의, 이상 트래픽 유발 행위를 로깅합니다.

### 3. 분석 데이터 파이프라인 & 시각화 (Backend & UI)
* **FastAPI 기반 REST API**: 에이전트가 수집한 원시(Raw) 행위 로그를 고속으로 수집하고 구조화합니다.
* **PostgreSQL 데이터 모델링**: 수집된 정적/동적 메타데이터를 관계형 데이터베이스에 안정적으로 적재합니다.
* **종합 분석 리포트**: 악성코드의 위험도 점수(Risk Score), 핵심 행위 시그니처, IOC(개념 지표)를 요약한 대시보드를 제공합니다.

---

## Tech Stacks & Architecture

### Environment & Agents
* **Languages**: Python 3.10+, C# (.NET / WinUI 3)
* **Frameworks**: FastAPI (Backend API)
* **Database**: PostgreSQL
* **Infrastructure**: Docker / VirtualBox Isolation Environment
* **Tools**: Open-source monitoring utilities integration

### System Workflow
1. **Sample Submission**: 사용자가 웹 대시보드 또는 API를 통해 분석 대상 파일(PE, 스크립트 등)을 제출합니다.
2. **Analysis Trigger**: 샌드박스 가상 환경이 구동되며 내부 에이전트가 활성화됩니다.
3. **Behavior Logging**: 악성코드 실행 후 발생하는 파일/레지스트리/네트워크 행위를 에이전트가 실시간으로 수집합니다.
4. **Report Generation**: 수집된 로그를 FastAPI 백엔드로 전송, 파싱 후 데이터베이스에 저장하고 위험도 시그니처를 매핑하여 리포트를 생성합니다.

---

## 실행 및 설치 방법 (Installation & Quick Start)

### Prerequisites
* Python 3.10 이상
* PostgreSQL Database
* Docker (샌드박스 컨테이너 환경 운용 시)

### 1. 레포지토리 클론 및 의존성 설치
```bash
git clone [https://github.com/jcello1695/Qsight.git](https://github.com/jcello1695/Qsight.git)
cd Qsight
pip install -r requirements.txt
2. 환경 변수 설정 (.env)
프로젝트 루트 디렉토리에 .env 파일을 생성하고 데이터베이스 및 API 설정을 입력합니다.

코드 스니펫
DATABASE_URL=postgresql://user:password@localhost:5432/qsight_db
API_SECRET_KEY=your_secret_key_here
LOG_LEVEL=INFO
3. 백엔드 API 서버 서버 실행
Bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

프로젝트 디렉토리 구조 (Directory Structure)
Plaintext
Qsight/
├── agent/               # 가상 환경 내부 행위 수집 에이전트 (C# / Python)
├── backend/             # FastAPI 기반 로그 수집 및 리포팅 서버
│   ├── app/
│   │   ├── api/        # 엔드포인트 라우터
│   │   ├── core/       # 설정 및 보안 모듈
│   │   ├── models/     # 데이터베이스 스키마
│   │   └── services/   # 분석 및 파싱 로직
├── config/              # 환경 설정 파일
├── tests/               # 단위 테스트 및 분석 샘플 테스트 스크립트
├── requirements.txt     # 의존성 패키지 목록
└── README.md            # 프로젝트 가이드라인

안전 유의사항 (Disclaimer)
본 플랫폼은 안전하게 격리된 환경(Sandbox) 내에서 악성코드를 분석하도록 설계되었습니다. 실제 호스트 환경이나 격리되지 않은 네트워크 시스템에서 분석 샘플을 실행할 경우 심각한 보안 피해를 초래할 수 있으므로, 반드시 독립된 가상화 환경에서만 테스트 및 운용하시기 바랍니다.
