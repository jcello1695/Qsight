# Q-Sight: 실시간 감시 기반 악성코드 이원화 분석 플랫폼

> **"사용자가 실행하기 전, 생성 단계에서 차단한다."** > Q-Sight는 C# WinUI3 환경에서 C++ 에이전트를 통해 주요 다운로드 및 수신 폴더를 실시간 모니터링하고, 정적/동적 이원화 분석 알고리즘을 통해 위협을 식별하는 지능형 엔드포인트 보안 솔루션 샌드박스입니다.

---

## 1. 시스템 아키텍처 (System Architecture)

Q-Sight는 자원 효율성과 정밀한 분석을 동시에 달성하기 위해 **[에이전트 - 백엔드 - 분석 엔진]** 구조가 유기적으로 연동되는 **이원화(Static/Dynamic) 분석 아키텍처**를 채택했습니다.

1. **Endpoint Agent (C# / C++)**
   - OS 및 사용자 주요 파일 수신 경로를 실시간 모니터링합니다.
   - 프로세스 트리, 파일 시스템 변경, 레지스트리 변조, 외부 네트워크 통신을 후킹 및 추적합니다.
2. **Backend Server (FastAPI / AWS EC2)**
   - 에이전트로부터 수집된 실시간 위협 행위 로그 파이프라인을 관리합니다.
   - 동적 분석을 위한 가상 환경(Sandbox)의 오케스트레이션을 제어합니다.
3. **Analysis Engine (Python / Artifact Analysis)**
   - 규칙 기반 Severity 분류 및 MITRE ATT&CK 프레임워크 매핑을 수행합니다.
   - LLM 파이프라인을 연동하여 분석가 관점의 자연어 리포트를 생성합니다.

---

## 2. 핵심 기능 (Core Features)

### 주요 경로 실시간 자동 추적감시 (Real-time Watchdog)
- 사용자가 악성코드를 수동으로 실행하기 전, 파일 유입 단계에서 위협을 차단하기 위해 주요 폴더를 상시 감시합니다.
- **기본 추적 폴더**: `C:\Downloads`, `D:\Downloads`, `내 문서\KakaoTalk 받은 파일` 등

### 행위 기반 이원화 분석 (Dual-Stage Analysis)
- **정적 분석 (자동 실행)**: 파일 생성 즉시 해시($SHA256$) 추출 및 규칙 기반 엔진을 통해 `Unknown/의심/위험`을 1차 분류하여 대시보드에 업데이트합니다.
- **동적 분석 (온디맨드 실행)**: 정적 분석에서 위험도가 모호한 `Unknown` 파일에 한해, 사용자의 요청에 따라 AWS EC2 가상 환경에서 가상 아티팩트를 구동해 정밀 샌드박스 분석을 수행합니다.

### 분석가 관점의 대시보드 및 시각화 (WinUI3 UI/UX)
- **Unknown 집중 관리 탭**: 탐지되거나 안전한 파일 외에, 정밀 검사가 필요한 파일들만 별도로 격리하여 보여주는 전용 섹션을 제공합니다.
- **프로세스 트리 시각화**: 수집된 `PID`와 `PPID`의 상관관계를 분석하여 부모-자식 프로세스의 실행 계층 구조를 한눈에 파악할 수 있도록 시각화합니다.
- **미트레 어택(MITRE ATT&CK) 매핑**: `RUN_KEY_PERSISTENCE`, `C2_CONNECTION` 등의 규칙 매칭을 통해 공격자의 전술을 프로파일링합니다.

---

## 3. 기술 스택 (Tech Stack)

- **Frontend & App Core**: C# (WinUI3 / .NET)
- **Security Agent Engine**: C++ (Windows Native API / Toolhelp32 / IPHelper)
- **Backend API**: Python (FastAPI / nlohmann-json API)
- **Analysis & Automation**: Python (VBoxManage CLI Wrapper)
- **Infrastructure**: AWS EC2 (`t3.medium` 기반 운영 및 모니터링 후 Scale-up 전략)

---

## 4. 프로젝트 구조 (Project Structure)

```text
📂 Q-Sight
├── 📂 QSightApp (C# WinUI3 메인 어플리케이션)
│   ├── App.xaml.cs
│   └── 📂 Views (대시보드, Logs, About 탭 UI)
├── 📂 QAgent (C++ 실제 위협 행위 추적 모듈)
│   ├── QManager.cpp  (데이터 축적 및 전역 상태 관리)
│   ├── QAgent.cpp    (Process/File/Registry/Network 실시간 추적)
│   └── QReport.cpp   (확정 스키마 기반 JSON Report 빌더)
└── 📂 QAnalysisEngine (Python 분석 및 오케스트레이션)
    ├── main.py
    ├── models.py     (Behavior JSON 스키마 모델)
    └── 📂 rules      (YAML 기반 MITRE ATT&CK 탐지 규칙 10종)
