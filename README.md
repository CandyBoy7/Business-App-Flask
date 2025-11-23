\# 🚀 Business App - Flask 기반 유료 구독 서비스 (Subscription Service)



\## 📌 프로젝트 소개



이 프로젝트는 Python의 \*\*Flask 프레임워크\*\*를 사용하여 구현한 \*\*구독 기반 업무 관리 웹 애플리케이션\*\*입니다. 사용자 인증, 데이터베이스 관리, 그리고 \*\*정기 결제 시스템(빌링키 기반)\*\* 연동까지 완벽하게 구현하여 실제 서비스 환경을 시뮬레이션했습니다.



\### 주요 기능



\* \*\*회원 관리:\*\* Flask-Login과 Flask-Bcrypt를 이용한 안전한 회원가입/로그인/로그아웃 시스템.

\* \*\*유료 구독 모델:\*\* 일반 사용자와 프리미엄 구독자를 구분하여 콘텐츠 접근 제한 (Project 생성 개수 제한).

\* \*\*정기 결제 연동:\*\* 아임포트(I'mport) API를 이용한 빌링키 발급 및 월별 자동 결제 갱신 로직 구현.

\* \*\*백그라운드 스케줄링:\*\* Flask-APScheduler를 이용해 정해진 주기마다 구독 갱신을 자동으로 처리.

\* \*\*업무 관리:\*\* 프로젝트 생성, 수정, 삭제 기능.



\### 기술 스택



| 분류 | 기술 | 사용 목적 |

| :--- | :--- | :--- |

| \*\*Backend\*\* | Python, Flask | 웹 애플리케이션 프레임워크 |

| \*\*Database\*\* | Flask-SQLAlchemy, SQLite | ORM 및 로컬 데이터 저장 |

| \*\*Security\*\* | Flask-Bcrypt, Flask-Login | 비밀번호 암호화 및 세션 관리 |

| \*\*Payments\*\* | I'mport API (via `requests`) | 결제 연동 및 빌링키 관리 |

| \*\*Scheduling\*\*| Flask-APScheduler | 정기 구독 갱신 자동화 |

| \*\*Frontend\*\* | Jinja2, Bootstrap 5 | 템플릿 엔진 및 반응형 디자인 |



\## 💻 실행 방법



\### 1. 환경 설정



```bash

\# Git 클론 (GitHub에서 코드를 다운로드합니다)

git clone \[https://github.com/CandyBoy7/Business-App-Flask.git](https://github.com/CandyBoy7/Business-App-Flask.git)

cd Business-App-Flask



\# 가상 환경 생성 및 활성화 (선택 사항이지만 권장)

\# python -m venv venv

\# .\\venv\\Scripts\\activate



\# 필요한 패키지 설치

pip install -r requirements.txt

