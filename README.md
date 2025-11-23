# 💰 Flask 기반 유료 구독 비즈니스 앱 (Business App with Subscription)

## 🌟 프로젝트 개요

본 프로젝트는 Flask 프레임워크를 사용하여 구현한 **SaaS(Software as a Service) 형태의 비즈니스 앱**입니다. 핵심 목표는 **정기 구독 모델**을 성공적으로 구현하고, 비구독자와 유료 구독자를 차별화하여 서비스의 가치를 높이는 데 있습니다.

- **핵심 기능:** 사용자별 프로젝트 생성 및 관리, 유료 구독자 전용 콘텐츠 제공
- **구현 목표:** 안정적인 정기 결제 로직, 스케줄러를 이용한 구독 자동 갱신 및 만료 처리, 관리자 대시보드 구축.

---

## 🚀 주요 기능 및 구현 포인트

### 1. 유료 구독 및 프로젝트 생성 제한 로직

| 기능 | 설명 | 구현 기술 |
| :--- | :--- | :--- |
| **무료 사용자 제한** | 비구독자는 **최대 10개**의 프로젝트만 생성 가능합니다. | `app.py` 라우트(`create_project`)에서 `current_user.is_premium`과 `project_count`를 체크하여 제한. |
| **프리미엄 무제한** | 유료 구독자(`is_premium=True`)는 프로젝트를 **무제한**으로 생성할 수 있습니다. | `User` 모델의 `is_premium` 필드 사용. |
| **관리자 대시보드** | `is_admin` 필드를 가진 관리자만 접근 가능하며, 전체 사용자 목록, 구독 상태, 만료일을 한눈에 확인 가능합니다. | `admin_required` 데코레이터, `admin_dashboard.html`. |

### 2. 정기 결제 및 구독 관리

본 프로젝트는 **아임포트(Iamport)**를 통한 빌링키 기반 정기 결제 로직을 구현하였습니다.

* **빌링키 발급:** 사용자가 첫 결제 시, `customer_uid`를 아임포트에 전송하여 **빌링키(정기 결제용 카드 정보)**를 안전하게 저장합니다.
* **구독 상태 업데이트:** 결제 성공 시, DB의 `subscription_active`, `is_premium`을 `True`로 설정하고 `subscription_expires`를 **1개월 뒤**로 설정합니다.
* **자동 갱신 스케줄러:** **Flask-APScheduler**를 사용하여 30분마다 만료일이 임박한(7일 이내) 사용자를 조회하고, 아임포트 API를 통해 **자동 결제(`subscribe/payments/again`)**를 시도합니다. 실패 시 사용자 구독 상태를 `False`로 변경하여 접근을 차단합니다.

### 3. 안정적인 배포 환경 구축

* **WSGI 서버 사용:** Flask 개발 서버 대신, 실제 프로덕션 환경에서 사용되는 **Waitress WSGI 서버**를 사용하여 앱을 구동했습니다. (Waitress는 Windows 환경에서 안정적인 운영을 위한 최적의 선택입니다.)
* **환경 변수 관리:** `SECRET_KEY`, `IMP_KEY`, `IMP_SECRET` 등 민감 정보를 환경 변수를 통해 안전하게 관리하도록 설계했습니다.

---

## ⚙️ 기술 스택 및 환경

* **백엔드 프레임워크:** Python / Flask
* **데이터베이스:** SQLite (Flask-SQLAlchemy)
* **결제 시스템:** Iamport API (나이스페이 결제 모듈 연동)
* **스케줄링:** Flask-APScheduler
* **보안:** Flask-Bcrypt (비밀번호 해싱), Flask-Login (사용자 세션 관리)
* **WSGI 서버:** Waitress

---

## 🛠️ 프로젝트 실행 방법

### 1. 환경 설정

1.  **가상 환경 활성화** (권장):
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    ```

2.  **필요 라이브러리 설치:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **환경 변수 설정:** (필요시)
    ```bash
    # SECRET_KEY는 필수
    $env:SECRET_KEY="your_super_secret_key"
    
    # 결제 테스트 시 아임포트 키 및 나이스페이 MID 설정
    $env:IMP_KEY="[YOUR_IAMPORT_REST_API_KEY]"
    $env:IMP_SECRET="[YOUR_IAMPORT_SECRET_KEY]"
    $env:NICEPAY_MID="gkdlvy046m" 
    ```

### 2. 데이터베이스 및 관리자 계정 설정

1.  **DB 파일 생성:** `site.db` 파일을 생성하고 테이블을 초기화합니다.
    ```bash
    flask shell
    from app import db
    db.create_all()
    exit()
    ```

2.  **관리자 계정 승격:** `/register`로 가입 후, Flask Shell에서 다음 명령어를 실행하여 관리자 권한을 부여합니다.
    ```bash
    flask shell
    from app import User, db
    admin_user = User.query.filter_by(email='[가입한_이메일]').first()
    admin_user.is_admin = True
    db.session.commit()
    exit()
    ```

### 3. 서버 실행 (Waitress 사용)

Waitress를 사용하여 서버를 안정적으로 구동합니다.

```bash
waitress-serve --listen=127.0.0.1:8000 'app:app'