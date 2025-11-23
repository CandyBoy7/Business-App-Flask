import os
import requests
import json
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from functools import wraps # ⬅️ 추가: 데코레이터 사용을 위해 import

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_apscheduler import APScheduler

# ----------------------------------------------------
# 1. 애플리케이션 및 환경 설정
# ----------------------------------------------------

# Flask 앱 초기화
app = Flask(__name__)

# 환경 변수에서 SECRET_KEY 로드 (보안을 위해 필수)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_super_secret_key_that_should_be_long_and_complex')

# 아임포트 환경 변수 설정
IMP_KEY = os.environ.get('IMP_KEY', 'REST_API_Key를_여기에_입력하세요')
IMP_SECRET = os.environ.get('IMP_SECRET', 'SECRET_Key를_여기에_입력하세요')
NICEPAY_MID = os.environ.get('NICEPAY_MID', 'NICEPAY_가맹점_ID_입력')
PAYMENT_AMOUNT = 5000  # 월 구독료 5000원

# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 라이브러리 초기화
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'
scheduler = APScheduler()

# ----------------------------------------------------
# 2. 모델 정의 (DB 테이블)
# ----------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_premium = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False) # ⬅️ 추가된 관리자 필드
    project_count = db.Column(db.Integer, default=0, nullable=False)
    # 구독 정보
    customer_uid = db.Column(db.String(200), unique=True, nullable=True) # 아임포트 빌링키 발급용 고유 ID
    subscription_active = db.Column(db.Boolean, default=False, nullable=False)
    subscription_expires = db.Column(db.DateTime, nullable=True)
    
    # 릴레이션: 사용자가 만든 프로젝트 목록
    projects = db.relationship('Project', backref='author', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', 'Premium: {self.is_premium}', 'Admin: {self.is_admin}')"

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_completed = db.Column(db.Boolean, default=False)
    # 외래 키: 어떤 사용자가 만든 프로젝트인지 연결
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Project('{self.title}', '{self.date_created}', 'Completed: {self.is_completed}')"

# ----------------------------------------------------
# 3. 로그인 매니저 및 유틸리티
# ----------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_iamport_token():
    """아임포트 액세스 토큰을 발급받아 반환합니다."""
    url = "https://api.iamport.kr/users/getToken"
    headers = {'Content-Type': 'application/json'}
    data = {
        'imp_key': IMP_KEY,
        'imp_secret': IMP_SECRET
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            return response.json()['response']['access_token']
        else:
            app.logger.error(f"아임포트 토큰 발급 실패: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"아임포트 토큰 발급 요청 오류: {e}")
        return None

def issue_new_subscription(user):
    """사용자의 is_premium, subscription_active 상태와 만료일을 업데이트합니다."""
    # 1. 상태 업데이트
    user.is_premium = True
    user.subscription_active = True
    
    # 2. 만료일 설정 (오늘로부터 한 달 뒤)
    user.subscription_expires = datetime.utcnow() + relativedelta(months=+1)
    
    # 3. DB 저장
    db.session.commit()
    app.logger.info(f"사용자 {user.username}의 구독이 성공적으로 시작/갱신되었습니다.")


def process_payment_schedule(user, token, merchant_uid, amount):
    """빌링키를 이용해 다음 달 결제를 예약 요청합니다."""
    url = "https://api.iamport.kr/subscribe/payments/again"
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    data = {
        'customer_uid': user.customer_uid, # 빌링키
        'merchant_uid': merchant_uid,     # 새롭게 생성할 거래 고유 ID
        'amount': amount,
        'name': '유료 비즈니스 앱 정기 구독 갱신',
        'buyer_email': user.email
    }
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response_data = response.json()

        if response_data.get('code') == 0:
            # 결제 성공
            app.logger.info(f"정기 결제 갱신 성공 (User: {user.username}, MID: {merchant_uid})")
            return True, "결제 성공"
        else:
            # 결제 실패 또는 에러
            app.logger.error(f"정기 결제 갱신 실패 (User: {user.username}): {response_data.get('message')}")
            return False, response_data.get('message', '알 수 없는 오류')
            
    except requests.exceptions.RequestException as e:
        app.logger.error(f"정기 결제 요청 오류 (User: {user.username}): {e}")
        return False, "요청 중 네트워크 오류 발생"


# ----------------------------------------------------
# 4. APScheduler 배경 작업
# ----------------------------------------------------

@scheduler.task('interval', id='check_subs', minutes=30, misfire_grace_time=900)
def check_and_renew_subscriptions():
    """
    30분마다 만료 예정인 구독을 확인하고 자동 결제를 시도하는 백그라운드 작업입니다.
    """
    with app.app_context():
        app.logger.info("--- 정기 구독 확인 작업 시작 ---")
        
        # 만료일이 오늘을 기준으로 7일 이내인 사용자들을 조회
        target_date = datetime.utcnow() + timedelta(days=7)
        
        # 구독 활성화 상태이고, 만료일이 target_date보다 빠른 사용자
        users_to_renew = User.query.filter(
            User.subscription_active == True,
            User.is_premium == True,
            User.subscription_expires < target_date,
            User.customer_uid.isnot(None) # 빌링키가 있는 사용자만 처리
        ).all()
        
        if not users_to_renew:
            app.logger.info("갱신 대상 사용자가 없습니다.")
            return

        token = get_iamport_token()
        if not token:
            app.logger.error("토큰 발급 실패로 갱신 작업을 진행할 수 없습니다.")
            return

        for user in users_to_renew:
            # 결제 시도: 매번 고유한 merchant_uid를 생성
            merchant_uid = f'renew_{user.id}_{datetime.now().strftime("%Y%m%d%H%M%S")}'
            
            success, message = process_payment_schedule(user, token, merchant_uid, PAYMENT_AMOUNT)
            
            if success:
                # 갱신 성공 시: 만료일을 한 달 연장합니다.
                user.subscription_expires = user.subscription_expires + relativedelta(months=+1)
                db.session.commit()
                app.logger.info(f"사용자 {user.username} 구독 만료일 갱신: {user.subscription_expires}")
            else:
                # 갱신 실패 시: is_premium 상태를 비활성화하고 알림 처리 
                user.is_premium = False
                user.subscription_active = False
                db.session.commit()
                app.logger.warning(f"사용자 {user.username} 정기 결제 갱신 실패! 구독이 해지되었습니다.")
                flash(f"정기 결제에 실패하여 프리미엄 구독이 해지되었습니다. ({message})", 'danger')

        app.logger.info("--- 정기 구독 확인 작업 완료 ---")


# ----------------------------------------------------
# 5. 라우트 정의
# ----------------------------------------------------

@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # 사용자 고유 ID (아임포트 빌링키 저장에 사용)
        customer_uid = f"user_{datetime.now().strftime('%Y%m%d%H%M%S')}_{email.replace('@', '_').replace('.', '-')}"
        
        user = User(username=username, email=email, password=hashed_password, customer_uid=customer_uid)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('회원가입이 완료되었습니다!', 'success')
            return redirect(url_for('login'))
        except:
            flash('이미 존재하는 사용자 이름 또는 이메일입니다.', 'danger')

    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('로그인 성공!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('로그인 실패. 이메일 또는 비밀번호를 확인하세요.', 'danger')

    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/pricing")
@login_required
def pricing():
    # 아임포트 설정 정보를 템플릿에 전달
    iamport_config = {
        'imp_key': IMP_KEY,
        'nicepay_mid': NICEPAY_MID,
        'payment_amount': PAYMENT_AMOUNT
    }
    return render_template('pricing.html', 
                           iamport_config=iamport_config,
                           user_email=current_user.email,
                           user_name=current_user.username)


@app.route("/payment_callback", methods=['POST'])
@login_required
def payment_callback():
    data = request.get_json() if request.is_json else request.form
    
    imp_uid = data.get('imp_uid')
    customer_uid = data.get('customer_uid')
    success = data.get('success') == 'true'

    if not success:
        flash("결제가 취소되었거나 실패했습니다.", 'warning')
        return jsonify({'redirect': url_for('pricing')})

    # 1. 아임포트 토큰 발급
    token = get_iamport_token()
    if not token:
        flash("결제 검증을 위한 토큰 발급에 실패했습니다.", 'danger')
        return jsonify({'redirect': url_for('pricing')})
    
    headers = { 'Authorization': token }
    
    # 2. 결제 정보 조회 (검증)
    url = f"https://api.iamport.kr/payments/{imp_uid}"
    response = requests.get(url, headers=headers)
    payment_data = response.json().get('response', {})
    
    if payment_data.get('status') == 'paid' and payment_data.get('amount') == PAYMENT_AMOUNT:
        # 3. DB 업데이트 및 빌링키 저장 요청
        user = current_user
        
        # 빌링키(customer_uid)를 아임포트에 저장 요청
        url_billkey = "https://api.iamport.kr/subscribe/customer/" + customer_uid
        requests.post(url_billkey, headers=headers, data=json.dumps({'card_uid': imp_uid}))
        
        # 구독 시작 처리
        issue_new_subscription(user)

        flash("결제가 성공적으로 확인되어 프리미엄 구독이 시작되었습니다! 이제 모든 프로젝트를 무제한으로 만드실 수 있습니다.", 'success')
        return jsonify({'redirect': url_for('premium_content')})
    else:
        # 결제 위변조 의심 (실제 금액과 다름) 또는 상태 이상
        flash("결제 검증에 실패했습니다. 관리자에게 문의하세요.", 'danger')
        # 필요하다면 결제 취소 API 호출 (예시에서는 생략)
        return jsonify({'redirect': url_for('pricing')})


@app.route("/premium")
@login_required
def premium_content():
    if current_user.is_premium:
        return render_template('premium.html')
    else:
        flash("프리미엄 구독자만 접근할 수 있습니다.", 'warning')
        return redirect(url_for('pricing'))


@app.route("/limit_reached")
@login_required
def limit_reached():
    return render_template('limit_reached.html')


# ----------------------------------------------------
# 6. 프로젝트 관리 라우트
# ----------------------------------------------------

@app.route("/projects")
@login_required
def list_projects():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.date_created.desc()).all()
    return render_template('projects.html', projects=projects)

@app.route("/project/new", methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        # 프리미엄 체크: 10개 초과 && 프리미엄이 아닐 때 접근 제한
        if current_user.project_count >= 10 and not current_user.is_premium:
            flash("일반 사용자는 프로젝트를 10개까지만 만들 수 있습니다. 프리미엄으로 업그레이드하세요.", 'danger')
            return redirect(url_for('limit_reached'))

        title = request.form.get('title')
        content = request.form.get('content')
        
        project = Project(title=title, content=content, user_id=current_user.id)
        
        db.session.add(project)
        current_user.project_count += 1 # 프로젝트 개수 증가
        db.session.commit()
        
        flash('새 프로젝트가 생성되었습니다.', 'success')
        return redirect(url_for('list_projects'))
    
    return render_template('edit_project.html', title='새 프로젝트 생성', project=None)

@app.route("/project/<int:project_id>")
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    if project.author != current_user:
        flash('접근 권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))
    return render_template('project_detail.html', project=project)

@app.route("/project/<int:project_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.author != current_user:
        flash('수정 권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))

    if request.method == 'POST':
        project.title = request.form.get('title')
        project.content = request.form.get('content')
        project.is_completed = 'is_completed' in request.form 
        db.session.commit()
        flash('프로젝트가 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('project_detail', project_id=project.id))
    
    return render_template('edit_project.html', title='프로젝트 수정', project=project)

@app.route("/project/<int:project_id>/delete", methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.author != current_user:
        flash('삭제 권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))

    db.session.delete(project)
    current_user.project_count -= 1 # 프로젝트 개수 감소
    db.session.commit()
    flash('프로젝트가 삭제되었습니다.', 'success')
    return redirect(url_for('list_projects'))

@app.route("/project/<int:project_id>/toggle_complete", methods=['POST'])
@login_required
def toggle_complete(project_id):
    project = Project.query.get_or_404(project_id)
    if project.author != current_user:
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))
        
    project.is_completed = not project.is_completed
    db.session.commit()
    flash('프로젝트 상태가 변경되었습니다.', 'info')
    return redirect(url_for('project_detail', project_id=project.id))


# ----------------------------------------------------
# 7. 관리자 페이지 라우트
# ----------------------------------------------------

def admin_required(f):
    """관리자 권한이 있는 사용자만 접근 가능하도록 하는 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('관리자만 접근할 수 있습니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)


# ----------------------------------------------------
# 8. 애플리케이션 실행
# ----------------------------------------------------

# Waitress/Gunicorn 사용 시 스케줄러 초기화 (ConflictingIdError 방지)
with app.app_context():
    # DB 테이블이 없으면 생성 (Waitress 실행 전에 한 번은 필요)
    db.create_all()

if not scheduler.running:
    existing_jobs = scheduler.get_jobs()
    job_ids = [job.id for job in existing_jobs]
    
    # 'check_subs' 작업이 등록되어 있지 않을 때만 추가
    if 'check_subs' not in job_ids:
        scheduler.add_job(id='check_subs', func=check_and_renew_subscriptions, trigger='interval', minutes=30)
    
    scheduler.init_app(app)
    
    # 스케줄러가 정지 상태일 때만 시작
    # (APScheduler.state 0: STATE_STOPPED)
    if scheduler.state == 0: 
        scheduler.start()