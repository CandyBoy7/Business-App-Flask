# app.py

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, 
    UserMixin, 
    login_user, 
    current_user, 
    logout_user, 
    login_required
)
from flask_apscheduler import APScheduler
from dateutil.relativedelta import relativedelta
from datetime import datetime, timedelta, date 
import os # 환경 변수를 사용하기 위해 os 모듈 import
import requests 

# --- 1. Flask 앱 및 설정 ---
app = Flask(__name__)
# SECRET_KEY를 환경 변수에서 가져오고, 없으면 개발용 임시값 사용
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secure_and_random_ascii_key_for_flask') 

# --- 2. 데이터베이스 및 확장 기능 초기화 ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

scheduler = APScheduler()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 3. 아임포트(I'mport) 설정 ---
# imp_key와 imp_secret을 환경 변수에서 가져오고, 없으면 임시 문자열 사용
IAMPORT_CONFIG = {
    "imp_key": os.environ.get("IMP_KEY", "REST_API_Key를_여기에_입력하세요"), 
    "imp_secret": os.environ.get("IMP_SECRET", "REST_API_Secret을_여기에_입력하세요"), 
    "nicepay_mid": "gkdlvj046m", 
    "payment_amount": 5000 
}


# --- 4. 데이터베이스 모델 정의 ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False) 
    is_premium = db.Column(db.Boolean, default=False, nullable=False) 
    billing_key = db.Column(db.String(100), nullable=True) 
    subscription_expires = db.Column(db.DateTime, nullable=True) 

    def __repr__(self):
        return f"User('{self.username}', 'Premium: {self.is_premium}')"

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    author = db.relationship('User', backref=db.backref('projects', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"Project('{self.title}', User ID: {self.user_id}')"

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_complete = db.Column(db.Boolean, default=False)
    priority = db.Column(db.Integer, default=1, nullable=False) 
    due_date = db.Column(db.Date, nullable=True) 
    
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False) 
    project = db.relationship('Project', backref=db.backref('tasks', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"Task('{self.content}', Priority: {self.priority}, Complete: {self.is_complete}')"

# ----------------------------------------------------

# --- 5. 아임포트 전용 함수 (변경 없음) ---

def get_iamport_token():
    """아임포트 API 호출을 위한 액세스 토큰을 발급받습니다."""
    url = "https://api.iamport.kr/users/getToken"
    headers = {"Content-Type": "application/json"}
    data = {
        "imp_key": IAMPORT_CONFIG["imp_key"],
        "imp_secret": IAMPORT_CONFIG["imp_secret"]
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()['response']['access_token']
    except requests.RequestException as e:
        print(f"아임포트 토큰 발급 오류: {e}")
        return None

def get_billing_key(customer_uid):
    """아임포트 API를 통해 빌링키 정보를 조회합니다."""
    access_token = get_iamport_token()
    if not access_token:
        return None

    url = f"https://api.iamport.kr/customer/{customer_uid}"
    headers = {"Authorization": access_token}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data['code'] == 0 and data['response'] and data['response'].get('card_name'):
            return data['response']['customer_uid'] 
        return None
    except requests.RequestException as e:
        print(f"빌링키 조회 오류: {e}")
        return None

def request_subscription_payment(user_id, customer_uid, amount):
    """빌링키를 사용하여 사용자에게 정기 결제를 요청합니다."""
    access_token = get_iamport_token()
    if not access_token:
        return False, "토큰 발급 실패"

    url = "https://api.iamport.kr/subscribe/payments/again"
    merchant_uid = f"MUID_RENEW_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

    headers = {
        "Authorization": access_token,
        "Content-Type": "application/json"
    }
    data = {
        "customer_uid": customer_uid, 
        "merchant_uid": merchant_uid, 
        "amount": amount,
        "name": "프리미엄 구독 자동 갱신 결제",
        "buyer_name": User.query.get(user_id).username
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        payment_data = response.json()['response']

        if payment_data.get('status') == 'paid' and payment_data.get('amount') == amount:
            return True, "결제 성공"
        else:
            return False, f"결제 실패: {payment_data.get('fail_reason', 'PG사 응답 오류')}"
            
    except requests.RequestException as e:
        print(f"자동 결제 요청 오류: {e}")
        return False, "API 통신 오류"

def check_and_renew_subscriptions():
    """만료일이 임박한 유저를 찾아 정기 결제를 시도합니다."""
    one_week_later = datetime.utcnow() + timedelta(days=7)
    
    users_to_renew = User.query.filter(
        User.is_premium == True,
        User.billing_key.isnot(None), 
        User.subscription_expires <= one_week_later
    ).all()
    
    if not users_to_renew:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 갱신 대상 사용자 없음.")
        return

    print(f"[{datetime.now().strftime('%H:%M:%S')}] {len(users_to_renew)}명 갱신 시도.")
    
    for user in users_to_renew:
        success, message = request_subscription_payment(
            user.id, 
            user.billing_key, 
            IAMPORT_CONFIG["payment_amount"]
        )
        
        if success:
            user.subscription_expires = user.subscription_expires + relativedelta(months=1)
            db.session.commit()
            print(f"✅ 유저 {user.username} 구독 갱신 성공. 다음 만료일: {user.subscription_expires.strftime('%Y-%m-%d')}")
        else:
            user.is_premium = False
            user.billing_key = None 
            db.session.commit()
            print(f"❌ 유저 {user.username} 구독 갱신 실패: {message}. 프리미엄 해제 처리됨.")

# ----------------------------------------------------

# --- 6. 사용자 인증 경로 (변경 없음) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user = User(username=username, email=email, password=hashed_password, is_premium=False)
        db.session.add(user)
        db.session.commit()
        
        flash('회원가입이 완료되었습니다. 로그인해 주세요!', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('로그인 실패. 이메일 또는 비밀번호를 확인해 주세요.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('성공적으로 로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

# ----------------------------------------------------

# --- 7. 아임포트 결제 경로 (변경 없음) ---

@app.route('/payment-callback', methods=['POST'])
@login_required
def payment_callback():
    imp_uid = request.form.get('imp_uid')
    customer_uid = request.form.get('customer_uid') 
    pay_success = request.form.get('success')

    if pay_success == 'true':
        access_token = get_iamport_token()
        if not access_token:
            flash('결제 검증 실패: 서버 인증 오류.', 'danger')
            return redirect(url_for('pricing'))
        
        url = f"https://api.iamport.kr/payments/{imp_uid}"
        headers = {"Authorization": access_token, "Content-Type": "application/json"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            payment_data = response.json()['response']
            
            if payment_data['status'] == 'paid' and payment_data['amount'] == IAMPORT_CONFIG["payment_amount"]:
                billing_key_check = get_billing_key(customer_uid)

                if billing_key_check:
                    current_user.is_premium = True
                    current_user.billing_key = customer_uid
                    
                    one_month_later = datetime.utcnow() + relativedelta(months=1) 
                    current_user.subscription_expires = one_month_later
                    
                    db.session.commit()
                    flash("🎉 정기 구독 결제가 성공적으로 처리되었으며, 빌링키가 저장되었습니다!", 'success')
                    return redirect(url_for('list_projects'))
                else:
                    flash('결제는 성공했으나, 정기 결제를 위한 카드 정보(빌링키) 저장에 실패했습니다.', 'danger')
                    return redirect(url_for('pricing'))

            else:
                flash('결제 검증 실패: 금액이 일치하지 않습니다.', 'danger')
                return redirect(url_for('pricing'))

        except requests.RequestException:
            flash('결제 검증 실패: 아임포트 API 통신 오류.', 'danger')
            return redirect(url_for('pricing'))
            
    else:
        flash('결제가 취소되었거나 실패했습니다.', 'warning')
        return redirect(url_for('pricing'))

# ----------------------------------------------------

# --- 8. 앱 핵심 기능 경로 (프로젝트 및 Task 관리) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/premium')
@login_required
def premium_content():
    if current_user.is_premium:
        return render_template('premium.html', user=current_user.username)
    else:
        flash('프리미엄 콘텐츠를 이용하려면 구독이 필요합니다.', 'warning')
        return redirect(url_for('pricing'))

@app.route('/pricing')
def pricing():
    return render_template('pricing.html', 
                           iamport_config=IAMPORT_CONFIG,
                           user_email=current_user.email if current_user.is_authenticated else 'guest@example.com',
                           user_name=current_user.username if current_user.is_authenticated else '고객')


@app.route('/create_project', methods=['GET'])
@login_required
def create_project():
    project_count = Project.query.filter_by(user_id=current_user.id).count()
    FREE_LIMIT = 1 

    if not current_user.is_premium and project_count >= FREE_LIMIT:
        return render_template('limit_reached.html', limit=FREE_LIMIT)
    
    new_project = Project(
        title=f"프로젝트 {project_count + 1}", 
        description="새로운 업무를 시작합니다.", 
        user_id=current_user.id
    )
    
    db.session.add(new_project)
    db.session.commit()
    
    # 프로젝트 생성 후 상세 페이지로 즉시 리다이렉션
    flash(f'새 프로젝트 "{new_project.title}"가 생성되었습니다.', 'success')
    return redirect(url_for('project_detail', project_id=new_project.id)) 

@app.route('/projects')
@login_required
def list_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    return render_template('projects.html', projects=projects, user=current_user)


@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('접근 권한이 없는 프로젝트입니다.', 'danger')
        return redirect(url_for('list_projects'))
    
    tasks = project.tasks
    
    total_tasks = len(tasks)
    completed_tasks = sum(1 for task in tasks if task.is_complete)
    completion_rate = f"{int(completed_tasks / total_tasks * 100)}%" if total_tasks > 0 else "0%"
    
    return render_template('project_detail.html', 
                           project=project, 
                           tasks=tasks, 
                           completion_rate=completion_rate)


@app.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('접근 권한이 없는 프로젝트입니다.', 'danger')
        return redirect(url_for('list_projects'))
    
    if request.method == 'POST':
        project.title = request.form.get('title')
        project.description = request.form.get('description')
        
        db.session.commit()
        flash('프로젝트가 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('project_detail', project_id=project.id))

    return render_template('edit_project.html', project=project)


@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)

    if project.user_id != current_user.id:
        flash('접근 권한이 없는 프로젝트입니다.', 'danger')
        return redirect(url_for('list_projects'))

    try:
        db.session.delete(project)
        db.session.commit()
        flash(f'프로젝트 "{project.title}"가 완전히 삭제되었습니다.', 'success')
    except Exception as e:
        flash(f'프로젝트 삭제 중 오류가 발생했습니다: {e}', 'danger')
    
    return redirect(url_for('list_projects'))


@app.route('/project/<int:project_id>/add_task', methods=['POST'])
@login_required
def add_task(project_id):
    project = Project.query.get_or_404(project_id)

    if project.user_id != current_user.id:
        flash('접근 권한이 없는 프로젝트입니다.', 'danger')
        return redirect(url_for('list_projects'))
    
    if request.method == 'POST':
        task_content = request.form.get('content')
        task_priority = int(request.form.get('priority', 1)) 
        due_date_str = request.form.get('due_date') 

        task_due_date = None
        if due_date_str:
            try:
                task_due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date() 
            except ValueError:
                flash('마감일 형식이 올바르지 않습니다.', 'danger')
                return redirect(url_for('project_detail', project_id=project.id))

        if task_content:
            task = Task(
                content=task_content, 
                project_id=project.id,
                priority=task_priority,
                due_date=task_due_date
            )
            db.session.add(task)
            db.session.commit()
            flash('새 할 일이 추가되었습니다.', 'success')
        else:
            flash('할 일 내용을 입력해 주세요.', 'danger')
    
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/task/<int:task_id>/edit', methods=['POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    project = task.project
    
    if project.user_id != current_user.id:
        flash('접근 권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))

    if request.method == 'POST':
        task_content = request.form.get('content')
        task_priority = int(request.form.get('priority', task.priority)) 
        due_date_str = request.form.get('due_date')
        
        task_due_date = None
        if due_date_str:
            try:
                task_due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('마감일 형식이 올바르지 않습니다.', 'danger')
                return redirect(url_for('project_detail', project_id=project.id))
        elif due_date_str == '':
             # 입력 필드가 빈 문자열로 넘어오면 마감일 제거
             task_due_date = None
        else:
             # 입력 필드가 없으면 기존 값 유지
             task_due_date = task.due_date 
        
        if task_content:
            task.content = task_content
            task.priority = task_priority
            task.due_date = task_due_date
            
            db.session.commit()
            flash('할 일이 성공적으로 수정되었습니다.', 'success')
        else:
            flash('할 일 내용을 비워둘 수 없습니다.', 'danger')
    
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/task/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    project = task.project
    
    if project.user_id != current_user.id:
        flash('접근 권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))
    
    task.is_complete = not task.is_complete
    db.session.commit()
    
    status = "완료" if task.is_complete else "미완료"
    flash(f'"{task.content}" 항목이 {status} 처리되었습니다.', 'info')
    
    return redirect(request.referrer or url_for('project_detail', project_id=project.id))


@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    project = task.project
    
    if project.user_id != current_user.id:
        flash('접근 권한이 없습니다.', 'danger')
        return redirect(url_for('list_projects'))
    
    db.session.delete(task)
    db.session.commit()
    flash(f'"{task.content}" 항목이 삭제되었습니다.', 'success')
    
    return redirect(request.referrer or url_for('project_detail', project_id=project.id))

# ----------------------------------------------------

# --- 9. 앱 실행 및 초기 데이터 설정 (스케줄러 시작) ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if User.query.count() == 0:
            hashed_pw = bcrypt.generate_password_hash('1234').decode('utf-8')
            future_date = datetime.utcnow() + relativedelta(years=1)
            
            premium_user = User(username='user_a', email='a@premium.com', password=hashed_pw, is_premium=True, subscription_expires=future_date)
            free_user = User(username='user_b', email='b@free.com', password=hashed_pw, is_premium=False)

            db.session.add(premium_user)
            db.session.add(free_user)
            db.session.commit()
            print("테스트 사용자 데이터베이스에 삽입 완료. (ID 1: 유료, ID 2: 무료. 비밀번호: 1234)")

    scheduler.add_job(id='check_subs', func=check_and_renew_subscriptions, trigger='interval', minutes=30)
    scheduler.init_app(app)
    scheduler.start()

    app.run(debug=True)