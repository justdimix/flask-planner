import os
import math
import uuid
import json
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta, date, time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dateutil.relativedelta import relativedelta

# --- 1. Flask Application Setup ---
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# --- 2. Database & Config ---
app.config['SECRET_KEY'] = 'This should be a long, random, and SECRET string'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Uploads
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'news_pics'), exist_ok=True)

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "200 per hour"],
    storage_uri="memory://"
)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- 3. Model Definitions ---

# Association table for Resource Visibility
resource_visibility = db.Table('resource_visibility',
                               db.Column('resource_id', db.Integer, db.ForeignKey('resource.id'), primary_key=True),
                               db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
                               )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # Roles
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)

    admin_notes = db.Column(db.Text, nullable=True)

    # Profile fields
    full_name = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    work_status = db.Column(db.String(50), default='Office')
    about_me = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.String(150), nullable=False, default='default.jpg')

    tasks = db.relationship('Task', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    logs = db.relationship('AuditLog', backref='actor', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(200), nullable=True)

    # Tasks linked to this resource
    tasks = db.relationship('Task', backref='resource_obj', lazy='dynamic', cascade="all, delete-orphan")

    # Visibility: Which users can see this resource (Many-to-Many)
    # If empty, visible to everyone. Super Admin always sees all.
    allowed_users = db.relationship('User', secondary=resource_visibility,
                                    backref=db.backref('visible_resources', lazy='dynamic'))


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_admin_task = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    task_group_id = db.Column(db.String(36), nullable=True)
    color = db.Column(db.String(7), default='#ffffff')

    recurrence = db.Column(db.String(20), default='none')
    recurrence_end = db.Column(db.DateTime, nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=True)

    def __repr__(self):
        return f'<Task {self.title}>'


class NewsPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    image_filename = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class EventSummary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    image_filename = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(140), nullable=True)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --- 4. User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- 5. Helper Functions ---

def log_action(user_id, action, details=None):
    try:
        log = AuditLog(user_id=user_id, action=action, details=details)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Logging error: {e}")
        db.session.rollback()


def get_visible_resources(user):
    """Returns list of resources visible to the user"""
    all_resources = Resource.query.all()
    if user.is_super_admin:
        return all_resources

    visible = []
    for res in all_resources:
        # If allowed_users is empty, it's public. Otherwise check membership.
        if not res.allowed_users or user in res.allowed_users:
            visible.append(res)
    return visible


def split_task_logic(title, description, start_dt, end_dt, target_id, is_global, color='#ffffff',
                     external_group_id=None, recurrence='none', recurrence_end=None, is_resource=False):
    current_start = start_dt
    created_tasks = []
    group_id = external_group_id if external_group_id else str(uuid.uuid4())

    if current_start >= end_dt: return 0

    while current_start < end_dt:
        day_start_bound = datetime.combine(current_start.date(), time(7, 0))
        day_end_bound = datetime.combine(current_start.date(), time(21, 0))

        chunk_start = max(current_start, day_start_bound)
        chunk_end = min(end_dt, day_end_bound)

        if chunk_start < chunk_end:
            new_task = Task(
                title=title,
                description=description,
                start_time=chunk_start,
                end_time=chunk_end,
                is_admin_task=is_global if not is_resource else False,
                created_at=datetime.utcnow(),
                task_group_id=group_id,
                color=color,
                recurrence=recurrence,
                recurrence_end=recurrence_end
            )

            if is_resource:
                new_task.resource_id = target_id
                new_task.user_id = None
            else:
                new_task.user_id = target_id
                new_task.resource_id = None

            db.session.add(new_task)
            created_tasks.append(new_task)

        next_day = current_start.date() + timedelta(days=1)
        current_start = datetime.combine(next_day, time(7, 0))

        if (current_start - start_dt).days > 60: break

    if not created_tasks:
        fallback = Task(
            title=title, description=description, start_time=start_dt, end_time=end_dt,
            is_admin_task=is_global if not is_resource else False,
            created_at=datetime.utcnow(), task_group_id=group_id, color=color,
            recurrence=recurrence, recurrence_end=recurrence_end
        )
        if is_resource:
            fallback.resource_id = target_id
            fallback.user_id = None
        else:
            fallback.user_id = target_id
            fallback.resource_id = None

        db.session.add(fallback)
        created_tasks.append(fallback)

    db.session.commit()
    return len(created_tasks)


@app.route('/update_resource/<int:id>', methods=['POST'])
@login_required
def update_resource(id):
    # Проверка прав администратора
    if not current_user.is_admin:
        flash("Unauthorized", "error")
        return redirect(url_for('resources_list'))

    resource = Resource.query.get_or_404(id)

    # Получаем данные из формы
    name = request.form.get('name')
    description = request.form.get('description')

    if name:
        resource.name = name
    if description is not None:
        resource.description = description

    # --- ИСПРАВЛЕННАЯ ЛОГИКА ВИДИМОСТИ ---
    visible_user_ids_raw = request.form.get('visible_user_ids')

    # Очищаем список
    resource.allowed_users = []

    # Сценарий 1: Глобальный доступ (пришло 'all')
    # Оставляем список пустым (в вашей системе пустой = виден всем)
    if visible_user_ids_raw == 'all':
        pass

        # Сценарий 2: Ограниченный или Приватный доступ
    else:
        try:
            import json
            user_ids = json.loads(visible_user_ids_raw)

            # Добавляем выбранных пользователей
            for uid in user_ids:
                user = User.query.get(uid)
                if user:
                    resource.allowed_users.append(user)

            # !!! ФИКС !!!
            # Если список все еще пуст (выбрали "Private"),
            # обязательно добавляем админа, чтобы список НЕ был пустым.
            # Иначе система посчитает ресурс глобальным.
            if not resource.allowed_users:
                resource.allowed_users.append(current_user)

        except Exception as e:
            flash("Error parsing user selection", "error")
            print(f"Debug Error: {e}")

    # Сохраняем
    try:
        db.session.commit()
        flash("Resource updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error updating resource.", "error")

    return redirect(url_for('resources_list'))
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('calendar_view'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated: return redirect(url_for('calendar_view'))
    if request.method == 'POST':
        username_or_email = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
        login_user(user, remember=True)
        log_action(user.id, 'LOGIN', 'User logged in')
        flash('You have successfully logged in!', 'success')
        return redirect(url_for('calendar_view'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("11 per hour")
def register():
    if current_user.is_authenticated: return redirect(url_for('calendar_view'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not (username and email and password): return redirect(url_for('register'))
        if User.query.filter((User.username == username) | (User.email == email)).first(): return redirect(
            url_for('register'))
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        if User.query.count() == 0: new_user.is_admin = True; new_user.is_super_admin = True
        try:
            db.session.add(new_user)
            db.session.commit()
            log_action(new_user.id, 'REGISTER', f'New user: {username}')
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            return redirect(url_for('register'))
    return render_template('register.html')


@app.route('/profile', defaults={'user_id': None}, methods=['GET', 'POST'])
@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id):
    if user_id and current_user.is_admin:
        target_user = db.session.get(User, int(user_id))
        if not target_user:
            flash('User not found.', 'error')
            return redirect(url_for('admin_dashboard'))
    else:
        target_user = current_user
    is_self = (target_user.id == current_user.id)
    can_edit_info = is_self or current_user.is_super_admin
    can_change_status = is_self or current_user.is_super_admin
    if request.method == 'POST':
        if not can_edit_info:
            flash('Permission denied.', 'error')
            return redirect(url_for('profile', user_id=target_user.id))
        username = request.form.get('username')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        about_me = request.form.get('about_me')
        if can_change_status:
            work_status = request.form.get('work_status')
            if work_status: target_user.work_status = work_status
        if username: target_user.username = username
        if email: target_user.email = email
        if full_name: target_user.full_name = full_name
        if phone: target_user.phone = phone
        if about_me is not None: target_user.about_me = about_me
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{target_user.id}_{uuid.uuid4().hex[:8]}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', unique_filename))
                target_user.profile_pic = unique_filename
        try:
            db.session.commit()
            log_action(current_user.id, 'PROFILE_UPDATE', f'Updated profile {target_user.username}')
            flash(f'Profile updated successfully!', 'success')
            if user_id: return redirect(url_for('profile', user_id=target_user.id))
            return redirect(url_for('profile'))
        except IntegrityError:
            db.session.rollback()
    return render_template('profile.html', user=target_user, can_edit=can_edit_info,
                           can_change_status=can_change_status)


@app.route('/reset_profile_pic', methods=['POST'])
@login_required
def reset_profile_pic():
    user_id = request.form.get('user_id')
    if user_id:
        target_user = db.session.get(User, int(user_id))
        if not target_user: return redirect(url_for('profile'))
        if not current_user.is_admin and current_user.id != target_user.id:
            return redirect(url_for('profile', user_id=target_user.id))
    else:
        target_user = current_user
    target_user.profile_pic = 'default.jpg'
    db.session.commit()
    log_action(current_user.id, 'RESET_PIC', f'Reset avatar for {target_user.username}')
    flash('Profile picture reset.', 'success')
    if target_user.id != current_user.id: return redirect(url_for('profile', user_id=target_user.id))
    return redirect(url_for('profile'))


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    new_password = request.form.get('new_password')
    if not new_password: return redirect(url_for('calendar_view'))
    current_user.set_password(new_password)
    db.session.commit()
    log_action(current_user.id, 'PASSWORD_CHANGE', 'User changed their own password')
    flash('Password updated.', 'success')
    return redirect(url_for('calendar_view'))


@app.route('/add_task', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def add_task():
    # ... (same) ...
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        color = request.form.get('color', '#ffffff')
        recurrence = request.form.get('recurrence', 'none')
        recurrence_end_str = request.form.get('recurrence_end')
        target_user_id = request.form.get('target_user_id')
        target_resource_id_hidden = request.form.get('target_resource_id')
        assignment_mode = request.form.get('assignment_mode', 'me')
        target_ids = []
        resource_ids = []
        is_global = False
        if not current_user.is_admin:
            target_ids = [current_user.id]
        else:
            if target_resource_id_hidden:
                resource_ids.append(int(target_resource_id_hidden))
            else:
                if assignment_mode == 'all_users':
                    is_global = True; target_ids = [current_user.id]
                elif assignment_mode == 'all_admins':
                    admins = User.query.filter_by(is_admin=True).all()
                    target_ids = [u.id for u in admins]
                elif assignment_mode == 'custom':
                    custom_user_ids = request.form.getlist('selected_users')
                    target_ids = [int(uid) for uid in custom_user_ids]
                    custom_res_ids = request.form.getlist('selected_resources')
                    resource_ids = [int(rid) for rid in custom_res_ids]
                    if not target_ids and not resource_ids: return redirect(url_for('calendar_view'))
                else:
                    target_user_id = request.form.get('target_user_id')
                    if target_user_id:
                        target_ids = [int(target_user_id)]
                    else:
                        target_ids = [current_user.id]
        try:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')
            recurrence_end = None
            if recurrence != 'none' and recurrence_end_str: recurrence_end = datetime.strptime(recurrence_end_str,
                                                                                               '%Y-%m-%d')
            if start_time >= end_time: return redirect(url_for('calendar_view'))
        except ValueError:
            return redirect(url_for('calendar_view'))

        def create_tasks_for_target(t_id, is_res=False):
            series_group_id = str(uuid.uuid4())
            curr_start = start_time
            curr_end = end_time
            while True:
                split_task_logic(title, description, curr_start, curr_end, t_id, is_global, color, series_group_id,
                                 recurrence, recurrence_end, is_res)
                if recurrence == 'none': break
                if recurrence == 'daily':
                    curr_start += timedelta(days=1); curr_end += timedelta(days=1)
                elif recurrence == 'weekly':
                    curr_start += timedelta(weeks=1); curr_end += timedelta(weeks=1)
                elif recurrence == 'monthly':
                    curr_start += relativedelta(months=1); curr_end += relativedelta(months=1)
                if recurrence_end and curr_start.date() > recurrence_end.date(): break
                if (curr_start - start_time).days > 365: break

        for uid in target_ids: create_tasks_for_target(uid, is_res=False)
        for rid in resource_ids: create_tasks_for_target(rid, is_res=True)
        log_action(current_user.id, 'TASK_CREATE', f'Created task "{title}"')
        flash(f'Tasks created successfully.', 'success')
        if resource_ids and len(resource_ids) == 1 and not target_ids: return redirect(
            url_for('view_resource_calendar', id=resource_ids[0]))
        if current_user.is_admin and len(target_ids) == 1 and target_ids[0] != current_user.id: return redirect(
            url_for('admin_view_user', user_id=target_ids[0]))
        return redirect(url_for('calendar_view'))
    return redirect(url_for('calendar_view'))


@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    if task_id == 0:
        if request.form.get('action') == 'delete_self':
            if current_user.is_super_admin: return redirect(url_for('profile'))
            user = current_user
            logout_user()
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for('home'))
        return redirect(url_for('calendar_view'))
    task = db.session.get(Task, task_id)
    if not task: return redirect(url_for('calendar_view'))
    if task.resource_id and not current_user.is_admin: return redirect(url_for('calendar_view'))
    if not task.resource_id and not current_user.is_admin and task.user_id != current_user.id: return redirect(
        url_for('calendar_view'))
    owner_id = task.user_id
    resource_id = task.resource_id
    group_id = task.task_group_id
    if group_id:
        Task.query.filter_by(task_group_id=group_id).delete()
    else:
        db.session.delete(task)
    db.session.commit()
    log_action(current_user.id, 'TASK_DELETE', f'Deleted task')
    flash('Task deleted.', 'success')
    if resource_id: return redirect(url_for('view_resource_calendar', id=resource_id))
    if current_user.is_admin and owner_id != current_user.id: return redirect(
        url_for('admin_view_user', user_id=owner_id))
    return redirect(url_for('calendar_view'))


@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = db.session.get(Task, task_id)
    if not task: return redirect(url_for('calendar_view'))
    if task.resource_id and not current_user.is_admin: return redirect(url_for('calendar_view'))
    if not task.resource_id and not current_user.is_admin and task.user_id != current_user.id: return redirect(
        url_for('calendar_view'))
    if not current_user.is_admin and task.is_admin_task: return redirect(url_for('calendar_view'))
    group_id = task.task_group_id
    full_start_time = task.start_time
    full_end_time = task.end_time
    if group_id:
        group_tasks = Task.query.filter_by(task_group_id=group_id).order_by(Task.start_time).all()
        if group_tasks: full_start_time = group_tasks[0].start_time; full_end_time = group_tasks[-1].end_time
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_str = request.form.get('start_time')
        end_str = request.form.get('end_time')
        color = request.form.get('color')
        try:
            new_start = datetime.strptime(start_str, '%Y-%m-%dT%H:%M')
            new_end = datetime.strptime(end_str, '%Y-%m-%dT%H:%M')
            if new_start >= new_end: return render_template('edit_task.html', task=task, full_start_time=new_start,
                                                            full_end_time=new_end)
            owner_id = task.user_id
            res_id = task.resource_id
            is_global = task.is_admin_task
            if group_id:
                Task.query.filter_by(task_group_id=group_id).delete()
            else:
                db.session.delete(task)
            target = res_id if res_id else owner_id
            is_res = True if res_id else False
            split_task_logic(title, description, new_start, new_end, target, is_global, color, is_resource=is_res)
            db.session.commit()
            log_action(current_user.id, 'TASK_EDIT', f'Edited task "{title}"')
            flash('Task updated.', 'success')
            if res_id: return redirect(url_for('view_resource_calendar', id=res_id))
            if current_user.is_admin and owner_id != current_user.id: return redirect(
                url_for('admin_view_user', user_id=owner_id))
            return redirect(url_for('calendar_view'))
        except ValueError:
            flash('Invalid date.', 'error')
    return render_template('edit_task.html', task=task, full_start_time=full_start_time, full_end_time=full_end_time)


@app.route('/calendar')
@login_required
def calendar_view():
    all_users = []
    all_resources = []
    if current_user.is_admin:
        all_users = User.query.all()
        all_users.sort(key=lambda u: (not u.is_super_admin, not u.is_admin, u.username.lower()))
        all_resources = get_visible_resources(current_user)
    offset = request.args.get('offset', 0, type=int)
    return render_calendar_for_user(current_user, all_users=all_users, all_resources=all_resources, offset=offset)


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('calendar_view'))
    search_query = request.args.get('q', '')
    if search_query:
        users = User.query.filter(User.username.ilike(f'%{search_query}%')).all()
    else:
        users = User.query.all()
    users.sort(key=lambda u: (not u.is_super_admin, not u.is_admin, u.username.lower()))
    return render_template('admin.html', users=users, search_query=search_query)


# ... (admin/news routes) ...
@app.route('/admin/logs')
@login_required
def admin_logs():
    if not current_user.is_super_admin: return redirect(url_for('admin_dashboard'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template('audit_logs.html', logs=logs)


@app.route('/admin/save_notes', methods=['POST'])
@login_required
def save_user_notes():
    if not current_user.is_admin: return redirect(url_for('home'))
    user_id = request.form.get('user_id')
    notes = request.form.get('admin_notes')
    user = db.session.get(User, int(user_id))
    if user:
        user.admin_notes = notes
        db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_status(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))
    if user_id == current_user.id: return redirect(url_for('admin_dashboard'))
    if user.is_admin and not current_user.is_super_admin: return redirect(url_for('admin_dashboard'))
    user.is_admin = not user.is_admin
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    if user_id == current_user.id: return redirect(url_for('admin_dashboard'))
    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))
    if user.is_super_admin: return redirect(url_for('admin_dashboard'))
    if user.is_admin and not current_user.is_super_admin: return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))
    if (user.is_admin or user.is_super_admin) and not current_user.is_super_admin: return redirect(
        url_for('admin_dashboard'))
    user.set_password('1234')
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/view/<int:user_id>')
@login_required
def admin_view_user(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))
    offset = request.args.get('offset', 0, type=int)
    all_users = User.query.all()
    all_resources = get_visible_resources(current_user)
    return render_calendar_for_user(user, viewed_by_admin=True, all_users=all_users, all_resources=all_resources,
                                    offset=offset)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# --- RESOURCES ROUTES (UPDATED) ---
@app.route('/resources')
@login_required
def resources_list():
    all_users = []
    if current_user.is_admin:  # Changed to allow admins to see user list for resource perm
        all_users = User.query.all()
        all_users.sort(key=lambda u: u.username.lower())
    visible_resources = get_visible_resources(current_user)
    return render_template('resources.html', resources=visible_resources, all_users=all_users)


@app.route('/resources/add', methods=['POST'])
@login_required
def add_resource():
    if not current_user.is_admin:  # Changed to is_admin
        flash('Access denied.', 'error')
        return redirect(url_for('resources_list'))

    name = request.form.get('name')
    description = request.form.get('description')

    if name:
        try:
            res = Resource(name=name, description=description)
            # Add Allowed Users Logic for Create
            allowed_ids = request.form.getlist('allowed_users')
            for uid in allowed_ids:
                user = db.session.get(User, int(uid))
                if user: res.allowed_users.append(user)

            db.session.add(res)
            db.session.commit()
            log_action(current_user.id, 'RESOURCE_CREATE', f'Created resource {name}')
            flash('Resource created.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Resource name already exists.', 'error')
    return redirect(url_for('resources_list'))


@app.route('/resources/edit/<int:id>', methods=['POST'])
@login_required
def edit_resource(id):
    if not current_user.is_admin:  # Changed to is_admin
        flash('Access denied.', 'error')
        return redirect(url_for('resources_list'))

    res = db.session.get(Resource, id)
    if res:
        name = request.form.get('name')
        description = request.form.get('description')

        allowed_ids = request.form.getlist('allowed_users')
        res.allowed_users = []
        for uid in allowed_ids:
            user = db.session.get(User, int(uid))
            if user: res.allowed_users.append(user)

        if name: res.name = name
        res.description = description

        try:
            db.session.commit()
            log_action(current_user.id, 'RESOURCE_EDIT', f'Edited resource {name}')
            flash('Resource updated.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Resource name error.', 'error')
    return redirect(url_for('resources_list'))


@app.route('/resources/delete/<int:id>', methods=['POST'])
@login_required
def delete_resource(id):
    if not current_user.is_admin: return redirect(url_for('resources_list'))  # Changed to is_admin
    res = db.session.get(Resource, id)
    if res:
        db.session.delete(res)
        db.session.commit()
        log_action(current_user.id, 'RESOURCE_DELETE', f'Deleted resource {res.name}')
        flash('Resource deleted.', 'success')
    return redirect(url_for('resources_list'))


@app.route('/resources/view/<int:id>')
@login_required
def view_resource_calendar(id):
    resource = db.session.get(Resource, id)
    if not resource or (resource not in get_visible_resources(current_user)):
        flash('Resource not found or access denied.', 'error')
        return redirect(url_for('resources_list'))
    offset = request.args.get('offset', 0, type=int)
    all_users = []
    all_resources = []
    if current_user.is_admin:
        all_users = User.query.all()
        all_users.sort(key=lambda u: (not u.is_super_admin, not u.is_admin, u.username.lower()))
        all_resources = get_visible_resources(current_user)
    return render_calendar_for_user(current_user, viewed_by_admin=True, all_users=all_users,
                                    all_resources=all_resources, offset=offset, viewed_resource=resource)


# ... (news routes same) ...
@app.route('/news')
@login_required
def news():
    news_posts = NewsPost.query.order_by(NewsPost.created_at.desc()).all()
    event_summaries = EventSummary.query.order_by(EventSummary.created_at.desc()).all()
    return render_template('news.html', news=news_posts, events=event_summaries)


@app.route('/news/add_post', methods=['POST'])
@login_required
def add_news_post():
    if not current_user.is_admin: return redirect(url_for('news'))
    text = request.form.get('text')
    filename = ''
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"news_{uuid.uuid4().hex[:8]}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'news_pics', unique_filename))
            filename = unique_filename
    new_post = NewsPost(text=text, image_filename=filename)
    db.session.add(new_post)
    db.session.commit()
    return redirect(url_for('news'))


@app.route('/news/add_event', methods=['POST'])
@login_required
def add_event_summary():
    if not current_user.is_admin: return redirect(url_for('news'))
    text = request.form.get('text')
    filename = ''
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"event_{uuid.uuid4().hex[:8]}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'news_pics', unique_filename))
            filename = unique_filename
    new_event = EventSummary(text=text, image_filename=filename)
    db.session.add(new_event)
    db.session.commit()
    return redirect(url_for('news'))


@app.route('/news/delete/<string:type>/<int:id>', methods=['POST'])
@login_required
def delete_news_item(type, id):
    if not current_user.is_admin: return redirect(url_for('news'))
    if type == 'post':
        item = db.session.get(NewsPost, id)
    else:
        item = db.session.get(EventSummary, id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('news'))


@app.route('/news/edit_post/<int:id>', methods=['POST'])
@login_required
def edit_news_post(id):
    if not current_user.is_admin: return redirect(url_for('news'))
    post = db.session.get(NewsPost, id)
    if not post: return redirect(url_for('news'))
    text = request.form.get('text')
    if text: post.text = text
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"news_{uuid.uuid4().hex[:8]}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'news_pics', unique_filename))
            post.image_filename = unique_filename
    db.session.commit()
    return redirect(url_for('news'))


@app.route('/news/edit_event/<int:id>', methods=['POST'])
@login_required
def edit_event_summary(id):
    if not current_user.is_admin: return redirect(url_for('news'))
    event = db.session.get(EventSummary, id)
    if not event: return redirect(url_for('news'))
    text = request.form.get('text')
    if text: event.text = text
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"event_{uuid.uuid4().hex[:8]}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'news_pics', unique_filename))
            event.image_filename = unique_filename
    db.session.commit()
    return redirect(url_for('news'))


@app.route('/notifications')
@login_required
def notifications():
    received_messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()
    unread_count = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()
    possible_recipients = []
    if current_user.is_admin:
        possible_recipients = User.query.all()
    else:
        possible_recipients = User.query.filter((User.is_admin == True) | (User.is_super_admin == True)).all()
    possible_recipients.sort(key=lambda u: (not u.is_super_admin, not u.is_admin, u.username.lower()))
    return render_template('notifications.html', received_messages=received_messages, sent_messages=sent_messages,
                           unread_count=unread_count, recipients=possible_recipients)


@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    subject = request.form.get('subject')
    body = request.form.get('body')
    recipient_mode = request.form.get('recipient_mode')
    target_ids = []
    if not current_user.is_admin:
        custom_ids = request.form.getlist('recipients')
        target_ids = [int(uid) for uid in custom_ids]
    else:
        if recipient_mode == 'everyone':
            users = User.query.all()
            target_ids = [u.id for u in users if u.id != current_user.id]
        elif recipient_mode == 'all_users':
            users = User.query.filter_by(is_admin=False, is_super_admin=False).all()
            target_ids = [u.id for u in users if u.id != current_user.id]
        elif recipient_mode == 'all_admins':
            admins = User.query.filter((User.is_admin == True) | (User.is_super_admin == True)).all()
            target_ids = [u.id for u in admins if u.id != current_user.id]
        else:
            custom_ids = request.form.getlist('recipients')
            target_ids = [int(uid) for uid in custom_ids]
    for rid in target_ids:
        msg = Message(sender_id=current_user.id, recipient_id=rid, subject=subject, body=body)
        db.session.add(msg)
    db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/mark_read/<int:message_id>', methods=['POST'])
@login_required
def mark_read(message_id):
    msg = db.session.get(Message, message_id)
    if msg and msg.recipient_id == current_user.id:
        msg.is_read = True
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 403


@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = db.session.get(Message, message_id)
    if not msg: return redirect(url_for('notifications'))
    if msg.recipient_id != current_user.id and msg.sender_id != current_user.id: return redirect(
        url_for('notifications'))
    db.session.delete(msg)
    db.session.commit()
    return redirect(url_for('notifications'))


# --- Helper for Grid Rendering ---
def render_calendar_for_user(user, viewed_by_admin=False, all_users=None, all_resources=None, offset=0,
                             viewed_resource=None):
    now = datetime.now()
    today = now.date()
    if now.weekday() == 6 and now.hour >= 21:
        base_start = today + timedelta(days=1)
    else:
        base_start = today - timedelta(days=today.weekday())
    start_of_view = base_start + timedelta(weeks=offset)
    end_of_view = start_of_view + timedelta(days=13)

    if viewed_resource:
        tasks = viewed_resource.tasks.all()
    else:
        user_tasks = user.tasks.all()
        global_tasks = Task.query.filter_by(is_admin_task=True).all()
        tasks = list(set(user_tasks + global_tasks))

    time_slots = []
    current_time = datetime.strptime("07:00", "%H:%M")
    end_time_limit = datetime.strptime("21:00", "%H:%M")
    while current_time < end_time_limit:
        time_slots.append(current_time.time())
        current_time += timedelta(minutes=30)
    week_days = [start_of_view + timedelta(days=i) for i in range(14)]
    tasks_by_date = {d: [] for d in week_days}
    PX_PER_30_MIN = 20
    PX_PER_MIN = PX_PER_30_MIN / 30.0
    START_HOUR = 7
    for task in tasks:
        t_date = task.start_time.date()
        for day_in_view in week_days:
            day_start_bound = datetime.combine(day_in_view, time(7, 0))
            day_end_bound = datetime.combine(day_in_view, time(21, 0))
            task_start = task.start_time
            task_end = task.end_time
            latest_start = max(task_start, day_start_bound)
            earliest_end = min(task_end, day_end_bound)
            if latest_start < earliest_end:
                start_mins = (latest_start.hour - 7) * 60 + latest_start.minute
                duration_mins = (earliest_end - latest_start).total_seconds() / 60
                top_px = start_mins * PX_PER_MIN
                height_px = duration_mins * PX_PER_MIN
                visual_task = {
                    'id': task.id,
                    'title': task.title,
                    'description': task.description,
                    'start_time': task.start_time,
                    'end_time': task.end_time,
                    'is_admin_task': task.is_admin_task,
                    'color': task.color,
                    'author': task.author if task.user_id else None,
                    'user_id': task.user_id,
                    'resource_id': task.resource_id,
                    'created_at': task.created_at,
                    'style_top': top_px,
                    'style_height': height_px
                }
                if day_in_view in tasks_by_date: tasks_by_date[day_in_view].append(visual_task)
    return render_template('calendar.html', viewed_user=user if viewed_by_admin and not viewed_resource else None,
                           viewed_resource=viewed_resource, week_days=week_days, time_slots=time_slots,
                           tasks_by_date=tasks_by_date, current_date=today, all_users=all_users,
                           all_resources=all_resources, current_offset=offset)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)