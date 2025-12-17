import os
import math
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta, date, time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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

# Ensure directories exist
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


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

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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


# --- 4. User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- 5. Helper Functions ---

def split_task_logic(title, description, start_dt, end_dt, user_id, is_global, color='#ffffff'):
    current_start = start_dt
    created_tasks = []
    group_id = str(uuid.uuid4())

    if current_start >= end_dt:
        return 0

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
                user_id=user_id,
                is_admin_task=is_global,
                created_at=datetime.utcnow(),
                task_group_id=group_id,
                color=color
            )
            db.session.add(new_task)
            created_tasks.append(new_task)

        next_day = current_start.date() + timedelta(days=1)
        current_start = datetime.combine(next_day, time(7, 0))

        if (current_start - start_dt).days > 365:
            break

    if not created_tasks:
        fallback = Task(
            title=title,
            description=description,
            start_time=start_dt,
            end_time=end_dt,
            user_id=user_id,
            is_admin_task=is_global,
            created_at=datetime.utcnow(),
            task_group_id=group_id,
            color=color
        )
        db.session.add(fallback)
        created_tasks.append(fallback)

    db.session.commit()
    return len(created_tasks)


# --- 6. Routes ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('calendar_view'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('calendar_view'))

    if request.method == 'POST':
        username_or_email = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

        login_user(user, remember=True)
        flash('You have successfully logged in!', 'success')
        return redirect(url_for('calendar_view'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('calendar_view'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not (username and email and password):
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('User with this username or email already exists.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        if User.query.count() == 0:
            new_user.is_admin = True
            new_user.is_super_admin = True

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Database error during registration.', 'error')
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
            flash(f'Profile updated successfully!', 'success')
            if user_id:
                return redirect(url_for('profile', user_id=target_user.id))
            return redirect(url_for('profile'))

        except IntegrityError:
            db.session.rollback()
            flash('Username or Email already taken.', 'error')

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
    flash('Profile picture reset to default.', 'success')

    if target_user.id != current_user.id:
        return redirect(url_for('profile', user_id=target_user.id))
    return redirect(url_for('profile'))


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    new_password = request.form.get('new_password')
    if not new_password:
        flash('Password cannot be empty.', 'error')
        return redirect(url_for('calendar_view'))

    current_user.set_password(new_password)
    db.session.commit()
    flash('Your password has been updated successfully.', 'success')
    return redirect(url_for('calendar_view'))


@app.route('/add_task', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def add_task():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        target_user_id = request.form.get('target_user_id')
        assignment_mode = request.form.get('assignment_mode', 'me')
        color = request.form.get('color', '#ffffff')

        target_ids = []
        is_global = False

        if not current_user.is_admin:
            target_ids = [current_user.id]
        else:
            if assignment_mode == 'all_users':
                is_global = True
                target_ids = [current_user.id]
            elif assignment_mode == 'all_admins':
                admins = User.query.filter_by(is_admin=True).all()
                target_ids = [u.id for u in admins]
            elif assignment_mode == 'custom':
                custom_ids = request.form.getlist('selected_users')
                target_ids = [int(uid) for uid in custom_ids]
                if not target_ids:
                    flash('No users selected.', 'error')
                    return redirect(url_for('calendar_view'))
            else:
                target_user_id = request.form.get('target_user_id')
                if target_user_id:
                    target_ids = [int(target_user_id)]
                else:
                    target_ids = [current_user.id]

        try:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')

            if start_time >= end_time:
                flash('End time must be after start time.', 'error')
                return redirect(url_for('calendar_view'))

        except ValueError:
            flash('Invalid date/time format.', 'error')
            return redirect(url_for('calendar_view'))

        total_created = 0
        if is_global:
            count = split_task_logic(title, description, start_time, end_time, current_user.id, True, color)
            total_created = count
            flash(f'Global task created.', 'success')
        else:
            for uid in target_ids:
                count = split_task_logic(title, description, start_time, end_time, uid, False, color)
                total_created += count
            flash(f'Task assigned.', 'success')

        if current_user.is_admin and len(target_ids) == 1 and target_ids[0] != current_user.id:
            return redirect(url_for('admin_view_user', user_id=target_ids[0]))
        return redirect(url_for('calendar_view'))

    return redirect(url_for('calendar_view'))


@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    if task_id == 0:
        if request.form.get('action') == 'delete_self':
            if current_user.is_super_admin:
                flash('Super Admin cannot delete themselves.', 'error')
                return redirect(url_for('profile'))
            user = current_user
            logout_user()
            db.session.delete(user)
            db.session.commit()
            flash('Your account has been deleted.', 'success')
            return redirect(url_for('home'))
        return redirect(url_for('calendar_view'))

    task = db.session.get(Task, task_id)
    if not task:
        flash('Task not found.', 'error')
        return redirect(url_for('calendar_view'))

    if not current_user.is_admin and task.user_id != current_user.id:
        flash('Permission denied.', 'error')
        return redirect(url_for('calendar_view'))

    owner_id = task.user_id
    group_id = task.task_group_id

    if group_id:
        tasks_in_group = Task.query.filter_by(task_group_id=group_id).all()
        for t in tasks_in_group:
            db.session.delete(t)
    else:
        db.session.delete(task)

    db.session.commit()
    flash('Task deleted.', 'success')

    if current_user.is_admin and owner_id != current_user.id:
        return redirect(url_for('admin_view_user', user_id=owner_id))
    return redirect(url_for('calendar_view'))


@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = db.session.get(Task, task_id)
    if not task:
        flash('Task not found.', 'error')
        return redirect(url_for('calendar_view'))

    if not current_user.is_admin and task.user_id != current_user.id:
        flash('Permission denied.', 'error')
        return redirect(url_for('calendar_view'))

    if not current_user.is_admin and task.is_admin_task:
        flash('Only admins can edit global tasks.', 'error')
        return redirect(url_for('calendar_view'))

    group_id = task.task_group_id
    full_start_time = task.start_time
    full_end_time = task.end_time

    if group_id:
        group_tasks = Task.query.filter_by(task_group_id=group_id).order_by(Task.start_time).all()
        if group_tasks:
            full_start_time = group_tasks[0].start_time
            full_end_time = group_tasks[-1].end_time

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_str = request.form.get('start_time')
        end_str = request.form.get('end_time')
        color = request.form.get('color')

        try:
            new_start = datetime.strptime(start_str, '%Y-%m-%dT%H:%M')
            new_end = datetime.strptime(end_str, '%Y-%m-%dT%H:%M')

            if new_start >= new_end:
                flash('End time must be after start time.', 'error')
                return render_template('edit_task.html', task=task, full_start_time=new_start, full_end_time=new_end)

            owner_id = task.user_id
            is_global = task.is_admin_task

            if group_id:
                Task.query.filter_by(task_group_id=group_id).delete()
            else:
                db.session.delete(task)

            split_task_logic(title, description, new_start, new_end, owner_id, is_global, color)

            db.session.commit()
            flash('Task updated.', 'success')

            if current_user.is_admin and owner_id != current_user.id:
                return redirect(url_for('admin_view_user', user_id=owner_id))
            return redirect(url_for('calendar_view'))

        except ValueError:
            flash('Invalid date format.', 'error')

    return render_template('edit_task.html', task=task, full_start_time=full_start_time, full_end_time=full_end_time)


@app.route('/calendar')
@login_required
def calendar_view():
    all_users = []
    if current_user.is_admin:
        all_users = User.query.all()
    # Handle Week Offset
    offset = request.args.get('offset', 0, type=int)
    return render_calendar_for_user(current_user, all_users=all_users, offset=offset)


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('calendar_view'))

    # Search and sort
    search_query = request.args.get('q', '')
    if search_query:
        users = User.query.filter(User.username.ilike(f'%{search_query}%')).all()
    else:
        users = User.query.all()

    users.sort(key=lambda u: (not u.is_super_admin, not u.is_admin, u.username.lower()))

    return render_template('admin.html', users=users, search_query=search_query)


@app.route('/admin/save_notes', methods=['POST'])
@login_required
def save_user_notes():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user_id = request.form.get('user_id')
    notes = request.form.get('admin_notes')

    user = db.session.get(User, int(user_id))
    if user:
        user.admin_notes = notes
        db.session.commit()
        flash('Notes updated.', 'success')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_status(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))

    if user_id == current_user.id:
        flash('Cannot change own status.', 'error')
        return redirect(url_for('admin_dashboard'))

    if user.is_admin and not current_user.is_super_admin:
        flash('Only Super Admin can revoke rights.', 'error')
        return redirect(url_for('admin_dashboard'))

    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Status updated for {user.username}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    if user_id == current_user.id: return redirect(url_for('admin_dashboard'))

    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))

    if user.is_super_admin:
        flash('Cannot delete Super Admin.', 'error')
        return redirect(url_for('admin_dashboard'))

    if user.is_admin and not current_user.is_super_admin:
        flash('Only Super Admin can delete other Admins.', 'error')
        return redirect(url_for('admin_dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))

    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))

    if (user.is_admin or user.is_super_admin) and not current_user.is_super_admin:
        flash('Permission denied.', 'error')
        return redirect(url_for('admin_dashboard'))

    user.set_password('1234')
    db.session.commit()
    flash(f'Password reset for {user.username}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/view/<int:user_id>')
@login_required
def admin_view_user(user_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    user = db.session.get(User, int(user_id))
    if not user: return redirect(url_for('admin_dashboard'))
    offset = request.args.get('offset', 0, type=int)
    return render_calendar_for_user(user, viewed_by_admin=True, all_users=User.query.all(), offset=offset)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# --- NEWS & EVENTS ROUTES ---
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

    # UPDATED: Character count check (200)
    if len(text) > 200:
        flash('News text too long (max 200 chars).', 'error')
        return redirect(url_for('news'))

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
    flash('News posted successfully.', 'success')

    return redirect(url_for('news'))


@app.route('/news/add_event', methods=['POST'])
@login_required
def add_event_summary():
    if not current_user.is_admin: return redirect(url_for('news'))

    text = request.form.get('text')

    # UPDATED: Character count check (120)
    if len(text) > 120:
        flash('Event text too long (max 120 chars).', 'error')
        return redirect(url_for('news'))

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
    flash('Event summary posted.', 'success')

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
        flash('Item deleted.', 'success')

    return redirect(url_for('news'))


@app.route('/news/edit_post/<int:id>', methods=['POST'])
@login_required
def edit_news_post(id):
    if not current_user.is_admin: return redirect(url_for('news'))
    post = db.session.get(NewsPost, id)
    if not post: return redirect(url_for('news'))

    text = request.form.get('text')
    if text:
        # UPDATED: Character count check (200)
        if len(text) > 200:
            flash('Text too long.', 'error')
            return redirect(url_for('news'))
        post.text = text

    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"news_{uuid.uuid4().hex[:8]}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'news_pics', unique_filename))
            post.image_filename = unique_filename

    db.session.commit()
    flash('News updated.', 'success')
    return redirect(url_for('news'))


@app.route('/news/edit_event/<int:id>', methods=['POST'])
@login_required
def edit_event_summary(id):
    if not current_user.is_admin: return redirect(url_for('news'))
    event = db.session.get(EventSummary, id)
    if not event: return redirect(url_for('news'))

    text = request.form.get('text')
    if text:
        # UPDATED: Character count check (120)
        if len(text) > 120:
            flash('Text too long.', 'error')
            return redirect(url_for('news'))
        event.text = text

    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"event_{uuid.uuid4().hex[:8]}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'news_pics', unique_filename))
            event.image_filename = unique_filename

    db.session.commit()
    flash('Event updated.', 'success')
    return redirect(url_for('news'))


# --- NOTIFICATIONS ROUTES ---
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

    return render_template('notifications.html',
                           received_messages=received_messages,
                           sent_messages=sent_messages,
                           unread_count=unread_count,
                           recipients=possible_recipients)


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

    if not target_ids:
        flash('No recipients selected.', 'error')
        return redirect(url_for('notifications'))

    for rid in target_ids:
        msg = Message(sender_id=current_user.id, recipient_id=rid, subject=subject, body=body)
        db.session.add(msg)

    db.session.commit()
    flash(f'Message sent to {len(target_ids)} users.', 'success')
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
    if not msg:
        flash('Message not found.', 'error')
        return redirect(url_for('notifications'))
    if msg.recipient_id != current_user.id and msg.sender_id != current_user.id:
        flash('Permission denied.', 'error')
        return redirect(url_for('notifications'))
    db.session.delete(msg)
    db.session.commit()
    flash('Message deleted.', 'success')
    return redirect(url_for('notifications'))


# --- Helper for Grid Rendering (Absolute Positioning) ---
def render_calendar_for_user(user, viewed_by_admin=False, all_users=None, offset=0):
    now = datetime.now()
    today = now.date()

    if now.weekday() == 6 and now.hour >= 21:
        base_start = today + timedelta(days=1)
    else:
        base_start = today - timedelta(days=today.weekday())

    start_of_view = base_start + timedelta(weeks=offset)
    end_of_view = start_of_view + timedelta(days=13)

    user_tasks = user.tasks.all()
    global_tasks = Task.query.filter_by(is_admin_task=True).all()
    all_tasks = list(set(user_tasks + global_tasks))

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

    for task in all_tasks:
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
                    'author': task.author,
                    'user_id': task.user_id,
                    'created_at': task.created_at,
                    'style_top': top_px,
                    'style_height': height_px
                }

                if day_in_view in tasks_by_date:
                    tasks_by_date[day_in_view].append(visual_task)

    return render_template(
        'calendar.html',
        viewed_user=user if viewed_by_admin else None,
        week_days=week_days,
        time_slots=time_slots,
        tasks_by_date=tasks_by_date,
        current_date=today,
        all_users=all_users,
        current_offset=offset
    )


if __name__ == '__main__':
    app.run(debug=True)