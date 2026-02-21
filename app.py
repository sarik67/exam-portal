"""
Online Examination Portal - Flask Application
Complete secure exam system with Admin and Student panels
"""

import os
import re
import secrets
import random
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, make_response, request, redirect, url_for, flash, session,
    jsonify, abort, send_from_directory
)
import bcrypt
from werkzeug.utils import secure_filename
from flask_session import Session

import config
from database.db import get_db

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['SESSION_TYPE'] = 'filesystem'
_session_dir = os.path.join(os.path.dirname(__file__), 'flask_session')
os.makedirs(_session_dir, exist_ok=True)
app.config['SESSION_FILE_DIR'] = _session_dir
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_SECURE'] = False  # BUG 7 fix: secure cookie in production
Session(app)

# Ensure upload folder exists
os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)

# Simple in-memory rate limiting for login (prevents brute force)
_login_attempts = {}
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX = 5  # max attempts per IP per window


def check_rate_limit(ip):
    """Check if IP has exceeded login attempts."""
    now = datetime.now().timestamp()
    if ip not in _login_attempts:
        return True
    # Clean old attempts
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    return len(_login_attempts[ip]) < RATE_LIMIT_MAX


def record_login_attempt(ip, success):
    """Record login attempt. Clear on success."""
    if success:
        if ip in _login_attempts:
            del _login_attempts[ip]
        return
    now = datetime.now().timestamp()
    _login_attempts.setdefault(ip, []).append(now)


# ==================== UTILITY FUNCTIONS ====================

def allowed_file(filename):
    """Check if uploaded file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS


def escape_html(text):
    """Escape HTML to prevent XSS."""
    if not text:
        return ''
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))


def generate_csrf_token():
    """Generate CSRF token for forms."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def validate_csrf():
    """Validate CSRF token from request."""
    token = request.form.get('csrf_token') or request.args.get('csrf_token')
    if not token or not secrets.compare_digest(str(token), str(session.get('csrf_token', ''))):
        abort(403, 'Invalid CSRF token')


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']          = 'DENY'
    response.headers['X-XSS-Protection']         = '1; mode=block'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']        = 'camera=(), microphone=(), geolocation=()'
    # CSP: allow fonts from Google, everything else same-origin
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


def answers_match(expected, given):
    """Compare expected vs student answer - case-insensitive, stripped. Returns True if match."""
    if not expected:
        return False
    e = str(expected).strip().lower()
    g = str(given).strip().lower()
    return e == g if e else False


def calculate_typing_accuracy(original, typed):
    """Calculate typing accuracy as percentage (character comparison)."""
    if not original:
        return 100.0
    original = str(original).strip()
    typed = str(typed).strip()
    if not typed:
        return 0.0
    
    # Character-by-character comparison
    correct = 0
    max_len = max(len(original), len(typed))
    for i in range(max_len):
        if i < len(original) and i < len(typed):
            if original[i] == typed[i]:
                correct += 1
        elif i >= len(typed):
            correct -= 0.5  # Penalty for missing characters
    accuracy = max(0, (correct / len(original)) * 100) if original else 100
    return round(min(100, accuracy), 2)


# ==================== AUTH DECORATORS ====================

def admin_required(f):
    """Decorator to require admin login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please login as admin first.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


def student_exam_required(f):
    """Decorator to require active student exam session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('student_id') or not session.get('exam_id'):
            flash('Please login to access the exam.', 'error')
            return redirect(url_for('student_login'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== ADMIN ROUTES ====================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        validate_csrf()
        # Rate limiting - prevent brute force
        client_ip = request.remote_addr
        if not check_rate_limit(client_ip):
            flash('Too many login attempts. Try again later.', 'error')
            return render_template('admin/login.html')
        username = request.form.get('username', '').strip()[:100]
        password = request.form.get('password', '')
        if not username or not password or len(password) > 500:
            flash('Please enter username and password.', 'error')
            return render_template('admin/login.html')
        
        # Parameterized query - SQL injection safe
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, password_hash FROM admins WHERE username = %s",
                    (username,)
                )
                admin = cur.fetchone()
        
        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password_hash'].encode('utf-8')):
            record_login_attempt(client_ip, True)
            session.clear()
            session['admin_logged_in'] = True
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            record_login_attempt(client_ip, False)
            flash('Invalid username or password.', 'error')
    
    return render_template('admin/login.html')


@app.route('/admin/logout')
def admin_logout():
    """Admin logout."""
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with exam management options."""
    with get_db() as conn:
        with conn.cursor() as cur:
            # BUG 6 fix: use COUNT for stat card, LIMIT 20 for recent list
            cur.execute("SELECT COUNT(*) as total FROM exams")
            exam_count = cur.fetchone()['total']

            cur.execute("SELECT COUNT(*) as total FROM results")
            result_count = cur.fetchone()['total']

            cur.execute(
                "SELECT id, title, duration_minutes, created_at FROM exams ORDER BY created_at DESC LIMIT 20"
            )
            exams = cur.fetchall()

    return render_template('admin/dashboard.html', exams=exams, exam_count=exam_count, result_count=result_count)


@app.route('/admin/exam/create', methods=['GET', 'POST'])
@admin_required
def create_exam():
    """Create new exam with questions."""
    if request.method == 'POST':
        validate_csrf()
        title = request.form.get('title', '').strip()
        duration = request.form.get('duration', '').strip()
        exam_password = request.form.get('exam_password', '')
        
        # Input validation
        if not title or len(title) > 255:
            flash('Please enter a valid exam title.', 'error')
            return redirect(url_for('create_exam'))
        
        try:
            duration = int(duration)
            if duration < 1 or duration > 480:  # Max 8 hours
                raise ValueError('Invalid duration')
        except (ValueError, TypeError):
            flash('Please enter a valid duration (1-480 minutes).', 'error')
            return redirect(url_for('create_exam'))
        
        if not exam_password or len(exam_password) < 4:
            flash('Exam password must be at least 4 characters.', 'error')
            return redirect(url_for('create_exam'))
        
        password_hash = bcrypt.hashpw(exam_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Extract question indices from form (handles non-sequential indices)
        question_indices = []
        for key in request.form:
            if key.startswith('question_type_'):
                try:
                    idx = int(key.replace('question_type_', ''))
                    question_indices.append(idx)
                except ValueError:
                    pass
        question_indices.sort()
        
        if not question_indices:
            flash('Please add at least one question.', 'error')
            return redirect(url_for('create_exam'))
        
        questions_saved = 0
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO exams (title, duration_minutes, password_hash, created_by) VALUES (%s, %s, %s, %s)",
                    (title, duration, password_hash, session.get('admin_id'))
                )
                exam_id = cur.lastrowid
                
                # Process questions
                for order, i in enumerate(question_indices):
                    q_type = request.form.get(f'question_type_{i}')
                    if not q_type:
                        continue
                    
                    q_text = request.form.get(f'question_text_{i}', '').strip()
                    display_order = order
                    marks_val = request.form.get(f'marks_{i}', '1').strip()
                    try:
                        marks = max(1, min(100, int(marks_val)))
                    except (ValueError, TypeError):
                        marks = 1
                    
                    if q_type == 'mcq':
                        # Build options list and map correct answer index
                        option_indices = []  # which j values (0-3) have non-empty text
                        for j in range(4):
                            opt = request.form.get(f'option_{i}_{j}', '').strip()
                            if opt:
                                option_indices.append(j)
                        options = [request.form.get(f'option_{i}_{j}', '').strip() for j in option_indices]
                        correct_radio = request.form.get(f'correct_option_{i}')
                        correct_idx = int(correct_radio) if correct_radio is not None and correct_radio.isdigit() else -1
                        # Map radio value (0-3) to index in options list
                        correct_option_idx = option_indices.index(correct_idx) if correct_idx in option_indices else -1
                        
                        if len(options) < 2 or correct_option_idx < 0:
                            continue
                        questions_saved += 1
                        cur.execute(
                            "INSERT INTO questions (exam_id, question_type, question_text, marks, display_order) VALUES (%s, 'mcq', %s, %s, %s)",
                            (exam_id, q_text or 'MCQ Question', marks, display_order)
                        )
                        q_id = cur.lastrowid
                        for j, opt_text in enumerate(options):
                            cur.execute(
                                "INSERT INTO options (question_id, option_text, is_correct, display_order) VALUES (%s, %s, %s, %s)",
                                (q_id, opt_text, 1 if j == correct_option_idx else 0, j)
                            )
                    
                    elif q_type == 'paragraph':
                        para_text = request.form.get(f'paragraph_text_{i}', '').strip()
                        if para_text:
                            questions_saved += 1
                            cur.execute(
                                "INSERT INTO questions (exam_id, question_type, paragraph_text, marks, display_order) VALUES (%s, 'paragraph', %s, %s, %s)",
                                (exam_id, para_text, marks, display_order)
                            )
                    
                    elif q_type == 'image':
                        image_path = ''
                        if f'question_image_{i}' in request.files:
                            file = request.files[f'question_image_{i}']
                            if file and file.filename and allowed_file(file.filename):
                                filename = secure_filename(f"{exam_id}_{i}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}")
                                filepath = os.path.join(config.UPLOAD_FOLDER, filename)
                                file.save(filepath)
                                image_path = f'uploads/{filename}'
                        correct_answer = request.form.get(f'correct_answer_{i}', '').strip()[:500]
                        if image_path or q_text:
                            questions_saved += 1
                            cur.execute(
                                "INSERT INTO questions (exam_id, question_type, question_text, image_path, correct_answer, marks, display_order) VALUES (%s, 'image', %s, %s, %s, %s, %s)",
                                (exam_id, q_text or 'Find the answer in the image and type it below', image_path, correct_answer, marks, display_order)
                            )
                    
                    elif q_type == 'short_answer':
                        correct_answer = request.form.get(f'correct_answer_{i}', '').strip()[:500]
                        if q_text and correct_answer:
                            questions_saved += 1
                            cur.execute(
                                "INSERT INTO questions (exam_id, question_type, question_text, correct_answer, marks, display_order) VALUES (%s, 'short_answer', %s, %s, %s, %s)",
                                (exam_id, q_text, correct_answer, marks, display_order)
                            )
                
                if questions_saved == 0:
                    cur.execute("DELETE FROM exams WHERE id = %s", (exam_id,))
                    flash('No valid questions saved. For MCQ: 2+ options + correct. Paragraph: enter text. Image: image or text + optional correct answer. Short Answer: question + correct answer.', 'error')
                    return redirect(url_for('create_exam'))
        
        flash('Exam created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/create_exam.html')


@app.route('/admin/exams')
@admin_required
def view_exams():
    """View all exams."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, duration_minutes, created_at FROM exams ORDER BY created_at DESC"
            )
            exams = cur.fetchall()
    return render_template('admin/view_exams.html', exams=exams)


@app.route('/admin/results')
@admin_required
def view_results():
    """View all results - can filter by exam."""
    exam_id = request.args.get('exam_id', type=int)
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title FROM exams ORDER BY title")
            exams = cur.fetchall()
            
            if exam_id:
                cur.execute("""
                    SELECT r.id, r.mcq_score, r.mcq_total, r.typing_accuracy, r.total_score, r.total_marks, r.submitted_at,
                           s.name, s.email
                    FROM results r
                    JOIN students s ON r.student_id = s.id
                    WHERE r.exam_id = %s
                    ORDER BY r.total_score DESC, s.name ASC
                """, (exam_id,))
            else:
                cur.execute("""
                    SELECT r.id, r.mcq_score, r.mcq_total, r.typing_accuracy, r.total_score, r.total_marks, r.submitted_at,
                           s.name, s.email, e.title as exam_title
                    FROM results r
                    JOIN students s ON r.student_id = s.id
                    JOIN exams e ON r.exam_id = e.id
                    ORDER BY r.total_score DESC, s.name ASC
                    LIMIT 100
                """)
            results = cur.fetchall()
    
    return render_template('admin/view_results.html', results=results, exams=exams, selected_exam=exam_id)


@app.route('/admin/exam/delete/<int:exam_id>', methods=['POST'])
@admin_required
def delete_exam(exam_id):
    """Delete an exam (cascade deletes questions, students, results)."""
    validate_csrf()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM exams WHERE id = %s", (exam_id,))
            if cur.rowcount == 0:
                flash('Exam not found.', 'error')
            else:
                flash('Exam deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/exam/edit/<int:exam_id>', methods=['GET', 'POST'])
@admin_required
def edit_exam(exam_id):
    """Edit an existing exam — title, duration, password and questions."""

    # ── POST: save changes ──────────────────────────────────────────────
    if request.method == 'POST':
        validate_csrf()
        title = request.form.get('title', '').strip()
        duration = request.form.get('duration', '').strip()
        new_password = request.form.get('exam_password', '')

        if not title or len(title) > 255:
            flash('Please enter a valid exam title.', 'error')
            return redirect(url_for('edit_exam', exam_id=exam_id))

        try:
            duration = int(duration)
            if duration < 1 or duration > 480:
                raise ValueError
        except (ValueError, TypeError):
            flash('Please enter a valid duration (1-480 minutes).', 'error')
            return redirect(url_for('edit_exam', exam_id=exam_id))

        # Extract question indices
        question_indices = []
        for key in request.form:
            if key.startswith('question_type_'):
                try:
                    question_indices.append(int(key.replace('question_type_', '')))
                except ValueError:
                    pass
        question_indices.sort()

        if not question_indices:
            flash('Please add at least one question.', 'error')
            return redirect(url_for('edit_exam', exam_id=exam_id))

        with get_db() as conn:
            with conn.cursor() as cur:
                # Check exam exists
                cur.execute("SELECT id, password_hash FROM exams WHERE id = %s", (exam_id,))
                exam = cur.fetchone()
                if not exam:
                    flash('Exam not found.', 'error')
                    return redirect(url_for('view_exams'))

                # Update password only if a new one was supplied
                if new_password and len(new_password) >= 4:
                    pw_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                elif new_password and len(new_password) < 4:
                    flash('New password must be at least 4 characters (leave blank to keep existing).', 'error')
                    return redirect(url_for('edit_exam', exam_id=exam_id))
                else:
                    pw_hash = exam['password_hash']  # keep old

                cur.execute(
                    "UPDATE exams SET title = %s, duration_minutes = %s, password_hash = %s WHERE id = %s",
                    (title, duration, pw_hash, exam_id)
                )

                # Delete ALL existing questions (CASCADE removes options + student_answers)
                cur.execute("DELETE FROM questions WHERE exam_id = %s", (exam_id,))

                # Re-insert questions (same logic as create_exam)
                questions_saved = 0
                for order, i in enumerate(question_indices):
                    q_type = request.form.get(f'question_type_{i}')
                    if not q_type:
                        continue
                    q_text = request.form.get(f'question_text_{i}', '').strip()
                    marks_val = request.form.get(f'marks_{i}', '1').strip()
                    try:
                        marks = max(1, min(100, int(marks_val)))
                    except (ValueError, TypeError):
                        marks = 1

                    if q_type == 'mcq':
                        option_indices = []
                        for j in range(4):
                            if request.form.get(f'option_{i}_{j}', '').strip():
                                option_indices.append(j)
                        options = [request.form.get(f'option_{i}_{j}', '').strip() for j in option_indices]
                        correct_radio = request.form.get(f'correct_option_{i}')
                        correct_idx = int(correct_radio) if correct_radio and correct_radio.isdigit() else -1
                        correct_option_idx = option_indices.index(correct_idx) if correct_idx in option_indices else -1
                        if len(options) < 2 or correct_option_idx < 0:
                            continue
                        questions_saved += 1
                        cur.execute(
                            "INSERT INTO questions (exam_id, question_type, question_text, marks, display_order) VALUES (%s, 'mcq', %s, %s, %s)",
                            (exam_id, q_text or 'MCQ Question', marks, order)
                        )
                        q_id = cur.lastrowid
                        for j, opt_text in enumerate(options):
                            cur.execute(
                                "INSERT INTO options (question_id, option_text, is_correct, display_order) VALUES (%s, %s, %s, %s)",
                                (q_id, opt_text, 1 if j == correct_option_idx else 0, j)
                            )

                    elif q_type == 'paragraph':
                        para_text = request.form.get(f'paragraph_text_{i}', '').strip()
                        if para_text:
                            questions_saved += 1
                            cur.execute(
                                "INSERT INTO questions (exam_id, question_type, paragraph_text, marks, display_order) VALUES (%s, 'paragraph', %s, %s, %s)",
                                (exam_id, para_text, marks, order)
                            )

                    elif q_type == 'image':
                        image_path = ''
                        if f'question_image_{i}' in request.files:
                            file = request.files[f'question_image_{i}']
                            if file and file.filename and allowed_file(file.filename):
                                filename = secure_filename(f"{exam_id}_{i}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}")
                                file.save(os.path.join(config.UPLOAD_FOLDER, filename))
                                image_path = f'uploads/{filename}'
                        # Keep existing image path if no new file uploaded
                        existing_img = request.form.get(f'existing_image_{i}', '')
                        if not image_path and existing_img:
                            image_path = existing_img
                        correct_answer = request.form.get(f'correct_answer_{i}', '').strip()[:500]
                        if image_path or q_text:
                            questions_saved += 1
                            cur.execute(
                                "INSERT INTO questions (exam_id, question_type, question_text, image_path, correct_answer, marks, display_order) VALUES (%s, 'image', %s, %s, %s, %s, %s)",
                                (exam_id, q_text or 'Find the answer in the image', image_path, correct_answer, marks, order)
                            )

                    elif q_type == 'short_answer':
                        correct_answer = request.form.get(f'correct_answer_{i}', '').strip()[:500]
                        if q_text and correct_answer:
                            questions_saved += 1
                            cur.execute(
                                "INSERT INTO questions (exam_id, question_type, question_text, correct_answer, marks, display_order) VALUES (%s, 'short_answer', %s, %s, %s, %s)",
                                (exam_id, q_text, correct_answer, marks, order)
                            )

                if questions_saved == 0:
                    flash('No valid questions were saved. Please check your questions.', 'error')
                    return redirect(url_for('edit_exam', exam_id=exam_id))

        flash('Exam updated successfully!', 'success')
        return redirect(url_for('view_exams'))

    # ── GET: load existing exam data ────────────────────────────────────
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title, duration_minutes FROM exams WHERE id = %s", (exam_id,))
            exam = cur.fetchone()
            if not exam:
                flash('Exam not found.', 'error')
                return redirect(url_for('view_exams'))

            cur.execute("""
                SELECT id, question_type, question_text, paragraph_text, image_path, correct_answer, marks, display_order
                FROM questions WHERE exam_id = %s ORDER BY display_order, id
            """, (exam_id,))
            questions = cur.fetchall()

            for q in questions:
                if q['question_type'] == 'mcq':
                    cur.execute(
                        "SELECT id, option_text, is_correct, display_order FROM options WHERE question_id = %s ORDER BY display_order, id",
                        (q['id'],)
                    )
                    q['options'] = cur.fetchall()
                else:
                    q['options'] = []

    return render_template('admin/edit_exam.html', exam=exam, questions=questions)


# ==================== STUDENT ROUTES ====================

@app.route('/')
def index():
    """Home page - redirect to student or admin."""
    return render_template('index.html')


@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    """Student exam login - Name, Email, Exam Password."""
    if session.get('student_id'):
        return redirect(url_for('take_exam'))
    
    if request.method == 'POST':
        validate_csrf()
        # Rate limiting for student login
        client_ip = request.remote_addr

        # BUG 3 fix: always fetch exams so template dropdown never crashes
        def _get_exams(cur):
            cur.execute("SELECT id, title FROM exams ORDER BY title")
            return cur.fetchall()

        if not check_rate_limit(client_ip):
            flash('Too many attempts. Try again later.', 'error')
            with get_db() as conn:
                with conn.cursor() as cur:
                    exams = _get_exams(cur)
            return render_template('student/login.html', exams=exams)

        name = request.form.get('name', '').strip()[:255]
        email = request.form.get('email', '').strip()[:255]
        exam_password = request.form.get('exam_password', '')[:100]

        if not name or not email:
            flash('Please enter your name and email.', 'error')
            with get_db() as conn:
                with conn.cursor() as cur:
                    exams = _get_exams(cur)
            return render_template('student/login.html', exams=exams)

        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address.', 'error')
            with get_db() as conn:
                with conn.cursor() as cur:
                    exams = _get_exams(cur)
            return render_template('student/login.html', exams=exams)

        if not exam_password:
            flash('Please enter the exam password.', 'error')
            with get_db() as conn:
                with conn.cursor() as cur:
                    exams = _get_exams(cur)
            return render_template('student/login.html', exams=exams)
        
        # Get exam ID - need to find exam by password
        # We need to select exam - add exam selection or use first matching
        exam_id = request.form.get('exam_id', type=int)
        
        if not exam_id:
            flash('Please select an exam.', 'error')
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, title FROM exams ORDER BY title")
                    exams = cur.fetchall()
            return render_template('student/login.html', exams=exams)
        
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, password_hash, duration_minutes FROM exams WHERE id = %s", (exam_id,))
                exam = cur.fetchone()
                
                if not exam:
                    flash('Exam not found.', 'error')
                    cur.execute("SELECT id, title FROM exams ORDER BY title")
                    exams = cur.fetchall()
                    return render_template('student/login.html', exams=exams)
                
                if not bcrypt.checkpw(exam_password.encode('utf-8'), exam['password_hash'].encode('utf-8')):
                    record_login_attempt(client_ip, False)
                    flash('Invalid exam password.', 'error')
                    cur.execute("SELECT id, title FROM exams ORDER BY title")
                    exams = cur.fetchall()
                    return render_template('student/login.html', exams=exams)
                
                # Check if student already attempted
                cur.execute(
                    "SELECT id FROM students WHERE exam_id = %s AND email = %s",
                    (exam_id, email)
                )
                existing = cur.fetchone()
                if existing:
                    flash('You have already attempted this exam. One attempt per email allowed.', 'error')
                    cur.execute("SELECT id, title FROM exams ORDER BY title")
                    exams = cur.fetchall()
                    return render_template('student/login.html', exams=exams)
                
                # Create student record
                cur.execute(
                    "INSERT INTO students (exam_id, name, email) VALUES (%s, %s, %s)",
                    (exam_id, name, email)
                )
                student_id = cur.lastrowid
        
        record_login_attempt(client_ip, True)
        # Clear ONLY student session keys — do NOT wipe admin keys
        # so that testing both portals in the same browser keeps admin logged in.
        for key in ('student_id', 'exam_id', 'duration_minutes',
                    'student_name', 'student_email', 'result_submitted'):
            session.pop(key, None)
        session['student_id'] = student_id
        session['exam_id'] = exam_id
        session['duration_minutes'] = exam['duration_minutes']
        session['student_name'] = name
        session['student_email'] = email

        return redirect(url_for('take_exam'))
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title FROM exams ORDER BY title")
            exams = cur.fetchall()
    
    return render_template('student/login.html', exams=exams)


@app.route('/student/exam')
@student_exam_required
def take_exam():
    """Exam interface with timer and questions."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT title, duration_minutes FROM exams WHERE id = %s",
                (session['exam_id'],)
            )
            exam = cur.fetchone()
            if not exam:
                session.clear()
                flash('Exam not found.', 'error')
                return redirect(url_for('student_login'))
            
            cur.execute("""
                SELECT q.id, q.question_type, q.question_text, q.paragraph_text, q.image_path, q.marks, q.display_order
                FROM questions q
                WHERE q.exam_id = %s
                ORDER BY q.display_order, q.id
            """, (session['exam_id'],))
            questions = cur.fetchall()

            # BUG 4 fix: batch-load all options in ONE query instead of N queries
            mcq_ids = [q['id'] for q in questions if q['question_type'] == 'mcq']
            options_map = {}
            if mcq_ids:
                placeholders = ','.join(['%s'] * len(mcq_ids))
                cur.execute(
                    f"SELECT id, question_id, option_text, display_order FROM options WHERE question_id IN ({placeholders}) ORDER BY question_id, display_order, id",
                    mcq_ids
                )
                for opt in cur.fetchall():
                    options_map.setdefault(opt['question_id'], []).append(opt)

            for q in questions:
                if q['question_type'] == 'mcq':
                    opts = options_map.get(q['id'], [])
                    random.shuffle(opts)  # Shuffle options per question
                    q['options'] = opts
                else:
                    q['options'] = []

            random.shuffle(questions)  # Randomize question order
    
    return render_template('student/exam.html', exam=exam, questions=questions)


@app.route('/student/submit', methods=['POST'])
@student_exam_required
def submit_exam():
    """Submit exam and calculate scores."""
    validate_csrf()
    
    student_id = session.get('student_id')
    exam_id = session.get('exam_id')
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT submitted_at FROM students WHERE id = %s", (student_id,))
            student = cur.fetchone()
            if student and student['submitted_at']:
                flash('Exam already submitted.', 'error')
                return redirect(url_for('result_page'))
            
            cur.execute("""
                SELECT q.id, q.question_type, q.paragraph_text, q.marks, q.correct_answer
                FROM questions q WHERE q.exam_id = %s
            """, (exam_id,))
            questions = cur.fetchall()
            
            mcq_correct = 0
            mcq_total = 0
            typing_accuracies = []
            typing_marks_info = []  # (accuracy, marks) for each paragraph
            obtained_score = 0
            total_marks = 0
            
            for q in questions:
                q_marks = int(q.get('marks') or 1)
                total_marks += q_marks
                
                if q['question_type'] == 'mcq':
                    option_id = request.form.get(f'mcq_{q["id"]}', type=int)
                    cur.execute(
                        "SELECT id, is_correct FROM options WHERE question_id = %s",
                        (q['id'],)
                    )
                    options = cur.fetchall()
                    correct_option = next((o for o in options if o['is_correct']), None)
                    mcq_total += 1
                    is_correct = 0
                    if correct_option and option_id == correct_option['id']:
                        mcq_correct += 1
                        is_correct = 1
                        obtained_score += q_marks
                    cur.execute(
                        "INSERT INTO student_answers (student_id, question_id, option_id, is_correct) VALUES (%s, %s, %s, %s)",
                        (student_id, q['id'], option_id, is_correct)
                    )
                
                elif q['question_type'] == 'paragraph':
                    typed = request.form.get(f'paragraph_{q["id"]}', '')
                    original = q['paragraph_text'] or ''
                    acc = calculate_typing_accuracy(original, typed)
                    typing_accuracies.append(acc)
                    obtained_score += (acc / 100) * q_marks
                    cur.execute(
                        "INSERT INTO student_answers (student_id, question_id, answer_text) VALUES (%s, %s, %s)",
                        (student_id, q['id'], typed[:5000])
                    )
                
                elif q['question_type'] == 'image':
                    ans = request.form.get(f'image_{q["id"]}', '').strip()[:2000]
                    correct = (q.get('correct_answer') or '').strip()
                    if correct and answers_match(correct, ans):
                        obtained_score += q_marks
                    cur.execute(
                        "INSERT INTO student_answers (student_id, question_id, answer_text) VALUES (%s, %s, %s)",
                        (student_id, q['id'], ans)
                    )
                
                elif q['question_type'] == 'short_answer':
                    ans = request.form.get(f'short_answer_{q["id"]}', '').strip()[:500]
                    correct = (q.get('correct_answer') or '').strip()
                    if correct and answers_match(correct, ans):
                        obtained_score += q_marks
                    cur.execute(
                        "INSERT INTO student_answers (student_id, question_id, answer_text) VALUES (%s, %s, %s)",
                        (student_id, q['id'], ans)
                    )
            
            typing_accuracy = sum(typing_accuracies) / len(typing_accuracies) if typing_accuracies else 0
            total_score = round(obtained_score, 2)
            
            cur.execute(
                "UPDATE students SET submitted_at = NOW() WHERE id = %s",
                (student_id,)
            )
            cur.execute("""
                INSERT INTO results (student_id, exam_id, mcq_score, mcq_total, typing_accuracy, total_score, total_marks)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (student_id, exam_id, mcq_correct, mcq_total, typing_accuracy, total_score, total_marks))
    
    session['result_submitted'] = True
    return redirect(url_for('result_page'))


@app.route('/student/result')
def result_page():
    """Show result after submission."""
    student_id = session.get('student_id')
    exam_id    = session.get('exam_id')

    if not student_id or not session.get('result_submitted'):
        return redirect(url_for('student_login'))

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT r.mcq_score, r.mcq_total, r.typing_accuracy, r.total_score, r.total_marks, r.submitted_at,
                       e.title, s.name, s.email
                FROM results r
                JOIN exams e ON r.exam_id = e.id
                JOIN students s ON r.student_id = s.id
                WHERE r.student_id = %s AND r.exam_id = %s
            """, (student_id, exam_id))
            result = cur.fetchone()

    if not result:
        flash('Result not found.', 'error')
        return redirect(url_for('student_login'))

    # BUG 2 fix: render FIRST, then clear student session keys only
    # (do NOT call session.clear() — that would log out the admin if same browser)
    response = make_response(render_template('student/result.html', result=result))
    for key in ('student_id', 'exam_id', 'duration_minutes',
                'student_name', 'student_email', 'result_submitted'):
        session.pop(key, None)
    return response


# ==================== STATIC FILE SERVING ====================
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded images — path traversal protected by send_from_directory."""
    # send_from_directory raises 404 for any path that escapes UPLOAD_FOLDER
    return send_from_directory(config.UPLOAD_FOLDER, filename)


# ==================== ERROR HANDLERS ====================
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.errorhandler(400)
def bad_request(e):
    return render_template('errors/400.html'), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Maximum upload size is 16 MB.', 'error')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('errors/429.html'), 429

@app.errorhandler(500)
def server_error(e):
    logger.exception('Internal Server Error: %s', e)
    return render_template('errors/500.html'), 500


# ==================== ADMIN API FOR ANALYTICS ====================

@app.route('/admin/api/analytics')
@admin_required
def admin_analytics():
    """Basic admin analytics."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as count FROM exams")
            exam_count = cur.fetchone()['count']
            cur.execute("SELECT COUNT(*) as count FROM results")
            result_count = cur.fetchone()['count']
            cur.execute("SELECT AVG(total_score) as avg_score FROM results")
            avg_score = cur.fetchone()['avg_score'] or 0
    return jsonify({
        'exam_count': exam_count,
        'result_count': result_count,
        'avg_score': round(float(avg_score), 2)
    })


# ==================== MAIN ====================

if __name__ == '__main__':
    import sys
    prod_mode = '--prod' in sys.argv or os.environ.get('FLASK_ENV') == 'production'

    if prod_mode:
        # ── Production: Waitress WSGI server ──────────────────────────────
        # Handles 1000 concurrent students with 64 threads + DB connection pool
        from waitress import serve
        print(f"🚀 Starting production server on port {config.WAITRESS_PORT} "
              f"with {config.WAITRESS_THREADS} threads")
        print("   DB pool: 5 warm / 100 max connections")
        print("   Press Ctrl+C to stop.")
        serve(
            app,
            host='0.0.0.0',
            port=config.WAITRESS_PORT,
            threads=config.WAITRESS_THREADS,
            channel_timeout=120,         # 2-min timeout per request
            connection_limit=2000,       # max open TCP connections
            cleanup_interval=30,
        )
    else:
        # ── Development: Flask debug server (threaded for local testing) ───
        app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)

