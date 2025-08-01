from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import qrcode
import random
import string
from io import BytesIO
import base64
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'give_any_secret_code_here' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gate_pass.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False) 
    department = db.Column(db.String(50))
    roll_number = db.Column(db.String(20))
    photo_path = db.Column(db.String(200))
    is_verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class GatePass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    out_time = db.Column(db.DateTime, nullable=False)
    in_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    otp = db.Column(db.String(6))
    qr_code = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship('User', foreign_keys=[student_id], backref='gate_passes')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_passes')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def generate_qr_code(gate_pass):
    # Create QR code data
    qr_data = {
        'gate_pass_id': gate_pass.id,
        'student_id': gate_pass.student_id,
        'otp': gate_pass.otp
    }
    qr_data_str = json.dumps(qr_data)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data_str)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    filename = f"gate_pass_{gate_pass.id}.png"
    app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    img.save(filepath)
    
    return filename

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password', 'danger')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with this email', 'danger')
            return redirect(url_for('login'))
            
        if not user.check_password(password):
            flash('Invalid password', 'danger')
            return redirect(url_for('login'))
            
        if user.role == 'student' and not user.is_verified:
            flash('Your account is pending verification by HOD. Please wait for approval.', 'warning')
            return redirect(url_for('login'))
            
        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        department = request.form.get('department')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))

        if role == 'hod' and not department:
            flash('Department is required for HOD', 'danger')
            return redirect(url_for('signup'))

        user = User(
            email=email,
            role=role,
            department=department if role == 'hod' else None,
            is_verified=True if role in ['hod', 'security'] else False
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/signup/student', methods=['GET', 'POST'])
def student_signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        roll_number = request.form.get('roll_number')
        department = request.form.get('department')
        photo = request.files.get('photo')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('student_signup'))

        if photo:
            filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(photo_path)
        else:
            flash('Photo is required', 'danger')
            return redirect(url_for('student_signup'))

        user = User(
            email=email,
            name=name,
            role='student',
            department=department,
            roll_number=roll_number,
            photo_path=filename,
            is_verified=False
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please wait for HOD verification.', 'success')
        return redirect(url_for('login'))

    return render_template('signup/student.html')

@app.route('/signup/hod', methods=['GET', 'POST'])
def hod_signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        department = request.form.get('department')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('hod_signup'))

        if not department:
            flash('Department is required', 'danger')
            return redirect(url_for('hod_signup'))

        user = User(
            email=email,
            name=name,
            role='hod',
            department=department,
            is_verified=True  # HOD accounts are automatically verified
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup/hod.html')

@app.route('/signup/security', methods=['GET', 'POST'])
def security_signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('security_signup'))

        user = User(
            email=email,
            name=name,
            role='security',
            is_verified=True  # Security accounts are automatically verified
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup/security.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'hod':
        pending_students = User.query.filter_by(role='student', is_verified=False, department=current_user.department).all()
        pending_passes = GatePass.query.join(User, GatePass.student_id == User.id).filter(
            User.department == current_user.department,
            GatePass.status == 'pending'
        ).all()
        return render_template('hod_dashboard.html', 
                             pending_students=pending_students,
                             pending_passes=pending_passes)
    elif current_user.role == 'student':
        gate_passes = GatePass.query.filter_by(student_id=current_user.id).all()
        return render_template('student_dashboard.html', gate_passes=gate_passes)
    elif current_user.role == 'security':
        return render_template('security_dashboard.html')
    else:  # admin
        return render_template('admin_dashboard.html', User=User, GatePass=GatePass)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/verify_student/<int:student_id>', methods=['POST'])
@login_required
def verify_student(student_id):
    if current_user.role != 'hod':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    student = User.query.get_or_404(student_id)
    if student.department != current_user.department:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    student.is_verified = True
    db.session.commit()
    flash('Student verified successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/request_gate_pass', methods=['POST'])
@login_required
def request_gate_pass():
    if current_user.role != 'student':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    purpose = request.form.get('purpose')
    out_time = datetime.strptime(request.form.get('out_time'), '%Y-%m-%dT%H:%M')
    in_time = datetime.strptime(request.form.get('in_time'), '%Y-%m-%dT%H:%M')

    gate_pass = GatePass(
        student_id=current_user.id,
        purpose=purpose,
        out_time=out_time,
        in_time=in_time
    )
    db.session.add(gate_pass)
    db.session.commit()

    flash('Gate pass request submitted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/approve_gate_pass/<int:pass_id>', methods=['POST'])
@login_required
def approve_gate_pass(pass_id):
    if current_user.role != 'hod':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
        
    gate_pass = GatePass.query.get_or_404(pass_id)
    student = User.query.get(gate_pass.student_id)
    
    if student.department != current_user.department:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Generate OTP and QR code
        gate_pass.otp = generate_otp()
        gate_pass.qr_code = generate_qr_code(gate_pass)
        gate_pass.status = 'approved'
        db.session.commit()
        
        flash('Gate pass approved successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error generating QR code. Please try again.', 'danger')
        print(f"Error generating QR code: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_gate_pass/<int:pass_id>', methods=['POST'])
@login_required
def reject_gate_pass(pass_id):
    if current_user.role != 'hod':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    gate_pass = GatePass.query.get_or_404(pass_id)
    student = User.query.get(gate_pass.student_id)
    
    if student.department != current_user.department:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    gate_pass.status = 'rejected'
    gate_pass.approved_by = current_user.id
    db.session.commit()

    flash('Gate pass rejected', 'success')
    return redirect(url_for('dashboard'))

@app.route('/verify_gate_pass', methods=['POST'])
@login_required
def verify_gate_pass():
    if current_user.role != 'security':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
        
    otp = request.form.get('otp')
    gate_pass = GatePass.query.filter_by(otp=otp, status='approved').first()
    
    if not gate_pass:
        return jsonify({'error': 'Invalid OTP'}), 400
        
    student = User.query.get(gate_pass.student_id)
    
    # Store the response data before invalidating
    response_data = {
        'name': student.name,
        'roll_number': student.roll_number,
        'department': student.department,
        'photo': url_for('static', filename=f'uploads/{student.photo_path}', _external=True) if student.photo_path else None,
        'out_time': gate_pass.out_time.strftime('%Y-%m-%d %H:%M'),
        'in_time': gate_pass.in_time.strftime('%Y-%m-%d %H:%M')
    }
    
    # Invalidate the OTP and QR code
    gate_pass.otp = None
    gate_pass.qr_code = None
    db.session.commit()
    
    return jsonify(response_data)

@app.route('/scan_qr_code', methods=['POST'])
@login_required
def scan_qr_code():
    if current_user.role != 'security':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
        
    qr_data = request.json
    gate_pass = GatePass.query.filter_by(
        id=qr_data.get('gate_pass_id'),
        otp=qr_data.get('otp'),
        status='approved'
    ).first()
    
    if not gate_pass:
        return jsonify({'error': 'Invalid QR code'}), 400
        
    student = User.query.get(gate_pass.student_id)
    
    # Store the response data before invalidating
    response_data = {
        'name': student.name,
        'roll_number': student.roll_number,
        'department': student.department,
        'photo': url_for('static', filename=f'uploads/{student.photo_path}', _external=True) if student.photo_path else None,
        'out_time': gate_pass.out_time.strftime('%Y-%m-%d %H:%M'),
        'in_time': gate_pass.in_time.strftime('%Y-%m-%d %H:%M')
    }
    
    # Invalidate the OTP and QR code
    gate_pass.otp = None
    gate_pass.qr_code = None
    db.session.commit()
    
    return jsonify(response_data)

def init_db():
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                email='admin@college.edu',
                role='admin',
                is_verified=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 
