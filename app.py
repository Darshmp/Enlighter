from flask import Flask, json, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps
from flask import jsonify
from flask_mail import Mail, Message
import sys
import time
import shutil
from sqlalchemy import text
import flask
from functools import wraps
# from werkzeug.security import safe_str_cmp

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-this-in-production'  # Replace with a real secret key

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///enlighter.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)



# Email configuration - Using company email address
SMTP_SERVER = "smtp.gmail.com"  # Or your company's SMTP server
SMTP_PORT = 587
COMPANY_EMAIL = "darshanmpreddy@gmail.com"  # Company email address
COMPANY_EMAIL_PASSWORD = "tthh faqu etme mvrn"    # Company email app password
SECRET_ADMINS = ['darshanmpreddy@gmail.com']
SECRET_ADMIN_CREDENTIALS = {
    'admin123': 'admin123'  # username: password
}

app.config['MAIL_SERVER'] = SMTP_SERVER
app.config['MAIL_PORT'] = SMTP_PORT
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "darshanmpreddy@gmail.com"
app.config['MAIL_PASSWORD'] = "tthh faqu etme mvrn" 
app.config['MAIL_DEFAULT_SENDER'] = "darshanmpreddy@gmail.com"

mail = Mail(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(200))
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    code_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(20), nullable=False)  # beginner, intermediate, advanced
    image_url = db.Column(db.String(500))
    duration = db.Column(db.String(50))
    lessons = db.Column(db.Integer)
    rating = db.Column(db.Float)
    reviews_count = db.Column(db.Integer)
    features = db.Column(db.Text)  # JSON string of features
    outcomes = db.Column(db.Text)  # JSON string of learning outcomes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200), nullable=False)
    user_email = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    
# Create tables
with app.app_context():
    db.create_all()

def log_system_action(action, details=None):
    try:
        log = SystemLog(
            action=action,
            user_email=session.get('user_email', 'unknown'),
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging action: {e}")

# Add this function instead:
def safe_str_cmp(a, b):
    """Compare two strings in constant time to avoid timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

# Helper function to send email from company address
def send_verification_email(user_email, code):
    try:
        msg = MIMEText(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #452FF4 0%, #41E295 100%); 
                         padding: 20px; text-align: center; color: white; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                .code {{ font-size: 32px; font-weight: bold; text-align: center; margin: 20px 0; 
                        color: #452FF4; letter-spacing: 5px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Enlighter Tech</h1>
                </div>
                <div class="content">
                    <h2>Email Verification</h2>
                    <p>Thank you for registering with Enlighter Tech. Use the verification code below to complete your registration:</p>
                    <div class="code">{code}</div>
                    <p>This code will expire in 10 minutes. If you didn't request this, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Enlighter Tech. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """, "html")
        
        msg['Subject'] = 'Verify Your Email - Enlighter Tech'
        msg['From'] = COMPANY_EMAIL
        msg['To'] = user_email
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(COMPANY_EMAIL, COMPANY_EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in and is admin
        admin_emails = ['admin@enlighter.com']  # Add your admin emails here
        if 'user_id' not in session or session.get('user_email') not in admin_emails:
            flash('Admin access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def secret_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Only allow secret admin access, not regular admins
        if not session.get('secret_admin_logged_in'):
            flash('Secret admin access required.', 'error')
            return redirect(url_for('secret_admin_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/secret-admin/login', methods=['GET', 'POST'])
def secret_admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check credentials
        if (username in SECRET_ADMIN_CREDENTIALS and 
            safe_str_cmp(password, SECRET_ADMIN_CREDENTIALS[username])):
            session['secret_admin_logged_in'] = True
            session['user_email'] = username
            flash('Secret admin login successful!', 'success')
            return redirect(url_for('admin_control_panel'))
        else:
            flash('Invalid secret admin credentials.', 'error')
    
    return render_template('secret_admin_login.html')

@app.route('/secret-admin/logout')
def secret_admin_logout():
    session.pop('secret_admin_logged_in', None)
    flash('Secret admin logged out successfully.', 'success')
    return redirect(url_for('index'))
    
# Admin course management
@app.route('/admin/courses')
@admin_required
def admin_courses():
    courses = Course.query.all()
    return render_template('admin_courses.html', courses=courses)

@app.route('/admin/course/add', methods=['GET', 'POST'])
# @admin_required
def admin_add_course():
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form['title']
            description = request.form['description']
            category = request.form['category']
            level = request.form['level']
            image_url = request.form['image_url']
            duration = request.form['duration']
            lessons = request.form['lessons']
            rating = request.form.get('rating', 0)
            reviews_count = request.form.get('reviews_count', 0)
            
            # Process features and outcomes (convert from textarea to JSON)
            features = request.form['features'].split('\n') if request.form['features'] else []
            outcomes = request.form['outcomes'].split('\n') if request.form['outcomes'] else []
            
            # Create new course
            new_course = Course(
                title=title,
                description=description,
                category=category,
                level=level,
                image_url=image_url,
                duration=duration,
                lessons=lessons,
                rating=float(rating),
                reviews_count=int(reviews_count),
                features=json.dumps(features),
                outcomes=json.dumps(outcomes)
            )
            
            db.session.add(new_course)
            db.session.commit()
            
            flash('Course added successfully!', 'success')
            return redirect(url_for('admin_courses'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding course: {str(e)}', 'error')
    
    return render_template('admin_course_form.html', course=None, title='Add Course')

@app.route('/admin/course/edit/<int:course_id>', methods=['GET', 'POST'])
# @admin_required
def admin_edit_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    if request.method == 'POST':
        try:
            # Update course data
            course.title = request.form['title']
            course.description = request.form['description']
            course.category = request.form['category']
            course.level = request.form['level']
            course.image_url = request.form['image_url']
            course.duration = request.form['duration']
            course.lessons = request.form['lessons']
            course.rating = float(request.form.get('rating', 0))
            course.reviews_count = int(request.form.get('reviews_count', 0))
            
            # Process features and outcomes
            features = request.form['features'].split('\n') if request.form['features'] else []
            outcomes = request.form['outcomes'].split('\n') if request.form['outcomes'] else []
            
            course.features = json.dumps(features)
            course.outcomes = json.dumps(outcomes)
            course.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            flash('Course updated successfully!', 'success')
            return redirect(url_for('admin_courses'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating course: {str(e)}', 'error')
    
    # Convert JSON strings back to lists for editing
    features = json.loads(course.features) if course.features else []
    outcomes = json.loads(course.outcomes) if course.outcomes else []
    
    return render_template('admin_course_form.html', 
                         course=course, 
                         features="\n".join(features),
                         outcomes="\n".join(outcomes),
                         title='Edit Course')

@app.route('/admin/course/delete/<int:course_id>', methods=['POST'])
# @admin_required
def admin_delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    try:
        db.session.delete(course)
        db.session.commit()
        flash('Course deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting course: {str(e)}', 'error')
    
    return redirect(url_for('admin_courses'))

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['fullName']
        email = request.form['email']
        phone = request.form.get('phone', '')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.is_verified:
                flash('Email already registered. Please login instead.', 'error')
                return redirect(url_for('login'))
            else:
                # User exists but not verified, update details
                existing_user.full_name = full_name
                existing_user.phone = phone
        else:
            # Create new user
            existing_user = User(full_name=full_name, email=email, phone=phone)
            db.session.add(existing_user)
        
        # Generate verification code
        verification_code = ''.join(secrets.choice('0123456789') for i in range(6))
        existing_user.verification_code = verification_code
        existing_user.code_expiry = datetime.utcnow() + timedelta(minutes=10)
        
        db.session.commit()
        
        # Send verification email from company address
        if send_verification_email(email, verification_code):
            session['verify_email'] = email
            return redirect(url_for('verify_email'))
        else:
            flash('Failed to send verification email. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    email = session.get('verify_email')
    if not email:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        verification_code = request.form['verificationCode']
        user = User.query.filter_by(email=email).first()
        
        if user and user.verification_code == verification_code and user.code_expiry > datetime.utcnow():
            session['set_password_email'] = email
            return redirect(url_for('set_password'))
        else:
            flash('Invalid or expired verification code. Please try again.', 'error')
    
    return render_template('verify_email.html', email=email)

@app.route('/resend-code')
def resend_code():
    email = session.get('verify_email')
    if not email:
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first()
    if user:
        # Generate new verification code
        verification_code = ''.join(secrets.choice('0123456789') for i in range(6))
        user.verification_code = verification_code
        user.code_expiry = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()
        
        # Send verification email from company address
        if send_verification_email(email, verification_code):
            flash('Verification code has been resent to your email.', 'success')
        else:
            flash('Failed to resend verification code. Please try again.', 'error')
    
    return redirect(url_for('verify_email'))

@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    email = session.get('set_password_email')
    if not email:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return render_template('set_password.html', email=email)
        
        # Update user with password and mark as verified
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            user.is_verified = True
            user.verification_code = None
            user.code_expiry = None
            db.session.commit()
            
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('set_password.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        # Debug prints (remove in production)
        print(f"Login attempt: {email}")
        print(f"User found: {user is not None}")
        if user:
            print(f"User has password: {user.password is not None}")
            print(f"User is verified: {user.is_verified}")
        
        if not user or not user.password:
            flash('Invalid email or password. Please try again.', 'error')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Invalid email or password. Please try again.', 'error')
            return redirect(url_for('login'))
        
        if not user.is_verified:
            flash('Please verify your email before logging in.', 'error')
            return redirect(url_for('login'))
        
        # Login successful - set session
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.full_name
        
        if remember:
            session.permanent = True
        
        flash('Login successful!', 'success')
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/forgot-password')
def forgot_password():
    # Implement password reset functionality here
    return "Password reset page coming soon"

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    # Get user data and render dashboard
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

# Admin routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get all users
    users = User.query.all()
    
    # Count verified users
    verified_users = User.query.filter_by(is_verified=True).count()
    
    # Count recent users (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_users = User.query.filter(User.created_at >= thirty_days_ago).count()
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         verified_users=verified_users, 
                         recent_users=recent_users)

@app.route('/admin/user/<int:user_id>')
# @admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin_user_detail.html', user=user, datetime=datetime)

# Create admin user route (for initial setup)
@app.route('/create-admin')
def create_admin():
    # Check if admin already exists
    existing_admin = User.query.filter_by(email='admin@enlighter.com').first()
    if not existing_admin:
        admin_user = User(
            full_name="Admin User",
            email="admin@enlighter.com",
            phone="8867060569",
            password=generate_password_hash("1234"),
            is_verified=True
        )
        db.session.add(admin_user)
        db.session.commit()
        return "Admin user created successfully! Email: admin@enlighter.com, Password: 1234"
    else:
        return "Admin user already exists."

# Existing routes
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # Save to database
        new_contact = Contact(
            name=name,
            email=email,
            phone=phone,
            subject=subject,
            message=message
        )
        
        db.session.add(new_contact)
        db.session.commit()
        
        # Send confirmation email to user
        try:
            msg = Message(
                subject="Thank you for contacting Enlighter Tech",
                recipients=[email],
                html=f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: linear-gradient(135deg, #452FF4 0%, #41E295 100%); 
                                 padding: 20px; text-align: center; color: white; border-radius: 10px 10px 0 0; }}
                        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                        .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Enlighter Tech</h1>
                        </div>
                        <div class="content">
                            <h2>Thank you for contacting us!</h2>
                            <p>Dear {name},</p>
                            <p>We've received your message and our team will get back to you within 24 hours.</p>
                            <p><strong>Your Message:</strong></p>
                            <p>{message}</p>
                            <p>If you have any urgent questions, please call us at +91 74116 68259.</p>
                        </div>
                        <div class="footer">
                            <p>&copy; 2025 Enlighter Tech. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
            )
            mail.send(msg)
        except Exception as e:
            print(f"Error sending confirmation email: {e}")
        
        flash('Your message has been sent successfully! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html')

# Add admin contact management route
@app.route('/admin/contacts')
@admin_required
def admin_contacts():
    contacts = Contact.query.order_by(Contact.created_at.desc()).all()
    return render_template('admin_contacts.html', contacts=contacts)

@app.route('/admin/contact/<int:contact_id>')
@admin_required
def admin_contact_detail(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    # Mark as read
    contact.is_read = True
    db.session.commit()
    return render_template('admin_contact_detail.html', contact=contact)

@app.route('/admin/contact/delete/<int:contact_id>', methods=['POST'])
# @admin_required
def admin_delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    try:
        db.session.delete(contact)
        db.session.commit()
        flash('Contact message deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting message: {str(e)}', 'error')
    
    return redirect(url_for('admin_contacts'))

@app.route('/admin/contact/mark_read/<int:contact_id>')
@admin_required
def admin_mark_contact_read(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    contact.is_read = True
    db.session.commit()
    flash('Message marked as read.', 'success')
    return redirect(url_for('admin_contacts'))

@app.route('/enroll')
def enroll():
    return render_template('enroll.html')

@app.route('/')
def index():
    return render_template('index.html')

# @app.route('/courses')
# def courses():
#     return render_template('courses.html')

@app.route('/courses')
def courses():
    courses = Course.query.all()
    return render_template('courses.html', courses=courses)

@app.route('/cd/<int:course_id>')
def cd(course_id):
    course = Course.query.get_or_404(course_id)
    return render_template('cd.html', course=course)

@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        return json.loads(value)
    return []

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/course_details')
def course_details():
    return render_template('course_details.html')

@app.route('/course_details2')
def course_details2():
    return render_template('course_details2.html')

@app.route('/course_details3')
def course_details3():
    return render_template('course_details3.html')

@app.route('/course_details4')
def course_details4():
    return render_template('course_details4.html')

@app.route('/course_details5')
def course_details5():
    return render_template('course_details5.html')

@app.route('/course_details6')
def course_details6():
    return render_template('course_details6.html')


# Admin control panel route
@app.route('/admin/control-panel')
@secret_admin_required  # This ensures only secret admins can access
def admin_control_panel():
    # Get counts for dashboard
    users_count = User.query.count()
    courses_count = Course.query.count()
    contacts_count = Contact.query.count()
    
    # Get all data for management sections
    all_users = User.query.all()
    all_courses = Course.query.all()
    all_contacts = Contact.query.order_by(Contact.created_at.desc()).all()
    
    # Get system logs
    system_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(50).all()
    
    # Get system information
    python_version = sys.version
    flask_version = flask.__version__
    current_time = datetime.utcnow()
    
    # Calculate uptime (this is a simple implementation)
    # In a real application, you'd want to track start time
    uptime = "Unknown"
    
    # Get admin email
    admin_email = session.get('user_email', 'Unknown')
    
    return render_template('admin_control_panel.html',
                         users_count=users_count,
                         courses_count=courses_count,
                         contacts_count=contacts_count,
                         all_users=all_users,
                         all_courses=all_courses,
                         all_contacts=all_contacts,
                         system_logs=system_logs,
                         python_version=python_version,
                         flask_version=flask_version,
                         current_time=current_time,
                         uptime=uptime,
                         admin_email=admin_email)

# Update admin credentials
@app.route('/admin/update-credentials', methods=['POST'])
# @admin_required
def admin_update_credentials():
    try:
        admin_email = request.form['admin_email']
        current_password = request.form['current_password']
        new_password = request.form.get('new_password')
        
        # Get current admin user
        admin_user = User.query.filter_by(email=session['user_email']).first()
        
        if not admin_user or not check_password_hash(admin_user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('admin_control_panel'))
        
        # Update email if changed
        if admin_email != admin_user.email:
            admin_user.email = admin_email
            session['user_email'] = admin_email
            log_system_action("Admin email updated", f"Changed to {admin_email}")
        
        # Update password if provided
        if new_password:
            admin_user.password = generate_password_hash(new_password)
            log_system_action("Admin password updated")
        
        db.session.commit()
        
        flash('Admin credentials updated successfully.', 'success')
        log_system_action("Admin credentials updated")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating credentials: {str(e)}', 'error')
        log_system_action("Failed to update admin credentials", str(e))
    
    return redirect(url_for('admin_control_panel'))

# Create new admin user
@app.route('/admin/create-admin-user', methods=['POST'])
# @admin_required
def admin_create_admin_user():
    try:
        name = request.form['new_admin_name']
        email = request.form['new_admin_email']
        password = request.form['new_admin_password']
        phone = request.form.get('new_admin_phone', '')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists.', 'error')
            return redirect(url_for('admin_control_panel'))
        
        # Create new admin user
        new_admin = User(
            full_name=name,
            email=email,
            phone=phone,
            password=generate_password_hash(password),
            is_verified=True
        )
        
        db.session.add(new_admin)
        db.session.commit()
        
        flash('New admin user created successfully.', 'success')
        log_system_action("New admin user created", f"Email: {email}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating admin user: {str(e)}', 'error')
        log_system_action("Failed to create admin user", str(e))
    
    return redirect(url_for('admin_control_panel'))

# Backup database
@app.route('/admin/backup-database', methods=['POST'])
# @admin_required
def admin_backup_database():
    try:
        # Create backup directory if it doesn't exist
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Create backup file name with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'enlighter_backup_{timestamp}.db')
        
        # Copy current database to backup location
        shutil.copy2('enlighter.db', backup_file)
        
        flash(f'Database backup created successfully: {os.path.basename(backup_file)}', 'success')
        log_system_action("Database backup created", f"File: {os.path.basename(backup_file)}")
        
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'error')
        log_system_action("Failed to create database backup", str(e))
    
    return redirect(url_for('admin_control_panel'))

# Reset demo data
@app.route('/admin/reset-demo-data', methods=['POST'])
# @admin_required
def admin_reset_demo_data():
    try:
        # This is a placeholder - you would implement your demo data reset logic here
        flash('Demo data reset functionality not yet implemented.', 'info')
        log_system_action("Demo data reset attempted")
        
    except Exception as e:
        flash(f'Error resetting demo data: {str(e)}', 'error')
        log_system_action("Failed to reset demo data", str(e))
    
    return redirect(url_for('admin_control_panel'))

# Clear all data
@app.route('/admin/clear-database', methods=['POST'])
# @admin_required
def admin_clear_database():
    try:
        # Delete all data from tables (except admin users)
        admin_emails = ['admin@enlighter.com', session.get('user_email')]
        
        # Delete non-admin users
        User.query.filter(~User.email.in_(admin_emails)).delete()
        
        # Delete all courses
        Course.query.delete()
        
        # Delete all contacts
        Contact.query.delete()
        
        db.session.commit()
        
        flash('All non-admin data has been cleared successfully.', 'success')
        log_system_action("Database cleared", "All non-admin data removed")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing database: {str(e)}', 'error')
        log_system_action("Failed to clear database", str(e))
    
    return redirect(url_for('admin_control_panel'))

# Delete entire project
@app.route('/admin/delete-project', methods=['POST'])
# @admin_required
def admin_delete_project():
    try:
        # This is an extreme action - in a real application, you might want to
        # implement this differently or add additional safeguards
        
        # For safety, we'll just flash a message rather than actually deleting files
        flash('Project deletion functionality is disabled for safety.', 'warning')
        log_system_action("Project deletion attempted", "Functionality disabled for safety")
        
        # If you really want to implement this, you could do something like:
        # import shutil
        # project_root = os.path.dirname(os.path.abspath(__file__))
        # shutil.rmtree(project_root)
        # But this is extremely dangerous!
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        log_system_action("Failed to delete project", str(e))
    
    return redirect(url_for('admin_control_panel'))

# Delete user
@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
# @admin_required
def admin_delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent deleting yourself
        if user.email == session.get('user_email'):
            flash('You cannot delete your own account while logged in.', 'error')
            return redirect(url_for('admin_control_panel'))
        
        db.session.delete(user)
        db.session.commit()
        
        flash('User deleted successfully.', 'success')
        log_system_action("User deleted", f"User ID: {user_id}, Email: {user.email}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'error')
        log_system_action("Failed to delete user", str(e))
    
    return redirect(url_for('admin_control_panel'))



if __name__ == '__main__':
    app.run(debug=True)