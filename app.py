from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template, request, flash, redirect, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Email
from flask_mail import Mail, Message
from sqlalchemy import func
from datetime import datetime
from datetime import timedelta
from time import time
import jwt
import random
import logging

# configs
app = Flask(__name__)
app.config['SECRET_KEY'] = '55197e79f9c0f860af246d97a6360cb0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'colesjulius3@gmail.com'
app.config['MAIL_PASSWORD'] = 'rcqz gmrd gtcx vgfw'
app.config['MAIL_DEFAULT_SENDER'] = 'colesjulius3@gmail.com'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)

# Association table for the many-to-many relationship between Question and Topic
question_topics = db.Table('question_topics',
    db.Column('question_id', db.Integer, db.ForeignKey('question.id'), primary_key=True),
    db.Column('topic_id', db.Integer, db.ForeignKey('topic.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', back_populates='role')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', back_populates='users')
    email_verified = db.Column(db.Boolean, default=False)
    quiz_attempts = db.relationship('QuizAttempt', back_populates='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    def __repr__(self):
        return f'<User {self.username}>'
    
    def has_role(self, role_name):
        return self.role.name == role_name if self.role else False
    
    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Increased length to accommodate longer topic names
    subject = db.Column(db.String(100), nullable=False)

    def __str__(self):
        return f"{self.name} ({self.subject})"

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    options = db.Column(db.String(500), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)
    explanation = db.Column(db.String(500))
    subject = db.Column(db.String(100), nullable=False)
    difficulty = db.Column(db.String(20))
    topics = db.relationship('Topic', secondary=question_topics, backref=db.backref('questions', lazy='dynamic'))

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    topics = db.Column(db.String(500), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='quiz_attempts')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class UserView(ModelView):
    column_list = ('id', 'username', 'email', 'role', 'email_verified')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/admin')
@login_required
def admin():
    if not current_user.has_role('admin'):
        abort(403)  # Forbidden
    # Admin page logic here
    return render_template('admin.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.email_verified:
                login_user(user, remember=form.remember_me.data)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', title='Sign In', form=form)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash('A verification email has been sent to your email address. Please verify your email to complete registration.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/profile')
@login_required
def profile():
    return redirect(url_for('dashboard'))

@app.route('/verify_email/<token>')
def verify_email(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=3600)  # Token expires after 1 hour
    except:
        return 'The verification link is invalid or has expired.'
    
    user = User.query.filter_by(email=email).first()
    if user.email_verified:
        return 'Email already verified. Please login.'
    else:
        user.email_verified = True
        db.session.commit()
        return 'Thank you for verifying your email address!'

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    subjects = {
        'Engineering Mathematics': [
            'Algebra and Complex Numbers',
            'Trigonometry',
            'Analytic Geometry',
            'Probability & Statistics',
            'Calculus 1',
            'Calculus 2',
            'Engineering Data Analysis',
            'Differential Equations',
            'Numerical Methods & Analysis'
        ],
        'Engineering Science and Allied Subjects': [
            'Chemistry for Engineers',
            'Physics for Engineers',
            'Computer Programming, Microprocessor Systems and Logic Circuits and Switching Theory',
            'Material Science, Environmental Science and Engineering',
            'Fluid Mechanics',
            'Fundamental of Deformable Bodies',
            'Basic Thermodynamics',
            'EE Laws, Codes, Professional Ethics, BOSH & Electrical Standards and Practices',
            'Engineering Economics',
            'Technopreneurship 101 and Management of Engineering Projects'
        ],
        'Electrical Engineering': [
            'Electromagnetism',
            'Electric Circuits 1',
            'Electric Circuits 2',
            'Fundamentals of Electronic Communications, Electronics 1 and 2',
            'Electrical Apparatus & Devices, Industrial Electronics',
            'Electrical Machinery 1',
            'Electrical Machinery 2',
            'Instrumentation & Control, Feedback Control System and Research Methods',
            'Electrical Systems & Illumination Engineering Design',
            'Fundamental of Power Plants Engineering Designs and Distribution Systems and Substation Design',
            'Power System Analysis'
        ]
    }
    
    if request.method == 'POST':
        session['subject'] = request.form.get('subject')
        session['topics'] = request.form.getlist('topics')
        session['difficulty'] = request.form.get('difficulty')
        session['score'] = 0
        session['questions_asked'] = 0
        return redirect(url_for('quiz_setup'))
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        subject = request.args.get('subject')
        return jsonify(subjects.get(subject, []))
    
    selected_subject = request.args.get('subject', 'Engineering Mathematics')
    topics = subjects.get(selected_subject, [])
    return render_template('index.html', subjects=subjects, topics=topics, selected_subject=selected_subject)

@app.route('/quiz_setup', methods=['GET', 'POST'])
@login_required
def quiz_setup():
    app.logger.debug(f"Session at start of quiz route: {session}")
    
    if request.method == 'POST':
        answer = request.form.get('answer')
        correct_answer = request.form.get('correct_answer')
        if answer == correct_answer:
            session['score'] = session.get('score', 0) + 1
        session['questions_asked'] = session.get('questions_asked', 0) + 1
        
        app.logger.debug(f"Questions asked: {session['questions_asked']}")
        
        if session['questions_asked'] >= 10:
            return redirect(url_for('result'))
    
    app.logger.debug(f"Subject: {session.get('subject')}")
    app.logger.debug(f"Topics: {session.get('topics')}")
    app.logger.debug(f"Difficulty: {session.get('difficulty')}")

    # Query questions that match the subject, difficulty, and any of the selected topics
    questions = Question.query.filter(
        Question.subject == session.get('subject'),
        Question.difficulty == session.get('difficulty'),
        Question.topics.any(Topic.name.in_(session.get('topics', [])))
    ).all()
    
    app.logger.debug(f"Retrieved questions: {questions}")
    
    if not questions:
        app.logger.warning(f"No questions found for subject={session.get('subject')}, topics={session.get('topics')}, difficulty={session.get('difficulty')}")
        return redirect(url_for('result'))
    
    question = random.choice(questions)
    app.logger.debug(f"Selected question: {question.text}")
    
    options = question.options.split(',')
    app.logger.debug(f"Options before shuffle: {options}")
    
    random.shuffle(options)
    app.logger.debug(f"Options after shuffle: {options}")

    app.logger.debug(f"Question: {question.text if question else 'No question'}")
    app.logger.debug(f"Options: {options}")
    app.logger.debug(f"Correct answer: {question.correct_answer if question else 'No correct answer'}")

    return render_template('quiz.html', question=question, options=options)

@app.route('/result')
@login_required
def result():
    score = session.get('score', 0)
    total_questions = session.get('questions_asked', 0)
    subject = session.get('subject')
    topics = session.get('topics', [])
    difficulty = session.get('difficulty')
    
    save_quiz_attempt(current_user.id, subject, topics, difficulty, score, total_questions)
    
    session.clear()
    return render_template('result.html', 
                           score=score, 
                           total=total_questions, 
                           subject=subject, 
                           topics=topics, 
                           difficulty=difficulty)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get overall statistics
    total_attempts = QuizAttempt.query.filter_by(user_id=current_user.id).count()
    avg_score = db.session.query(func.avg(QuizAttempt.score)).filter_by(user_id=current_user.id).scalar() or 0
    
    # Get subject-wise performance
    subject_performance = db.session.query(
        QuizAttempt.subject,
        func.avg(QuizAttempt.score).label('avg_score'),
        func.count(QuizAttempt.id).label('attempts')
    ).filter_by(user_id=current_user.id).group_by(QuizAttempt.subject).all()
    
    # Get recent quiz attempts
    recent_attempts = QuizAttempt.query.filter_by(user_id=current_user.id).order_by(QuizAttempt.date.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                           total_attempts=total_attempts, 
                           avg_score=avg_score,
                           subject_performance=subject_performance,
                           recent_attempts=recent_attempts)

def init_db():
    db.create_all()
    if Role.query.count() == 0:
        admin_role = Role(name='admin')
        user_role = Role(name='user')
        db.session.add(admin_role)
        db.session.add(user_role)
        db.session.commit()

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message('Reset Your Password',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

def send_verification_email(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps(user.email, salt='email-verification-salt')
    verify_url = url_for('verify_email', token=token, _external=True)
    
    subject = "Please verify your email"
    body = f"Thanks for signing up! Please click the link to verify your email: {verify_url}"
    
    msg = Message(subject=subject, recipients=[user.email], body=body)
    mail.send(msg)

def save_quiz_attempt(user_id, subject, topics, difficulty, score, total_questions):
    quiz_attempt = QuizAttempt(
        user_id=user_id,
        subject=subject,
        topics=','.join(topics),
        difficulty=difficulty,
        score=score,
        total_questions=total_questions
    )
    db.session.add(quiz_attempt)
    db.session.commit()

def add_role_to_user(user, role_name):
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        role = Role(name=role_name)
        db.session.add(role)
    user.role = role

admin = Admin(app, name='Quiz Admin', template_mode='bootstrap3')
admin.add_view(ModelView(Question, db.session))
admin.add_view(ModelView(Topic, db.session))
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Role, db.session))

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)