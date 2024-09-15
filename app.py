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
from sqlalchemy import func, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from time import time
from dotenv import load_dotenv
import os
import jwt
import random
import logging

# configs
load_dotenv()  # Load environment variables from .env file
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
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
    rank = db.Column(db.Integer, default=8)
    honor_points = db.Column(db.Integer, default=5)
    current_streak = db.Column(db.Integer, default=0)
    longest_streak = db.Column(db.Integer, default=0)
    last_quiz_date = db.Column(db.Date)
    achievements = db.relationship('Achievement', secondary='user_achievements', back_populates='users')
    quiz_attempts = db.relationship('QuizAttempt', back_populates='user', cascade='all, delete-orphan')

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
    
class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    users = db.relationship('User', secondary='user_achievements', back_populates='achievements')

user_achievements = db.Table('user_achievements',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('achievement_id', db.Integer, db.ForeignKey('achievement.id'), primary_key=True)
)

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
    topics = relationship('Topic', secondary=question_topics, backref=db.backref('questions', lazy='dynamic'))
    quiz_attempts = relationship('QuizAttempt', back_populates='question')

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, ForeignKey('question.id'))
    subject = db.Column(db.String(100), nullable=False)
    topics = db.Column(db.String(500), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completion_time = db.Column(db.Integer)  # in minutes

    user = relationship('User', back_populates='quiz_attempts')
    question = relationship('Question', back_populates='quiz_attempts')

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
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.email_verified:
                login_user(user, remember=form.remember_me.data)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
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
    return redirect(url_for('home'))

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
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
        return redirect(url_for('home'))
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
        return redirect(url_for('home'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('home'))
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

@app.route('/')
def home():
    total_attempts = 0
    avg_score = 0
    if current_user.is_authenticated:
        total_attempts = QuizAttempt.query.filter_by(user_id=current_user.id).count()
        avg_score = db.session.query(func.avg(QuizAttempt.score)).filter_by(user_id=current_user.id).scalar() or 0
    return render_template('home.html', total_attempts=total_attempts, avg_score=avg_score)

@app.route('/random_question')
@login_required
def random_question():
    question = Question.query.order_by(func.random()).first()
    return render_template('random_question.html', question=question)

@app.route('/quiz_setup', methods=['GET', 'POST'])
@login_required
def quiz_setup():
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
        return redirect(url_for('quiz'))
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        subject = request.args.get('subject')
        return jsonify(subjects.get(subject, []))
    
    selected_subject = request.args.get('subject', 'Engineering Mathematics')
    topics = subjects.get(selected_subject, [])
    return render_template('quiz_setup.html', subjects=subjects, topics=topics, selected_subject=selected_subject)

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
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
    update_user_stats(current_user.id, score, subject)
    
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
    user = current_user
    total_quizzes = QuizAttempt.query.filter_by(user_id=user.id).count()
    highest_score = db.session.query(func.max(QuizAttempt.score)).filter_by(user_id=user.id).scalar() or 0
    favorite_subject = db.session.query(
        QuizAttempt.subject, 
        func.count(QuizAttempt.id).label('count')
    ).filter_by(user_id=user.id).group_by(QuizAttempt.subject).order_by(func.count(QuizAttempt.id).desc()).first()
    
    recent_quizzes = QuizAttempt.query.filter_by(user_id=user.id).order_by(QuizAttempt.date.desc()).limit(15).all()
    
    subject_progress = db.session.query(
        QuizAttempt.subject,
        func.avg(QuizAttempt.score).label('avg_score'),
        func.count(QuizAttempt.id).label('attempts')
    ).filter_by(user_id=user.id).group_by(QuizAttempt.subject).all()

    achievements = current_user.achievements
    
    return render_template('dashboard.html', 
                           user=current_user,
                           total_quizzes=total_quizzes,
                           highest_score=highest_score,
                           favorite_subject=favorite_subject,
                           recent_quizzes=recent_quizzes,
                           subject_progress=subject_progress,
                           achievements=current_user.achievements)

@app.template_filter('unique')
def unique_filter(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]

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
        total_questions=total_questions,
        date=datetime.utcnow()  # Ensure date is always set
    )
    db.session.add(quiz_attempt)
    db.session.commit()

def add_role_to_user(user, role_name):
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        role = Role(name=role_name)
        db.session.add(role)
    user.role = role

# Functions to update user stats
def update_user_stats(user_id, quiz_score, quiz_subject):
    user = User.query.get(user_id)
    today = datetime.utcnow().date()

    # Update streak
    if user.last_quiz_date:
        days_since_last_quiz = (today - user.last_quiz_date).days
        if days_since_last_quiz == 1:
            user.current_streak += 1
            user.longest_streak = max(user.longest_streak, user.current_streak)
        elif days_since_last_quiz > 1:
            user.current_streak = 1
    else:
        user.current_streak = 1

    user.last_quiz_date = today

    # Update honor points and rank
    honor_gained = calculate_honor(quiz_score, quiz_subject)
    user.honor_points += honor_gained
    user.rank = calculate_rank(user.honor_points)

    # Check for new achievements
    check_achievements(user)

    db.session.commit()

def calculate_honor(quiz_score, quiz_subject):
    # Implement your own logic here
    base_honor = quiz_score
    subject_multiplier = 1.5 if quiz_subject == 'Advanced Topics' else 1
    return int(base_honor * subject_multiplier)

def calculate_rank(honor_points):
    # Implement your own ranking system
    if honor_points < 100:
        return 8
    elif honor_points < 150:
        return 7
    elif honor_points < 300:
        return 6
    # ... and so on

def check_achievements(user):
    # Get all quiz attempts for the user
    quiz_attempts = QuizAttempt.query.filter_by(user_id=user.id).all()
    
    # Calculate various statistics
    total_attempts = len(quiz_attempts)
    perfect_scores = sum(1 for attempt in quiz_attempts if attempt.score == attempt.total_questions)
    distinct_subjects = set(attempt.subject for attempt in quiz_attempts)
    
    # Check for streaks
    if quiz_attempts:
        dates = sorted(set(attempt.date.date() for attempt in quiz_attempts))
        current_streak = 1
        max_streak = 1
        for i in range(1, len(dates)):
            if (dates[i] - dates[i-1]) == timedelta(days=1):
                current_streak += 1
                max_streak = max(max_streak, current_streak)
            else:
                current_streak = 1
    else:
        max_streak = 0

    # Define achievements
    achievements = [
        ("Quiz Novice", "Complete your first quiz", total_attempts >= 1),
        ("Streak Master", "Maintain a 7-day streak", max_streak >= 7),
        ("Perfect Score", "Get 100% on any quiz", perfect_scores > 0),
        ("Quiz Marathoner", "Attempt quizzes for 30 consecutive days", max_streak >= 30),
        ("Diligent Learner", "Complete quizzes from all available subjects", len(distinct_subjects) >= 3),  # Assuming there are at least 3 subjects
    ]

    # Check each achievement
    for name, description, condition in achievements:
        achievement = Achievement.query.filter_by(name=name).first()
        if achievement and achievement not in user.achievements and condition:
            user.achievements.append(achievement)

    db.session.commit()

# Make sure these helper functions are defined
def max_consecutive_days(dates):
    if not dates:
        return 0
    dates = sorted(set(dates))
    max_streak = current_streak = 1
    for i in range(1, len(dates)):
        if (dates[i] - dates[i-1]).days == 1:
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            current_streak = 1
    return max_streak

def max_consecutive_true(bool_list):
    max_streak = current_streak = 0
    for value in bool_list:
        if value:
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            current_streak = 0
    return max_streak

# Populate initial achievements
def populate_achievements():
    achievements = [
        Achievement(name="Quiz Novice", description="Complete your first quiz"),
        Achievement(name="Streak Master", description="Maintain a 7-day streak"),
        Achievement(name="Perfect Score", description="Get 100% on any quiz"),
        Achievement(name="Quiz Marathoner", description="Attempt quizzes for 30 consecutive days"),
        Achievement(name="Diligent Learner", description="Complete quizzes from all available subjects"),
    ]
    for achievement in achievements:
        existing = Achievement.query.filter_by(name=achievement.name).first()
        if not existing:
            db.session.add(achievement)
        else:
            existing.description = achievement.description
    db.session.commit()

admin = Admin(app, name='Quiz Admin', template_mode='bootstrap3')
admin.add_view(ModelView(Question, db.session))
admin.add_view(ModelView(Topic, db.session))
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Role, db.session))

if __name__ == '__main__':
    with app.app_context():
        init_db()
        populate_achievements()
    app.run(debug=True)