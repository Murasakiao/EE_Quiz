from datetime import datetime
from app import app, db, QuizAttempt

def cleanup_quiz_attempts():
    with app.app_context():
        attempts_without_date = QuizAttempt.query.filter(QuizAttempt.date == None).all()
        for attempt in attempts_without_date:
            attempt.date = datetime.utcnow()
        db.session.commit()

if __name__ == '__main__':
    cleanup_quiz_attempts()