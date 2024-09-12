import json
from app import db, Question
from app import app

def update_questions_from_json(json_file):
    with open(json_file, 'r') as file:
        questions = json.load(file)
    
    for q in questions:
        question = Question.query.filter_by(text=q['text']).first()

        if question:
            # If the question exists, update its details
            question.options = q['options']
            question.correct_answer = q['correct_answer']
            question.explanation = q['explanation']
            question.subject = q['subject']
            question.difficulty = q['difficulty']
        else:
            # If the question doesn't exist, add a new entry
            new_question = Question(
                text=q['text'],
                options=q['options'],
                correct_answer=q['correct_answer'],
                explanation=q['explanation'],
                subject=q['subject'],
                difficulty=q['difficulty']
            )
            db.session.add(new_question)

    db.session.commit()
    print("Questions updated successfully")

if __name__ == "__main__":
    with app.app_context():
        update_questions_from_json('questions\q2.json')
