import json
from flask import Flask
from app import db, Question, Topic

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
db.init_app(app)

def export_db_to_json():
    try:
        with app.app_context():
            questions = Question.query.all()
            data = []
            for question in questions:
                data.append({
                    'id': question.id,
                    'text': question.text,
                    'options': question.options,
                    'correct_answer': question.correct_answer,
                    'explanation': question.explanation,
                    'subject': question.subject,
                    'difficulty': question.difficulty,
                    'topics': [topic.name for topic in question.topics]
                })
           
            with open('questions.json', 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"Successfully exported {len(data)} questions to questions.json")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    export_db_to_json()