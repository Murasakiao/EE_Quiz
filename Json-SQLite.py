import json
from flask import Flask
from sqlalchemy.exc import OperationalError
from app import db, Question, Topic  # Import your app and models
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import FlushError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
db.init_app(app)

def import_json_to_db():
    with app.app_context():
        db.create_all()
       
        try:
            db.session.query(Question).delete()
            db.session.query(Topic).delete()
            db.session.commit()
        except OperationalError:
            db.session.rollback()
       
        try:
            with open('questions.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
        except UnicodeDecodeError:
            with open('questions.json', 'r', encoding='iso-8859-1') as f:
                data = json.load(f)
       
        print(f"Loaded {len(data)} items from JSON file")
       
        topic_cache = {}
        
        for index, item in enumerate(data):
            print(f"Processing item {index + 1}:")
            print(json.dumps(item, indent=2))
           
            topics = []
            if 'topics' in item:
                for topic_name in item['topics']:
                    cache_key = (topic_name, item['subject'])
                    if cache_key not in topic_cache:
                        topic = Topic.query.filter_by(name=topic_name, subject=item['subject']).first()
                        if not topic:
                            topic = Topic(name=topic_name, subject=item['subject'])
                            db.session.add(topic)
                            try:
                                db.session.flush()
                            except IntegrityError:
                                db.session.rollback()
                                topic = Topic.query.filter_by(name=topic_name, subject=item['subject']).first()
                        topic_cache[cache_key] = topic
                    topics.append(topic_cache[cache_key])
            else:
                print(f"Warning: 'topics' key missing in item {index + 1}")
           
            required_fields = ['text', 'options', 'correct_answer', 'subject', 'difficulty']
            if all(field in item for field in required_fields):
                question = Question(
                    text=item['text'],
                    options=item['options'],
                    correct_answer=item['correct_answer'],
                    explanation=item.get('explanation', ''),
                    subject=item['subject'],
                    difficulty=item['difficulty']
                )
                db.session.add(question)
                try:
                    db.session.flush()
                    for topic in topics:
                        if topic not in question.topics:
                            question.topics.append(topic)
                            db.session.flush()
                except (IntegrityError, FlushError):
                    db.session.rollback()
                    print(f"Error occurred at item {index + 1}. Rolling back and continuing...")
            else:
                print(f"Error: Missing required fields in item {index + 1}")
           
            if (index + 1) % 100 == 0:
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    print(f"Error occurred at item {index + 1}. Rolling back and continuing...")
       
        try:
            db.session.commit()
            print("Database update completed")
        except IntegrityError:
            db.session.rollback()
            print("Final commit failed. Some data may not have been saved.")

if __name__ == '__main__':
    import_json_to_db()
    print("Script execution finished")