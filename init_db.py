import csv
from app import db, Question
from app import app

def import_questions_from_csv(filename):
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(f"Importing question: {row['Question Text']}")  # Debug print
            question = Question(
                text=row['Question Text'],
                options=f"{row['Option A']},{row['Option B']},{row['Option C']},{row['Option D']}",
                correct_answer=row['Correct Answer'],
                explanation=row['Explanation'],  
                subject=row['Subject'],
                difficulty=row['Difficulty'] 
            )
            db.session.add(question)
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        import_questions_from_csv('questions\qb_1.csv')
