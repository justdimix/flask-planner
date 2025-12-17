from app import app, db

# Create the database tables based on the latest models in app.py
with app.app_context():
    db.create_all()
    print("Database has been recreated successfully with the new schema (including admin_notes)!")