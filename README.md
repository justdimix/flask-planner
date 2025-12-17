📅 Calendar Planner

Corporate web task planner with role system, internal messaging, and administration features.

✨ Features

🗓️ Smart Calendar

Visualization: Clear 2-week grid with 30-minute intervals.

Absolute Positioning: Tasks are displayed at exact times (e.g., 09:30 - 10:30) without being tied to rigid grid cells with 30 minute interval cropping.

Grouping: Automatic splitting of long tasks into daily segments (07:00 to 21:00) when spanning across multiple days.

Customization: Background color selection for each task.

👥 Role System

User: View own schedule, profile management, send messages to administrators.

Admin: Manage users, create global tasks, post news, view calendars of other users.

Super Admin (Owner): Full access, manage administrator rights, protection from deletion.

👤 Personal Profile

Avatar: Photo upload with cropping and zooming capabilities before saving.

Status: Set work status (In Office, Remote, Sick, Vacation).

Data: Edit contact information.

📨 Communication

Internal Mail: Send messages between users (User -> Admin, Admin -> All/Selected).

Notifications: Unread message indicators, read status tracking.

News & Events: Dedicated page with a news feed managed by administrators. Lightbox for image viewing.

🛡️ Security

Rate Limiting: Protection against spam and brute-force attacks.

Validation: Strict input validation (restricted words in usernames, character limits).

🚀 Installation & Launch (Local)

1. Clone the repository

git clone [https://github.com/justdimix/flask-planner.git](https://github.com/justdimix/flask-planner.git)
cd flask-planner


2. Create Virtual Environment

Windows:

python -m venv venv
venv\Scripts\activate


macOS/Linux:

python3 -m venv venv
source venv/bin/activate


3. Install Dependencies

pip install -r requirements.txt


4. Run the Application

python app.py


On the first run, database.db will be created automatically. The first registered user will automatically be granted Super Admin rights.

🌐 Deployment on PythonAnywhere

Create an account at PythonAnywhere.

Upload the code via Bash console:

git clone [https://github.com/justdimix/flask-planner.git](https://github.com/justdimix/flask-planner.git) mysite


Configure the virtual environment:

cd mysite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


Create the database:

python -c "from app import app, db; app.app_context().push(); db.create_all()"


In the Web tab, configure the source code path, virtual environment path, and WSGI file (refer to detailed deployment guide).

Click the Reload button.

🛠️ Technologies

Backend: Python, Flask, SQLAlchemy, Flask-Login, Flask-Limiter.

Frontend: HTML5, Tailwind CSS, JavaScript.

Libraries: Flatpickr (calendar input), Cropper.js (image cropping).

Database: SQLite.
