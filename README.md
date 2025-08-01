# College Gate Pass System

A professional smart gate pass system for colleges that manages student gate passes with role-based access control.

## Features

- Role-based access control (Admin, HOD, Student, Security)
- Student registration with photo upload
- HOD verification of students
- Gate pass request and approval system
- Real-time status tracking
- Responsive web interface

## Prerequisites

- Python 3.7 or higher
- Python 3.12 or lesser
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd college-gate-pass
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
>>> exit()
```

5. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

### Student Registration
1. Click on "Student Sign Up"
2. Fill in the registration form with:
   - Email
   - Password
   - Full Name
   - Roll Number
   - Department
   - Photo
3. Wait for HOD verification

### HOD Registration
1. Click on "HOD Sign Up"
2. Fill in the registration form with:
   - Email
   - Password
   - Department
3. Login to verify students from your department

### Security Staff
1. Contact admin for account creation
2. Login to approve/reject gate passes

### Admin
1. Contact system administrator for account creation
2. Manage users and system settings

## Security Features

- Password hashing
- Role-based access control
- Session management
- File upload validation
- SQL injection prevention

