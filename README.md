# Moodle Rip-off: LMS File Management System

A lightweight Learning Management System focused on secure file management with VirusTotal integration, role-based permissions, and file sharing capabilities.

## Features

- **Secure File Upload** with VirusTotal malware scanning
- **Role-Based Access Control** (Student, Teacher, Administrator)
- **File Sharing** with UUID links and optional password protection
- **File Metadata Tracking** (views, checksums, sizes)
- **BinaryField Storage** (files stored as BLOBs in SQLite)
- **Automatic Compression** for large files (>5MB) before VirusTotal scanning
- **Permission Levels** for shared files (Public, Student, Teacher, Administrator)

## Tech Stack

- **Backend:** Python 3.11, Django 5.0.6
- **Database:** SQLite3
- **Security:** Argon2 password hashing, CSRF protection
- **External API:** VirusTotal v3 API
- **Storage:** Files stored as BLOBs in database (BinaryField)

## Setup Instructions

### 1. Prerequisites

- Python 3.11+
- pip
- Virtual environment (`.venv/`)

### 2. Clone and Setup

```bash
cd Moodle_rip-off

# Activate virtual environment
source .venv/bin/activate  # On Linux/Mac
# or
.venv\Scripts\activate  # On Windows

# Install dependencies
.venv/bin/pip install -r requirements.txt
```

### 3. Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your VirusTotal API key
# Get API key from: https://www.virustotal.com/gui/my-apikey
nano .env
```

Required environment variables:
- `SECRET_KEY`: Django secret key (generate a new one for production)
- `DEBUG`: Set to `False` in production
- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key

### 4. Database Setup

```bash
cd moodle_site

# Run migrations
../.venv/bin/python manage.py migrate

# Create a superuser for admin access
../.venv/bin/python manage.py createsuperuser
```

### 5. Run the Development Server

```bash
# From moodle_site/ directory
../.venv/bin/python manage.py runserver

# Server will start at http://127.0.0.1:8000/
```

## Usage Guide

### Initial Access

1. Navigate to `http://127.0.0.1:8000/`
2. Click "Login" or go to `/login/`
3. Create a new account or login with superuser credentials
4. Access the admin panel at `/admin/` to manage users and roles

### User Roles

1. **Student** (default) - Upload files, view files in enrolled courses
2. **Teacher** - All student permissions + manage course materials, create shares
3. **Administrator** - Full system access, manage all files and users

### Five Main Workflows

#### 1. Upload Submission File
- Go to `/files/upload/`
- Enter file name and description
- Select file (max 200 MB)
- Files >5MB are automatically compressed before VirusTotal scan
- Malicious files are rejected

#### 2. Generate File Share
- Go to file detail page: `/files/<id>/`
- Click "Create Share Link"
- Set permission levels and optional password/expiration
- Share URL format: `/s/<uuid>/`

#### 3. Delete File
- Go to file detail page: `/files/<id>/`
- Click "Delete" button
- Confirm deletion

#### 4. View File Metadata (API)
- POST to `/files/<id>/view/` returns JSON with metadata
- Updates view counter and last viewed timestamp

#### 5. Retrieve File
- Download: GET `/files/<id>/get/?download=true`
- Metadata only: GET `/files/<id>/get/`

## API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/files/` | GET | List accessible files | Yes |
| `/files/upload/` | POST | Upload new file | Yes |
| `/files/<id>/` | GET | View file details | Yes |
| `/files/<id>/view/` | POST | Update view metadata | Yes |
| `/files/<id>/get/` | GET | Download or get metadata | Yes |
| `/files/<id>/delete/` | POST | Delete file | Yes |
| `/files/<id>/share/create/` | POST | Create share link | Yes |
| `/s/<uuid>/` | GET/POST | Access shared file | No* |
| `/s/<uuid>/download/` | GET | Download via share | No* |

\* Auth required based on share permission level

## Security Features

See [SECURITY.md](SECURITY.md) for detailed security documentation.

Key security controls:
- Argon2 password hashing
- VirusTotal malware scanning
- CSRF protection
- Role-based permissions
- Content-type validation
- SQL injection protection (Django ORM)
- XSS protection (Django auto-escape)

## Troubleshooting

### VirusTotal API Errors
- Check `.env` file has correct API key
- Free tier has 32MB limit and rate limits

### File Upload Errors
- Files >200MB are rejected
- Check file extension matches content

### Permission Errors
- Check user role and file ownership
- Some actions require authentication

## Production Deployment

1. Set `DEBUG=False`
2. Change `SECRET_KEY`
3. Configure `ALLOWED_HOSTS`
4. Use production server (Gunicorn/uWSGI)
5. Set up HTTPS
6. Regular database backups

## License

Educational project. See CLAUDE.md for specifications.
