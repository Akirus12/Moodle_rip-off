# Moodle Rip-off: LMS File Management System

A lightweight Learning Management System focused on secure file management with VirusTotal integration, role-based permissions, and file sharing capabilities.

## 🚀 Quick Start (TL;DR)

```bash
cd Moodle_rip-off
./docker-setup.sh
docker compose up
# Visit http://localhost:8000
```

**Note:** VirusTotal is disabled by default for easy testing. All files upload instantly!

---

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

## Recent Updates

### Docker Support Added
- ✅ Dockerfile with all system dependencies (`libmagic1`)
- ✅ docker-compose.yml with environment variables
- ✅ Automated setup script (`docker-setup.sh`)
- ✅ VirusTotal bypass mode for testing without API key

### Bug Fixes
- ✅ Fixed `ImportError: failed to find libmagic` (added to Dockerfile)
- ✅ Fixed `NameError: name 'Tuple' is not defined` (import fix in permissions.py)
- ✅ Added `DISABLE_VIRUSTOTAL` setting for testing

## Setup Instructions

### Recommended: Docker Setup (Easy & Fast)

#### Prerequisites
- Docker
- Docker Compose

#### Quick Start

```bash
cd Moodle_rip-off

# Option 1: Automated setup script
./docker-setup.sh

# Option 2: Manual setup
docker compose build
docker compose run --rm web python manage.py migrate
docker compose run --rm web python manage.py createsuperuser

# Start the server
docker compose up
```

The server will be available at:
- **Main site:** http://localhost:8000
- **Admin panel:** http://localhost:8000/admin

**Note:** VirusTotal scanning is **DISABLED by default** in Docker for easy testing. All files will be accepted without malware scanning. To enable it, see the [Re-enabling VirusTotal](#re-enabling-virustotal) section.

For detailed Docker instructions, see [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md).

---

### Alternative: Local Python Setup

#### Prerequisites
- Python 3.11+
- pip
- Virtual environment (`.venv/`)
- System library: `libmagic` (for file type detection)

#### Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libmagic1
```

**macOS:**
```bash
brew install libmagic
```

**Windows:**
Download from: https://github.com/pidydx/libmagicwin64

#### Setup Steps

```bash
cd Moodle_rip-off

# Activate virtual environment
source .venv/bin/activate  # On Linux/Mac
# or
.venv\Scripts\activate  # On Windows

# Install dependencies
.venv/bin/pip install -r requirements.txt
```

#### Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add settings
nano .env
```

Required environment variables:
- `SECRET_KEY`: Django secret key (generate a new one for production)
- `DEBUG`: Set to `False` in production
- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (get from https://www.virustotal.com/gui/my-apikey)
- `DISABLE_VIRUSTOTAL`: Set to `True` for testing without API key

#### Database Setup

```bash
cd moodle_site

# Run migrations
../.venv/bin/python manage.py migrate

# Create a superuser for admin access
../.venv/bin/python manage.py createsuperuser
```

#### Run the Development Server

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

## Re-enabling VirusTotal

By default, VirusTotal scanning is disabled in Docker to allow testing without an API key.

### For Docker:

Edit `docker-compose.yml`:
```yaml
environment:
  - VIRUSTOTAL_API_KEY=your-api-key-here
  - DISABLE_VIRUSTOTAL=False
```

Then restart:
```bash
docker compose down
docker compose up
```

### For Local Python:

Edit `.env`:
```
VIRUSTOTAL_API_KEY=your-api-key-here
DISABLE_VIRUSTOTAL=False
```

Get your API key from: https://www.virustotal.com/gui/my-apikey

## Useful Docker Commands

```bash
# View logs
docker compose logs -f

# Stop server
docker compose down

# Stop and remove everything (including database)
docker compose down -v

# Access Django shell
docker compose run --rm web python manage.py shell

# Run any Django management command
docker compose run --rm web python manage.py <command>

# Restart server
docker compose restart

# Reset database
docker compose down -v
rm moodle_site/db.sqlite3
docker compose run --rm web python manage.py migrate
docker compose run --rm web python manage.py createsuperuser
```

## Troubleshooting

### VirusTotal API Errors
- **Invalid API key:** Check `.env` or `docker-compose.yml` has correct API key
- **File too large:** Free tier has 32MB limit; files >32MB will fail
- **API quota exceeded:** Free tier has rate limits (4 requests/minute)
- **Testing without API:** Set `DISABLE_VIRUSTOTAL=True` to bypass scanning

### File Upload Errors
- **File exceeds maximum size:** Files >200MB are rejected (configurable in settings.py)
- **File is empty:** Upload failed or file is 0 bytes
- **Content type mismatch:** File extension doesn't match content

### Permission Errors
- **You don't have permission:** Check your user role and file ownership
- **Authentication required:** Some actions require login

### Docker Errors

#### Port 8000 Already in Use
```bash
# Find what's using port 8000
sudo lsof -i :8000

# Or change the port in docker-compose.yml
ports:
  - "8001:8000"  # Use port 8001 instead
```

#### Database Locked Error
```bash
docker compose down
docker compose up
```

#### ImportError: failed to find libmagic
This is fixed in the Dockerfile. If you see this error, rebuild:
```bash
docker compose build --no-cache
```

#### Module Import Errors
Make sure you're using the correct Python version (3.11+):
```bash
docker compose run --rm web python --version
```

## Production Deployment

1. Set `DEBUG=False`
2. Change `SECRET_KEY`
3. Configure `ALLOWED_HOSTS`
4. Use production server (Gunicorn/uWSGI)
5. Set up HTTPS
6. Regular database backups

## What's Implemented and Ready to Test

### ✅ All 5 Core Workflows
1. **Upload Submission File** - Full VirusTotal integration with bypass mode
2. **Generate File Share** - UUID links with password protection
3. **Delete File** - Permission checks and cascade deletion
4. **Post View Request** - Metadata tracking and JSON API
5. **Retrieve File** - Download and metadata endpoints

### ✅ Complete Feature Set
- Custom User model with 3 roles (Student, Teacher, Administrator)
- File storage as BLOBs in SQLite
- SHA-256 checksums for all files
- Automatic file compression for large files (>5MB)
- Share links with expiration and permission levels
- Password-protected shares (Argon2 hashing)
- View tracking and metadata
- Full permission system
- Django admin interface
- Comprehensive error handling

### ✅ Security Features
- Argon2 password hashing for users
- PBKDF2/Argon2 for share passwords with salts
- VirusTotal malware scanning (with bypass for testing)
- CSRF protection on all forms
- Role-based access control
- Content-type validation
- Filename sanitization
- SQL injection protection (Django ORM)
- XSS protection (template auto-escaping)

### 📁 Project Structure
```
moodle_site/
├── core/                          # Main app
│   ├── models.py                  # All data models (481 lines)
│   ├── views.py                   # All 5 workflows (468 lines)
│   ├── forms.py                   # All forms with validation
│   ├── urls.py                    # Complete URL patterns
│   ├── admin.py                   # Django admin config
│   └── services/                  # Business logic
│       ├── virustotal_service.py  # VT API integration
│       ├── file_utils.py          # File utilities
│       └── permissions.py         # Permission checking
├── templates/core/                # 9 Django templates
│   ├── file_list.html
│   ├── file_upload.html
│   ├── file_detail.html
│   ├── file_delete.html
│   ├── file_share_create.html
│   ├── share_view.html
│   ├── share_password.html
│   ├── share_expired.html
│   └── share_denied.html
└── migrations/                    # Database migrations
```

### 🧪 Testing Checklist
- [ ] Create user account and login
- [ ] Upload files (different sizes and types)
- [ ] Create share links (with/without passwords)
- [ ] Test share links in incognito mode
- [ ] Download files
- [ ] Delete files
- [ ] Test permissions with different roles
- [ ] View file metadata
- [ ] Test API endpoints with curl
- [ ] Check admin panel

## License

Educational project. See CLAUDE.md for specifications.
