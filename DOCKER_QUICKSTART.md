# Docker Quick Start Guide

This guide will help you run the Moodle Rip-off project using Docker with VirusTotal disabled for testing.

## Prerequisites

- Docker installed
- Docker Compose installed

## Quick Start (Automated)

Run the setup script:

```bash
./docker-setup.sh
```

This will:
1. Build the Docker image
2. Run database migrations
3. Prompt you to create a superuser account
4. Provide instructions to start the server

## Manual Setup

If you prefer to run commands manually:

### 1. Build the Docker Image

```bash
docker compose build
```

### 2. Run Database Migrations

```bash
docker compose run --rm web python manage.py migrate
```

### 3. Create a Superuser

```bash
docker compose run --rm web python manage.py createsuperuser
```

Follow the prompts to create an admin account.

### 4. Start the Server

```bash
docker compose up
```

The server will be available at:
- **Main site:** http://localhost:8000
- **Admin panel:** http://localhost:8000/admin
- **Login:** http://localhost:8000/login

## Important: VirusTotal is DISABLED

By default, the Docker configuration has `DISABLE_VIRUSTOTAL=True` set. This means:

- ✅ Files will be accepted without real malware scanning
- ✅ All files will pass validation automatically
- ✅ You can test file upload/download without a VirusTotal API key
- ⚠️ **Do not use this in production!**

## Manual Testing Workflow

### 1. Create an Account

1. Visit http://localhost:8000
2. Click "Login" or navigate to http://localhost:8000/login
3. Fill out the registration form
4. You'll be logged in automatically

### 2. Upload a File

1. After logging in, click "Upload File" on the dashboard
2. Or navigate to http://localhost:8000/files/upload/
3. Fill in the form:
   - **File Name:** Test Document
   - **Description:** My first test file
   - **File:** Select any file from your computer (up to 200 MB)
4. Click "Upload & Scan"
5. The file will be uploaded without VirusTotal scanning
6. You'll see a success message and be redirected to the file detail page

### 3. View Files

1. Click "View Files" on the dashboard
2. Or navigate to http://localhost:8000/files/
3. You'll see a list of all your uploaded files

### 4. Create a Share Link

1. Go to a file's detail page
2. Click "Create Share Link"
3. Configure permissions:
   - **View Permission:** Who can see file info
   - **Download Permission:** Who can download the file
   - **Edit Permission:** Who can edit metadata
4. Optional: Set a password and expiration
5. Click "Create Share Link"
6. Copy the share URL (format: `/s/<uuid>/`)

### 5. Test Share Link

1. Open an incognito/private browser window
2. Navigate to the share URL: http://localhost:8000/s/<uuid>/
3. If password-protected, enter the password
4. You should see the file information
5. If permissions allow, you can download the file

### 6. Delete a File

1. Go to the file's detail page
2. Click "Delete" button
3. Confirm the deletion
4. File will be removed along with all its shares

## Testing with Different Roles

### Set User Roles via Admin Panel

1. Login to admin panel: http://localhost:8000/admin
2. Go to "Users"
3. Click on a user
4. Change the "Role" field to:
   - **student** (default)
   - **teacher**
   - **administrator**
5. Save

### Role Permissions

- **Student:** Can upload files, view files they have access to
- **Teacher:** Can create shares, delete files in their courses
- **Administrator:** Full access to all files

## Useful Docker Commands

### View Logs

```bash
docker compose logs -f
```

### Stop the Server

Press `Ctrl+C` in the terminal where `docker compose up` is running

Or run:
```bash
docker compose down
```

### Restart the Server

```bash
docker compose restart
```

### Access Django Shell

```bash
docker compose run --rm web python manage.py shell
```

### Run Django Commands

```bash
docker compose run --rm web python manage.py <command>
```

### Clean Up Everything

```bash
docker compose down -v  # Removes containers and volumes (deletes database!)
```

## Testing API Endpoints

### Upload File via curl

```bash
curl -X POST http://localhost:8000/files/upload/ \
  -H "Cookie: sessionid=YOUR_SESSION" \
  -F "name=API Upload Test" \
  -F "description=Uploaded via API" \
  -F "file=@/path/to/file.pdf" \
  -F "csrfmiddlewaretoken=YOUR_CSRF_TOKEN"
```

### Get File Metadata (JSON)

```bash
curl -X GET http://localhost:8000/files/1/get/ \
  -H "Cookie: sessionid=YOUR_SESSION"
```

### Download File

```bash
curl -X GET http://localhost:8000/files/1/get/?download=true \
  -H "Cookie: sessionid=YOUR_SESSION" \
  -o downloaded_file
```

### View Metadata (POST - updates view counter)

```bash
curl -X POST http://localhost:8000/files/1/view/ \
  -H "Cookie: sessionid=YOUR_SESSION" \
  -H "X-CSRFToken: YOUR_CSRF_TOKEN"
```

## Re-enabling VirusTotal

To enable VirusTotal scanning:

1. Get an API key from https://www.virustotal.com/gui/my-apikey
2. Edit `docker-compose.yml`:
   ```yaml
   environment:
     - VIRUSTOTAL_API_KEY=your-api-key-here
     - DISABLE_VIRUSTOTAL=False
   ```
3. Restart the container:
   ```bash
   docker compose down
   docker compose up
   ```

## Troubleshooting

### Port 8000 Already in Use

If you see "port is already allocated":

```bash
# Find what's using port 8000
sudo lsof -i :8000

# Stop the process or change the port in docker-compose.yml
ports:
  - "8001:8000"  # Change external port to 8001
```

### Database Locked Error

If you see "database is locked":

```bash
# Stop all containers
docker compose down

# Start again
docker compose up
```

### Permission Errors

If you see permission errors with volumes:

```bash
# Fix permissions
sudo chown -R $USER:$USER moodle_site/
```

### Reset Database

```bash
# Stop containers
docker compose down -v

# Remove database
rm moodle_site/db.sqlite3

# Run migrations again
docker compose run --rm web python manage.py migrate

# Create superuser again
docker compose run --rm web python manage.py createsuperuser
```

## File Size Limits for Testing

Current limits (configured in settings.py):
- **Maximum file size:** 200 MB
- **Large file threshold:** 5 MB (would trigger compression for VT, but disabled in testing)

To change these limits, edit `moodle_site/moodle_site/settings.py` and restart the container.

## Next Steps

Once you've tested manually:

1. Review the code in `moodle_site/core/`
2. Check the models in `models.py`
3. Explore the views in `views.py`
4. Look at the security features in `services/permissions.py`
5. Read the full documentation in `README.md` and `SECURITY.md`

## Getting Help

- Check server logs: `docker compose logs -f`
- Check Django errors in the browser (DEBUG=True is enabled)
- Review CLAUDE.md for project specifications
- Read README.md for detailed usage information
