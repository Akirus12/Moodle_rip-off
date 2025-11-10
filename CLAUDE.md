# Implement “The Moodle rip-off” (Django, SQLite, minimal JS)

## Context

We are building a small LMS-like file system with roles (**student, teacher, administrator**), file upload with **VirusTotal** scanning, sharing via UUID + optional password, file viewing/downloading, and deletion. Frontend should be simple Django templates with minimal vanilla JS (no frontend frameworks).

## Tech + constraints

* **Backend:** Python 3.11, **Django**.
* **DB:** **SQLite3**.
* **Storage:** files stored as **BLOBs** in DB (`BinaryField`).
* **Security:** use Django auth & password hashers; avoid MD5 for user passwords. For file-share passwords use strong hashing (Argon2 or PBKDF2). Enforce permission levels.
* **External:** **VirusTotal** file scan API (apikey via `VIRUSTOTAL_API_KEY` env). Use `requests`.
* **Libraries:** keep minimal; only Django + requests + argon2 (if needed). No HTMX/React/etc.
* **Style:** type-annotated Python, PEP8, clear separation of concerns, small functions.
* **Testing:** Django TestCase + minimal integration tests for each use case.

## High-level goals

1. Implement data model exactly matching the ERD (below), with pragmatic Django adjustments.
2. Implement the five workflows from the swimlane diagrams:

   * Upload (with VirusTotal scan & size/limit logic).
   * Create file share (UUID; optional password; salts & hash).
   * Delete file (permission + existence checks).
   * View record metadata (audit last-view/updates).
   * Retrieve file (metadata vs. download; permission & existence checks).
3. Ship minimal pages + forms for each use case; add REST-like JSON endpoints backing them.
4. Add permissions + role gates reflecting **PermissionLevel**.
5. Provide fixtures, seeds, and tests.
6. Deliver a concise README with run steps.

## Planning steps (AI must follow and show a checklist)

1. **Derive models** from ERD → write `models.py` and migrations.
2. **Design permissions**: map `PermissionLevel` to Django `Group`/`Permission` and per-object checks.
3. **Define services**: VirusTotal client, file checksum & size utilities, password hashing for shares.
4. **Define endpoints + templates** per use case.
5. **Implement forms/serializers** with validation.
6. **Write tests** that mirror the swimlane paths (success, branches, errors).
7. **Seed data** for demo.
8. **Harden**: content-type sniffing, size caps, filename sanitation, CSRF, headers.
9. **Document** in README.

## Data model (reflect ERD; adjust field types appropriately)

* `User` (extend `AbstractUser` or link 1-to-1):

  * `role` = enum `student|teacher|administrator`.
* `Course`, `UserCourse` (enrollments), `CoursePrerequisites`.
* `CourseMaterial` (FK Course).
* `Assignment` (FK Course) with `status` enum: `active|due|archived|hidden`.
* `File`

  * `name:str`, `description:str`, `bytes:BinaryField`, `extension:str`,
  * `date_uploaded:datetime`, `checksum_hash:char(64)` (SHA-256), `size:int` (bytes).
  * Relations: stored by CourseMaterial/Assignment as needed (per ERD “Contains/isStoredAs”).
* `FileShare`

  * `url_uuid:uuid`, `expiration_date:datetime|null`,
  * `view_permission_level`, `edit_permission_level`, `download_permission_level` (enum PermissionLevel),
  * `is_password_protected:bool`, `hashed_password:str|null`, `password_salt:str|null`.
* `Message`, `UserMessage` (scheduled/hasRead etc.).
* `PermissionLevel` enum: `public|student|teacher|administrator`.
* Any additional join tables from ERD.

**Notes:**

* Use Django choices/enums for `Role`, `PermissionLevel`, `Status`.
* Add `auto_now_add` / `auto_now` where reasonable.
* Add indexes on `url_uuid`, `checksum_hash`, and FK fields.

## Use-case requirements (implement exactly as flows)

### 1) Upload submission file

* **POST** `/files/upload/` (form + JSON). Inputs: file, name, description.
* Steps:

  1. Save temp in memory; compute size and SHA-256 checksum.
  2. If size > 200MB → **reject** with message.
  3. If size > 5MB → **compress** (zip) before sending to VirusTotal (respect API size caps; if not allowed, send original but mark large).
  4. Call **VirusTotal** (file scan). If response says **Contains Malware** (>=1 malicious engine) → **reject submission**.
  5. Store in DB (`File.bytes` BLOB), with checksum & size.
  6. Show **Confirm submission stored**.
* Keep an audit of VirusTotal report id + verdict.

### 2) Generate file share

* **POST** `/share/create/<file_id>/`
* Validate access to the file.
* Generate `url_uuid`. Optional `password`.
* If password given: generate random salt, hash with Argon2 (or PBKDF2 via Django). Store `is_password_protected=True`, `hashed_password`, `password_salt`.
* Set `view/edit/download` permission levels per form.
* Return share URL `/s/<uuid>`.

### 3) Delete file

* **POST** `/files/<id>/delete/`
* Validate: file exists + user has permission.
* If valid → delete and redirect to success. Else → show **Reject file deletion** with reason.

### 4) Post view request (metadata)

* **POST** `/files/<id>/view/`
* Validate request (existence + permission).
* If invalid → **Deny access**.
* If valid → update file metadata (`last_viewed_at`, viewer id, counter) and return sanitized JSON metadata.
* Response page shows metadata.

### 5) Retrieve file (blob or just metadata)

* **POST/GET** `/files/<id>/get?download=true|false`
* Validate request; if invalid → **Deny access**.
* If valid → fetch `File` + (branch)

  * `download=true` → stream bytes with `Content-Disposition: attachment`.
  * else → return metadata JSON.
* Respect `FileShare` rules when accessed via `/s/<uuid>`; if password protected, prompt and verify hash.

## Permission logic

* Default rule:

  * **Public**: unauthenticated access allowed only via a valid share with `public` level.
  * **Student**: enrolled student or owner.
  * **Teacher**: course teacher or administrator.
  * **Administrator**: superuser.
* On each endpoint, write a decorator or service `check_permission(user, file, action)` that evaluates: direct ownership/enrollment, course/assignment context, and (if via share) the share’s `*_permission_level` and password status.

## VirusTotal integration

* Use `requests`.
* Endpoint: file scan upload, then poll/report (respect rate limits).
* Minimal config in `settings.py` (apikey from env).
* Treat verdict as **malicious if any engine flags malicious**. Store `report_id`, raw summary JSON, and boolean `is_malicious`.
* If VT unavailable → fail closed (reject upload) with user-friendly message.

## Views / URLs / Templates (minimal)

* `/` dashboard.
* `/files/` list + upload form (name, description, file).
* `/files/<id>/` detail with actions: view metadata, download, delete, create share.
* `/share/<file_id>/create/` form with permissions + optional password + expiry.
* `/s/<uuid>` landing page: if password protected → prompt; else show metadata + download button (if allowed).
* Use Django templates and **vanilla JS** only for small UX (form POST, password prompt). CSRF enabled.

## Forms & validation

* Server-side validation for sizes, extensions, MIME sniffing, description length.
* Sanitize filenames; store original separately from safe internal name.
* Zip compression for >5MB (server-side; keep checksum of pre-zip data in a separate column if needed).

## Tests (must pass)

* Upload flow: small clean file → stored; malicious VT verdict → rejected; >200MB → rejected.
* Share flow: UUID generation, password success/failure, permission levels enforced.
* Delete flow: owner vs. unauthorized.
* View/update metadata: increments counter.
* Retrieve: metadata vs. download branches; denied when missing permissions.
* Permissions matrix across roles.

## Project layout

```
Moodle_rip-off/
  CLAUDE.md
  README.md
  Dockerfile
  docker-compose.yml
  requirements.txt

  moodle_site/
    manage.py
    db.sqlite3

    moodle_site/
      __init__.py
      settings.py
      urls.py
      asgi.py
      wsgi.py

    home/                 # simple app with forms/views for auth and home
      __init__.py
      apps.py
      forms.py
      views.py

    administrating/       # placeholder admin-oriented app (scaffolded)
      __init__.py
      apps.py
      admin.py
      models.py
      urls.py
      views.py
      migrations/

    templates/            # Django templates used by installed apps
      base.html
      home.html
      auth_panel.html
      administrating.html

    static/               # static assets (if any)

  templates/              # repository-level (currently unused)
  home/                   # repository-level (currently unused)
```

## Deliverables

* Fully working Django project with migrations, seeds, and minimal templates.
* `.env.example` with `VIRUSTOTAL_API_KEY=`, `DEBUG=`, `SECRET_KEY=`.
* `README.md` with setup, run, and test instructions (`python manage.py runserver`).
* A short SECURITY.md listing key controls (hashing, CSRF, permissions, content-type checks).

## Acceptance criteria

* All five swimlane flows are reproducible via UI and via HTTP calls (document example `curl` commands).
* Permissions behave per `PermissionLevel` and role.
* VirusTotal integration works and blocks malicious samples.
* Files live in SQLite as BLOBs and download correctly.
* Test suite green.
