# Secure Files

Django application for secure file storage and sharing.

## PythonAnywhere Deployment

This project is now configured to work well on PythonAnywhere:

- settings can load a local `.env` file automatically
- static assets can be collected into `staticfiles`
- production can use either SQLite or a server database

### 1. Create a virtualenv and install dependencies

```bash
pip install -r requirements.txt
```

### 2. Add a `.env` file in the project root

Example:

```env
DJANGO_ENV=production
DEBUG=false
SECRET_KEY=replace-this-with-a-long-random-secret
ALLOWED_HOSTS=yourusername.pythonanywhere.com
CSRF_TRUSTED_ORIGINS=https://yourusername.pythonanywhere.com
SQLITE_PATH=/home/yourusername/securefiles/db.sqlite3
```

If you want to use a server database instead, set either:

- `DATABASE_URL=postgres://...` or `mysql://...`
- or `DB_ENGINE`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, and optional `DB_PORT`

### 3. Run migrations and collect static files

```bash
python manage.py migrate
python manage.py collectstatic --noinput
```

### 4. Configure static files in PythonAnywhere

In the PythonAnywhere **Web** tab, add this static mapping:

- URL: `/static/`
- Directory: `/home/yourusername/securefiles/staticfiles`

### 5. Configure the WSGI file

Use the template in `pythonanywhere_wsgi.py.example` and copy its contents into your PythonAnywhere WSGI configuration file.

Update these values first:

- `/home/yourusername/securefiles`
- `/home/yourusername/.virtualenvs/your-venv-name`
- `yourusername`

### 6. Reload the web app

After saving the WSGI file and static mapping, reload the app from the **Web** tab.

## Other Platforms

The old Render files are still present:

- `render.yaml`
- `Procfile`

They are no longer the primary deployment path, but they remain usable if you deploy there again later.
