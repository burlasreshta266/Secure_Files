# Secure Files

Django application for secure file storage and sharing.

## Deployment

### Render dashboard environment variables

In your Render **Web Service → Environment** settings, add:

- `DJANGO_ENV=production`
- `SECRET_KEY=<long-random-secret>`
- `ALLOWED_HOSTS=<your-render-service>.onrender.com` (include custom domain too, if used)
- `DATABASE_URL=<Render Postgres internal URL>`
  - or use `DB_NAME` / `DB_USER` / `DB_PASSWORD` / `DB_HOST` / `DB_PORT`

For production safety, keep `DEBUG` unset or set `DEBUG=false`.

Install dependencies:

```bash
pip install -r requirements.txt
```

Run database migrations:

```bash
python manage.py migrate
```

Collect static assets for production:

```bash
python manage.py collectstatic --noinput
```

Start the application with Gunicorn:

```bash
gunicorn securefiles.wsgi:application --bind 0.0.0.0:${PORT:-8000}
```

Recommended production order:

1. `python manage.py migrate`
2. `python manage.py collectstatic --noinput`
3. `gunicorn securefiles.wsgi:application --bind 0.0.0.0:${PORT:-8000}`
