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

Render service command settings:

- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn securefiles.wsgi:application --bind 0.0.0.0:$PORT`
- **Pre-Deploy Command**: `python manage.py migrate && python manage.py collectstatic --noinput`

These are codified in `render.yaml`. The `Procfile` still includes a matching `release` command for compatibility.
