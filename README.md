# Secure Files

Django application for secure file storage and sharing.

## Deployment

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
