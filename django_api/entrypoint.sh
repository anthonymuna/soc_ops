#!/bin/sh
set -e

echo "Waiting for postgres..."
while ! nc -z postgres 5432; do
  sleep 2
done

echo "Waiting for ml_service..."
while ! curl -sf http://ml_service:8000/health > /dev/null 2>&1; do
  sleep 2
done
echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Running migrations..."
python manage.py makemigrations auth_app alerts reports config brain
python manage.py migrate --noinput

echo "Creating superuser..."
if [ "$DJANGO_SUPERUSER_USERNAME" ] && [ "$DJANGO_SUPERUSER_PASSWORD" ]; then
    python manage.py createsuperuser --noinput || echo "Superuser already exists."
fi

echo "Starting Gunicorn..."
exec gunicorn syndicate4.wsgi:application --bind 0.0.0.0:8080 --workers 4 --timeout 120
