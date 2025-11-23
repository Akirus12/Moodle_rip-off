#!/bin/bash

# Docker Setup Script for Moodle Rip-off
# This script sets up and runs the Django app in Docker with VirusTotal disabled for testing

set -e

echo "=================================="
echo "Moodle Rip-off Docker Setup"
echo "=================================="
echo ""

# Build the Docker image
echo "📦 Building Docker image..."
docker compose build

# Run makemigrations
echo "Running makemigrations..."
docker compose run --rm web python manage.py makemigrations

# Run migrations
echo "Applying database migrations..."
docker compose run --rm web python manage.py migrate

echo ""

# --- CHECK FOR EXISTING SUPERUSER ---
echo "Checking for existing superuser..."

SUPERUSER_NAME=$(docker compose run --rm web \
  python manage.py shell -c \
  "from django.contrib.auth import get_user_model; User=get_user_model(); u=User.objects.filter(is_superuser=True).first(); print(u.username if u else '')")

if [ -n "$SUPERUSER_NAME" ]; then
  echo "Superuser already exists (${SUPERUSER_NAME})."

  # Ask: create another?
  read -p "Do you want to create another superuser? [y/N]: " CREATE_NEW
  CREATE_NEW=${CREATE_NEW,,}  # lowercase normalize

  if [[ "$CREATE_NEW" == "y" || "$CREATE_NEW" == "yes" ]]; then
    echo ""
    echo "Creating an additional superuser..."
    docker compose run --rm web python manage.py createsuperuser
  else
    echo "Skipping superuser creation."
  fi
else
  echo "No superuser found."
  echo "Creating initial superuser now..."
  docker compose run --rm web python manage.py createsuperuser
fi

echo ""
echo "Setup complete!"
echo ""
echo "To start the server, run:"
echo "  docker compose up"
echo ""
echo "Then visit: http://localhost:8000"
echo "Admin panel: http://localhost:8000/admin"
echo ""
echo "VirusTotal scanning is DISABLED for testing."
echo "Files will be accepted without real malware scanning."
echo ""
