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

# Run migrations
echo "🗄️  Running database migrations..."
docker compose run --rm web python manage.py migrate

# Create superuser
echo ""
echo "👤 Creating superuser account..."
echo "Please enter the following information:"
docker compose run --rm web python manage.py createsuperuser

echo ""
echo "✅ Setup complete!"
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
