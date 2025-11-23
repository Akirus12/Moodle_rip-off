#!/usr/bin/env bash
set -euo pipefail

# Clean local dev artifacts for Moodle_rip-off (caches, DB, Docker volumes, optional venv).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

DO_DOCKER=1
DO_DB=1
DO_PYCACHE=1
DO_VENV=0
FORCE=0

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

usage() {
  cat <<'EOF'
Usage: ./clean.sh [options]

Default behavior:
  - Remove Python caches (*.pyc, __pycache__, .pytest_cache, .ruff_cache)
  - Delete SQLite DB at moodle_site/db.sqlite3 (if present)
  - docker compose down --volumes --remove-orphans (if Docker is available)

Options:
  --skip-docker     Skip Docker containers/volumes cleanup
  --skip-db         Skip deleting the SQLite DB
  --skip-pycache    Skip Python cache cleanup
  --purge-venv      Also delete .venv (prompted unless --force)
  --force           Do not prompt when deleting .venv
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-docker) DO_DOCKER=0 ;;
    --skip-db) DO_DB=0 ;;
    --skip-pycache) DO_PYCACHE=0 ;;
    --purge-venv) DO_VENV=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

log() {
  echo "[clean] $1"
}

clean_pycache() {
  if [[ "$DO_PYCACHE" -eq 0 ]]; then
    log "Skipping Python cache cleanup."
    return
  fi

  log "Removing Python caches..."
  find "$ROOT_DIR" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$ROOT_DIR" -name "*.py[co]" -delete 2>/dev/null || true
  find "$ROOT_DIR" -name ".pytest_cache" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$ROOT_DIR" -name ".ruff_cache" -type d -prune -exec rm -rf {} + 2>/dev/null || true
}

clean_db() {
  if [[ "$DO_DB" -eq 0 ]]; then
    log "Skipping SQLite DB removal."
    return
  fi

  local db_path="$ROOT_DIR/moodle_site/db.sqlite3"
  local db_journal="$ROOT_DIR/moodle_site/db.sqlite3-journal"

  if [[ -f "$db_path" ]]; then
    log "Deleting SQLite DB at $db_path"
    rm -f "$db_path" "$db_journal"
  else
    log "No SQLite DB found at $db_path"
  fi
}

clean_docker() {
  if [[ "$DO_DOCKER" -eq 0 ]]; then
    log "Skipping Docker cleanup."
    return
  fi

  if ! have_cmd docker; then
    log "Docker is not installed; skipping Docker cleanup."
    return
  fi

  local compose_cmd=""
  if docker compose version >/dev/null 2>&1; then
    compose_cmd="docker compose"
  elif have_cmd docker-compose; then
    compose_cmd="docker-compose"
  else
    log "docker compose not available; skipping Docker cleanup."
    return
  fi

  log "Stopping containers and removing volumes via: $compose_cmd"
  $compose_cmd down --volumes --remove-orphans
}

clean_venv() {
  if [[ "$DO_VENV" -eq 0 ]]; then
    log "Skipping .venv removal."
    return
  fi

  local venv_path="$ROOT_DIR/.venv"
  if [[ ! -d "$venv_path" ]]; then
    log "No .venv directory found."
    return
  fi

  if [[ "$FORCE" -eq 0 ]]; then
    read -r -p "Delete virtual environment at $venv_path? [y/N] " reply
    case "$reply" in
      [yY][eE][sS]|[yY]) ;;
      *) log "Aborted .venv removal."; return ;;
    esac
  fi

  log "Deleting virtual environment at $venv_path"
  rm -rf "$venv_path"
}

main() {
  clean_pycache
  clean_db
  clean_docker
  clean_venv
  log "Done."
}

main
