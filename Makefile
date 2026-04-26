.PHONY: setup run feeds seed health

# First-time setup
setup:
	@echo "=== S1 Query Assistant v3 — Setup ==="
	@echo "1. Installing Python dependencies..."
	cd backend && pip install -r requirements.txt
	@echo "2. Initializing database..."
	cd backend && python -c "from database import init_db; init_db()"
	@echo "3. Seeding query library (70 queries)..."
	cd backend && python library_seed.py
	@echo "4. Running initial feed fetch..."
	cd backend && python feed_fetcher.py
	@echo ""
	@echo "=== Setup complete ==="
	@echo "Next: Install Ollama + Phi-4-mini (optional but recommended):"
	@echo "  curl -fsSL https://ollama.com/install.sh | sh"
	@echo "  ollama pull phi4-mini"
	@echo ""
	@echo "Then run: make run"

# Start the backend server
run:
	cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Run in production (no reload)
prod:
	cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2

# Fetch threat feeds (also runs via cron)
feeds:
	cd backend && python feed_fetcher.py

# Re-seed the query library
seed:
	cd backend && python library_seed.py

# Health check
health:
	@curl -s http://localhost:8000/api/health | python -m json.tool

# View API docs
docs:
	@echo "Open http://localhost:8000/docs in your browser"
