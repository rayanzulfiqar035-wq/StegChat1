# Step 1: Project Setup

**Goal:** a clean project skeleton that starts, reads its configuration from `.env`, and is safe to commit.
**Depends on:** nothing.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 5, 13, 14, 15.

## Create or modify

`app.py`, `extensions.py`, `config.py`, `requirements.txt`, `.env.example`, `.gitignore`, `templates/base.html`, `static/css/style.css`, `docs/` (this specification set).

## Tasks

1. Create the folder layout from main section 13. Empty placeholder files are fine for later steps, but only create what this step needs.
2. Create a virtual environment (`python -m venv venv`) and install: `flask flask-socketio simple-websocket flask-sqlalchemy flask-login flask-wtf flask-talisman flask-limiter argon2-cffi python-dotenv pytest bandit pip-audit`. Then run `pip freeze > requirements.txt`.
3. `config.py`: load `.env` with python-dotenv and expose a `Config` class with the variables from main section 14. `SECRET_KEY` has no default; the app must refuse to start without it.
4. `extensions.py`: create `db`, `login_manager`, `csrf` (`CSRFProtect`) and `socketio` (`async_mode="threading"`). Leave `limiter` and Talisman for Step 8.
5. `app.py`: an application factory `create_app()` that loads config, initialises the extensions, and registers a single route `/` returning a short "server running" page. Add a `__main__` block that runs `socketio.run(app, host="127.0.0.1", port=5000, allow_unsafe_werkzeug=True)`.
6. `.gitignore`: `venv/`, `.env`, `certs/`, `instance/`, `logs/`, `__pycache__/`, `*.db`, `*.pem`.
7. `.env.example`: every variable name from main section 14 with placeholder values only.
8. `templates/base.html`: a minimal layout with a `<meta name="csrf-token">` tag, no inline scripts, and a link to `static/css/style.css`.
9. `git init`, then the first commit.

## Must not do

- Do not add accounts, models, or chat code yet.
- Do not commit `.env` or any key or certificate.

## Acceptance checks

- [ ] `pip install -r requirements.txt` works in a fresh virtual environment.
- [ ] `python app.py` starts without errors and `http://127.0.0.1:5000/` returns 200.
- [ ] Starting without `SECRET_KEY` in `.env` fails with a clear message.
- [ ] `git status` shows `.env`, `venv/`, `certs/`, `instance/` as untracked and ignored.
- [ ] `.env.example` contains no real secret.

## Security checklist

- [ ] No secret is hard-coded anywhere.
- [ ] No debug mode enabled in the code that would be left on by default.

## Commit

`step 1: project scaffold`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_01_setup.md.
Implement ONLY Step 1. First reply with a short plan listing the files you will create.
Wait for my approval before editing. After implementing, run the acceptance checks
and report each one as pass or fail. Do not start Step 2.
```
