# Step 2: Accounts (Registration, Login, Logout)

**Goal:** users can register and log in. Passwords are stored only as Argon2id hashes.
**Depends on:** Step 1.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 9, 10 (the `/register`, `/login`, `/logout`, `/chat` rows).

## Create or modify

`models.py`, `auth.py`, `app.py`, `config.py`, `templates/login.html`, `templates/register.html`, `templates/chat.html`, `static/css/style.css`.

## Tasks

1. `models.py`: the `User` model exactly as in main section 9 (public key columns exist but stay empty for now).
2. Registration form (Flask-WTF `FlaskForm`): username must match `^[A-Za-z0-9_]{3,32}$` and is stored **lowercase**; password at least 12 characters; password confirmation. Reject a duplicate username with a normal form error.
3. Hash with `argon2.PasswordHasher` (defaults are fine). Store only the hash. After a successful `verify`, call `check_needs_rehash` and update the hash if needed.
4. Login form: look up the user and verify the password. Use **one generic message** ("Invalid username or password") for an unknown user and for a wrong password. When the username does not exist, still run a dummy hash verification so the response time does not reveal which usernames exist.
5. Flask-Login: `user_loader`, `login_required` on `/chat`, and an unauthorised handler that redirects to `/login`.
6. Logout is a **POST** with a CSRF token (a small form with a button), never a plain link.
7. Sessions: set `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`, `PERMANENT_SESSION_LIFETIME` from `SESSION_MINUTES`, and mark the session permanent at login. (`SESSION_COOKIE_SECURE` is switched on in Step 3.)
8. `/chat` shows the logged-in username and the logout button, nothing else yet.
9. Create the tables at startup with `db.create_all()` (SQLite file under `instance/`).
10. Every form is rendered by Jinja2 with the CSRF token included.

## Must not do

- Do not store or log plaintext passwords, even temporarily.
- Do not use SHA-256, MD5 or bcrypt for passwords; Argon2id only.
- Do not add key handling or chat yet.

## Acceptance checks

- [ ] Registering creates a row whose `password_hash` starts with `$argon2id$` (check with DB Browser for SQLite or `sqlite3`).
- [ ] The login error text is identical for a wrong password and for an unknown username.
- [ ] `/chat` redirects to `/login` when logged out, and works when logged in.
- [ ] Logout works only via POST with a valid CSRF token; a POST without the token is rejected.
- [ ] Usernames `Alice` and `alice` cannot both exist.
- [ ] A 5-character password is rejected.
- [ ] The session cookie has `HttpOnly` and `SameSite=Lax` (DevTools, Application tab).

## Security checklist

- [ ] Password only ever handled inside the hash and verify calls.
- [ ] No username or password appears in logs or error pages.

## Commit

`step 2: accounts with argon2`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_02_accounts.md.
Implement ONLY Step 2. First reply with a short plan listing the files you will
create or change. Wait for my approval before editing. After implementing, run the
acceptance checks and report each one as pass or fail. Do not start Step 3.
```
