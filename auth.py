"""Authentication blueprint: registration, login and logout.

Routes
------
GET  /register  — show registration form
POST /register  — create account
GET  /login     — show login form
POST /login     — authenticate and start session
POST /logout    — end session (CSRF-protected, POST only)

Security notes are inline with ``# SECURITY:`` markers.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from threading import RLock
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp, ValidationError

from extensions import db, limiter
from models import LoginAttempt, User
from audit import audit_event

auth_bp = Blueprint("auth", __name__)

# SECURITY: use the argon2-cffi default parameters (Argon2id, time_cost=3,
# memory_cost=65536, parallelism=4).  These meet current OWASP recommendations.
_ph = PasswordHasher()

# SECURITY: pre-hash a fixed dummy so an unknown username still runs a full
# Argon2 verification, keeping response time constant and hiding whether a
# username exists.
_DUMMY_HASH: str = _ph.hash("dummy-password-to-prevent-timing-attack")

_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
_login_lock = RLock()


def _utc_now():
    return datetime.now(timezone.utc)


def account_locked(username, now):
    """The fifth failure starts a full 15-minute lock, not a sliding reset."""
    latest = LoginAttempt.query.filter_by(username=username, success=False).order_by(
        LoginAttempt.created_at.desc(), LoginAttempt.id.desc()).limit(5).all()
    if len(latest) < 5:
        return False
    newest = latest[0].created_at.replace(tzinfo=timezone.utc)
    oldest = latest[-1].created_at.replace(tzinfo=timezone.utc)
    return newest - oldest <= timedelta(minutes=15) and now < newest + timedelta(minutes=15)


def authenticate(username, password):
    """Serialize lockout checks and verification to enforce the account cap."""
    with _login_lock:
        locked = account_locked(username, _utc_now())
        user = User.query.filter_by(username=username).first()
        valid = False
        try:
            # SECURITY: perform full verification even for missing/locked users.
            _ph.verify(user.password_hash if user else _DUMMY_HASH, password)
            valid = user is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        if locked:
            # Do not extend the lock window by recording blocked requests.
            audit_event("lockout", username)
            audit_event("login_failure", username)
            return None
        db.session.add(LoginAttempt(username=username, ip=request.remote_addr or "unknown",
                                    success=valid, created_at=_utc_now()))
        if valid and _ph.check_needs_rehash(user.password_hash):
            user.password_hash = _ph.hash(password)
        db.session.commit()
        audit_event("login_success" if valid else "login_failure", username)
        if not valid and account_locked(username, _utc_now()):
            audit_event("lockout", username)
        return user if valid else None


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


class RegisterForm(FlaskForm):
    """Registration form with username, password and confirmation."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=32, message="Username must be 3–32 characters."),
            Regexp(
                r"^[A-Za-z0-9_]{3,32}$",
                message="Username may only contain letters, digits and underscores.",
            ),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, message="Password must be at least 12 characters."),
        ],
    )
    confirm = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords do not match."),
        ],
    )
    submit = SubmitField("Register")

    def validate_username(self, field: StringField) -> None:
        """Reject a username that is already taken (case-insensitive)."""
        normalised = field.data.strip().lower()
        if User.query.filter_by(username=normalised).first():
            raise ValidationError("That username is already taken.")


class LoginForm(FlaskForm):
    """Login form with username and password."""

    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=32),
                          Regexp(r"^[A-Za-z0-9_]{3,32}$")])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_bp.get("/register")
@auth_bp.post("/register")
@limiter.limit("10 per hour", methods=["POST"])
def register() -> str:
    """Show or process the registration form.

    On success the user is redirected to the login page.
    """
    if current_user.is_authenticated:
        return redirect(url_for("auth.chat_placeholder"))

    form = RegisterForm()
    if form.validate_on_submit():
        # SECURITY: normalise to lowercase before storing so 'Alice' == 'alice'.
        username = form.username.data.strip().lower()

        # SECURITY: hash with Argon2id; plaintext password is used only here
        # and is not stored, logged or returned anywhere.
        password_hash = _ph.hash(form.password.data)

        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        audit_event("registration", username)

        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.get("/login")
@auth_bp.post("/login")
@limiter.limit("5 per minute", methods=["POST"])
def login() -> str:
    """Show or process the login form.

    SECURITY: identical error message and dummy hash verification for unknown
    username, so the response time and content do not reveal whether an account
    exists.
    """
    if current_user.is_authenticated:
        return redirect(url_for("auth.chat_placeholder"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        user = authenticate(username, form.password.data)
        if user:
            # Mark the session permanent so PERMANENT_SESSION_LIFETIME applies.
            session.permanent = True
            login_user(user)
            # Redirect to the page the user originally wanted, or /chat.
            next_page = request.args.get("next")
            # SECURITY: only allow relative next-URLs to prevent open redirect.
            # Rejects protocol-relative URLs (//evil.com) and non-local schemes.
            if next_page:
                parsed = urlsplit(next_page)
                if (
                    not parsed.netloc
                    and not parsed.scheme
                    and next_page.startswith("/")
                    and not next_page.startswith(("//", "/\\"))
                ):
                    return redirect(next_page)
            return redirect(url_for("auth.chat_placeholder"))

        # SECURITY: one generic message for wrong username AND wrong password.
        flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


@auth_bp.post("/logout")
@login_required
def logout() -> str:
    """End the session.

    SECURITY: POST-only so a third-party page cannot log the user out with a
    plain <img> or <a> tag.  Flask-WTF CSRFProtect rejects requests that lack a
    valid CSRF token.
    """
    from events import disconnect_user  # deferred to avoid import cycles

    disconnect_user(current_user.id)
    audit_event("logout", current_user.username)
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.get("/chat")
@login_required
def chat_placeholder() -> str:
    """Placeholder chat page — shows the logged-in username and logout button.

    Real chat functionality is added in Step 4.
    """
    return render_template("chat.html")
