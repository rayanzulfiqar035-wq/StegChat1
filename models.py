"""ORM models for the secure chat application.

Only the `User` model exists in Step 2.  `PendingMessage` and `LoginAttempt`
are added in later steps.  All columns are defined exactly as in
docs/PROJECT_MAIN.md section 9.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask_login import UserMixin

from extensions import db


class User(UserMixin, db.Model):
    """Registered user account.

    Public-key columns are nullable so a user can register before generating
    keys (key upload happens in Step 5).

    SECURITY: `password_hash` is an Argon2id digest; the plaintext password is
    never stored or logged anywhere.
    """

    __tablename__ = "users"

    id: db.Mapped[int] = db.mapped_column(primary_key=True)

    # SECURITY: stored lowercase; enforced at registration so 'Alice' and
    # 'alice' are treated as the same account.
    username: db.Mapped[str] = db.mapped_column(
        db.String(32), unique=True, nullable=False, index=True
    )

    # SECURITY: Argon2id hash only — never the plaintext password.
    password_hash: db.Mapped[str] = db.mapped_column(db.String(255), nullable=False)

    # Public keys are uploaded in Step 5; nullable until then.
    ecdh_public_jwk: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    ecdsa_public_jwk: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)

    created_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    # Flask-Login expects `get_id()` to return a string; UserMixin provides
    # that by calling `str(self.id)`.

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"
