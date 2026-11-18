"""ORM models for the secure chat application.

Users and temporary encrypted deliveries. All columns are defined as in
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


class PendingMessage(db.Model):
    """Ciphertext retained until recipient acknowledgment or expiry."""

    __tablename__ = "pending_messages"
    # SECURITY: never reuse a deleted delivery ID for a later message.
    __table_args__ = {"sqlite_autoincrement": True}
    id: db.Mapped[int] = db.mapped_column(primary_key=True)
    sender_id: db.Mapped[int] = db.mapped_column(db.ForeignKey("users.id"), nullable=False)
    recipient_id: db.Mapped[int] = db.mapped_column(db.ForeignKey("users.id"), nullable=False, index=True)
    kind: db.Mapped[str] = db.mapped_column(db.String(16), nullable=False)
    ciphertext: db.Mapped[str] = db.mapped_column(db.Text, nullable=False)
    iv: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    ephemeral_public_key: db.Mapped[str] = db.mapped_column(db.Text, nullable=False)
    signature: db.Mapped[str] = db.mapped_column(db.Text, nullable=False)
    client_ts: db.Mapped[int] = db.mapped_column(db.BigInteger, nullable=False)
    created_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    sender = db.relationship(User, foreign_keys=[sender_id], lazy="joined")
    recipient = db.relationship(User, foreign_keys=[recipient_id], lazy="joined")

    def envelope(self) -> dict:
        """Rebuild the original signed fields without modifying their encoding."""
        return {"id": self.id, "v": 1, "kind": self.kind,
                "sender": self.sender.username, "recipient": self.recipient.username,
                "ts": self.client_ts, "eph": self.ephemeral_public_key,
                "iv": self.iv, "ct": self.ciphertext, "sig": self.signature}
