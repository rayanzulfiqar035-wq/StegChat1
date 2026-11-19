"""Shared phonebook authorization for HTTP changes and encrypted delivery."""
from threading import RLock

from sqlalchemy import case, or_, select

from models import PhonebookContact

# SECURITY: the single-process threading server serializes contact revocation
# with message storage, live forwarding and reconnect delivery under one lock.
contact_lock = RLock()


def contact_between(first_id: int, second_id: int):
    """Find one canonical relationship; self-contact is never permitted."""
    if first_id == second_id:
        return None
    low, high = sorted((first_id, second_id))
    return PhonebookContact.query.filter_by(user_a_id=low, user_b_id=high).first()


def is_approved(first_id: int, second_id: int) -> bool:
    """Only an explicitly accepted request grants messaging permission."""
    contact = contact_between(first_id, second_id)
    return contact is not None and contact.accepted


def approved_peer_ids(user_id: int):
    """Build a subquery so unauthorized rows cannot consume the replay limit."""
    return select(case(
        (PhonebookContact.user_a_id == user_id, PhonebookContact.user_b_id),
        else_=PhonebookContact.user_a_id,
    )).where(PhonebookContact.accepted.is_(True), or_(
        PhonebookContact.user_a_id == user_id, PhonebookContact.user_b_id == user_id))
