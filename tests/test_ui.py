"""Access boundaries and entry navigation for the redesigned workspace."""
import pytest

from test_step6 import BASE, account_hash, app, csrf, login


def test_entry_opens_login_with_registration_link(app):
    client = app.test_client()
    response = client.get("/", base_url=BASE)
    assert response.status_code == 302 and response.location.endswith("/login")
    page = client.get("/", base_url=BASE, follow_redirects=True)
    assert page.status_code == 200 and 'action="/login"' in page.text
    assert 'href="/register"' in page.text
    assert "private-messaging.svg" in page.text
    assert login(app).get("/", base_url=BASE, follow_redirects=True).status_code == 200


@pytest.mark.parametrize("path", ["/stego", "/stego/image", "/stego/audio", "/stego/text"])
def test_new_workspace_pages_require_authentication(app, path):
    response = app.test_client().get(path, base_url=BASE)
    assert response.status_code == 302 and "/login?next=" in response.location
    signed_in = login(app).get(path, base_url=BASE)
    assert signed_in.status_code == 200
    assert 'href="/chat"' in signed_in.text and 'href="/stego"' in signed_in.text
    assert "unsafe-inline" not in signed_in.headers["Content-Security-Policy"]


@pytest.mark.parametrize("path", ["/stego/audio", "/stego/text"])
def test_placeholders_have_no_upload_or_message_endpoint(app, path):
    client = login(app)
    response = client.get(path, base_url=BASE)
    assert "Coming soon" in response.text and "<fieldset disabled" in response.text
    assert "chat.js" not in response.text and "socket.io.min.js" not in response.text
    result = client.post(path, base_url=BASE, headers={
        "Referer": BASE + path, "X-CSRFToken": csrf(client)})
    assert result.status_code == 405
