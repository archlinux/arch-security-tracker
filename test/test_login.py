from werkzeug.exceptions import Unauthorized
from flask import url_for
from flask_login import current_user

from .conftest import assert_logged_in, assert_not_logged_in, logged_in, create_user, DEFAULT_USERNAME
from config import TRACKER_PASSWORD_LENGTH_MIN
from app.form.login import ERROR_INVALID_USERNAME_PASSWORD, ERROR_ACCOUNT_DISABLED


def test_login_view(db, client):
    resp = client.get(url_for('login'))
    assert 200 == resp.status_code


@create_user
def test_login_success(db, client):
    resp = client.post(url_for('login'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=DEFAULT_USERNAME))
    assert_logged_in(resp)
    assert DEFAULT_USERNAME == current_user.name


@create_user
def test_login_invalid_credentials(db, client):
    resp = client.post(url_for('login'), data={'username': DEFAULT_USERNAME,
                                               'password': 'N' * TRACKER_PASSWORD_LENGTH_MIN})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_INVALID_USERNAME_PASSWORD in resp.data.decode()


@create_user(active=False)
def test_login_disabled(db, client):
    resp = client.post(url_for('login'), data={'username': DEFAULT_USERNAME, 'password': DEFAULT_USERNAME})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()


@logged_in
def test_logout(db, client):
    resp = client.post(url_for('logout'), follow_redirects=True)
    assert_not_logged_in(resp)
