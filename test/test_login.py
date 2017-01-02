import pytest

from werkzeug.exceptions import Unauthorized
from flask import url_for
from flask_login import current_user

from .conftest import create_user, USERNAME
from config import TRACKER_PASSWORD_LENGTH_MIN
from app.form.login import ERROR_INVALID_USERNAME_PASSWORD, ERROR_ACCOUNT_DISABLED


@pytest.fixture(autouse=True)
def setup(db):
    create_user(db)


@pytest.fixture
def assert_logged_in(response, status_code=200):
    assert status_code == response.status_code
    assert b'logout' in response.data
    assert b'login' not in response.data
    assert current_user.is_authenticated


@pytest.fixture
def assert_not_logged_in(response, status_code=200):
    assert status_code == response.status_code
    assert b'logout' not in response.data
    assert b'login' in response.data
    assert not current_user.is_authenticated


def test_login_success(client):
    resp = client.post(url_for('login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=USERNAME))
    assert_logged_in(resp)
    assert USERNAME == current_user.name


def test_login_invalid_credentials(client):
    resp = client.post(url_for('login'), data={'username': USERNAME,
                                               'password': 'N' * TRACKER_PASSWORD_LENGTH_MIN})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_INVALID_USERNAME_PASSWORD in resp.data.decode()


def test_login_disabled(client, db):
    username = 'deactivated-user-account'
    create_user(db, username=username, active=False)
    resp = client.post(url_for('login'), data={'username': username, 'password': username})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()


def test_logout(client):
    resp = client.post(url_for('login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=USERNAME))
    assert_logged_in(resp)
    resp = client.post(url_for('logout'), follow_redirects=True)
    assert_not_logged_in(resp)
