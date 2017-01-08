from werkzeug.exceptions import Unauthorized
from flask import url_for
from flask_login import current_user

from .conftest import logged_in, assert_logged_in, assert_not_logged_in, create_user
from app.user import random_string
from app.form.login import ERROR_ACCOUNT_DISABLED


USERNAME = 'cyberwehr87654321'
PASSWORD = random_string()
EMAIL = '{}@cyber.cyber'.format(USERNAME)


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_delete_user(db, client):
    resp = client.post(url_for('delete_user', username=USERNAME), follow_redirects=True,
                       data=dict(confirm='confirm'))
    resp = client.post(url_for('logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD))
    assert_not_logged_in(resp, status_code=Unauthorized.code)


@logged_in
def test_create_user(db, client):
    resp = client.post(url_for('create_user'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD,
                                 email=EMAIL, active=True))
    assert resp.status_code == 200

    resp = client.post(url_for('logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD))
    assert_logged_in(resp)
    assert USERNAME == current_user.name


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_edit_user(db, client):
    resp = client.post(url_for('edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=EMAIL, password=PASSWORD))
    assert resp.status_code == 200

    resp = client.post(url_for('logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('login'), data={'username': USERNAME, 'password': PASSWORD})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()
