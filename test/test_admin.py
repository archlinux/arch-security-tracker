from flask import url_for
from flask_login import current_user
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound
from werkzeug.exceptions import Unauthorized

from tracker.form.admin import ERROR_EMAIL_EXISTS
from tracker.form.admin import ERROR_USERNAME_EXISTS
from tracker.form.login import ERROR_ACCOUNT_DISABLED
from tracker.model.enum import UserRole
from tracker.user import random_string

from .conftest import DEFAULT_USERNAME
from .conftest import assert_logged_in
from .conftest import assert_not_logged_in
from .conftest import create_user
from .conftest import logged_in

USERNAME = 'cyberwehr87654321'
PASSWORD = random_string()
EMAIL = '{}@cyber.cyber'.format(USERNAME)


@create_user(username=USERNAME, password=PASSWORD, role=UserRole.administrator)
@logged_in
def test_delete_user(db, client):
    resp = client.post(url_for('tracker.delete_user', username=USERNAME), follow_redirects=True,
                       data=dict(confirm='confirm'))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD))
    assert_not_logged_in(resp, status_code=Unauthorized.code)


@logged_in
def test_delete_last_admin_fails(db, client):
    resp = client.post(url_for('tracker.delete_user', username=DEFAULT_USERNAME), follow_redirects=True,
                       data=dict(confirm='confirm'))
    assert resp.status_code == Forbidden.code


@logged_in
def test_delete_user_not_found(db, client):
    resp = client.post(url_for('tracker.delete_user', username='nobody'), follow_redirects=True,
                       data=dict(confirm='confirm'))
    assert resp.status_code == NotFound.code


@logged_in
def test_create_user(db, client):
    role = UserRole.security_team
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD,
                                 email=EMAIL, active=True, role=role.name))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD))
    assert_logged_in(resp)
    assert USERNAME == current_user.name
    assert EMAIL == current_user.email
    assert role == current_user.role


@logged_in
def test_create_duplicate_user_fails(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=PASSWORD,
                                 email=EMAIL, active=True))
    assert resp.status_code == 200
    assert ERROR_USERNAME_EXISTS in resp.data.decode()


@logged_in
def test_create_duplicate_email_fails(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD,
                                 email=current_user.email, active=True))
    assert resp.status_code == 200
    assert ERROR_EMAIL_EXISTS in resp.data.decode()


@logged_in
def test_create_incomplete_form(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(email=EMAIL, active=True))
    assert resp.status_code == 200
    assert 'This field is required.' in resp.data.decode()


@logged_in
def test_create_user_in_password(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=USERNAME,
                           password=USERNAME+PASSWORD, email=EMAIL,
                           active=True))
    assert resp.status_code == 200
    assert 'Password must not contain the username.' in resp.data.decode()


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_edit_user(db, client):
    new_password = random_string()
    new_email = '{}foo'.format(EMAIL)
    new_role = UserRole.security_team
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=new_email, password=new_password,
                       role=new_role.name, active=True))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data={'username': USERNAME, 'password': new_password})
    assert_logged_in(resp)
    assert USERNAME == current_user.name
    assert new_email == current_user.email
    assert new_role == current_user.role


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_edit_preserves_password(db, client):
    new_email = '{}foo'.format(EMAIL)
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=new_email, active=True))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data={'username': USERNAME, 'password': PASSWORD})
    assert_logged_in(resp)
    assert USERNAME == current_user.name
    assert new_email == current_user.email


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_deactive_user(db, client):
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=EMAIL, password=PASSWORD))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), data={'username': USERNAME, 'password': PASSWORD})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()


@create_user(username=USERNAME, password=PASSWORD)
@logged_in(role=UserRole.security_team)
def test_edit_requires_admin(db, client):
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=EMAIL, password=PASSWORD))
    assert resp.status_code == Forbidden.code


@create_user(username=USERNAME, password=PASSWORD)
@logged_in(role=UserRole.security_team)
def test_list_user(db, client):
    resp = client.get(url_for('tracker.list_user'), follow_redirects=True)
    assert resp.status_code == 200
    assert USERNAME in resp.data.decode()
