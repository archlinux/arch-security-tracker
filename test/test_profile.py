from flask import url_for
from flask_login import current_user

from .conftest import logged_in, assert_logged_in, assert_not_logged_in, DEFAULT_USERNAME
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX
from app.form.user import ERROR_PASSWORD_CONTAINS_USERNAME, ERROR_PASSWORD_REPEAT_MISMATCHES, ERROR_PASSWORD_INCORRECT
from app.user import random_string


@logged_in
def test_change_password(db, client):
    new_password = DEFAULT_USERNAME[::-1]
    resp = client.post(url_for('edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password,
                                 password_current=DEFAULT_USERNAME))
    assert resp.status_code == 200

    # logout and test if new password was applied
    resp = client.post(url_for('logout'), follow_redirects=True)
    assert_not_logged_in(resp)
    resp = client.post(url_for('login'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=new_password))
    assert_logged_in(resp)
    assert DEFAULT_USERNAME == current_user.name


@logged_in
def test_invalid_password_length(db, client):
    resp = client.post(url_for('edit_own_user_profile'), follow_redirects=True,
                       data=dict(password='1234', new_password='1234', password_current=DEFAULT_USERNAME))
    assert 'Field must be between {} and {} characters long.' \
           .format(TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX) in resp.data.decode()
    assert resp.status_code == 200


@logged_in
def test_password_must_not_contain_username(db, client):
    new_password = '{}123'.format(DEFAULT_USERNAME)
    resp = client.post(url_for('edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password,
                                 password_current=DEFAULT_USERNAME))
    assert resp.status_code == 200
    assert ERROR_PASSWORD_CONTAINS_USERNAME in resp.data.decode()


@logged_in
def test_password_repeat_mismatches(db, client):
    new_password = random_string()
    resp = client.post(url_for('edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password[::-1],
                                 password_current=DEFAULT_USERNAME))
    assert resp.status_code == 200
    assert ERROR_PASSWORD_REPEAT_MISMATCHES in resp.data.decode()


@logged_in
def test_current_password_incorrect(db, client):
    new_password = random_string()
    resp = client.post(url_for('edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password,
                                 password_current=new_password))
    assert resp.status_code == 200
    assert ERROR_PASSWORD_INCORRECT in resp.data.decode()
