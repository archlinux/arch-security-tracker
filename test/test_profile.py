from flask import url_for
from flask_login import current_user

from .conftest import logged_in, assert_logged_in, assert_not_logged_in, DEFAULT_USERNAME
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX


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
