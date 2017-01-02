import pytest
from .conftest import create_user, USERNAME


@pytest.fixture(autouse=True)
def setup(db):
    create_user(db)


def test_login(client):
    resp = client.post('/login',
                       data=dict(username=USERNAME, password=USERNAME),
                       follow_redirects=True)
    assert 200 == resp.status_code
    assert b'Issues' in resp.data


def test_login_invalid(client):
    resp = client.post('/login', data={'username': USERNAME, 'password': 'nein'})
    assert 200 == resp.status_code
    assert b'Login' in resp.data
