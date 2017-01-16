import pytest

from functools import wraps
from flask import url_for
from flask_login import current_user

from app import app as flask_app, db as flask_db
from app.user import random_string, hash_password
from app.model.user import User
from app.model.enum import UserRole, Severity, Remote
from app.model.cve import CVE, issue_types

DEFAULT_USERNAME = 'cyberwehr12345678'
ERROR_LOGIN_REQUIRED = 'Please log in to access this page.'
ERROR_INVALID_CHOICE = 'Not a valid choice'


@pytest.fixture(scope="session")
def app(request):
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['SERVER_NAME'] = 'localhost'
    with flask_app.app_context():
        yield flask_app


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


@pytest.fixture(scope="session")
def db(request):
    yield flask_db
    flask_db.drop_all()


@pytest.fixture(autouse=True, scope='function')
def run_scoped(app, db, client, request):
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()

        options = dict(bind=connection, binds={})
        session = db.create_scoped_session(options=options)

        db.session = session
        db.create_all()

        with client:
            yield

        db.drop_all()
        transaction.rollback()
        connection.close()
        session.remove()


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


@pytest.fixture
def logged_in(func=None, role=UserRole.administrator, username=DEFAULT_USERNAME, password=None):
    def decorator(func):
        @create_user(role=role, username=username, password=password)
        @wraps(func)
        def wrapper(db, client, *args, **kwargs):
            resp = client.post(url_for('login'), follow_redirects=True,
                               data=dict(username=username, password=password if password else username))
            assert_logged_in(resp)
            func(db=db, client=client, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


@pytest.fixture
def create_user(func=None, username=DEFAULT_USERNAME, password=None, role=UserRole.reporter,
                email=None, salt=None, active=True):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            user = User()
            user.active = active
            user.name = username
            user.password = password if password else username
            user.role = role
            user.email = email if email else '{}@cyber.cyber'.format(username)
            user.salt = salt if salt else random_string()
            user.password = hash_password(user.password, user.salt)

            db.session.add(user)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


DEFAULT_ISSUE_ID = 'CVE-2016-1337'


def default_issue_dict():
    return dict(cve=DEFAULT_ISSUE_ID, issue_type=issue_types[0], remote=Remote.unknown.name,
                severity=Severity.unknown.name, description=None, notes=None, reference=None)


@pytest.fixture
def create_issue(func=None, id=DEFAULT_ISSUE_ID, issue_type=issue_types[0], remote=Remote.unknown,
                 severity=Severity.unknown, description=None, notes=None, reference=None):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            issue = CVE()
            issue.id = id
            issue.issue_type = issue_type
            issue.remote = remote
            issue.severity = severity
            issue.description = description
            issue.notes = notes
            issue.reference = reference

            db.session.add(issue)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)
