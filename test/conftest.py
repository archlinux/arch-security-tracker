import pytest

from functools import wraps
from datetime import datetime
from flask import url_for
from flask_login import current_user

from app import app as flask_app, db as flask_db
from app.user import random_string, hash_password
from app.advisory import advisory_get_label
from app.model.user import User
from app.model.enum import UserRole, Severity, Remote, Affected, Publication, affected_to_status
from app.model.advisory import Advisory
from app.model.cve import CVE, issue_types
from app.model.cvegroup import CVEGroup
from app.model.cvegroupentry import CVEGroupEntry
from app.model.cvegrouppackage import CVEGroupPackage
from app.model.package import Package

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


def assert_logged_in(response, status_code=200):
    assert status_code == response.status_code
    assert b'logout' in response.data
    assert b'login' not in response.data
    assert current_user.is_authenticated


def assert_not_logged_in(response, status_code=200):
    assert status_code == response.status_code
    assert b'logout' not in response.data
    assert b'login' in response.data
    assert not current_user.is_authenticated


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


def default_issue_dict(overrides=dict()):
    data = dict(cve=DEFAULT_ISSUE_ID, issue_type=issue_types[0], remote=Remote.unknown.name,
                severity=Severity.unknown.name, description=None, notes=None, reference=None)
    data.update(overrides)
    return data


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


def create_package(func=None, id=None, name=None, base=None, version='1.0-1', arch='any',
                   database='core', description='', url=None, filename='somefile-1.0-1-any.tar.xz',
                   md5sum='md5', sha256sum='sha256', builddate=0):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            package = Package()
            if id:
                package.id = id
            package.name = name
            package.base = base if base else name
            package.version = version
            package.arch = arch
            package.database = database
            package.description = description
            package.url = url
            package.filename = filename
            package.md5sum = md5sum
            package.sha256sum = sha256sum
            package.builddate = builddate

            db.session.add(package)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


DEFAULT_GROUP_ID = 1
DEFAULT_GROUP_NAME = 'AVG-{}'.format(DEFAULT_GROUP_ID)


def default_group_dict(overrides=dict()):
    data = dict(cve=DEFAULT_ISSUE_ID, pkgnames='foopkg', affected='1.0-1', fixed='1.1-1',
                status=Affected.unknown.name, bug_ticket=None, reference=None, notes=None,
                advisory_qualified=True)
    data.update(overrides)
    return data


def create_group(func=None, id=DEFAULT_GROUP_ID, status=None, severity=Severity.unknown,
                 affected='1.0-1', fixed=None, bug_ticket=None, reference=None, notes=None,
                 created=datetime.utcnow(), advisory_qualified=True, issues=[DEFAULT_ISSUE_ID], packages=['foo']):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            group = CVEGroup()
            if id:
                group.id = id
            group.status = status if status else affected_to_status(Affected.affected, packages[0], fixed)
            group.severity = severity
            group.affected = affected
            group.fixed = fixed
            group.bug_ticket = bug_ticket
            group.reference = reference
            group.notes = notes
            group.created = created
            group.advisory_qualified = advisory_qualified

            db.session.add(group)
            db.session.commit()

            for issue in issues:
                cve = db.get_or_create(CVE, id=issue)
                db.get_or_create(CVEGroupEntry, group=group, cve=cve)
            for pkgname in packages:
                db.get_or_create(CVEGroupPackage, pkgname=pkgname, group=group)
            db.session.commit()

            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


DEFAULT_ADVISORY_ID = advisory_get_label()
DEFAULT_ADVISORY_CONTENT = """\nImpact\n======\n\nRobots will take over\n\nReferences\n'
                              \nWorkaround\n==========\n\nUpdate your machine\n\nDescription\n"""


def create_advisory(func=None, id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[0],
                    publication=Publication.scheduled, workaround=None, impact=None, content=None, created=datetime.utcnow(),
                    reference=None):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            advisory = Advisory()
            advisory.id = id
            advisory.group_package_id = group_package_id
            advisory.advisory_type = advisory_type
            advisory.publication = publication
            advisory.workaround = workaround
            advisory.impact = impact
            advisory.content = content
            advisory.created = created
            advisory.reference = reference

            db.session.add(advisory)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


def get_advisory(advisory_id=DEFAULT_ADVISORY_ID):
    return Advisory.query.get(advisory_id)


def advisory_count():
    return len(Advisory.query.all())
