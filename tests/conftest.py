import pytest

from app import app as flask_app, db as flask_db
from app.user import random_string, hash_password
from app.model.user import User
from app.model.enum import UserRole

USERNAME = 'cyberwehr12345678'


@pytest.fixture(scope="session")
def app(request):
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
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
def run_scoped(app, db, request):
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()

        options = dict(bind=connection, binds={})
        session = db.create_scoped_session(options=options)

        db.session = session
        db.create_all()

        yield

        db.drop_all()
        transaction.rollback()
        connection.close()
        session.remove()


def create_user(db, username=USERNAME, password=None, role=UserRole.reporter,
                email=None, salt=None, active=True):
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
    return user
