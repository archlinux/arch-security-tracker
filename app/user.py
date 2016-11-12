from flask_login import current_user, login_required
from app import login_manager
from app.model.user import User
from app.view.error import forbidden
from functools import wraps
from scrypt import hash as shash
from base64 import b85encode
from os import urandom


def random_string(length=16):
    salt = b85encode(urandom(length))
    return salt.decode()


def hash_password(password, salt):
    hashed = b85encode(shash(password, salt))
    return hashed.decode()


@login_manager.user_loader
def load_user(user_id):
    user = User.query.filter(User.id == int(user_id)).first()
    user.is_authenticated = True
    return user


def reporter_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.role.is_reporter():
            return forbidden()
        return func(*args, **kwargs)
    return login_required(decorated_view)


def security_team_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.role.is_security_team():
            return forbidden()
        return func(*args, **kwargs)
    return login_required(decorated_view)


def administrator_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.role.is_administrator():
            return forbidden()
        return func(*args, **kwargs)
    return login_required(decorated_view)
