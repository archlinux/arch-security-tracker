from base64 import b85encode
from functools import wraps
from os import urandom

from flask_login import current_user
from flask_login import login_required
from scrypt import hash as shash
from sqlalchemy.exc import IntegrityError

from config import SSO_ADMINISTRATOR_GROUP
from config import SSO_ENABLED
from config import SSO_REPORTER_GROUP
from config import SSO_SECURITY_TEAM_GROUP
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker import login_manager
from tracker.model.user import Guest
from tracker.model.user import User
from tracker.model.user import UserRole

login_manager.anonymous_user = Guest


def random_string(length=TRACKER_PASSWORD_LENGTH_MIN):
    salt = b85encode(urandom(length))
    return salt.decode()


def hash_password(password, salt):
    hashed = b85encode(shash(password, salt[:User.SALT_LENGTH]))
    return hashed.decode()[:User.PASSWORD_LENGTH]


@login_manager.user_loader
def load_user(session_token):
    if not session_token:
        return Guest()

    user = User.query.filter_by(token=session_token).first()
    if not user:
        return Guest()
    user.is_authenticated = True
    return user


def permission_required(permission):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not permission.fget(current_user.role):
                from tracker.view.error import forbidden
                return forbidden()
            return func(*args, **kwargs)
        return login_required(decorated_view)
    return decorator


def reporter_required(func):
    return permission_required(UserRole.is_reporter)(func)


def security_team_required(func):
    return permission_required(UserRole.is_security_team)(func)


def administrator_required(func):
    return permission_required(UserRole.is_administrator)(func)


def require_expected_sso_state(expected):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if SSO_ENABLED is not expected:
                from tracker.view.error import not_found
                return not_found()
            return func(*args, **kwargs)
        return decorated_view
    return decorator


def only_with_sso(func):
    return require_expected_sso_state(expected=True)(func)


def only_without_sso(func):
    return require_expected_sso_state(expected=False)(func)


def user_can_edit_issue(advisories=[]):
    role = current_user.role
    if not role.is_reporter:
        return False
    if role.is_security_team:
        return True
    return 0 == len(advisories)


def user_can_delete_issue(advisories=[]):
    role = current_user.role
    if not role.is_reporter:
        return False
    return 0 == len(advisories)


def user_can_edit_group(advisories=[]):
    return user_can_edit_issue(advisories)


def user_can_delete_group(advisories=[]):
    return user_can_delete_issue(advisories)


def user_can_handle_advisory():
    return current_user.role.is_security_team


def user_can_watch_log():
    return True


def user_can_watch_user_log():
    return current_user.role.is_reporter


def user_invalidate(user):
    user.token = None
    user.is_authenticated = False


def user_assign_new_token(user, max_tries=32):
    def assign_token(token):
        user.token = token
        return user
    return user_generate_new_token(assign_token, max_tries)


def user_generate_new_token(callback, max_tries=32):
    failed = 0
    while failed < max_tries:
        try:
            token = random_string(User.TOKEN_LENGTH)
            token_owners = User.query.filter_by(token=token).count()
            if 0 != token_owners:
                failed += 1
                continue
            user = callback(token)
            db.session.commit()
            return user
        except IntegrityError:
            db.session.rollback()
            failed += 1
    raise Exception('Failed to obtain unique token within {} tries'.format(max_tries))


def get_user_role_from_idp_groups(idp_groups):
    group_names_for_roles = {
        SSO_ADMINISTRATOR_GROUP: UserRole.administrator,
        SSO_SECURITY_TEAM_GROUP: UserRole.security_team,
        SSO_REPORTER_GROUP: UserRole.reporter
    }

    eligible_roles = [group_names_for_roles[group] for group in idp_groups if group in group_names_for_roles]

    if eligible_roles:
        return sorted(eligible_roles, reverse=False)[0]
    return None
