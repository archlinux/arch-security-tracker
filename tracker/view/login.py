from authlib.integrations.base_client.errors import AuthlibBaseError
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from werkzeug.exceptions import Unauthorized

from config import SSO_ENABLED
from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker import oauth
from tracker import tracker
from tracker.form import LoginForm
from tracker.model.user import User
from tracker.user import get_user_role_from_idp_groups
from tracker.user import hash_password
from tracker.user import random_string
from tracker.user import user_assign_new_token
from tracker.user import user_invalidate
from tracker.util import add_params_to_uri
from tracker.view.error import bad_request
from tracker.view.error import forbidden

LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB = "Your email address is associated with a different sub"
LOGIN_ERROR_USERNAME_ASSOCIATE_WITH_DIFFERENT_EMAIL = "Your username is associated with a different email address"
LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME = "Your email address is associated with a different username"
LOGIN_ERROR_EMAIL_ADDRESS_NOT_VERIFIED = "Current email address is not verified"
LOGIN_ERROR_PERMISSION_DENIED = "Not allowed to sign in"
LOGIN_ERROR_MISSING_USER_SUB_FROM_TOKEN = "Missing user sub from token"
LOGIN_ERROR_MISSING_EMAIL_FROM_TOKEN = "Missing email address from token"
LOGIN_ERROR_MISSING_USERNAME_FROM_TOKEN = "Missing username from token"
LOGIN_ERROR_MISSING_GROUPS_FROM_TOKEN = "Missing groups from token"
LOGIN_ERROR_MISSING_USERINFO_FROM_TOKEN = "Missing userinfo from token"


@tracker.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('tracker.index'))

    if SSO_ENABLED:
        # detect if we are being redirected
        args = request.args
        if args.get('state') and args.get('code'):
            return sso_auth()

        redirect_url = url_for('tracker.login', _external=True)
        return oauth.idp.authorize_redirect(redirect_url)

    form = LoginForm()
    if not form.validate_on_submit():
        status_code = Unauthorized.code if form.is_submitted() else 200
        return render_template('login.html',
                               title='Login',
                               form=form,
                               User=User,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX}), status_code

    user = user_assign_new_token(form.user)
    user.is_authenticated = True
    login_user(user)
    return redirect(url_for('tracker.index'))


@tracker.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('tracker.index'))

    user_invalidate(current_user)
    logout_user()

    if SSO_ENABLED:
        metadata = oauth.idp.load_server_metadata()
        end_session_endpoint = metadata.get('end_session_endpoint')
        params = {'redirect_uri': url_for('tracker.index', _external=True)}
        return redirect(add_params_to_uri(end_session_endpoint, params))

    return redirect(url_for('tracker.index'))


def sso_auth():
    try:
        token = oauth.idp.authorize_access_token()
    except AuthlibBaseError as e:
        return bad_request(f'{e.description}')

    userinfo = token.get('userinfo')
    if not userinfo:
        return bad_request(LOGIN_ERROR_MISSING_USERINFO_FROM_TOKEN)

    idp_user_sub = userinfo.get('sub')
    if not idp_user_sub:
        return bad_request(LOGIN_ERROR_MISSING_USER_SUB_FROM_TOKEN)

    idp_email_verified = userinfo.get('email_verified')
    if not idp_email_verified:
        return forbidden(LOGIN_ERROR_EMAIL_ADDRESS_NOT_VERIFIED)

    idp_email = userinfo.get('email')
    if not idp_email:
        return bad_request(LOGIN_ERROR_MISSING_EMAIL_FROM_TOKEN)

    idp_username = userinfo.get('preferred_username')
    if not idp_username:
        return bad_request(LOGIN_ERROR_MISSING_USERNAME_FROM_TOKEN)

    idp_groups = userinfo.get('groups')
    if idp_groups is None:
        return bad_request(LOGIN_ERROR_MISSING_GROUPS_FROM_TOKEN)

    user_role = get_user_role_from_idp_groups(idp_groups)
    if not user_role:
        return forbidden(LOGIN_ERROR_PERMISSION_DENIED)

    # get local user from current authenticated idp id
    user = db.get(User, idp_id=idp_user_sub)

    if not user:
        # get local user from idp email address
        user = db.get(User, email=idp_email)
        if user:
            # prevent impersonation by checking whether this email is associated with an idp id
            if user.idp_id:
                return forbidden(LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB)
            # email is already associated with a different username
            if user.name != idp_username:
                return forbidden(LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME)
        # prevent integrity error for mismatching mail between db and keycloak
        check_user = db.get(User, name=idp_username)
        if check_user and check_user.email != idp_email:
            return forbidden(LOGIN_ERROR_USERNAME_ASSOCIATE_WITH_DIFFERENT_EMAIL)

    if user:
        user.role = user_role
        user.email = idp_email
    else:
        salt = random_string()
        user = db.create(User,
                         name=idp_username,
                         email=idp_email,
                         salt=salt,
                         password=hash_password(random_string(TRACKER_PASSWORD_LENGTH_MAX), salt),
                         role=user_role,
                         active=True,
                         idp_id=idp_user_sub)
        db.session.add(user)

    db.session.commit()
    user = user_assign_new_token(user)
    user.is_authenticated = True
    login_user(user)

    return redirect(url_for('tracker.index'))
