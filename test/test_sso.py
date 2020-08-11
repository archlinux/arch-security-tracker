from unittest.mock import patch

from authlib.integrations.base_client.errors import AuthlibBaseError
from flask_login import current_user
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import Forbidden

from config import SSO_ADMINISTRATOR_GROUP
from config import SSO_REPORTER_GROUP
from config import SSO_SECURITY_TEAM_GROUP
from tracker.model import User
from tracker.model.enum import UserRole
from tracker.user import get_user_role_from_idp_groups
from tracker.view.login import LOGIN_ERROR_EMAIL_ADDRESS_NOT_VERIFIED
from tracker.view.login import LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB
from tracker.view.login import \
    LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME
from tracker.view.login import LOGIN_ERROR_MISSING_EMAIL_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_GROUPS_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_USER_SUB_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_USERNAME_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_PERMISSION_DENIED
from tracker.view.login import \
    LOGIN_ERROR_USERNAME_ASSOCIATE_WITH_DIFFERENT_EMAIL
from tracker.view.login import sso_auth

from .conftest import create_user

DEFAULTEMAIL = "cyberwehr12345678@cyber.cyber"
UPDATEDEMAIL = "cyberwehr1@cyber.cyber"
TESTINGSUB = "wasd"
TESTINGNAME = "Peter"


class MockedIdp(object):
    def __init__(self, username=TESTINGNAME, email=DEFAULTEMAIL, sub=TESTINGSUB, groups=["Administrator"],
                 verified=True, throws=None):
        self.email = email
        self.sub = sub
        self.groups = groups
        self.verified = verified
        self.username = username
        self.throws = throws

    def authorize_access_token(self):
        if self.throws:
            raise self.throws
        return "Schinken"

    def parse_id_token(self, token):
        token = {}
        if self.sub is not None:
            token["sub"] = self.sub
        if self.email is not None:
            token["email"] = self.email
        if self.verified is not None:
            token["email_verified"] = self.verified
        if self.groups is not None:
            token["groups"] = self.groups
        if self.username is not None:
            token["preferred_username"] = self.username
        return token


@patch("tracker.oauth.idp", MockedIdp(email=UPDATEDEMAIL), create=True)
@create_user(email=DEFAULTEMAIL, idp_id=TESTINGSUB)
def test_successful_authentication_and_role_email_update(app, db):
    initial_user = User.query.all()[0]
    assert initial_user.email != UPDATEDEMAIL
    assert initial_user.role != UserRole.administrator

    with app.test_request_context('/login'):
        result = sso_auth()
        assert 302 == result.status_code

        assert len(User.query.all()) == 1
        assert current_user.is_authenticated
        assert current_user.email == UPDATEDEMAIL
        assert current_user.role == UserRole.administrator


@patch('tracker.oauth.idp', MockedIdp(email=DEFAULTEMAIL, sub="STONKS"), create=True)
@create_user(idp_id="wasd")
def test_impersonation_prevention(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB in result.data.decode()

        assert not current_user.is_authenticated


@patch('tracker.oauth.idp', MockedIdp(email=UPDATEDEMAIL, sub="STONKS"), create=True)
@create_user(username=TESTINGNAME, idp_id="wasd")
def test_username_associated_with_different_email(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_USERNAME_ASSOCIATE_WITH_DIFFERENT_EMAIL in result.data.decode()

        assert not current_user.is_authenticated


@patch('tracker.oauth.idp', MockedIdp(email=UPDATEDEMAIL, sub="STONKS"), create=True)
@create_user(username="foobar", email=UPDATEDEMAIL)
def test_email_associated_with_different_username(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME in result.data.decode()

        assert not current_user.is_authenticated


@patch('tracker.oauth.idp', MockedIdp(email=DEFAULTEMAIL), create=True)
def test_jit_provisioning(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert 302 == result.status_code

        assert current_user.is_authenticated
        assert current_user.email == DEFAULTEMAIL
        assert current_user.role == UserRole.administrator
        assert current_user.idp_id == TESTINGSUB
        assert current_user.name == TESTINGNAME
        assert current_user.active


@patch('tracker.oauth.idp', MockedIdp(verified=False), create=True)
def test_verified_email_requirement(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ADDRESS_NOT_VERIFIED in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(groups=["foobar"]), create=True)
def test_permission_denied_lack_of_group(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_PERMISSION_DENIED in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(sub=None), create=True)
def test_missing_sub_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_USER_SUB_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(email=None), create=True)
def test_missing_email_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_EMAIL_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(username=None), create=True)
def test_missing_username_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_USERNAME_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(groups=None), create=True)
def test_missing_group_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_GROUPS_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(throws=AuthlibBaseError(error="foo", description="foo bar error")), create=True)
def test_token_authorization_fails(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert "foo bar error" in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


def test_get_user_role_from_idp_groups_no_match():
    assert get_user_role_from_idp_groups(['random']) is None


def test_get_user_role_from_idp_groups_returns_highest_role():
    assert get_user_role_from_idp_groups([SSO_REPORTER_GROUP, SSO_ADMINISTRATOR_GROUP,
                                          SSO_SECURITY_TEAM_GROUP]).is_administrator


def test_get_user_role_from_idp_groups_same_multiple_times():
    assert get_user_role_from_idp_groups([SSO_REPORTER_GROUP, SSO_REPORTER_GROUP,
                                          "foo", "foo"]).is_reporter
