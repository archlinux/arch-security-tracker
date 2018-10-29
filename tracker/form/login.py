import pyotp

from hmac import compare_digest

from wtforms import PasswordField
from wtforms import StringField
from wtforms import SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import Length

from flask import session

from flask_login import current_user

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker.model.user import User
from tracker.user import hash_password
from tracker.user import random_string

from .base import BaseForm

ERROR_INVALID_USERNAME_PASSWORD = 'Invalid username or password.'
ERROR_INVALID_OTP = 'Invalid OTP code.'
ERROR_ACCOUNT_DISABLED = 'Account is disabled.'
dummy_password = hash_password(random_string(), random_string())


class LoginForm(BaseForm):
    username = StringField(u'Username', validators=[DataRequired(), Length(max=User.NAME_LENGTH)])
    password = PasswordField(u'Password', validators=[DataRequired(), Length(min=TRACKER_PASSWORD_LENGTH_MIN, max=TRACKER_PASSWORD_LENGTH_MAX)])
    login = SubmitField(u'login')

    def validate(self):
        self.user = None
        rv = BaseForm.validate(self)
        if not rv:
            return False

        def fail():
            self.password.errors.append(ERROR_INVALID_USERNAME_PASSWORD)
            return False

        user = User.query.filter(User.name == self.username.data).first()
        if not user:
            compare_digest(dummy_password, hash_password(self.password.data, 'the cake is a lie!'))
            return fail()
        if not compare_digest(user.password, hash_password(self.password.data, user.salt)):
            return fail()
        if not user.active:
            self.username.errors.append(ERROR_ACCOUNT_DISABLED)
            return False
        self.user = user
        return True


class OTPForm(BaseForm):
    otp_code = StringField(u'OTP Code', validators=[DataRequired(), Length(max=6)])
    login = SubmitField(u'login')

    def validate(self):
        self.user = None
        rv = BaseForm.validate(self)
        if not rv:
            return False

        def fail():
            self.otp_code.errors.append(ERROR_INVALID_OTP)
            return False

        if not session.get('two_factor'):
            return False

        user = User.query.filter(User.name == session['two_factor']).first()
        totp = pyotp.TOTP(user.otp_token)
        if not totp.verify(self.otp_code.data):
            return fail()
        self.user = user
        return True
