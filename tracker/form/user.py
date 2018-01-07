from flask_login import current_user
from .base import BaseForm
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX
from tracker.user import hash_password
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from hmac import compare_digest


ERROR_PASSWORD_CONTAINS_USERNAME = 'Password must not contain the username.'
ERROR_PASSWORD_REPEAT_MISMATCHES = 'Repeated password mismatches.'
ERROR_PASSWORD_INCORRECT = 'Current password incorrect.'


class UserPasswordForm(BaseForm):
    password = PasswordField(u'New Password', validators=[DataRequired(), Length(min=TRACKER_PASSWORD_LENGTH_MIN, max=TRACKER_PASSWORD_LENGTH_MAX)])
    password_repeat = PasswordField(u'Repeat Password', validators=[DataRequired(), Length(min=TRACKER_PASSWORD_LENGTH_MIN, max=TRACKER_PASSWORD_LENGTH_MAX)])
    password_current = PasswordField(u'Current Password', validators=[DataRequired(), Length(min=TRACKER_PASSWORD_LENGTH_MIN, max=TRACKER_PASSWORD_LENGTH_MAX)])
    submit = SubmitField(u'submit')

    def __init__(self, edit=False):
        super().__init__()

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False

        if current_user.name in self.password.data:
            self.password.errors.append(ERROR_PASSWORD_CONTAINS_USERNAME)
            return False

        if self.password.data != self.password_repeat.data:
            self.password_repeat.errors.append(ERROR_PASSWORD_REPEAT_MISMATCHES)
            return False

        if not compare_digest(current_user.password, hash_password(self.password_current.data, current_user.salt)):
            self.password_current.errors.append(ERROR_PASSWORD_INCORRECT)
            return False

        return True
