from .base import BaseForm
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX
from app.model.user import User
from app.user import hash_password, random_string
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from hmac import compare_digest


ERROR_INVALID_USERNAME_PASSWORD = 'Invalid username or password.'
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
