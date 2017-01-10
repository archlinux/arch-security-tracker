from .base import BaseForm
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX
from app.model.user import User, username_regex
from app.model.enum import UserRole
from wtforms import StringField, SelectField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Optional, Length, Email, Regexp
from wtforms.fields.html5 import EmailField
from sqlalchemy import or_


ERROR_USERNAME_EXISTS = 'Username already exists.'
ERROR_EMAIL_EXISTS = 'E-Mail already exists.'


class UserForm(BaseForm):
    username = StringField(u'Username', validators=[DataRequired(), Length(max=User.NAME_LENGTH), Regexp(username_regex)])
    email = EmailField(u'E-Mail', validators=[DataRequired(), Length(max=User.EMAIL_LENGTH), Email()])
    password = PasswordField(u'Password', validators=[Optional(), Length(min=TRACKER_PASSWORD_LENGTH_MIN, max=TRACKER_PASSWORD_LENGTH_MAX)])
    role = SelectField(u'Role', choices=[(e.name, e.label) for e in [*UserRole]], default=UserRole.reporter.name, validators=[DataRequired()])
    active = BooleanField(u'Active', default=True)
    random_password = BooleanField(u'Randomize password', default=False)
    submit = SubmitField(u'submit')

    def __init__(self, edit=False):
        super().__init__()
        self.edit = edit

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False

        if self.username.data in self.password.data:
            self.password.errors.append('Password must not contain the username.')
            return False

        if self.edit:
            return True

        user = User.query.filter(or_(User.name == self.username.data,
                                     User.email == self.email.data)).first()
        if not user:
            return True
        if user.name == self.username.data:
            self.username.errors.append(ERROR_USERNAME_EXISTS)
        if user.email == self.email.data:
            self.email.errors.append(ERROR_EMAIL_EXISTS)
        return False
