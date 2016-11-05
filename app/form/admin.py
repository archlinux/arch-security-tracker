from .base import BaseForm
from app.model.user import User
from app.model.enum import UserRole
from wtforms import StringField, SelectField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Optional, Length, Email
from wtforms.fields.html5 import EmailField
from sqlalchemy import or_


class CreateUserForm(BaseForm):
    username = StringField(u'Username', validators=[DataRequired(), Length(max=User.NAME_LENGTH)])
    email = EmailField(u'E-Mail', validators=[DataRequired(), Length(max=User.EMAIL_LENGTH), Email()])
    password = PasswordField(u'Password', validators=[Optional(), Length(min=User.PASSWORD_MIN_LENGTH)])
    role = SelectField(u'Role', choices=[(e.name, e.label) for e in [*UserRole]], default=UserRole.reporter.name, validators=[DataRequired()])
    create = SubmitField(u'create')

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False

        user = User.query.filter(or_(User.name == self.username.data, User.email == self.email.data)).first()
        if not user:
            return True
        if self.username.data in self.password.data:
            self.password.errors.append('Password must not contain the username.')
        if user.name == self.username.data:
            self.username.errors.append('Username already exists.')
        if user.email == self.email.data:
            self.email.errors.append('E-Mail already exists.')
        return False
